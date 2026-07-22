// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Settlement Layer Wallet RPCs (BP30)
 *
 * Wallet operations for the settlement layer:
 * - lock: M0 → Vault + M1 Receipt (TX_LOCK)
 * - unlock: Vault + M1 → M0 (TX_UNLOCK)
 * - transfer_m1: Transfer M1 receipt to another address
 * - split_m1: Split M1 receipt into multiple receipts
 * - getwalletstate: Get settlement state of wallet (includes M1 receipts)
 *
 * All operations use M0/M1 nomenclature.
 */

#include "rpc/server.h"

#ifdef ENABLE_WALLET

#include "key_io.h"
#include "net/net.h"
#include "script/sign.h"
#include "state/settlement.h"
#include "state/settlement_builder.h"
#include "state/settlementdb.h"
#include "htlc/htlc.h"
#include "htlc/htlcdb.h"
#include "script/conditional.h"
#include "script/template_hash.h"
#include "core_io.h"
#include "crypto/sha256.h"
#include "random.h"
#include "txmempool.h"
#include "validation.h"
#include "utilmoneystr.h"
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include "support/cleanse.h"

#include <limits>

#include <univalue.h>

/**
 * lock - Lock M0 into Vault, receive M1 receipt
 *
 * Creates a TX_LOCK transaction:
 * - Input: M0 (standard UTXO)
 * - Output[0]: Vault (M0 locked)
 * - Output[1]: M1 Receipt (transferable claim)
 *
 * Invariant effect: M0_vaulted += P, M1_supply += P
 */
static UniValue lock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "lock amount\n"
            "\nLock M0 into a Vault and receive an M1 receipt (TX_LOCK).\n"
            "\nArguments:\n"
            "1. amount    (numeric, required) Amount of M0 to lock\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",           (string) Transaction ID\n"
            "  \"vault_outpoint\": \"...\", (string) Vault UTXO outpoint\n"
            "  \"receipt_outpoint\": \"...\", (string) M1 Receipt outpoint\n"
            "  \"amount\": x.xxx           (numeric) Amount locked\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("lock", "100.0")
            + HelpExampleRpc("lock", "100.0")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse amount
    CAmount lockAmount = AmountFromValue(request.params[0]);
    if (lockAmount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Lock amount must be positive");
    }

    // Estimate total needed (amount + fee buffer)
    CAmount feeEstimate = 500;  // Fee estimate (1 M0 = 1 sat model)
    CAmount totalNeeded = lockAmount + feeEstimate;

    // Get available coins
    std::vector<COutput> vAvailableCoins;
    pwallet->AvailableCoins(&vAvailableCoins);

    // Filter out settlement layer UTXOs (Vaults, Receipts) - only M0 standard can be locked
    if (g_settlementdb) {
        std::vector<COutput> vM0Coins;
        for (const COutput& out : vAvailableCoins) {
            COutPoint outpoint(out.tx->GetHash(), out.i);
            if (g_settlementdb->IsM0Standard(outpoint)) {
                vM0Coins.push_back(out);
            }
        }
        vAvailableCoins = std::move(vM0Coins);
    }

    // Select coins
    std::set<std::pair<const CWalletTx*, unsigned int>> setCoins;
    CAmount nValueIn = 0;
    if (!pwallet->SelectCoinsToSpend(vAvailableCoins, totalNeeded, setCoins, nValueIn)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient funds. Need %s M0", FormatMoney(totalNeeded)));
    }

    // Build LockInput vector
    std::vector<LockInput> inputs;
    for (const auto& coin : setCoins) {
        LockInput input;
        input.outpoint = COutPoint(coin.first->GetHash(), coin.second);
        input.amount = coin.first->tx->vout[coin.second].nValue;
        input.scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
        inputs.push_back(input);
    }

    // Generate new addresses for receipt and change
    // BP30 v2.0: Vault uses OP_TRUE script (no address needed - consensus-protected)
    CPubKey receiptPubKey;
    if (!pwallet->GetKeyFromPool(receiptPubKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out");
    }
    CScript receiptDest = GetScriptForDestination(receiptPubKey.GetID());

    CPubKey changePubKey;
    if (!pwallet->GetKeyFromPool(changePubKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out");
    }
    CScript changeDest = GetScriptForDestination(changePubKey.GetID());

    // Build the lock transaction
    // BP30 v2.0: No vaultDest parameter - vault uses OP_TRUE (consensus-protected)
    LockResult lockResult = BuildLockTransaction(inputs, lockAmount, receiptDest, changeDest);

    if (!lockResult.success) {
        throw JSONRPCError(RPC_WALLET_ERROR, lockResult.error);
    }

    // Sign the transaction
    CMutableTransaction& mtx = lockResult.mtx;

    // Create a const CTransaction for signing
    const CTransaction txConst(mtx);

    for (size_t i = 0; i < mtx.vin.size(); i++) {
        const COutPoint& prevout = mtx.vin[i].prevout;

        // Find the input in our selected coins
        const CWalletTx* pwtx = nullptr;
        for (const auto& coin : setCoins) {
            if (coin.first->GetHash() == prevout.hash && coin.second == prevout.n) {
                pwtx = coin.first;
                break;
            }
        }

        if (!pwtx) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to find input transaction");
        }

        const CScript& scriptPubKey = pwtx->tx->vout[prevout.n].scriptPubKey;
        const CAmount& amount = pwtx->tx->vout[prevout.n].nValue;

        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, i, amount, SIGHASH_ALL),
                             scriptPubKey, sigdata, txConst.GetRequiredSigVersion())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing failed");
        }
        UpdateTransaction(mtx, i, sigdata);
    }

    // Convert to CTransactionRef and commit via wallet
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    // Use wallet's CommitTransaction for proper handling
    CReserveKey reserveKey(pwallet);
    const CWallet::CommitResult& res = pwallet->CommitTransaction(tx, reserveKey, g_connman.get());

    if (res.status != CWallet::CommitStatus::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Transaction commit failed: %s", res.ToString()));
    }

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("vault_outpoint", strprintf("%s:%d", tx->GetHash().GetHex(), 0));
    result.pushKV("receipt_outpoint", strprintf("%s:%d", tx->GetHash().GetHex(), 1));
    result.pushKV("amount", ValueFromAmount(lockAmount));
    result.pushKV("fee", ValueFromAmount(lockResult.fee));

    return result;
}

/**
 * unlock - Burn M1 to recover M0 from vault pool (Bearer Asset Model)
 *
 * BP30 v2.1: M1 is a bearer asset with partial unlock support.
 * Specify amount and destination - M1 receipts are auto-selected.
 * If unlock amount < M1 input(s), M1 change is returned.
 *
 * Creates a TX_UNLOCK transaction:
 * - Input[0..N]: M1 Receipts (auto-selected from wallet)
 * - Input[N+1..K]: Vaults (auto-selected, OP_TRUE no signature)
 * - Input[K+1..]: M0 standard (for network fee)
 * - Output[0]: M0 to destination (unlocked)
 * - Output[1]: M1 change receipt (if partial unlock)
 * - Output[2]: M0 fee change (if any)
 *
 * Settlement layer conservation (A6 strict):
 *   sum(M1_in) == M0_out + sum(M1_change)
 *
 * Network fee is paid from separate M0 inputs (wallet layer).
 *
 * Invariant effect:
 * - M0_vaulted -= unlockAmount
 * - M1_supply -= (M1_in - M1_change)  // net burn
 */
static UniValue unlock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "unlock amount ( destination )\n"
            "\nBurn M1 to recover M0 from vault pool (TX_UNLOCK).\n"
            "\nBP30 v2.1 Bearer Asset Model:\n"
            "M1 is a bearer asset - burn M1 to claim M0 from any vault.\n"
            "Specify the amount you want to unlock. M1 receipts are\n"
            "automatically selected from your wallet.\n"
            "If your M1 receipt(s) exceed the unlock amount, you get\n"
            "M1 change back as a new receipt.\n"
            "\nNetwork fee is deducted from M1 balance (M1 fee model).\n"
            "\nArguments:\n"
            "1. amount        (numeric, required) Amount of M0 to unlock\n"
            "2. destination   (string, optional) Destination address for M0 output\n"
            "                                    (default: new wallet address)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",               (string) Transaction ID\n"
            "  \"m0_unlocked\": x.xxx,         (numeric) M0 amount recovered\n"
            "  \"m1_burned\": x.xxx,           (numeric) Net M1 burned\n"
            "  \"m1_change\": x.xxx,           (numeric) M1 change (if any)\n"
            "  \"m1_change_outpoint\": \"...\", (string) M1 change receipt (if any)\n"
            "  \"vaults_used\": n,             (numeric) Number of vaults consumed\n"
            "  \"fee\": x.xxx                  (numeric) Network fee (paid in M1)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("unlock", "100.0")
            + HelpExampleCli("unlock", "100.0 \"yDestinationAddress\"")
            + HelpExampleRpc("unlock", "100.0, \"yDestinationAddress\"")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse unlock amount
    CAmount unlockAmount = AmountFromValue(request.params[0]);
    if (unlockAmount <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unlock amount must be positive");
    }

    // Verify settlement DB is available
    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    }

    // Get destination script (from param or generate new)
    CScript destScript;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        CTxDestination dest = DecodeDestination(request.params[1].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
        }
        destScript = GetScriptForDestination(dest);
    } else {
        CPubKey destPubKey;
        if (!pwallet->GetKeyFromPool(destPubKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out");
        }
        destScript = GetScriptForDestination(destPubKey.GetID());
    }

    // Generate M1 change destination (always new address)
    CPubKey m1ChangePubKey;
    if (!pwallet->GetKeyFromPool(m1ChangePubKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out");
    }
    CScript m1ChangeScript = GetScriptForDestination(m1ChangePubKey.GetID());

    // Get available M1 receipts from wallet
    CWallet::AvailableCoinsFilter filter;
    filter.fExcludeSettlement = false;  // Include settlement UTXOs
    filter.minDepth = 1;  // Require at least 1 confirmation for unlock
    std::vector<COutput> vCoins;
    pwallet->AvailableCoins(&vCoins, nullptr, filter);

    // Collect M1 receipts (select smallest receipts first for efficient change)
    std::vector<std::pair<COutput, M1Receipt>> m1Candidates;
    CAmount totalM1Available = 0;

    for (const COutput& out : vCoins) {
        COutPoint outpoint(out.tx->GetHash(), out.i);
        if (g_settlementdb->IsM1Receipt(outpoint)) {
            M1Receipt receipt;
            if (g_settlementdb->ReadReceipt(outpoint, receipt)) {
                m1Candidates.push_back({out, receipt});
                totalM1Available += receipt.amount;
            }
        }
    }

    // Sort by amount (smallest first - better for change efficiency)
    std::sort(m1Candidates.begin(), m1Candidates.end(),
              [](const auto& a, const auto& b) {
                  return a.second.amount < b.second.amount;
              });

    // BP30 v3.0: M1 selection covers unlockAmount + estimated fee (M1 fee model)
    CAmount estimatedFee = 145;  // Conservative estimate matching builder minimum
    if (totalM1Available < unlockAmount + estimatedFee) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient M1 balance. Have %s, need %s (unlock=%s + fee~%s)",
                      FormatMoney(totalM1Available), FormatMoney(unlockAmount + estimatedFee),
                      FormatMoney(unlockAmount), FormatMoney(estimatedFee)));
    }

    // Select M1 receipts to cover unlockAmount + fee margin
    std::vector<M1Input> m1Inputs;
    CAmount selectedM1 = 0;

    for (const auto& candidate : m1Candidates) {
        if (selectedM1 >= unlockAmount + estimatedFee) break;

        const COutput& out = candidate.first;
        const M1Receipt& receipt = candidate.second;

        M1Input m1Input;
        m1Input.outpoint = receipt.outpoint;
        m1Input.amount = receipt.amount;
        m1Input.scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        m1Inputs.push_back(m1Input);
        selectedM1 += receipt.amount;
    }

    // Find vault(s) from the global pool to cover the unlock amount
    std::vector<VaultEntry> vaultEntries;
    if (!g_settlementdb->FindVaultsForAmount(unlockAmount, vaultEntries)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Insufficient vault balance. Need %s M0 but no matching vaults found. "
                      "This could indicate a settlement layer invariant violation.",
                      FormatMoney(unlockAmount)));
    }

    // Build VaultInputs (no scriptPubKey needed - OP_TRUE)
    std::vector<VaultInput> vaultInputs;
    for (const auto& vaultEntry : vaultEntries) {
        VaultInput vaultInput;
        vaultInput.outpoint = vaultEntry.outpoint;
        vaultInput.amount = vaultEntry.amount;
        vaultInputs.push_back(vaultInput);
    }

    // Build settlement TX (conservation strict: M1_in == M0_out + M1_change)
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs, vaultInputs, unlockAmount, destScript, m1ChangeScript);

    if (!unlockResult.success) {
        throw JSONRPCError(RPC_WALLET_ERROR, unlockResult.error);
    }

    CMutableTransaction& mtx = unlockResult.mtx;

    // =========================================================================
    // BP30 v3.0: M1 fee model - NO M0 fee inputs required
    // Fee is paid from M1 receipt (deducted by BuildUnlockTransaction)
    // =========================================================================

    // =========================================================================
    // SIGNING
    // =========================================================================

    const CTransaction txConst(mtx);

    // Sign M1 receipt inputs (indices 0..m1Inputs.size()-1)
    for (size_t i = 0; i < m1Inputs.size(); i++) {
        const CScript& scriptPubKey = m1Inputs[i].scriptPubKey;
        const CAmount& amount = m1Inputs[i].amount;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, i, amount, SIGHASH_ALL),
                             scriptPubKey, sigdata, txConst.GetRequiredSigVersion())) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                strprintf("Signing M1 receipt input %d failed. Do you own this receipt?", i));
        }
        UpdateTransaction(mtx, i, sigdata);
    }

    // Vault inputs use OP_TRUE - no signature needed (already empty by default)
    // Vault indices: m1Inputs.size() .. m1Inputs.size() + vaultInputs.size() - 1

    // Commit transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    CReserveKey reserveKey(pwallet);
    const CWallet::CommitResult& res = pwallet->CommitTransaction(tx, reserveKey, g_connman.get());

    if (res.status != CWallet::CommitStatus::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Transaction commit failed: %s", res.ToString()));
    }

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("m0_unlocked", ValueFromAmount(unlockResult.unlockedAmount));
    result.pushKV("m1_burned", ValueFromAmount(unlockResult.m1Burned));
    result.pushKV("m1_change", ValueFromAmount(unlockResult.m1Change));
    if (unlockResult.m1Change > 0) {
        result.pushKV("m1_change_outpoint",
            strprintf("%s:%d", tx->GetHash().GetHex(), 1));
    }
    result.pushKV("vaults_used", (int)vaultInputs.size());
    result.pushKV("fee", ValueFromAmount(unlockResult.fee));

    return result;
}

/**
 * transfer_m1 - Transfer M1 receipt to a new owner
 *
 * Creates a TX_TRANSFER_M1 transaction:
 * - Input[0]: M1 Receipt (old owner)
 * - Input[1+]: M0 fee inputs (optional)
 * - Output[0]: M1 Receipt (new owner, same amount)
 * - Output[1]: M0 change (optional)
 *
 * Invariant effect: M1_supply unchanged (receipt changes owner, not supply)
 */
static UniValue transfer_m1(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "transfer_m1 receipt_outpoint destination\n"
            "\nTransfer an M1 receipt to a new owner (TX_TRANSFER_M1).\n"
            "\nArguments:\n"
            "1. receipt_outpoint    (string, required) M1 Receipt outpoint (txid:vout)\n"
            "2. destination         (string, required) Destination address for new owner\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",              (string) Transaction ID\n"
            "  \"new_receipt\": \"txid:vout\", (string) New M1 Receipt outpoint\n"
            "  \"amount\": x.xxx,             (numeric) M1 amount transferred\n"
            "  \"fee\": x.xxx                 (numeric) Fee paid\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("transfer_m1", "\"abc123:1\" \"yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo\"")
            + HelpExampleRpc("transfer_m1", "\"abc123:1\", \"yJYD2bfYYBe6qAojSzMKX949H7QoQifNAo\"")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse receipt outpoint (txid:n format)
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    }

    uint256 txid;
    txid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t receiptVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));

    COutPoint receiptOutpoint(txid, receiptVout);

    // Verify receipt is M1
    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    }
    if (!g_settlementdb->IsM1Receipt(receiptOutpoint)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint is not a valid M1 receipt");
    }

    // Parse destination address
    CTxDestination dest = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
    }
    CScript newDest = GetScriptForDestination(dest);

    // Get the wallet transaction for the receipt
    auto it = pwallet->mapWallet.find(txid);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Receipt transaction not found in wallet");
    }
    const CWalletTx& wtx = it->second;

    if (receiptVout >= wtx.tx->vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output index");
    }

    // Build TransferInput
    TransferInput transferInput;
    transferInput.receiptOutpoint = receiptOutpoint;
    transferInput.amount = wtx.tx->vout[receiptVout].nValue;
    transferInput.scriptPubKey = wtx.tx->vout[receiptVout].scriptPubKey;

    // Build the transfer transaction (M1 fee model: fee deducted from the receipt)
    TransferResult transferResult = BuildTransferTransaction(transferInput, newDest);

    if (!transferResult.success) {
        throw JSONRPCError(RPC_WALLET_ERROR, transferResult.error);
    }

    // Sign the transaction
    CMutableTransaction& mtx = transferResult.mtx;
    const CTransaction txConst(mtx);

    // Sign receipt input (vin[0])
    {
        const CScript& scriptPubKey = transferInput.scriptPubKey;
        const CAmount& amount = transferInput.amount;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, 0, amount, SIGHASH_ALL),
                             scriptPubKey, sigdata, txConst.GetRequiredSigVersion())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing receipt input failed");
        }
        UpdateTransaction(mtx, 0, sigdata);
    }

    // BP30 v3.0: M1 fee model - no M0 fee inputs, fee is paid from M1
    // The builder only creates 1 input (M1 receipt), no fee inputs to sign

    // Calculate actual fee (M1 fee model: fee = input - recipient output)
    CAmount actualFee = transferInput.amount - mtx.vout[0].nValue;

    // Commit transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    CReserveKey reserveKey(pwallet);
    const CWallet::CommitResult& res = pwallet->CommitTransaction(tx, reserveKey, g_connman.get());

    if (res.status != CWallet::CommitStatus::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Transaction commit failed: %s", res.ToString()));
    }

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("new_receipt", strprintf("%s:%d", tx->GetHash().GetHex(), 0));
    result.pushKV("amount", ValueFromAmount(transferInput.amount));
    result.pushKV("fee", ValueFromAmount(actualFee));

    return result;
}

/**
 * split_m1 - Split M1 receipt into multiple smaller receipts (UTXO change)
 *
 * BP30 v3.0: Enables partial unlocks via UTXO splitting.
 * Same TX_TRANSFER_M1 type, but with multiple outputs.
 *
 * Creates a TX_TRANSFER_M1 transaction:
 * - Input[0]: M1 Receipt (only input)
 * - Output[0..N-1]: New M1 Receipts (splits)
 * - Output[N]: M1 fee output (OP_TRUE, block producer claims)
 *
 * Invariant effect: M1_supply unchanged (redistribution + fee)
 * Fee: paid from M1 (deducted from split amounts)
 */
static UniValue split_m1(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "split_m1 receipt_outpoint outputs\n"
            "\nSplit an M1 receipt into multiple smaller receipts (TX_TRANSFER_M1).\n"
            "\nBP30 v2.4: Enables partial unlocks - split a large receipt,\n"
            "then unlock only the portion you need.\n"
            "\nM1 CONSERVATION: sum(outputs) + fee == receipt amount.\n"
            "Fee is paid from M1 (deducted from the receipt).\n"
            "\nArguments:\n"
            "1. receipt_outpoint    (string, required) M1 Receipt outpoint (txid:vout)\n"
            "2. outputs             (array, required) Array of output objects:\n"
            "   [\n"
            "     {\n"
            "       \"address\": \"...\",  (string) Destination address\n"
            "       \"amount\": x.xxx     (numeric) Amount for this output\n"
            "     }, ...\n"
            "   ]\n"
            "\nRules:\n"
            "- Minimum 2 outputs (otherwise use transfer_m1)\n"
            "- sum(outputs) + fee == receipt amount\n"
            "- Fee paid from M1 (deducted automatically)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",              (string) Transaction ID\n"
            "  \"new_receipts\": [             (array) New M1 Receipt outpoints\n"
            "    \"txid:0\", \"txid:1\", ...\n"
            "  ],\n"
            "  \"amounts\": [x.xxx, ...],     (array) Amount per receipt\n"
            "  \"fee\": x.xxx                 (numeric) Network fee\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("split_m1", "\"abc123:1\" '[{\"address\":\"yAddr1\",\"amount\":2},{\"address\":\"yAddr2\",\"amount\":8}]'")
            + HelpExampleRpc("split_m1", "\"abc123:1\", [{\"address\":\"yAddr1\",\"amount\":2},{\"address\":\"yAddr2\",\"amount\":8}]")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse receipt outpoint (txid:n format)
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    }

    uint256 txid;
    txid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t receiptVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));

    COutPoint receiptOutpoint(txid, receiptVout);

    // Verify settlement DB
    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    }
    if (!g_settlementdb->IsM1Receipt(receiptOutpoint)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint is not a valid M1 receipt");
    }

    // Parse outputs array
    const UniValue& outputsParam = request.params[1];
    if (!outputsParam.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "outputs must be an array");
    }
    if (outputsParam.size() < 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "split_m1 requires at least 2 outputs. For single output, use transfer_m1");
    }

    std::vector<SplitOutput> outputs;
    for (size_t i = 0; i < outputsParam.size(); i++) {
        const UniValue& outObj = outputsParam[i];
        if (!outObj.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %d must be an object", i));
        }

        // Get address
        const UniValue& addrVal = outObj["address"];
        if (!addrVal.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %d: address must be a string", i));
        }
        CTxDestination dest = DecodeDestination(addrVal.get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Output %d: invalid address", i));
        }

        // Get amount
        const UniValue& amtVal = outObj["amount"];
        CAmount amount = AmountFromValue(amtVal);
        if (amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %d: amount must be positive", i));
        }

        SplitOutput splitOut;
        splitOut.destination = GetScriptForDestination(dest);
        splitOut.amount = amount;
        outputs.push_back(splitOut);
    }

    // Get the wallet transaction for the receipt
    auto it = pwallet->mapWallet.find(txid);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Receipt transaction not found in wallet");
    }
    const CWalletTx& wtx = it->second;

    if (receiptVout >= wtx.tx->vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output index");
    }

    // Build TransferInput
    TransferInput transferInput;
    transferInput.receiptOutpoint = receiptOutpoint;
    transferInput.amount = wtx.tx->vout[receiptVout].nValue;
    transferInput.scriptPubKey = wtx.tx->vout[receiptVout].scriptPubKey;

    // BP30 v3.0: Verify outputs don't exceed receipt (fee will be deducted)
    CAmount totalOutput = 0;
    for (const auto& out : outputs) {
        totalOutput += out.amount;
    }
    if (totalOutput >= transferInput.amount) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("sum(outputs)=%s must be less than receipt=%s (M1 fee is deducted)",
                     FormatMoney(totalOutput), FormatMoney(transferInput.amount)));
    }

    // Build the split transaction (M1 fee model: fee deducted from the split)
    SplitResult splitResult = BuildSplitTransaction(transferInput, outputs);

    if (!splitResult.success) {
        throw JSONRPCError(RPC_WALLET_ERROR, splitResult.error);
    }

    // Sign the transaction
    CMutableTransaction& mtx = splitResult.mtx;
    const CTransaction txConst(mtx);

    // Sign receipt input (vin[0])
    {
        const CScript& scriptPubKey = transferInput.scriptPubKey;
        const CAmount& amount = transferInput.amount;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, 0, amount, SIGHASH_ALL),
                             scriptPubKey, sigdata, txConst.GetRequiredSigVersion())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing receipt input failed. Do you own this M1 receipt?");
        }
        UpdateTransaction(mtx, 0, sigdata);
    }

    // BP30 v3.0: M1 fee model - no M0 fee inputs, fee is paid from M1
    // The builder only creates 1 input (M1 receipt), no fee inputs to sign

    // Calculate actual fee (M1 fee model: fee output is the last vout)
    CAmount actualFee = splitResult.fee;

    // Commit transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    CReserveKey reserveKey(pwallet);
    const CWallet::CommitResult& res = pwallet->CommitTransaction(tx, reserveKey, g_connman.get());

    if (res.status != CWallet::CommitStatus::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Transaction commit failed: %s", res.ToString()));
    }

    // Build result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());

    UniValue newReceipts(UniValue::VARR);
    UniValue amounts(UniValue::VARR);
    for (size_t i = 0; i < outputs.size(); i++) {
        newReceipts.push_back(strprintf("%s:%d", tx->GetHash().GetHex(), i));
        amounts.push_back(ValueFromAmount(outputs[i].amount));
    }
    result.pushKV("new_receipts", newReceipts);
    result.pushKV("amounts", amounts);
    result.pushKV("fee", ValueFromAmount(actualFee));

    return result;
}

/**
 * sweepfees - collect pinned fee-receipts into spendable M0 (B4.4 O2b / O1).
 *
 * Fee-receipts (TRANSFER fee + covenant HTLC-claim fee, OP_TRUE outputs) are
 * registered at connect with an owner = the including block's coinbase vout[0]
 * script (UPGRADE_FEE_RECEIPT_PINNED). The spend covenant routes their value to
 * that owner regardless of WHO builds the sweep, and every sweep input is
 * OP_TRUE — so this RPC needs NO signatures: it scans DB_FEE_OWNER, groups by
 * owner (the covenant demands one owner per tx), and for each requested owner
 * builds a full-redeem TX_UNLOCK paying the owner script.
 */
extern void RelayTx(const uint256& hashTx);

static UniValue sweepfees(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "sweepfees ( \"owner_address\" dry_run )\n"
            "\nSweep producer-pinned fee-receipts (TRANSFER / covenant HTLC-claim fees)\n"
            "into spendable M0 paid to their registered owner script.\n"
            "Anyone may run this: the destination covenant forces the value to the\n"
            "owner, so sweeping is a service, never a theft.\n"
            "\nArguments:\n"
            "1. owner_address (string, optional) Sweep only fee-receipts owned by this\n"
            "                                    address's P2PKH script. Default: all owners.\n"
            "2. dry_run       (boolean, optional, default=false) List sweepable fees only.\n"
            "\nResult:\n"
            "{\n"
            "  \"owners\": [                  (array) one entry per owner script\n"
            "    {\n"
            "      \"owner\": \"address|hex\",  (string) owner script (address if standard)\n"
            "      \"receipts\": n,           (numeric) fee-receipts found\n"
            "      \"total\": x,              (numeric) total owned sats\n"
            "      \"txid\": \"hex\"            (string) sweep txid (absent on dry_run)\n"
            "    }, ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("sweepfees", "")
            + HelpExampleCli("sweepfees", "\"yOwnerAddress\" true")
        );
    }

    LOCK(cs_main);

    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    }

    // Optional owner filter.
    bool haveFilter = false;
    CScript filterScript;
    if (request.params.size() > 0 && !request.params[0].isNull() && !request.params[0].get_str().empty()) {
        CTxDestination dest = DecodeDestination(request.params[0].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid owner address");
        }
        filterScript = GetScriptForDestination(dest);
        haveFilter = true;
    }
    const bool dryRun = request.params.size() > 1 && request.params[1].get_bool();

    // Group live fee-receipts by owner. An entry may be stale (receipt already
    // swept — DB_FEE_OWNER is only erased on reorg-undo, not on spend), so keep
    // only outpoints that are still live M1 receipts.
    std::map<std::vector<unsigned char>, std::vector<std::pair<COutPoint, CAmount>>> byOwner;
    g_settlementdb->ForEachFeeOwner([&](const COutPoint& op, const CScript& owner) {
        if (haveFilter && owner != filterScript) return true;
        M1Receipt r;
        if (!g_settlementdb->ReadReceipt(op, r)) return true;  // stale entry
        byOwner[std::vector<unsigned char>(owner.begin(), owner.end())]
            .emplace_back(op, r.amount);
        return true;
    });

    UniValue owners(UniValue::VARR);
    for (const auto& kv : byOwner) {
        const CScript ownerScript(kv.first.begin(), kv.first.end());
        CAmount total = 0;
        for (const auto& rc : kv.second) total += rc.second;

        UniValue entry(UniValue::VOBJ);
        CTxDestination ownerDest;
        if (ExtractDestination(ownerScript, ownerDest)) {
            entry.pushKV("owner", EncodeDestination(ownerDest));
        } else {
            entry.pushKV("owner", HexStr(std::vector<unsigned char>(ownerScript.begin(), ownerScript.end())));
        }
        entry.pushKV("receipts", (int)kv.second.size());
        entry.pushKV("total", total);

        if (!dryRun) {
            // Full-redeem unlock: all owned fee-receipts -> M0 to the owner script.
            std::vector<M1Input> m1Inputs;
            for (const auto& rc : kv.second) {
                M1Input in;
                in.outpoint = rc.first;
                in.amount = rc.second;
                in.scriptPubKey = CScript() << OP_TRUE;
                m1Inputs.push_back(in);
            }
            std::vector<VaultEntry> vaultEntries;
            if (!g_settlementdb->FindVaultsForAmount(total, vaultEntries)) {
                entry.pushKV("error", "insufficient vaults to back the sweep");
                owners.push_back(entry);
                continue;
            }
            std::vector<VaultInput> vaultInputs;
            for (const auto& v : vaultEntries) {
                VaultInput vi;
                vi.outpoint = v.outpoint;
                vi.amount = v.amount;
                vaultInputs.push_back(vi);
            }
            // unlockAmount=0 => full redeem: m0Out = total - fee. Change script is
            // never used on a full redeem, but the covenant requires any change to
            // pay the owner anyway — pass the owner script.
            UnlockResult res = BuildUnlockTransaction(m1Inputs, vaultInputs,
                                                      /*unlockAmount=*/0,
                                                      ownerScript, ownerScript);
            if (!res.success) {
                entry.pushKV("error", res.error);
                owners.push_back(entry);
                continue;
            }
            // Every input is OP_TRUE (fee receipts + vaults): no signing. Relay
            // through the mempool like any other tx.
            CTransactionRef tx = MakeTransactionRef(std::move(res.mtx));
            CValidationState state;
            bool missingInputs = false;
            if (!AcceptToMemoryPool(mempool, state, tx, true, &missingInputs, false, true)) {
                entry.pushKV("error", strprintf("mempool rejected: %s%s",
                                                state.GetRejectReason(),
                                                missingInputs ? " (missing inputs)" : ""));
                owners.push_back(entry);
                continue;
            }
            RelayTx(tx->GetHash());
            entry.pushKV("txid", tx->GetHash().GetHex());
            entry.pushKV("m0_swept", res.unlockedAmount);
            entry.pushKV("fee", res.fee);
        }
        owners.push_back(entry);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("owners", owners);
    return result;
}

/**
 * getwalletstate - Unified wallet view (bp30.wallet.v1)
 *
 * One RPC to see everything:
 * - M0 balance (transparent)
 * - M1 receipts (with count, total, and optional list)
 *
 * Design: INTENT-focused (what can I do with my assets?)
 */
static UniValue getwalletstate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "getwalletstate ( verbose )\n"
            "\nReturns unified wallet state (bp30.wallet.v1 schema).\n"
            "\nArguments:\n"
            "1. verbose    (boolean, optional, default=false) Include full asset lists with vault status\n"
            "\nResult:\n"
            "{\n"
            "  \"schema\": \"bp30.wallet.v1\",\n"
            "  \"m0\": {\n"
            "    \"balance\": \"x.xxxxxxxx\",\n"
            "    \"unconfirmed\": \"x.xxxxxxxx\"\n"
            "  },\n"
            "  \"m1\": {\n"
            "    \"count\": n,\n"
            "    \"total\": \"x.xxxxxxxx\",\n"
            "    \"unlockable\": \"x.xxxxxxxx\",    (only receipts with active vault)\n"
            "    \"orphan_count\": n,               (receipts without active vault, if any)\n"
            "    \"receipts\": [                    (only if verbose=true)\n"
            "      {\n"
            "        \"outpoint\": \"txid:n\",\n"
            "        \"amount\": x.xxx,\n"
            "        \"confirmations\": n,\n"
            "        \"receipt_status\": \"confirmed|unconfirmed\",\n"
            "        \"vault_status\": \"active|closed|db_missing\",\n"
            "        \"vault_outpoint\": \"txid:n\",\n"
            "        \"unlockable\": true|false\n"
            "      }, ...\n"
            "    ]\n"
            "  },\n"
            "  \"total_value\": \"x.xxxxxxxx\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletstate", "")
            + HelpExampleCli("getwalletstate", "true")
            + HelpExampleRpc("getwalletstate", "")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    // Parse verbose parameter - accept bool, string "true"/"false", or object {"verbose": bool}
    bool verbose = false;
    if (request.params.size() > 0) {
        const UniValue& param = request.params[0];
        if (param.isBool()) {
            verbose = param.get_bool();
        } else if (param.isStr()) {
            std::string s = param.get_str();
            verbose = (s == "true" || s == "1");
        } else if (param.isObject()) {
            const UniValue& v = param["verbose"];
            if (v.isBool()) verbose = v.get_bool();
            else if (v.isStr()) verbose = (v.get_str() == "true");
        }
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue result(UniValue::VOBJ);
    result.pushKV("schema", "bp30.wallet.v1");

    // Get unconfirmed balance for reporting
    CAmount m0Unconfirmed = pwallet->GetUnconfirmedBalance();

    // Get all coins
    CWallet::AvailableCoinsFilter filter;
    filter.fExcludeSettlement = false;  // Include settlement UTXOs
    filter.minDepth = 0;
    std::vector<COutput> vCoins;
    pwallet->AvailableCoins(&vCoins, nullptr, filter);

    // Separate M0, M1, Vault
    CAmount m0AvailableTotal = 0;
    CAmount m1Total = 0;
    CAmount m1Unlockable = 0;  // Only receipts with active vault
    int m1Count = 0;
    int m1OrphanCount = 0;  // Receipts without active vault
    UniValue m1Receipts(UniValue::VARR);

    for (const COutput& out : vCoins) {
        COutPoint outpoint(out.tx->GetHash(), out.i);
        CAmount value = out.tx->tx->vout[out.i].nValue;

        if (g_settlementdb && g_settlementdb->IsM1Receipt(outpoint)) {
            m1Total += value;
            m1Count++;

            // BP30 v2.0: Bearer model - M1 status check
            std::string receiptStatus = "unknown";

            M1Receipt receipt;
            if (g_settlementdb->ReadReceipt(outpoint, receipt)) {
                // Receipt exists in settlement DB - it's unlockable
                receiptStatus = "active";
                m1Unlockable += value;
            } else {
                receiptStatus = "db_missing";  // Receipt in wallet but not in settlement DB
                m1OrphanCount++;
            }

            if (verbose) {
                UniValue r(UniValue::VOBJ);
                r.pushKV("outpoint", strprintf("%s:%d", outpoint.hash.GetHex(), outpoint.n));
                r.pushKV("amount", ValueFromAmount(value));
                r.pushKV("confirmations", out.nDepth);
                r.pushKV("receipt_status", out.nDepth > 0 ? "confirmed" : "unconfirmed");
                r.pushKV("settlement_status", receiptStatus);
                // BP30 v2.0: Bearer model - all active M1 is unlockable (from any vault)
                r.pushKV("unlockable", receiptStatus == "active");
                m1Receipts.push_back(r);
            }
        } else if (g_settlementdb && g_settlementdb->IsVault(outpoint)) {
            // Skip vaults - they're backing M1, not spendable
        } else {
            // M0 standard
            m0AvailableTotal += value;
        }
    }

    // M0 section
    UniValue m0(UniValue::VOBJ);
    m0.pushKV("balance", ValueFromAmount(m0AvailableTotal));
    m0.pushKV("unconfirmed", ValueFromAmount(m0Unconfirmed > m0AvailableTotal ?
                                              m0Unconfirmed - m0AvailableTotal : 0));
    result.pushKV("m0", m0);

    // M1 section
    UniValue m1(UniValue::VOBJ);
    m1.pushKV("count", m1Count);
    m1.pushKV("total", ValueFromAmount(m1Total));
    m1.pushKV("unlockable", ValueFromAmount(m1Unlockable));
    if (m1OrphanCount > 0) {
        m1.pushKV("orphan_count", m1OrphanCount);
    }
    if (verbose) {
        m1.pushKV("receipts", m1Receipts);
    }
    result.pushKV("m1", m1);

    // Total value
    CAmount totalValue = m0AvailableTotal + m1Total;
    result.pushKV("total_value", ValueFromAmount(totalValue));

    return result;
}

// =============================================================================
// HTLC RPCs (BP02)
// =============================================================================

/**
 * htlc_generate - Generate secret and hashlock for HTLC
 *
 * Returns a cryptographically secure random secret and its SHA256 hash.
 * The secret is used to claim the HTLC, the hashlock is shared publicly.
 */
static UniValue htlc_generate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "htlc_generate\n"
            "\nGenerate a secret/hashlock pair for HTLC atomic swap.\n"
            "\nResult:\n"
            "{\n"
            "  \"secret\": \"hex\",    (string) 32-byte random secret (keep private!)\n"
            "  \"hashlock\": \"hex\"   (string) SHA256(secret) - share this publicly\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc_generate", "")
        );
    }

    // Generate 32 bytes of cryptographic random
    std::vector<unsigned char> secret(32);
    GetStrongRandBytes(secret.data(), 32);

    // Compute SHA256
    uint256 hashlock;
    CSHA256().Write(secret.data(), 32).Finalize(hashlock.begin());

    UniValue result(UniValue::VOBJ);
    result.pushKV("secret", HexStr(secret));
    // Output hashlock in same byte order as input (NOT GetHex which reverses)
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));
    return result;
}

/**
 * htlc_list - List HTLC records
 *
 * Lists HTLCs known to the node, optionally filtered by status.
 */
static UniValue htlc_list(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "htlc_list ( \"status\" )\n"
            "\nList HTLC records.\n"
            "\nArguments:\n"
            "1. \"status\"     (string, optional) Filter by status: \"active\", \"claimed\", \"refunded\"\n"
            "\nResult:\n"
            "[...array of HTLC records...]\n"
        );
    }

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "HTLC database not initialized");
    }

    UniValue result(UniValue::VARR);

    std::vector<HTLCRecord> htlcs;
    g_htlcdb->GetActive(htlcs);

    for (const auto& htlc : htlcs) {
        UniValue obj(UniValue::VOBJ);
        // Use txid:vout format instead of COutPoint::ToString() debug format
        obj.pushKV("outpoint", strprintf("%s:%d", htlc.htlcOutpoint.hash.GetHex(), htlc.htlcOutpoint.n));
        obj.pushKV("hashlock", HexStr(Span<const unsigned char>(htlc.hashlock.begin(), htlc.hashlock.size())));
        obj.pushKV("amount", ValueFromAmount(htlc.amount));
        obj.pushKV("create_height", (int)htlc.createHeight);
        obj.pushKV("expiry_height", (int)htlc.expiryHeight);
        obj.pushKV("status", htlc.IsActive() ? "active" :
                             (htlc.status == HTLCStatus::CLAIMED ? "claimed" : "refunded"));
        result.push_back(obj);
    }

    return result;
}

/**
 * htlc_get - Get HTLC details
 */
static UniValue htlc_get(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "htlc_get \"outpoint\"\n"
            "\nGet details of a specific HTLC.\n"
            "\nArguments:\n"
            "1. \"outpoint\"   (string, required) HTLC outpoint (txid:vout)\n"
        );
    }

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "HTLC database not initialized");
    }

    std::string outpointStr = request.params[0].get_str();
    // Parse outpoint (format: txid:n)
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format (expected txid:n)");
    }

    uint256 txid;
    txid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t n = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint outpoint(txid, n);

    HTLCRecord htlc;
    if (!g_htlcdb->ReadHTLC(outpoint, htlc)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "HTLC not found");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("outpoint", htlc.htlcOutpoint.ToString());
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(htlc.hashlock.begin(), htlc.hashlock.size())));
    result.pushKV("amount", ValueFromAmount(htlc.amount));
    result.pushKV("source_receipt", htlc.sourceReceipt.ToString());
    result.pushKV("create_height", (int)htlc.createHeight);
    result.pushKV("expiry_height", (int)htlc.expiryHeight);
    result.pushKV("status", htlc.IsActive() ? "active" :
                           (htlc.status == HTLCStatus::CLAIMED ? "claimed" : "refunded"));
    if (!htlc.resolveTxid.IsNull()) {
        result.pushKV("resolve_txid", htlc.resolveTxid.GetHex());
    }
    if (!htlc.preimage.IsNull()) {
        result.pushKV("preimage", htlc.preimage.GetHex());
    }

    return result;
}

/**
 * htlc_verify - Verify preimage matches hashlock
 */
static UniValue htlc_verify(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "htlc_verify \"preimage\" \"hashlock\"\n"
            "\nVerify that a preimage matches a hashlock.\n"
            "\nArguments:\n"
            "1. \"preimage\"   (string, required) Hex-encoded preimage\n"
            "2. \"hashlock\"   (string, required) Hex-encoded hashlock\n"
            "\nResult:\n"
            "{\n"
            "  \"valid\": true|false\n"
            "}\n"
        );
    }

    std::vector<unsigned char> preimage = ParseHexV(request.params[0], "preimage");
    // Parse hashlock using raw bytes, NOT SetHex() which reverses byte order
    std::vector<unsigned char> hashlockBytes = ParseHex(request.params[1].get_str());
    if (hashlockBytes.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hashlock (must be 32-byte hex)");
    }
    uint256 hashlock;
    memcpy(hashlock.begin(), hashlockBytes.data(), 32);

    bool valid = VerifyPreimage(preimage, hashlock);

    UniValue result(UniValue::VOBJ);
    result.pushKV("valid", valid);
    return result;
}

/**
 * htlc_create_m1 - Lock M1 receipt in HTLC P2SH
 *
 * Creates HTLC_CREATE_M1 transaction:
 * - Input: M1 Receipt
 * - Output: HTLC P2SH (same amount)
 *
 * M1_supply unchanged (M1 is in "HTLC state", still backed by communal vault pool)
 */
static UniValue htlc_create_m1(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4) {
        throw std::runtime_error(
            "htlc_create_m1 \"receipt_outpoint\" \"hashlock\" \"claim_address\" ( expiry_blocks )\n"
            "\nLock an M1 receipt in an HTLC for atomic swap (HTLC_CREATE_M1).\n"
            "\nArguments:\n"
            "1. \"receipt_outpoint\" (string, required) M1 Receipt outpoint (txid:vout)\n"
            "2. \"hashlock\"         (string, required) SHA256 hashlock (hex, 32 bytes)\n"
            "3. \"claim_address\"    (string, required) Address that can claim with preimage\n"
            "4. expiry_blocks        (numeric, optional, default=288) Blocks until refundable (~2 days)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",              (string) Transaction ID\n"
            "  \"htlc_outpoint\": \"txid:0\",  (string) HTLC P2SH outpoint\n"
            "  \"amount\": x.xxx,             (numeric) M1 amount locked\n"
            "  \"hashlock\": \"hex\",          (string) Hashlock used\n"
            "  \"expiry_height\": n,          (numeric) Block height when refundable\n"
            "  \"claim_address\": \"...\",     (string) Address that can claim\n"
            "  \"refund_address\": \"...\",    (string) Address that can refund (your address)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc_create_m1", "\"abc123:1\" \"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592\" \"yClaimAddress\" 288")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Verify DBs available
    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    }
    if (!g_htlcdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");
    }

    // Parse receipt outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    }
    uint256 receiptTxid;
    receiptTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t receiptVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint receiptOutpoint(receiptTxid, receiptVout);

    // Verify it's an M1 receipt
    if (!g_settlementdb->IsM1Receipt(receiptOutpoint)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint is not a valid M1 receipt");
    }

    // Parse hashlock (32 bytes hex) - use raw bytes, NOT SetHex() which reverses
    std::string hashlockHex = request.params[1].get_str();
    std::vector<unsigned char> hashlockBytes = ParseHex(hashlockHex);
    if (hashlockBytes.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hashlock (must be 32-byte hex)");
    }
    uint256 hashlock;
    memcpy(hashlock.begin(), hashlockBytes.data(), 32);

    // Parse claim address
    CTxDestination claimDest = DecodeDestination(request.params[2].get_str());
    if (!IsValidDestination(claimDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid claim address");
    }
    const CKeyID* claimKeyID = boost::get<CKeyID>(&claimDest);
    if (!claimKeyID) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Claim address must be P2PKH");
    }

    // Parse expiry blocks (default 288 = ~2 days)
    uint32_t expiryBlocks = HTLC_DEFAULT_EXPIRY_BLOCKS;
    if (request.params.size() > 3) {
        expiryBlocks = request.params[3].get_int();
        if (expiryBlocks < HTLC_MIN_EXPIRY_BLOCKS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Expiry must be at least %d blocks", HTLC_MIN_EXPIRY_BLOCKS));
        }
        if (expiryBlocks > HTLC_MAX_EXPIRY_BLOCKS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Expiry must be at most %d blocks", HTLC_MAX_EXPIRY_BLOCKS));
        }
    }

    // Get current height and calculate expiry
    int currentHeight = chainActive.Height();
    uint32_t expiryHeight = currentHeight + expiryBlocks;

    // Get wallet TX for the receipt
    auto it = pwallet->mapWallet.find(receiptTxid);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Receipt transaction not found in wallet");
    }
    const CWalletTx& wtx = it->second;
    if (receiptVout >= wtx.tx->vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output index");
    }

    CAmount receiptAmount = wtx.tx->vout[receiptVout].nValue;
    CScript receiptScriptPubKey = wtx.tx->vout[receiptVout].scriptPubKey;

    // Get refund key from wallet (M1 goes back to creator on refund)
    CPubKey refundPubKey;
    if (!pwallet->GetKeyFromPool(refundPubKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out");
    }
    CKeyID refundKeyID = refundPubKey.GetID();

    // Create conditional script (HTLC redeem script)
    CScript redeemScript = CreateConditionalScript(hashlock, expiryHeight, *claimKeyID, refundKeyID);

    // Create P2SH scriptPubKey
    CScriptID scriptID(redeemScript);
    CScript htlcScriptPubKey = GetScriptForDestination(scriptID);

    // Build HTLC_CREATE_M1 transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;  // Required for special txes
    mtx.nType = CTransaction::TxType::HTLC_CREATE_M1;

    // Create and serialize HTLCCreatePayload into vExtraPayload
    HTLCCreatePayload payload;
    payload.nVersion = HTLC_CREATE_PAYLOAD_VERSION;
    payload.hashlock = hashlock;
    payload.expiryHeight = expiryHeight;
    payload.claimKeyID = *claimKeyID;
    payload.refundKeyID = refundKeyID;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << payload;
    mtx.extraPayload = std::vector<uint8_t>(ssPayload.begin(), ssPayload.end());

    // Input: M1 receipt
    mtx.vin.emplace_back(receiptOutpoint);

    // Output: HTLC P2SH (STRICT CONSERVATION: must equal receipt amount exactly)
    // HTLC transactions are fee-exempt to preserve atomic swap integrity
    mtx.vout.emplace_back(receiptAmount, htlcScriptPubKey);

    // Sign the receipt input
    const CTransaction txConst(mtx);
    SignatureData sigdata;
    if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, 0, receiptAmount, SIGHASH_ALL),
                         receiptScriptPubKey, sigdata, txConst.GetRequiredSigVersion())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Signing M1 receipt failed. Do you own this receipt?");
    }
    UpdateTransaction(mtx, 0, sigdata);

    // Create final transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const uint256& hashTx = tx->GetHash();

    // Accept to mempool with ignoreFees=true (HTLC preserves strict amount conservation)
    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
        }
    }

    // Relay to network
    if (g_connman) {
        CInv inv(MSG_TX, hashTx);
        g_connman->ForEachNode([&inv](CNode* pnode) {
            pnode->PushInventory(inv);
        });
    }

    // Mark the spent receipt as used in wallet
    {
        LOCK(pwallet->cs_wallet);
        pwallet->MarkDirty();
    }

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("htlc_outpoint", strprintf("%s:0", hashTx.GetHex()));
    result.pushKV("amount", ValueFromAmount(receiptAmount));
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));
    result.pushKV("expiry_height", (int)expiryHeight);
    result.pushKV("claim_address", EncodeDestination(*claimKeyID));
    result.pushKV("refund_address", EncodeDestination(refundKeyID));

    return result;
}

/**
 * htlc_claim - Claim HTLC with preimage
 *
 * Creates HTLC_CLAIM transaction:
 * - Input: HTLC P2SH (with preimage in scriptSig)
 * - Output: New M1 Receipt to claimer
 *
 * M1_supply unchanged (HTLC -> M1 Receipt, same backing)
 */
static UniValue htlc_claim(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "htlc_claim \"htlc_outpoint\" \"preimage\"\n"
            "\nClaim an HTLC by revealing the preimage (HTLC_CLAIM).\n"
            "\nArguments:\n"
            "1. \"htlc_outpoint\" (string, required) HTLC outpoint (txid:vout)\n"
            "2. \"preimage\"      (string, required) 32-byte preimage (hex)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",              (string) Transaction ID\n"
            "  \"receipt_outpoint\": \"...\",  (string) New M1 Receipt outpoint\n"
            "  \"amount\": x.xxx,             (numeric) M1 amount received\n"
            "  \"preimage\": \"hex\"           (string) Preimage used\n"
            "}\n"
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");
    }

    // Parse HTLC outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    }
    uint256 htlcTxid;
    htlcTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t htlcVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint htlcOutpoint(htlcTxid, htlcVout);

    // Get HTLC record
    HTLCRecord htlc;
    if (!g_htlcdb->ReadHTLC(htlcOutpoint, htlc)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC not found");
    }

    if (!htlc.IsActive()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("HTLC is not active (status: %s)",
                htlc.status == HTLCStatus::CLAIMED ? "claimed" : "refunded"));
    }

    // Parse preimage
    std::vector<unsigned char> preimage = ParseHexV(request.params[1], "preimage");
    if (preimage.size() != HTLC_PREIMAGE_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Preimage must be %d bytes", HTLC_PREIMAGE_SIZE));
    }

    // Verify preimage matches hashlock
    if (!VerifyPreimage(preimage, htlc.hashlock)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Preimage does not match hashlock");
    }

    // Get claim key from wallet
    CKey claimKey;
    if (!pwallet->GetKey(htlc.claimKeyID, claimKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Wallet does not have the claim key for this HTLC");
    }

    // Get HTLC transaction for the output value
    CTransactionRef htlcTx;
    uint256 blockHash;
    if (!GetTransaction(htlcTxid, htlcTx, blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC transaction not found");
    }

    CAmount htlcAmount = htlcTx->vout[htlcVout].nValue;
    CScript htlcScriptPubKey = htlcTx->vout[htlcVout].scriptPubKey;

    // Build HTLC_CLAIM transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;  // Required for special txes
    mtx.nType = CTransaction::TxType::HTLC_CLAIM;

    // Input: HTLC P2SH
    mtx.vin.emplace_back(htlcOutpoint);

    // Output: covenant-aware (HTLC3 P2SH or M1 Receipt)
    if (htlc.HasCovenant()) {
        // Covenant: output must be HTLC3 P2SH to match template C3
        CScript htlc3RedeemScript = CreateConditionalScript(
            htlc.hashlock, htlc.htlc3ExpiryHeight,
            htlc.htlc3ClaimKeyID, htlc.htlc3RefundKeyID);
        CScriptID htlc3ScriptID(htlc3RedeemScript);
        CScript htlc3ScriptPubKey = GetScriptForDestination(htlc3ScriptID);
        // Guard against underflow: covenantFee must be less than htlcAmount (C2 audit fix)
        if (htlc.covenantFee >= htlcAmount) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("HTLC amount (%lld) must exceed covenant fee (%lld)",
                          (long long)htlcAmount, (long long)htlc.covenantFee));
        }
        CAmount htlc3Amount = htlcAmount - htlc.covenantFee;
        mtx.vout.emplace_back(htlc3Amount, htlc3ScriptPubKey);
        // vout[1]: covenant fee as an OP_TRUE M1 fee receipt (producer claims it),
        // required by CheckHTLCClaim and committed in C3 (see htlc*_create_covenant).
        mtx.vout.emplace_back(htlc.covenantFee, CScript() << OP_TRUE);
    } else {
        // Standard: M1 Receipt to claimer
        CScript receiptScript = GetScriptForDestination(htlc.claimKeyID);
        mtx.vout.emplace_back(htlcAmount, receiptScript);
    }

    // Create scriptSig for claim (branch A)
    // Need to sign the transaction first
    const CTransaction txForSig(mtx);
    uint256 sighash = SignatureHash(htlc.redeemScript, txForSig, 0, SIGHASH_ALL, htlcAmount, txForSig.GetRequiredSigVersion());

    std::vector<unsigned char> sig;
    if (!claimKey.Sign(sighash, sig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign claim transaction");
    }
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    // Build scriptSig: <sig> <pubkey> <preimage> OP_TRUE <redeemScript>
    mtx.vin[0].scriptSig = CreateConditionalSpendA(sig, claimKey.GetPubKey(), preimage, htlc.redeemScript);

    // Submit to mempool directly (not CommitTransaction, which requires inputs
    // in wallet's mapWallet — fails for cross-node HTLC claims like Settlement Pivot)
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const uint256& hashTx = tx->GetHash();

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true))
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
    }

    // Relay to peers
    if (g_connman) {
        CInv inv(MSG_TX, hashTx);
        g_connman->ForEachNode([&inv](CNode* pnode) { pnode->PushInventory(inv); });
    }

    { LOCK(pwallet->cs_wallet); pwallet->MarkDirty(); }

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("preimage", HexStr(preimage));

    if (htlc.HasCovenant()) {
        result.pushKV("type", "pivot");
        result.pushKV("htlc3_outpoint", strprintf("%s:0", hashTx.GetHex()));
        result.pushKV("htlc3_amount", ValueFromAmount(htlcAmount - htlc.covenantFee));
        result.pushKV("covenant_fee", htlc.covenantFee);
    } else {
        result.pushKV("type", "standard");
        result.pushKV("receipt_outpoint", strprintf("%s:0", hashTx.GetHex()));
        result.pushKV("amount", ValueFromAmount(htlcAmount));
    }

    return result;
}

/**
 * htlc_refund - Refund expired HTLC
 *
 * Creates HTLC_REFUND transaction:
 * - Input: HTLC P2SH (with nLockTime >= expiry)
 * - Output: M1 Receipt back to creator
 *
 * M1_supply unchanged (HTLC -> M1 Receipt, same backing)
 */
static UniValue htlc_refund(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "htlc_refund \"htlc_outpoint\"\n"
            "\nRefund an expired HTLC back to the creator (HTLC_REFUND).\n"
            "\nArguments:\n"
            "1. \"htlc_outpoint\" (string, required) HTLC outpoint (txid:vout)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",              (string) Transaction ID\n"
            "  \"receipt_outpoint\": \"...\",  (string) New M1 Receipt outpoint\n"
            "  \"amount\": x.xxx              (numeric) M1 amount refunded\n"
            "}\n"
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");
    }

    // Parse HTLC outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    }
    uint256 htlcTxid;
    htlcTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t htlcVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint htlcOutpoint(htlcTxid, htlcVout);

    // Get HTLC record
    HTLCRecord htlc;
    if (!g_htlcdb->ReadHTLC(htlcOutpoint, htlc)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC not found");
    }

    if (!htlc.IsActive()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("HTLC is not active (status: %s)",
                htlc.status == HTLCStatus::CLAIMED ? "claimed" : "refunded"));
    }

    // Check if refundable (expired)
    int currentHeight = chainActive.Height();
    if (!htlc.IsRefundable(currentHeight)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("HTLC not yet refundable. Current height: %d, expiry: %d (wait %d more blocks)",
                currentHeight, htlc.expiryHeight, htlc.expiryHeight - currentHeight));
    }

    // Get refund key from wallet
    CKey refundKey;
    if (!pwallet->GetKey(htlc.refundKeyID, refundKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Wallet does not have the refund key for this HTLC");
    }

    // Get HTLC transaction for the output value
    CTransactionRef htlcTx;
    uint256 blockHash;
    if (!GetTransaction(htlcTxid, htlcTx, blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC transaction not found");
    }

    CAmount htlcAmount = htlcTx->vout[htlcVout].nValue;

    // Build HTLC_REFUND transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;  // Required for special txes
    mtx.nType = CTransaction::TxType::HTLC_REFUND;
    mtx.nLockTime = htlc.expiryHeight;  // Required for CHECKLOCKTIMEVERIFY

    // Input: HTLC P2SH (with sequence allowing CLTV)
    CTxIn txin(htlcOutpoint);
    txin.nSequence = 0xFFFFFFFE;  // Enable nLockTime (not final)
    mtx.vin.push_back(txin);

    // Output: M1 Receipt back to refunder
    CScript receiptScript = GetScriptForDestination(htlc.refundKeyID);
    mtx.vout.emplace_back(htlcAmount, receiptScript);

    // Create scriptSig for refund (branch B)
    const CTransaction txForSig(mtx);
    uint256 sighash = SignatureHash(htlc.redeemScript, txForSig, 0, SIGHASH_ALL, htlcAmount, txForSig.GetRequiredSigVersion());

    std::vector<unsigned char> sig;
    if (!refundKey.Sign(sighash, sig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign refund transaction");
    }
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    // Build scriptSig: <sig> <pubkey> OP_FALSE <redeemScript>
    mtx.vin[0].scriptSig = CreateConditionalSpendB(sig, refundKey.GetPubKey(), htlc.redeemScript);

    // Commit transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    CReserveKey reserveKey(pwallet);
    const CWallet::CommitResult& res = pwallet->CommitTransaction(tx, reserveKey, g_connman.get());

    if (res.status != CWallet::CommitStatus::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            strprintf("Transaction commit failed: %s", res.ToString()));
    }

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("receipt_outpoint", strprintf("%s:0", tx->GetHash().GetHex()));
    result.pushKV("amount", ValueFromAmount(htlcAmount));

    return result;
}

/**
 * htlc_extract_preimage - Extract preimage from a claim transaction
 *
 * Useful for the counterparty to learn the preimage after HTLC is claimed.
 */
static UniValue htlc_extract_preimage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "htlc_extract_preimage \"txid\"\n"
            "\nExtract the preimage from an HTLC claim transaction.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) HTLC_CLAIM transaction ID\n"
            "\nResult:\n"
            "{\n"
            "  \"preimage\": \"hex\",   (string) Extracted preimage (32 bytes)\n"
            "  \"hashlock\": \"hex\"    (string) Corresponding hashlock\n"
            "}\n"
        );
    }

    uint256 txid;
    txid.SetHex(request.params[0].get_str());

    // Get transaction
    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(txid, tx, blockHash, true)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction not found");
    }

    // Verify it's an HTLC_CLAIM
    if (tx->nType != CTransaction::TxType::HTLC_CLAIM) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction is not an HTLC_CLAIM");
    }

    if (tx->vin.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction has no inputs");
    }

    // Extract preimage from scriptSig
    // The scriptSig for claim is: <sig> <pubkey> <preimage> OP_TRUE <redeemScript>
    const CScript& scriptSig = tx->vin[0].scriptSig;

    // Parse scriptSig to find preimage
    std::vector<std::vector<unsigned char>> stack;
    opcodetype opcode;
    CScript::const_iterator it = scriptSig.begin();

    while (it < scriptSig.end()) {
        std::vector<unsigned char> data;
        if (!scriptSig.GetOp(it, opcode, data)) {
            break;
        }
        if (opcode <= OP_PUSHDATA4) {
            stack.push_back(data);
        } else if (opcode == OP_TRUE) {
            stack.push_back({1});  // OP_TRUE marker
        } else if (opcode == OP_FALSE) {
            stack.push_back({});   // OP_FALSE marker
        }
    }

    // stack should be: [sig, pubkey, preimage, OP_TRUE marker, redeemScript]
    if (stack.size() < 5) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not parse scriptSig");
    }

    // The preimage is at index 2 (after sig and pubkey)
    const std::vector<unsigned char>& preimage = stack[2];
    if (preimage.size() != HTLC_PREIMAGE_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Invalid preimage size: %d (expected %d)", preimage.size(), HTLC_PREIMAGE_SIZE));
    }

    // Compute hashlock
    uint256 hashlock;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hashlock.begin());

    UniValue result(UniValue::VOBJ);
    result.pushKV("preimage", HexStr(preimage));
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));

    return result;
}

// =============================================================================
// HTLC3S - 3-Secret HTLC RPCs for FlowSwap Protocol
// =============================================================================

/**
 * htlc3s_generate - Generate 3 secrets and hashlocks for FlowSwap HTLC3S
 */
static UniValue htlc3s_generate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "htlc3s_generate\n"
            "\nGenerate 3 secret/hashlock pairs for 3-secret HTLC (FlowSwap).\n"
            "\nResult:\n"
            "{\n"
            "  \"user\": {\"secret\": \"hex\", \"hashlock\": \"hex\"},\n"
            "  \"lp1\": {\"secret\": \"hex\", \"hashlock\": \"hex\"},\n"
            "  \"lp2\": {\"secret\": \"hex\", \"hashlock\": \"hex\"}\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc3s_generate", "")
        );
    }

    auto generatePair = []() -> std::pair<std::string, std::string> {
        std::vector<unsigned char> secret(32);
        GetStrongRandBytes(secret.data(), 32);
        uint256 hashlock;
        CSHA256().Write(secret.data(), 32).Finalize(hashlock.begin());
        return {HexStr(secret), HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size()))};
    };

    auto user = generatePair();
    auto lp1 = generatePair();
    auto lp2 = generatePair();

    UniValue result(UniValue::VOBJ);

    UniValue userObj(UniValue::VOBJ);
    userObj.pushKV("secret", user.first);
    userObj.pushKV("hashlock", user.second);
    result.pushKV("user", userObj);

    UniValue lp1Obj(UniValue::VOBJ);
    lp1Obj.pushKV("secret", lp1.first);
    lp1Obj.pushKV("hashlock", lp1.second);
    result.pushKV("lp1", lp1Obj);

    UniValue lp2Obj(UniValue::VOBJ);
    lp2Obj.pushKV("secret", lp2.first);
    lp2Obj.pushKV("hashlock", lp2.second);
    result.pushKV("lp2", lp2Obj);

    return result;
}

/**
 * htlc3s_list - List HTLC3S records
 */
static UniValue htlc3s_list(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "htlc3s_list ( \"status\" )\n"
            "\nList 3-secret HTLC records.\n"
            "\nArguments:\n"
            "1. \"status\"     (string, optional) Filter by status: \"active\", \"claimed\", \"refunded\"\n"
            "\nResult:\n"
            "[...array of HTLC3S records...]\n"
        );
    }

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "HTLC database not initialized");
    }

    UniValue result(UniValue::VARR);

    std::vector<HTLC3SRecord> htlcs;
    g_htlcdb->GetActive3S(htlcs);

    for (const auto& htlc : htlcs) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("outpoint", strprintf("%s:%d", htlc.htlcOutpoint.hash.GetHex(), htlc.htlcOutpoint.n));
        obj.pushKV("hashlock_user", HexStr(Span<const unsigned char>(htlc.hashlock_user.begin(), htlc.hashlock_user.size())));
        obj.pushKV("hashlock_lp1", HexStr(Span<const unsigned char>(htlc.hashlock_lp1.begin(), htlc.hashlock_lp1.size())));
        obj.pushKV("hashlock_lp2", HexStr(Span<const unsigned char>(htlc.hashlock_lp2.begin(), htlc.hashlock_lp2.size())));
        obj.pushKV("amount", ValueFromAmount(htlc.amount));
        obj.pushKV("create_height", (int)htlc.createHeight);
        obj.pushKV("expiry_height", (int)htlc.expiryHeight);
        obj.pushKV("status", htlc.IsActive() ? "active" :
                             (htlc.status == HTLCStatus::CLAIMED ? "claimed" : "refunded"));
        result.push_back(obj);
    }

    return result;
}

/**
 * htlc3s_get - Get HTLC3S details
 */
static UniValue htlc3s_get(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "htlc3s_get \"outpoint\"\n"
            "\nGet details of a specific 3-secret HTLC.\n"
            "\nArguments:\n"
            "1. \"outpoint\"   (string, required) HTLC3S outpoint (txid:vout)\n"
        );
    }

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "HTLC database not initialized");
    }

    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format (expected txid:n)");
    }

    uint256 txid;
    txid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t n = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint outpoint(txid, n);

    HTLC3SRecord htlc;
    if (!g_htlcdb->ReadHTLC3S(outpoint, htlc)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "HTLC3S not found");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("outpoint", htlc.htlcOutpoint.ToString());
    result.pushKV("hashlock_user", HexStr(Span<const unsigned char>(htlc.hashlock_user.begin(), htlc.hashlock_user.size())));
    result.pushKV("hashlock_lp1", HexStr(Span<const unsigned char>(htlc.hashlock_lp1.begin(), htlc.hashlock_lp1.size())));
    result.pushKV("hashlock_lp2", HexStr(Span<const unsigned char>(htlc.hashlock_lp2.begin(), htlc.hashlock_lp2.size())));
    result.pushKV("amount", ValueFromAmount(htlc.amount));
    result.pushKV("source_receipt", htlc.sourceReceipt.ToString());
    result.pushKV("create_height", (int)htlc.createHeight);
    result.pushKV("expiry_height", (int)htlc.expiryHeight);
    result.pushKV("claim_address", EncodeDestination(htlc.claimKeyID));
    result.pushKV("refund_address", EncodeDestination(htlc.refundKeyID));
    result.pushKV("has_covenant", htlc.HasCovenant());
    if (htlc.HasCovenant()) {
        result.pushKV("template_commitment", htlc.templateCommitment.GetHex());
        result.pushKV("covenant_dest_address", EncodeDestination(htlc.covenantDestKeyID));
    }
    result.pushKV("status", htlc.IsActive() ? "active" :
                           (htlc.status == HTLCStatus::CLAIMED ? "claimed" : "refunded"));
    if (!htlc.resolveTxid.IsNull()) {
        result.pushKV("resolve_txid", htlc.resolveTxid.GetHex());
    }
    if (!htlc.preimage_user.IsNull()) {
        result.pushKV("preimage_user", htlc.preimage_user.GetHex());
        result.pushKV("preimage_lp1", htlc.preimage_lp1.GetHex());
        result.pushKV("preimage_lp2", htlc.preimage_lp2.GetHex());
    }

    return result;
}

/**
 * htlc3s_verify - Verify 3 preimages match 3 hashlocks
 */
static UniValue htlc3s_verify(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 6) {
        throw std::runtime_error(
            "htlc3s_verify \"preimage_user\" \"preimage_lp1\" \"preimage_lp2\" \"hashlock_user\" \"hashlock_lp1\" \"hashlock_lp2\"\n"
            "\nVerify that 3 preimages match 3 hashlocks.\n"
            "\nArguments:\n"
            "1. \"preimage_user\"  (string, required) Hex-encoded preimage user\n"
            "2. \"preimage_lp1\"   (string, required) Hex-encoded preimage lp1\n"
            "3. \"preimage_lp2\"   (string, required) Hex-encoded preimage lp2\n"
            "4. \"hashlock_user\"  (string, required) Hex-encoded hashlock user\n"
            "5. \"hashlock_lp1\"   (string, required) Hex-encoded hashlock lp1\n"
            "6. \"hashlock_lp2\"   (string, required) Hex-encoded hashlock lp2\n"
            "\nResult:\n"
            "{\n"
            "  \"valid\": true|false,\n"
            "  \"user_valid\": true|false,\n"
            "  \"lp1_valid\": true|false,\n"
            "  \"lp2_valid\": true|false\n"
            "}\n"
        );
    }

    auto parsePreimage = [](const UniValue& v, const std::string& name) -> std::vector<unsigned char> {
        std::vector<unsigned char> bytes = ParseHexV(v, name);
        if (bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid %s (must be 32 bytes)", name));
        }
        return bytes;
    };

    auto parseHashlock = [](const UniValue& v, const std::string& name) -> uint256 {
        std::vector<unsigned char> bytes = ParseHex(v.get_str());
        if (bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid %s (must be 32 bytes)", name));
        }
        uint256 hashlock;
        memcpy(hashlock.begin(), bytes.data(), 32);
        return hashlock;
    };

    std::vector<unsigned char> preimage_user = parsePreimage(request.params[0], "preimage_user");
    std::vector<unsigned char> preimage_lp1 = parsePreimage(request.params[1], "preimage_lp1");
    std::vector<unsigned char> preimage_lp2 = parsePreimage(request.params[2], "preimage_lp2");
    uint256 hashlock_user = parseHashlock(request.params[3], "hashlock_user");
    uint256 hashlock_lp1 = parseHashlock(request.params[4], "hashlock_lp1");
    uint256 hashlock_lp2 = parseHashlock(request.params[5], "hashlock_lp2");

    bool userValid = VerifyPreimage(preimage_user, hashlock_user);
    bool lp1Valid = VerifyPreimage(preimage_lp1, hashlock_lp1);
    bool lp2Valid = VerifyPreimage(preimage_lp2, hashlock_lp2);

    UniValue result(UniValue::VOBJ);
    result.pushKV("valid", userValid && lp1Valid && lp2Valid);
    result.pushKV("user_valid", userValid);
    result.pushKV("lp1_valid", lp1Valid);
    result.pushKV("lp2_valid", lp2Valid);
    return result;
}

/**
 * htlc3s_find_by_hashlock - Find HTLC3S by any hashlock
 */
static UniValue htlc3s_find_by_hashlock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "htlc3s_find_by_hashlock \"hashlock\" \"type\"\n"
            "\nFind HTLC3S records by hashlock for cross-chain matching.\n"
            "\nArguments:\n"
            "1. \"hashlock\"  (string, required) Hex-encoded hashlock to search\n"
            "2. \"type\"      (string, required) Which hashlock: \"user\", \"lp1\", \"lp2\"\n"
            "\nResult:\n"
            "[...array of matching HTLC3S outpoints...]\n"
        );
    }

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "HTLC database not initialized");
    }

    std::vector<unsigned char> hashlockBytes = ParseHex(request.params[0].get_str());
    if (hashlockBytes.size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hashlock (must be 32 bytes)");
    }
    uint256 hashlock;
    memcpy(hashlock.begin(), hashlockBytes.data(), 32);

    std::string type = request.params[1].get_str();
    std::vector<COutPoint> outpoints;

    if (type == "user") {
        g_htlcdb->GetByHashlock3SUser(hashlock, outpoints);
    } else if (type == "lp1") {
        g_htlcdb->GetByHashlock3SLp1(hashlock, outpoints);
    } else if (type == "lp2") {
        g_htlcdb->GetByHashlock3SLp2(hashlock, outpoints);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid type (must be \"user\", \"lp1\", or \"lp2\")");
    }

    UniValue result(UniValue::VARR);
    for (const auto& op : outpoints) {
        result.push_back(strprintf("%s:%d", op.hash.GetHex(), op.n));
    }
    return result;
}

/**
 * htlc3s_create - Lock M1 receipt in 3-secret HTLC P2SH
 */
static UniValue htlc3s_create(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 5 || request.params.size() > 8) {
        throw std::runtime_error(
            "htlc3s_create \"receipt_outpoint\" \"hashlock_user\" \"hashlock_lp1\" \"hashlock_lp2\" \"claim_address\" ( expiry_blocks \"template_commitment\" \"covenant_dest_address\" )\n"
            "\nLock an M1 receipt in a 3-secret HTLC for FlowSwap (HTLC_CREATE_3S).\n"
            "\nArguments:\n"
            "1. \"receipt_outpoint\"      (string, required) M1 Receipt outpoint (txid:vout)\n"
            "2. \"hashlock_user\"         (string, required) SHA256 hashlock user (hex, 32 bytes)\n"
            "3. \"hashlock_lp1\"          (string, required) SHA256 hashlock lp1 (hex, 32 bytes)\n"
            "4. \"hashlock_lp2\"          (string, required) SHA256 hashlock lp2 (hex, 32 bytes)\n"
            "5. \"claim_address\"         (string, required) Address that can claim with 3 preimages\n"
            "6. expiry_blocks             (numeric, optional, default=288) Blocks until refundable\n"
            "7. \"template_commitment\"   (string, optional) C3 covenant hash (hex, 32 bytes) for per-leg\n"
            "8. \"covenant_dest_address\" (string, optional) LP_OUT address forced by covenant\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",\n"
            "  \"htlc_outpoint\": \"txid:0\",\n"
            "  \"amount\": x.xxx,\n"
            "  \"expiry_height\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("htlc3s_create", "\"abc123:1\" \"hash_user\" \"hash_lp1\" \"hash_lp2\" \"yClaimAddr\"")
            + HelpExampleCli("htlc3s_create", "\"abc123:1\" \"hash_user\" \"hash_lp1\" \"hash_lp2\" \"yClaimAddr\" 120 \"c3_hex\" \"yLpOutAddr\"")
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    }
    if (!g_htlcdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");
    }

    // Parse receipt outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    }
    uint256 receiptTxid;
    receiptTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t receiptVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint receiptOutpoint(receiptTxid, receiptVout);

    if (!g_settlementdb->IsM1Receipt(receiptOutpoint)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint is not a valid M1 receipt");
    }

    // Parse 3 hashlocks
    auto parseHashlock = [](const std::string& hex) -> uint256 {
        std::vector<unsigned char> bytes = ParseHex(hex);
        if (bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hashlock (must be 32-byte hex)");
        }
        uint256 hashlock;
        memcpy(hashlock.begin(), bytes.data(), 32);
        return hashlock;
    };

    uint256 hashlock_user = parseHashlock(request.params[1].get_str());
    uint256 hashlock_lp1 = parseHashlock(request.params[2].get_str());
    uint256 hashlock_lp2 = parseHashlock(request.params[3].get_str());

    // Parse claim address
    CTxDestination claimDest = DecodeDestination(request.params[4].get_str());
    if (!IsValidDestination(claimDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid claim address");
    }
    const CKeyID* claimKeyID = boost::get<CKeyID>(&claimDest);
    if (!claimKeyID) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Claim address must be P2PKH");
    }

    // Parse expiry blocks
    uint32_t expiryBlocks = HTLC_DEFAULT_EXPIRY_BLOCKS;
    if (request.params.size() > 5) {
        expiryBlocks = request.params[5].get_int();
        if (expiryBlocks < HTLC_MIN_EXPIRY_BLOCKS || expiryBlocks > HTLC_MAX_EXPIRY_BLOCKS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Expiry must be between %d and %d blocks", HTLC_MIN_EXPIRY_BLOCKS, HTLC_MAX_EXPIRY_BLOCKS));
        }
    }

    // Parse optional covenant params (per-leg mode)
    uint256 templateCommitment;
    CKeyID covenantDestKeyID;
    bool hasCovenant = false;

    if (request.params.size() > 6 && !request.params[6].isNull()) {
        std::string commitHex = request.params[6].get_str();
        if (!commitHex.empty()) {
            std::vector<unsigned char> commitBytes = ParseHex(commitHex);
            if (commitBytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "template_commitment must be 32-byte hex");
            }
            memcpy(templateCommitment.begin(), commitBytes.data(), 32);
            hasCovenant = true;
        }
    }

    if (hasCovenant) {
        if (request.params.size() <= 7 || request.params[7].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "covenant_dest_address required when template_commitment is set");
        }
        CTxDestination covDest = DecodeDestination(request.params[7].get_str());
        if (!IsValidDestination(covDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid covenant_dest_address");
        }
        const CKeyID* covKeyID = boost::get<CKeyID>(&covDest);
        if (!covKeyID) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "covenant_dest_address must be P2PKH");
        }
        covenantDestKeyID = *covKeyID;
    }

    int currentHeight = chainActive.Height();
    uint32_t expiryHeight = currentHeight + expiryBlocks;

    // Get wallet TX
    auto it = pwallet->mapWallet.find(receiptTxid);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Receipt transaction not found in wallet");
    }
    const CWalletTx& wtx = it->second;
    if (receiptVout >= wtx.tx->vout.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output index");
    }

    CAmount receiptAmount = wtx.tx->vout[receiptVout].nValue;
    CScript receiptScriptPubKey = wtx.tx->vout[receiptVout].scriptPubKey;

    // Validate amount is sufficient for covenant fee
    if (hasCovenant && receiptAmount <= CTV_FIXED_FEE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Receipt amount %d too small for covenant (min %d)",
                      receiptAmount, CTV_FIXED_FEE + 1));
    }

    // Get refund key
    CPubKey refundPubKey;
    if (!pwallet->GetKeyFromPool(refundPubKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out");
    }
    CKeyID refundKeyID = refundPubKey.GetID();

    // Create 3-secret conditional script (with or without covenant)
    CScript redeemScript;
    if (hasCovenant) {
        redeemScript = CreateConditional3SWithCovenantScript(
            hashlock_user, hashlock_lp1, hashlock_lp2, expiryHeight,
            *claimKeyID, refundKeyID, templateCommitment);
    } else {
        redeemScript = CreateConditional3SScript(
            hashlock_user, hashlock_lp1, hashlock_lp2, expiryHeight, *claimKeyID, refundKeyID);
    }

    // Create P2SH scriptPubKey
    CScriptID scriptID(redeemScript);
    CScript htlcScriptPubKey = GetScriptForDestination(scriptID);

    // Build HTLC_CREATE_3S transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CREATE_3S;

    // Create payload
    HTLC3SCreatePayload payload;
    payload.nVersion = hasCovenant ? HTLC3S_CREATE_PAYLOAD_VERSION_CTV : HTLC3S_CREATE_PAYLOAD_VERSION;
    payload.hashlock_user = hashlock_user;
    payload.hashlock_lp1 = hashlock_lp1;
    payload.hashlock_lp2 = hashlock_lp2;
    payload.expiryHeight = expiryHeight;
    payload.claimKeyID = *claimKeyID;
    payload.refundKeyID = refundKeyID;
    if (hasCovenant) {
        payload.templateCommitment = templateCommitment;
        payload.covenantDestKeyID = covenantDestKeyID;
    }

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << payload;
    mtx.extraPayload = std::vector<uint8_t>(ssPayload.begin(), ssPayload.end());

    // Input: M1 receipt
    mtx.vin.emplace_back(receiptOutpoint);

    // Output: HTLC3S P2SH
    mtx.vout.emplace_back(receiptAmount, htlcScriptPubKey);

    // Sign
    const CTransaction txConst(mtx);
    SignatureData sigdata;
    if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, 0, receiptAmount, SIGHASH_ALL),
                         receiptScriptPubKey, sigdata, txConst.GetRequiredSigVersion())) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Signing M1 receipt failed");
    }
    UpdateTransaction(mtx, 0, sigdata);

    // Submit
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const uint256& hashTx = tx->GetHash();

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
        }
    }

    // Relay
    if (g_connman) {
        CInv inv(MSG_TX, hashTx);
        g_connman->ForEachNode([&inv](CNode* pnode) {
            pnode->PushInventory(inv);
        });
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("htlc_outpoint", strprintf("%s:0", hashTx.GetHex()));
    result.pushKV("amount", ValueFromAmount(receiptAmount));
    result.pushKV("expiry_height", (int)expiryHeight);
    result.pushKV("claim_address", EncodeDestination(*claimKeyID));
    result.pushKV("refund_address", EncodeDestination(refundKeyID));
    result.pushKV("has_covenant", hasCovenant);
    if (hasCovenant) {
        result.pushKV("template_commitment", templateCommitment.GetHex());
        result.pushKV("covenant_dest_address", EncodeDestination(covenantDestKeyID));
    }

    return result;
}

/**
 * htlc3s_claim - Claim 3-secret HTLC with 3 preimages
 */
static UniValue htlc3s_claim(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4) {
        throw std::runtime_error(
            "htlc3s_claim \"htlc_outpoint\" \"preimage_user\" \"preimage_lp1\" \"preimage_lp2\"\n"
            "\nClaim a 3-secret HTLC by providing all 3 preimages (HTLC_CLAIM_3S).\n"
            "\nArguments:\n"
            "1. \"htlc_outpoint\"  (string, required) HTLC3S outpoint (txid:vout)\n"
            "2. \"preimage_user\"  (string, required) Hex-encoded preimage user (32 bytes)\n"
            "3. \"preimage_lp1\"   (string, required) Hex-encoded preimage lp1 (32 bytes)\n"
            "4. \"preimage_lp2\"   (string, required) Hex-encoded preimage lp2 (32 bytes)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",\n"
            "  \"receipt_outpoint\": \"txid:0\",\n"
            "  \"amount\": x.xxx\n"
            "}\n"
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");
    }

    // Parse HTLC outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format");
    }
    uint256 htlcTxid;
    htlcTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t htlcVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint htlcOutpoint(htlcTxid, htlcVout);

    // Read HTLC3S record
    HTLC3SRecord htlc;
    if (!g_htlcdb->ReadHTLC3S(htlcOutpoint, htlc)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC3S not found");
    }

    if (!htlc.IsActive()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC3S is not active");
    }

    // Parse 3 preimages
    auto parsePreimage = [](const std::string& hex) -> std::vector<unsigned char> {
        std::vector<unsigned char> bytes = ParseHex(hex);
        if (bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid preimage (must be 32 bytes)");
        }
        return bytes;
    };

    std::vector<unsigned char> preimage_user = parsePreimage(request.params[1].get_str());
    std::vector<unsigned char> preimage_lp1 = parsePreimage(request.params[2].get_str());
    std::vector<unsigned char> preimage_lp2 = parsePreimage(request.params[3].get_str());

    // Verify preimages
    if (!VerifyPreimages3S(preimage_user, preimage_lp1, preimage_lp2,
                           htlc.hashlock_user, htlc.hashlock_lp1, htlc.hashlock_lp2)) {
        memory_cleanse(preimage_user.data(), preimage_user.size());
        memory_cleanse(preimage_lp1.data(), preimage_lp1.size());
        memory_cleanse(preimage_lp2.data(), preimage_lp2.size());
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Preimage verification failed");
    }

    // Get signing key
    CKey claimKey;
    if (!pwallet->GetKey(htlc.claimKeyID, claimKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Claim key not in wallet");
    }

    // Get HTLC UTXO
    Coin htlcCoin;
    {
        LOCK(cs_main);
        if (!pcoinsTip->GetCoin(htlcOutpoint, htlcCoin)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC3S UTXO not found");
        }
    }

    // Build claim transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CLAIM_3S;

    mtx.vin.emplace_back(htlcOutpoint);

    // Output: covenant-aware (LP_OUT receipt or standard claimer receipt)
    if (htlc.HasCovenant()) {
        // Covenant: output must go to covenantDestKeyID with amount - CTV_FIXED_FEE
        // This matches the template committed at create time via htlc3s_compute_c3
        if (CTV_FIXED_FEE >= htlc.amount) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("HTLC3S amount (%lld) must exceed covenant fee (%lld)",
                          (long long)htlc.amount, (long long)CTV_FIXED_FEE));
        }
        CAmount outputAmount = htlc.amount - CTV_FIXED_FEE;
        CScript outputScript = GetScriptForDestination(htlc.covenantDestKeyID);
        mtx.vout.emplace_back(outputAmount, outputScript);
        // vout[1]: covenant fee as an OP_TRUE M1 fee receipt (producer claims it),
        // required by CheckHTLC3SClaim and committed in C3 (htlc3s_compute_c3).
        mtx.vout.emplace_back(CTV_FIXED_FEE, CScript() << OP_TRUE);
    } else {
        // Standard: M1 Receipt to claimer
        CScript outputScript = GetScriptForDestination(htlc.claimKeyID);
        mtx.vout.emplace_back(htlc.amount, outputScript);
    }

    // Sign with claim key and 3 preimages
    CTransaction txToSign(mtx);
    uint256 sighash = SignatureHash(htlc.redeemScript, txToSign, 0, SIGHASH_ALL, htlc.amount, txToSign.GetRequiredSigVersion());

    std::vector<unsigned char> sig;
    if (!claimKey.Sign(sighash, sig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign");
    }
    sig.push_back(SIGHASH_ALL);

    // Create scriptSig for branch A (claim)
    CScript scriptSig = CreateConditional3SSpendA(sig, claimKey.GetPubKey(),
                                                   preimage_user, preimage_lp1, preimage_lp2,
                                                   htlc.redeemScript);
    mtx.vin[0].scriptSig = scriptSig;

    // Submit
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const uint256& hashTx = tx->GetHash();

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
        }
    }

    // Relay
    if (g_connman) {
        CInv inv(MSG_TX, hashTx);
        g_connman->ForEachNode([&inv](CNode* pnode) {
            pnode->PushInventory(inv);
        });
    }

    // Cleanse preimages from memory after use
    memory_cleanse(preimage_user.data(), preimage_user.size());
    memory_cleanse(preimage_lp1.data(), preimage_lp1.size());
    memory_cleanse(preimage_lp2.data(), preimage_lp2.size());

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());

    if (htlc.HasCovenant()) {
        result.pushKV("type", "pivot");
        result.pushKV("receipt_outpoint", strprintf("%s:0", hashTx.GetHex()));
        result.pushKV("amount", ValueFromAmount(htlc.amount - CTV_FIXED_FEE));
        result.pushKV("covenant_fee", ValueFromAmount(CTV_FIXED_FEE));
        result.pushKV("covenant_dest", EncodeDestination(htlc.covenantDestKeyID));
    } else {
        result.pushKV("type", "standard");
        result.pushKV("receipt_outpoint", strprintf("%s:0", hashTx.GetHex()));
        result.pushKV("amount", ValueFromAmount(htlc.amount));
    }

    return result;
}

/**
 * htlc3s_refund - Refund expired 3-secret HTLC
 */
static UniValue htlc3s_refund(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "htlc3s_refund \"htlc_outpoint\"\n"
            "\nRefund an expired 3-secret HTLC (HTLC_REFUND_3S).\n"
            "\nArguments:\n"
            "1. \"htlc_outpoint\"  (string, required) HTLC3S outpoint (txid:vout)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",\n"
            "  \"receipt_outpoint\": \"txid:0\",\n"
            "  \"amount\": x.xxx\n"
            "}\n"
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!g_htlcdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");
    }

    // Parse HTLC outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format");
    }
    uint256 htlcTxid;
    htlcTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t htlcVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint htlcOutpoint(htlcTxid, htlcVout);

    // Read HTLC3S record
    HTLC3SRecord htlc;
    if (!g_htlcdb->ReadHTLC3S(htlcOutpoint, htlc)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC3S not found");
    }

    if (!htlc.IsActive()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC3S is not active");
    }

    // Check expiry
    int currentHeight = chainActive.Height();
    if ((uint32_t)currentHeight < htlc.expiryHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("HTLC3S not yet expired (current=%d, expiry=%d)", currentHeight, htlc.expiryHeight));
    }

    // Get refund key
    CKey refundKey;
    if (!pwallet->GetKey(htlc.refundKeyID, refundKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Refund key not in wallet");
    }

    // Build refund transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_REFUND_3S;
    mtx.nLockTime = htlc.expiryHeight;

    mtx.vin.emplace_back(htlcOutpoint, CScript(), CTxIn::SEQUENCE_FINAL - 1);

    // Output: M1 receipt back to creator
    CScript outputScript = GetScriptForDestination(htlc.refundKeyID);
    mtx.vout.emplace_back(htlc.amount, outputScript);

    // Sign with refund key
    CTransaction txToSign(mtx);
    uint256 sighash = SignatureHash(htlc.redeemScript, txToSign, 0, SIGHASH_ALL, htlc.amount, txToSign.GetRequiredSigVersion());

    std::vector<unsigned char> sig;
    if (!refundKey.Sign(sighash, sig)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign");
    }
    sig.push_back(SIGHASH_ALL);

    // Create scriptSig for branch B (refund)
    CScript scriptSig = CreateConditional3SSpendB(sig, refundKey.GetPubKey(), htlc.redeemScript);
    mtx.vin[0].scriptSig = scriptSig;

    // Submit
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const uint256& hashTx = tx->GetHash();

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
        }
    }

    // Relay
    if (g_connman) {
        CInv inv(MSG_TX, hashTx);
        g_connman->ForEachNode([&inv](CNode* pnode) {
            pnode->PushInventory(inv);
        });
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("receipt_outpoint", strprintf("%s:0", hashTx.GetHex()));
    result.pushKV("amount", ValueFromAmount(htlc.amount));

    return result;
}

// =============================================================================
// Covenant HTLC + Template Hash RPCs (Phase 4)
// =============================================================================

/**
 * htlc_create_m1_covenant - Create HTLC with OP_TEMPLATEVERIFY covenant
 *
 * Creates HTLC_CREATE_M1 with Settlement Pivot covenant: when the HTLC is
 * claimed, the spending TX is forced to create HTLC3 (M1 returns to LP).
 */
static UniValue htlc_create_m1_covenant(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 7) {
        throw std::runtime_error(
            "htlc_create_m1_covenant \"receipt_outpoint\" \"hashlock\" \"retail_claim_addr\" \"lp_claim_addr\" ( expiry_blocks lp_expiry_blocks covenant_fee )\n"
            "\nCreate a covenant HTLC that forces claim TX to atomically create HTLC3 (Settlement Pivot).\n"
            "\nArguments:\n"
            "1. \"receipt_outpoint\"  (string, required) M1 Receipt outpoint (txid:vout)\n"
            "2. \"hashlock\"          (string, required) SHA256 hashlock (hex, 32 bytes)\n"
            "3. \"retail_claim_addr\" (string, required) Address that can claim HTLC2 (retail)\n"
            "4. \"lp_claim_addr\"     (string, required) LP address that can claim HTLC3\n"
            "5. expiry_blocks         (numeric, optional, default=288) HTLC2 expiry (~2 days)\n"
            "6. lp_expiry_blocks      (numeric, optional, default=expiry_blocks+2) HTLC3 expiry; consensus requires child >= parent expiry + 2 (HTLC3S_MIN_LIFETIME)\n"
            "7. covenant_fee          (numeric, optional, default=200) PivotTx fee in satoshis\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",                    (string) Transaction ID\n"
            "  \"htlc_outpoint\": \"txid:0\",        (string) HTLC P2SH outpoint\n"
            "  \"amount\": x.xxx,                   (numeric) M1 amount locked\n"
            "  \"template_commitment\": \"hex\",      (string) C3 template hash\n"
            "  \"htlc3_redeem_script\": \"hex\",      (string) HTLC3 redeemScript\n"
            "  \"expiry_height\": n,                 (numeric) HTLC2 expiry height\n"
            "  \"htlc3_expiry_height\": n,           (numeric) HTLC3 expiry height\n"
            "}\n"
        );
    }

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!g_settlementdb) throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not available");
    if (!g_htlcdb) throw JSONRPCError(RPC_INTERNAL_ERROR, "HTLC database not available");

    // Parse receipt outpoint
    std::string outpointStr = request.params[0].get_str();
    size_t colonPos = outpointStr.find(':');
    if (colonPos == std::string::npos)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid outpoint format. Expected txid:n");
    uint256 receiptTxid;
    receiptTxid.SetHex(outpointStr.substr(0, colonPos));
    uint32_t receiptVout = ParseOutpointVout(outpointStr.substr(colonPos + 1));
    COutPoint receiptOutpoint(receiptTxid, receiptVout);

    if (!g_settlementdb->IsM1Receipt(receiptOutpoint))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint is not a valid M1 receipt");

    // Parse hashlock (raw bytes, NOT SetHex which reverses)
    std::vector<unsigned char> hashlockBytes = ParseHex(request.params[1].get_str());
    if (hashlockBytes.size() != 32)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hashlock (must be 32-byte hex)");
    uint256 hashlock;
    memcpy(hashlock.begin(), hashlockBytes.data(), 32);

    // Parse retail claim address (who claims HTLC2)
    CTxDestination retailClaimDest = DecodeDestination(request.params[2].get_str());
    if (!IsValidDestination(retailClaimDest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid retail claim address");
    const CKeyID* retailClaimKey = boost::get<CKeyID>(&retailClaimDest);
    if (!retailClaimKey)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Retail claim address must be P2PKH");

    // Parse LP claim address (who claims HTLC3)
    CTxDestination lpClaimDest = DecodeDestination(request.params[3].get_str());
    if (!IsValidDestination(lpClaimDest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid LP claim address");
    const CKeyID* lpClaimKey = boost::get<CKeyID>(&lpClaimDest);
    if (!lpClaimKey)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "LP claim address must be P2PKH");

    // Parse optional parameters
    uint32_t expiryBlocks = HTLC_DEFAULT_EXPIRY_BLOCKS;
    if (request.params.size() > 4) {
        expiryBlocks = request.params[4].get_int();
        if (expiryBlocks < HTLC_MIN_EXPIRY_BLOCKS || expiryBlocks > HTLC_MAX_EXPIRY_BLOCKS)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Expiry must be %d-%d blocks", HTLC_MIN_EXPIRY_BLOCKS, HTLC_MAX_EXPIRY_BLOCKS));
    }

    // F-HTLC-2 (ADR-HTLC3S-EXPIRY-CONSTRAINT): the legacy default was EQUALITY
    // with the parent expiry, which consensus now rejects (R1). When the caller
    // does not provide an explicit LP expiry, default the child to
    // parent + HTLC3S_MIN_LIFETIME; larger explicit margins are wallet policy.
    bool lpExpiryProvided = request.params.size() > 5;
    uint32_t lpExpiryBlocks = 0;
    if (lpExpiryProvided) {
        lpExpiryBlocks = request.params[5].get_int();
        if (lpExpiryBlocks < HTLC_MIN_EXPIRY_BLOCKS || lpExpiryBlocks > HTLC_MAX_EXPIRY_BLOCKS)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("LP expiry must be %d-%d blocks", HTLC_MIN_EXPIRY_BLOCKS, HTLC_MAX_EXPIRY_BLOCKS));
    }

    CAmount covenantFee = CTV_FIXED_FEE;
    if (request.params.size() > 6) {
        covenantFee = request.params[6].get_int64();
        if (covenantFee < 0 || covenantFee > 10000)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be 0-10000 satoshis");
    }

    int currentHeight = chainActive.Height();
    uint32_t expiryHeight = currentHeight + expiryBlocks;
    // Child expiry: explicit margin if provided, else the consensus floor
    // parent + HTLC3S_MIN_LIFETIME. All arithmetic in int64; both a sub-floor
    // explicit value and a uint32 overflow are rejected up front (consensus
    // would reject them anyway — fail fast with a precise message).
    int64_t htlc3Expiry64 = lpExpiryProvided
        ? (int64_t)currentHeight + (int64_t)lpExpiryBlocks
        : (int64_t)expiryHeight + (int64_t)HTLC3S_MIN_LIFETIME;
    if (htlc3Expiry64 < (int64_t)expiryHeight + (int64_t)HTLC3S_MIN_LIFETIME)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("HTLC3 expiry (%lld) must be at least parent expiry + %u blocks (HTLC3S_MIN_LIFETIME)",
                      (long long)htlc3Expiry64, HTLC3S_MIN_LIFETIME));
    if (htlc3Expiry64 > (int64_t)std::numeric_limits<uint32_t>::max())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC3 expiry overflows uint32 block height");
    uint32_t htlc3ExpiryHeight = (uint32_t)htlc3Expiry64;

    // Get wallet TX for receipt
    auto it = pwallet->mapWallet.find(receiptTxid);
    if (it == pwallet->mapWallet.end())
        throw JSONRPCError(RPC_WALLET_ERROR, "Receipt transaction not found in wallet");
    const CWalletTx& wtx = it->second;
    if (receiptVout >= wtx.tx->vout.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output index");

    CAmount receiptAmount = wtx.tx->vout[receiptVout].nValue;
    CScript receiptScriptPubKey = wtx.tx->vout[receiptVout].scriptPubKey;

    if (receiptAmount <= covenantFee)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Receipt amount (%lld) must exceed covenant fee (%lld)", receiptAmount, covenantFee));

    // Get refund key from wallet (LP refund for HTLC2, retail refund for HTLC3)
    CPubKey refundPubKey;
    if (!pwallet->GetKeyFromPool(refundPubKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out");
    CKeyID refundKeyID = refundPubKey.GetID();

    // === Build HTLC3 redeemScript (no covenant, standard conditional) ===
    // HTLC3: LP claims with same hashlock, retail can refund after htlc3ExpiryHeight
    CScript htlc3RedeemScript = CreateConditionalScript(
        hashlock, htlc3ExpiryHeight, *lpClaimKey, refundKeyID);

    // === Compute template commitment C3 ===
    // PivotTx template: nVersion=SAPLING, nType=HTLC_CLAIM, 1 input, 2 outputs
    // (vout[0]=P2SH(HTLC3) net of fee, vout[1]=OP_TRUE covenant fee receipt).
    CMutableTransaction templateTx;
    templateTx.nVersion = CTransaction::TxVersion::SAPLING;
    templateTx.nType = CTransaction::TxType::HTLC_CLAIM;
    templateTx.nLockTime = 0;
    templateTx.vin.resize(1);
    templateTx.vin[0].nSequence = 0xFFFFFFFF;

    // Output[0]: amount minus fee, to P2SH(HTLC3)
    CScriptID htlc3ScriptID(htlc3RedeemScript);
    CScript htlc3ScriptPubKey = GetScriptForDestination(htlc3ScriptID);
    templateTx.vout.emplace_back(receiptAmount - covenantFee, htlc3ScriptPubKey);
    // Output[1]: covenant fee as an OP_TRUE M1 fee receipt (producer claims it),
    // NOT left to the coinbase — keeps the fee backed M1 (no M1_supply drift, no
    // stranded vault). CheckHTLCClaim enforces this exact output at claim time.
    templateTx.vout.emplace_back(covenantFee, CScript() << OP_TRUE);

    uint256 C3 = ComputeTemplateHash(CTransaction(templateTx));

    // === Build HTLC2 with covenant ===
    CScript htlc2RedeemScript = CreateConditionalWithCovenantScript(
        hashlock, expiryHeight, *retailClaimKey, refundKeyID, C3);

    CScriptID htlc2ScriptID(htlc2RedeemScript);
    CScript htlc2ScriptPubKey = GetScriptForDestination(htlc2ScriptID);

    // === Build HTLC_CREATE_M1 TX ===
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CREATE_M1;

    // Payload v2 with covenant fields
    HTLCCreatePayload payload;
    payload.nVersion = HTLC_CREATE_PAYLOAD_VERSION_CTV;
    payload.hashlock = hashlock;
    payload.expiryHeight = expiryHeight;
    payload.claimKeyID = *retailClaimKey;
    payload.refundKeyID = refundKeyID;
    payload.templateCommitment = C3;
    payload.htlc3ExpiryHeight = htlc3ExpiryHeight;
    payload.htlc3ClaimKeyID = *lpClaimKey;
    payload.htlc3RefundKeyID = refundKeyID;

    CDataStream ssPayload(SER_NETWORK, PROTOCOL_VERSION);
    ssPayload << payload;
    mtx.extraPayload = std::vector<uint8_t>(ssPayload.begin(), ssPayload.end());

    // Input: M1 receipt
    mtx.vin.emplace_back(receiptOutpoint);

    // Output: HTLC P2SH (fee-exempt, full amount)
    mtx.vout.emplace_back(receiptAmount, htlc2ScriptPubKey);

    // Sign
    const CTransaction txConst(mtx);
    SignatureData sigdata;
    if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txConst, 0, receiptAmount, SIGHASH_ALL),
                         receiptScriptPubKey, sigdata, txConst.GetRequiredSigVersion()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Signing M1 receipt failed. Do you own this receipt?");
    UpdateTransaction(mtx, 0, sigdata);

    // Submit to mempool
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const uint256& hashTx = tx->GetHash();

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true))
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
    }

    // Relay
    if (g_connman) {
        CInv inv(MSG_TX, hashTx);
        g_connman->ForEachNode([&inv](CNode* pnode) { pnode->PushInventory(inv); });
    }

    { LOCK(pwallet->cs_wallet); pwallet->MarkDirty(); }

    // Result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("htlc_outpoint", strprintf("%s:0", hashTx.GetHex()));
    result.pushKV("amount", ValueFromAmount(receiptAmount));
    result.pushKV("template_commitment", HexStr(Span<const unsigned char>(C3.begin(), C3.size())));
    result.pushKV("htlc3_redeem_script", HexStr(Span<const unsigned char>(htlc3RedeemScript.data(), htlc3RedeemScript.size())));
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));
    result.pushKV("expiry_height", (int)expiryHeight);
    result.pushKV("htlc3_expiry_height", (int)htlc3ExpiryHeight);
    result.pushKV("claim_address", EncodeDestination(*retailClaimKey));
    result.pushKV("lp_claim_address", EncodeDestination(*lpClaimKey));
    result.pushKV("refund_address", EncodeDestination(refundKeyID));
    result.pushKV("covenant_fee", covenantFee);

    return result;
}

/**
 * gettemplatehash - Compute template hash for a raw transaction
 */
static UniValue gettemplatehash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "gettemplatehash \"tx_hex\"\n"
            "\nCompute the OP_TEMPLATEVERIFY template hash for a raw transaction.\n"
            "\nArguments:\n"
            "1. \"tx_hex\" (string, required) Raw transaction hex\n"
            "\nResult:\n"
            "{\n"
            "  \"template_hash\": \"hex\",  (string) Template commitment hash\n"
            "  \"nversion\": n,            (numeric) Transaction version\n"
            "  \"ntype\": n,               (numeric) Transaction type\n"
            "  \"nlocktime\": n,           (numeric) Lock time\n"
            "  \"inputs\": n,              (numeric) Input count\n"
            "  \"outputs\": n              (numeric) Output count\n"
            "}\n"
        );
    }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    CTransaction tx(mtx);
    uint256 hash = ComputeTemplateHash(tx);

    UniValue result(UniValue::VOBJ);
    result.pushKV("template_hash", HexStr(Span<const unsigned char>(hash.begin(), hash.size())));
    result.pushKV("nversion", tx.nVersion);
    result.pushKV("ntype", tx.nType);
    result.pushKV("nlocktime", (int64_t)tx.nLockTime);
    result.pushKV("inputs", (int64_t)tx.vin.size());
    result.pushKV("outputs", (int64_t)tx.vout.size());

    return result;
}

/**
 * htlc3s_compute_c3 - Compute C3 template hash for per-leg covenant
 *
 * Builds a template HTLC_CLAIM_3S transaction and returns its template hash.
 * Used by LP_IN to create covenant HTLC that forces output → LP_OUT.
 */
static UniValue htlc3s_compute_c3(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "htlc3s_compute_c3 amount \"dest_address\"\n"
            "\nCompute the C3 template hash for a per-leg covenant.\n"
            "The hash commits to a HTLC_CLAIM_3S TX with one output to dest_address.\n"
            "\nArguments:\n"
            "1. amount          (numeric, required) M1 amount in sats (output = amount - fee)\n"
            "2. \"dest_address\" (string, required) LP_OUT destination address (P2PKH)\n"
            "\nResult:\n"
            "{\n"
            "  \"template_hash\": \"hex\",\n"
            "  \"output_amount\": n,\n"
            "  \"fee\": n\n"
            "}\n"
        );
    }

    CAmount amount = request.params[0].get_int64();
    if (amount <= CTV_FIXED_FEE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be greater than covenant fee");
    }

    CTxDestination dest = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address");
    }

    // Build template claim TX (vout[0]=LP_OUT net of fee, vout[1]=OP_TRUE fee receipt)
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CLAIM_3S;
    mtx.nLockTime = 0;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = 0xFFFFFFFF;
    mtx.vout.emplace_back(amount - CTV_FIXED_FEE, GetScriptForDestination(dest));
    // Covenant fee as an OP_TRUE M1 fee receipt (producer claims it), NOT coinbase —
    // committed in C3 and enforced by CheckHTLC3SClaim.
    mtx.vout.emplace_back(CTV_FIXED_FEE, CScript() << OP_TRUE);

    CTransaction tx(mtx);
    uint256 hash = ComputeTemplateHash(tx);

    UniValue result(UniValue::VOBJ);
    // Use raw byte order (HexStr), NOT GetHex() which reverses endianness.
    // htlc3s_create parses with ParseHex+memcpy (raw), so output must match.
    result.pushKV("template_hash", HexStr(Span<const unsigned char>(hash.begin(), hash.size())));
    result.pushKV("output_amount", ValueFromAmount(amount - CTV_FIXED_FEE));
    result.pushKV("fee", ValueFromAmount(CTV_FIXED_FEE));

    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category       name                    actor (function)         okSafe argNames
  //  -------------- ----------------------- ------------------------ ------ --------
    // Core settlement operations (P1)
    { "settlement",  "lock",                 &lock,                   false, {"amount"} },
    { "settlement",  "unlock",               &unlock,                 false, {"amount", "destination"} },
    { "settlement",  "transfer_m1",          &transfer_m1,            false, {"receipt_outpoint", "destination"} },
    { "settlement",  "split_m1",             &split_m1,               false, {"receipt_outpoint", "outputs"} },
    // Unified wallet view
    { "settlement",  "getwalletstate",       &getwalletstate,         true,  {"verbose"} },
    // B4.4 O2b / O1: sweep producer-pinned fee-receipts (no signatures needed)
    { "settlement",  "sweepfees",            &sweepfees,              false, {"owner_address", "dry_run"} },
    // HTLC operations (BP02)
    { "htlc",        "htlc_generate",        &htlc_generate,          true,  {} },
    { "htlc",        "htlc_create_m1",       &htlc_create_m1,         false, {"receipt_outpoint", "hashlock", "claim_address", "expiry_blocks"} },
    { "htlc",        "htlc_create_m1_covenant", &htlc_create_m1_covenant, false, {"receipt_outpoint", "hashlock", "retail_claim_addr", "lp_claim_addr", "expiry_blocks", "lp_expiry_blocks", "covenant_fee"} },
    { "htlc",        "htlc_claim",           &htlc_claim,             false, {"htlc_outpoint", "preimage"} },
    { "htlc",        "htlc_refund",          &htlc_refund,            false, {"htlc_outpoint"} },
    { "htlc",        "htlc_list",            &htlc_list,              true,  {"status"} },
    { "htlc",        "htlc_get",             &htlc_get,               true,  {"outpoint"} },
    { "htlc",        "htlc_verify",          &htlc_verify,            true,  {"preimage", "hashlock"} },
    { "htlc",        "htlc_extract_preimage",&htlc_extract_preimage,  true,  {"txid"} },
    // HTLC3S operations (BP02-3S FlowSwap)
    { "htlc3s",      "htlc3s_generate",      &htlc3s_generate,        true,  {} },
    { "htlc3s",      "htlc3s_create",        &htlc3s_create,          false, {"receipt_outpoint", "hashlock_user", "hashlock_lp1", "hashlock_lp2", "claim_address", "expiry_blocks", "template_commitment", "covenant_dest_address"} },
    { "htlc3s",      "htlc3s_claim",         &htlc3s_claim,           false, {"htlc_outpoint", "preimage_user", "preimage_lp1", "preimage_lp2"} },
    { "htlc3s",      "htlc3s_refund",        &htlc3s_refund,          false, {"htlc_outpoint"} },
    { "htlc3s",      "htlc3s_list",          &htlc3s_list,            true,  {"status"} },
    { "htlc3s",      "htlc3s_get",           &htlc3s_get,             true,  {"outpoint"} },
    { "htlc3s",      "htlc3s_verify",        &htlc3s_verify,          true,  {"preimage_user", "preimage_lp1", "preimage_lp2", "hashlock_user", "hashlock_lp1", "hashlock_lp2"} },
    { "htlc3s",      "htlc3s_find_by_hashlock", &htlc3s_find_by_hashlock, true, {"hashlock", "type"} },
    // Covenant utilities (Phase 4)
    { "htlc",        "gettemplatehash",      &gettemplatehash,        true,  {"tx_hex"} },
    { "htlc3s",      "htlc3s_compute_c3",   &htlc3s_compute_c3,     true,  {"amount", "dest_address"} },
};
// clang-format on

void RegisterSettlementWalletRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}

#else // !ENABLE_WALLET

// Stub when wallet is disabled
void RegisterSettlementWalletRPCCommands(CRPCTable& t)
{
    // No wallet RPCs when wallet is disabled
}

#endif // ENABLE_WALLET
