// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/settlement_builder.h"

#include "script/script.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"

// Estimated tx sizes for fee calculation
static const size_t BASE_TX_SIZE = 10;      // Version, locktime, etc.
static const size_t INPUT_SIZE = 148;        // P2PKH input with signature
static const size_t OUTPUT_SIZE = 34;        // P2PKH output

// BP30 v2.0 (Bearer Asset Model):
// - Vault uses OP_TRUE script (anyone-can-spend, but consensus-protected)
// - Receipt is M1 bearer asset (CEX-listable, transferable)
// - No bidirectional link between vault and receipt
// - Any M1 holder can burn M1 to claim M0 from any vault

// =============================================================================
// BuildLockTransaction (Bearer Asset Model)
// =============================================================================


// OP_TRUE vault script (anyone-can-spend at script level)
// Consensus rule protects: vault can ONLY be spent by TX_UNLOCK
static CScript GetVaultScript()
{
    CScript script;
    script << OP_TRUE;
    return script;
}

LockResult BuildLockTransaction(
    const std::vector<LockInput>& inputs,
    CAmount lockAmount,
    const CScript& receiptDest,
    const CScript& changeDest,
    CAmount feeRate)
{
    LockResult result;
    result.success = false;
    result.fee = 0;

    // Validate inputs
    if (inputs.empty()) {
        result.error = "No inputs provided";
        return result;
    }

    if (lockAmount <= 0) {
        result.error = "Lock amount must be positive";
        return result;
    }

    // Calculate total input
    CAmount totalIn = 0;
    for (const auto& input : inputs) {
        totalIn += input.amount;
    }

    // BP30 v2.0: Vault is OP_TRUE (consensus-locked)
    // Receipt(P) is M1, handled specially by consensus
    // From M0 perspective: outputs = Vault(P) + Change

    // Estimate transaction size
    size_t numOutputs = 2;  // Vault + Receipt
    bool hasChange = false;

    // Estimate fee (will refine after knowing change)
    size_t estSize = BASE_TX_SIZE +
                     inputs.size() * INPUT_SIZE +
                     numOutputs * OUTPUT_SIZE;
    CAmount estFee = (estSize * feeRate) / 1000;

    // M0 accounting: only Vault + Change count as M0
    // Receipt(P) is M1, consensus excludes it from fee calculation
    CAmount m0OutputValue = lockAmount;  // Vault only

    // Check if change needed
    CAmount changeAmount = totalIn - m0OutputValue - estFee;
    if (changeAmount > 0) {
        hasChange = true;
        numOutputs++;
        estSize += OUTPUT_SIZE;
        estFee = (estSize * feeRate) / 1000;
        changeAmount = totalIn - m0OutputValue - estFee;
    }

    // Verify sufficient funds (need vault M0 + fee, Receipt is M1)
    if (totalIn < m0OutputValue + estFee) {
        result.error = strprintf("Insufficient funds: have %lld, need %lld + %lld fee",
                                 (long long)totalIn, (long long)m0OutputValue, (long long)estFee);
        return result;
    }

    // Build transaction
    // Settlement txes must use SAPLING version for special tx validation
    CMutableTransaction mtx;
    mtx.nType = CTransaction::TxType::TX_LOCK;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;

    // Add inputs
    for (const auto& input : inputs) {
        mtx.vin.emplace_back(input.outpoint);
    }

    // vout[0] = Vault (P amount - OP_TRUE script, consensus-protected)
    // BP30 v2.0: Vault is anyone-can-spend but consensus only allows TX_UNLOCK
    mtx.vout.emplace_back(lockAmount, GetVaultScript());

    // vout[1] = Receipt (P amount - M1 bearer asset)
    mtx.vout.emplace_back(lockAmount, receiptDest);

    // vout[2] = Change (if any)
    if (hasChange && changeAmount > 0) {
        mtx.vout.emplace_back(changeAmount, changeDest);
    }

    // Success
    result.success = true;
    result.mtx = mtx;
    result.vaultOutpoint = COutPoint(mtx.GetHash(), 0);
    result.receiptOutpoint = COutPoint(mtx.GetHash(), 1);
    result.lockedAmount = lockAmount;
    result.fee = estFee;

    return result;
}

// =============================================================================
// BuildUnlockTransaction (Bearer Asset Model - BP30 v2.1)
// =============================================================================

// Vault inputs use OP_TRUE - minimal input size (no signature needed)
static const size_t VAULT_INPUT_SIZE = 41;  // outpoint(36) + scriptSig(~5)

UnlockResult BuildUnlockTransaction(
    const std::vector<M1Input>& m1Inputs,
    const std::vector<VaultInput>& vaultInputs,
    CAmount unlockAmount,
    const CScript& destScript,
    const CScript& changeScript,
    CAmount feeRate)
{
    UnlockResult result;
    result.success = false;
    result.fee = 0;
    result.m1Burned = 0;
    result.m1Change = 0;

    // Validate inputs
    if (m1Inputs.empty()) {
        result.error = "No M1 receipt inputs provided";
        return result;
    }

    if (vaultInputs.empty()) {
        result.error = "No vault inputs provided";
        return result;
    }

    // Calculate M1 total available
    CAmount totalM1 = 0;
    for (const auto& m1 : m1Inputs) {
        totalM1 += m1.amount;
    }

    // Calculate vault total available
    CAmount totalVault = 0;
    for (const auto& vault : vaultInputs) {
        totalVault += vault.amount;
    }

    // BP30 v3.0 M1 FEE MODEL:
    //
    //   M1_in == M0_out + M1_change + M1_fee
    //
    // Fee is paid in M1 (deducted from unlock amount).
    // No M0 inputs required for fee - solves the UX deadlock!
    //
    // A6 Preservation:
    //   - M1_fee is NOT burned, it's transferred to block producer
    //   - Vault backing for M1_fee stays locked
    //   - Therefore A6 (M0_vaulted == M1_supply) is preserved
    //
    // Full unlock:   unlockAmount = 0 → M0_out = M1_in - fee, M1_change = 0
    // Partial unlock: unlockAmount > 0 → M0_out = unlockAmount, fee deducted from remainder

    // Estimate transaction size for fee calculation
    // Base: version(4) + locktime(4) + vin_count(1) + vout_count(1) + type(2)
    // Inputs: M1 receipts + vaults
    // Outputs: M0 out + optional M1 change + M1 fee + vault backing
    size_t estimatedSize = 12;  // Base overhead
    estimatedSize += m1Inputs.size() * 148;  // P2PKH input ~148 bytes
    estimatedSize += vaultInputs.size() * VAULT_INPUT_SIZE;
    estimatedSize += 34;  // M0 output (P2PKH)
    estimatedSize += 34;  // M1 change output (worst case)
    estimatedSize += 11;  // M1 fee output (OP_TRUE, minimal)
    estimatedSize += 11;  // Vault backing output (OP_TRUE)

    // Calculate M1 fee from transaction size
    // feeRate is in sat/kB, convert to actual fee
    CAmount m1Fee = (feeRate > 0) ? (feeRate * estimatedSize / 1000) : 0;
    if (m1Fee < 50 && feeRate > 0) {
        m1Fee = 50;  // Minimum fee to prevent dust
    }

    // Handle unlockAmount = 0 (full unlock - user gets everything minus fee)
    if (unlockAmount == 0) {
        if (totalM1 <= m1Fee) {
            result.error = strprintf("M1 available %lld <= fee %lld, cannot unlock",
                                     (long long)totalM1, (long long)m1Fee);
            return result;
        }
        unlockAmount = totalM1 - m1Fee;
    }

    // Validate: M1 must cover unlock amount + fee
    if (unlockAmount + m1Fee > totalM1) {
        result.error = strprintf("Unlock amount %lld + fee %lld exceeds M1 available %lld",
                                 (long long)unlockAmount, (long long)m1Fee, (long long)totalM1);
        return result;
    }

    // Validate: vaults must cover unlock amount + fee backing
    // (M1 fee needs vault backing to preserve A6)
    if (totalVault < unlockAmount + m1Fee) {
        result.error = strprintf("Insufficient vault M0: have %lld, need %lld (unlock=%lld + fee_backing=%lld)",
                                 (long long)totalVault, (long long)(unlockAmount + m1Fee),
                                 (long long)unlockAmount, (long long)m1Fee);
        return result;
    }

    // Calculate M1 change (user's remaining M1 after unlock and fee)
    CAmount m1Change = totalM1 - unlockAmount - m1Fee;

    // BP30 v3.1 (producer-incentive): the fee is an M0 coinbase fee, released from
    // the vault — there is no OP_TRUE fee receipt and no fee-backing output. The
    // vault releases unlockAmount (to the user) and m1Fee (to the coinbase), leaving
    // vaultChange as the re-locked OP_TRUE backing. CheckUnlock enforces
    // totalVault == unlockAmount + m1Fee + vaultChange.
    CAmount vaultChange = totalVault - unlockAmount - m1Fee;

    // Build transaction (SAPLING version required for special tx)
    CMutableTransaction mtx;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;

    // BP30 v3.0 canonical order:
    // - vin[0..N] = M1 Receipts (signed by M1 holders)
    // - vin[N+1..K] = Vaults (no signature - OP_TRUE)
    // NO M0 fee inputs (fee paid in M1)

    // Add M1 receipt inputs first
    for (const auto& m1 : m1Inputs) {
        mtx.vin.emplace_back(m1.outpoint);
    }

    // Add vault inputs (no signature needed - OP_TRUE)
    for (const auto& vault : vaultInputs) {
        mtx.vin.emplace_back(vault.outpoint);
    }

    // BP30 v3.1 canonical output order:
    // vout[0] = M0 output (unlocked funds to user)
    // vout[1] = M1 change receipt (if any, to user)
    // vout[2] = Vault change (OP_TRUE backing for the M1 change)
    // The fee (m1Fee) is NOT an output — it is left on the table for the coinbase.

    CScript opTrueScript = CScript() << OP_TRUE;

    // vout[0] = M0 output (unlocked funds)
    mtx.vout.emplace_back(unlockAmount, destScript);

    // vout[1] = M1 change receipt (if any)
    if (m1Change > 0) {
        mtx.vout.emplace_back(m1Change, changeScript);
    }

    // vout[2] = Vault change (OP_TRUE) — every vault satoshi not released to the user
    // (M0) or to the coinbase (fee) is re-locked here to keep A6.
    if (vaultChange > 0) {
        mtx.vout.emplace_back(vaultChange, opTrueScript);
    }

    // Calculate txid for result
    uint256 txid = mtx.GetHash();

    // Success
    result.success = true;
    result.mtx = mtx;
    result.unlockedAmount = unlockAmount;
    result.m1Burned = unlockAmount + m1Fee;  // BP30 v3.1: net M1 burned = M0_out + fee
    result.m1Change = m1Change;
    result.fee = m1Fee;  // BP30 v3.1: M0 coinbase fee (implicit, left on the table)

    if (m1Change > 0) {
        result.m1ChangeOutpoint = COutPoint(txid, 1);
    }

    return result;
}

// =============================================================================
// BuildTransferTransaction (BP30 v3.0 - M1 Fee Model)
// =============================================================================

TransferResult BuildTransferTransaction(
    const TransferInput& receipt,
    const CScript& newDest,
    CAmount feeRate)
{
    TransferResult result;
    result.success = false;

    // BP30 v3.0: M1 fee model — fee is paid in M1 (deducted from the transfer amount)

    // Estimate size (1 input, 2 outputs: recipient + fee)
    size_t numInputs = 1;   // M1 receipt only
    size_t numOutputs = 2;  // Recipient receipt + M1 fee

    size_t estSize = BASE_TX_SIZE +
                     numInputs * INPUT_SIZE +
                     numOutputs * OUTPUT_SIZE;
    CAmount m1Fee = (estSize * feeRate) / 1000;

    // Calculate recipient amount (M1 input minus fee)
    CAmount recipientAmount = receipt.amount - m1Fee;

    // Verify sufficient M1 for fee
    if (recipientAmount <= 0) {
        result.error = strprintf("M1 amount too small for fee: have %lld, need fee %lld",
                                 (long long)receipt.amount, (long long)m1Fee);
        return result;
    }

    // Build transaction (SAPLING version required for special tx)
    CMutableTransaction mtx;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;

    // vin[0] = M1 Receipt (only input - M1 fee model)
    mtx.vin.emplace_back(receipt.receiptOutpoint);

    // BP30 v3.0 canonical output order:
    // vout[0] = New M1 Receipt (recipient amount = input - fee)
    // vout[1] = M1 fee (OP_TRUE script, block producer claims)

    CScript opTrueScript = CScript() << OP_TRUE;

    // vout[0] = Recipient M1 receipt
    mtx.vout.emplace_back(recipientAmount, newDest);

    // vout[1] = M1 fee output (OP_TRUE - producer claims this)
    mtx.vout.emplace_back(m1Fee, opTrueScript);

    // Success
    result.success = true;
    result.mtx = mtx;
    result.newReceiptOutpoint = COutPoint(mtx.GetHash(), 0);

    return result;
}

// =============================================================================
// BuildSplitTransaction (BP30 v3.0 - M1 Fee Model)
// =============================================================================

SplitResult BuildSplitTransaction(
    const TransferInput& receipt,
    const std::vector<SplitOutput>& outputs,
    CAmount feeRate)
{
    SplitResult result;
    result.success = false;
    result.fee = 0;

    // BP30 v3.0: M1 fee model — fee is paid in M1 (deducted from the split)

    // Validate outputs
    if (outputs.empty()) {
        result.error = "No split outputs provided";
        return result;
    }

    if (outputs.size() < 2) {
        result.error = "Split requires at least 2 outputs (use transfer_m1 for 1 output)";
        return result;
    }

    // Calculate total output amount to recipients
    CAmount totalRecipientOutput = 0;
    for (const auto& out : outputs) {
        if (out.amount <= 0) {
            result.error = "Split output amount must be positive";
            return result;
        }
        if (out.destination.empty() || out.destination.IsUnspendable()) {
            result.error = "Split output destination must be spendable";
            return result;
        }
        totalRecipientOutput += out.amount;
    }

    // Estimate size (1 input, N recipient outputs + 1 fee output)
    size_t numInputs = 1;  // M1 receipt only
    size_t numOutputs = outputs.size() + 1;  // Recipients + M1 fee

    size_t estSize = BASE_TX_SIZE +
                     numInputs * INPUT_SIZE +
                     numOutputs * OUTPUT_SIZE;
    CAmount m1Fee = (estSize * feeRate) / 1000;

    // BP30 v3.0: M1 fee model - fee is paid in M1
    // Conservation: sum(recipient outputs) + fee == receipt.amount
    CAmount expectedTotal = totalRecipientOutput + m1Fee;

    if (expectedTotal > receipt.amount) {
        result.error = strprintf("Split outputs (%lld) + fee (%lld) exceed input (%lld)",
                                 (long long)totalRecipientOutput, (long long)m1Fee,
                                 (long long)receipt.amount);
        return result;
    }

    // Adjust fee if there's slack (ensures strict conservation)
    if (expectedTotal < receipt.amount) {
        m1Fee = receipt.amount - totalRecipientOutput;
    }

    // Build transaction (uses TX_TRANSFER_M1 type - same consensus rules)
    CMutableTransaction mtx;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;

    // vin[0] = M1 Receipt input (only input - M1 fee model)
    mtx.vin.emplace_back(receipt.receiptOutpoint);

    // BP30 v3.0 canonical output order:
    // vout[0..N-1] = New M1 receipts to recipients
    // vout[N] = M1 fee (OP_TRUE script, block producer claims)

    CScript opTrueScript = CScript() << OP_TRUE;

    // vout[0..N-1] = Recipient M1 receipts
    for (const auto& out : outputs) {
        mtx.vout.emplace_back(out.amount, out.destination);
    }

    // vout[N] = M1 fee output (OP_TRUE - producer claims this)
    mtx.vout.emplace_back(m1Fee, opTrueScript);

    // Build result
    result.success = true;
    result.mtx = mtx;
    result.fee = m1Fee;

    // Populate new receipt outpoints (only recipient outputs, not fee)
    uint256 txid = mtx.GetHash();
    for (size_t i = 0; i < outputs.size(); ++i) {
        result.newReceipts.push_back(COutPoint(txid, i));
    }

    return result;
}
