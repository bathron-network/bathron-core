// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "burnclaim/burnclaim.h"
#include "burnclaim/burnclaimdb.h"
#include "burnclaim/killswitch.h"
#include "btcspv/btcspv.h"
#include "state/settlementdb.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "key_io.h"
#include "merkleblock.h"
#include "net/net.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "pubkey.h"
#include "rpc/server.h"
#include "streams.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "fs.h"
// No wallet includes - burn claims don't need signing

#include <univalue.h>
#include <fstream>

// BCS v02 (A2): a burn destination is a key hash (v01 / type 0x00) or a
// script hash (type 0x01) — encode the address accordingly.
static CTxDestination BurnDestToTxDest(uint8_t destType, const uint160& hash)
{
    if (destType == BURN_DEST_P2SH) return CTxDestination(CScriptID(hash));
    return CTxDestination(CKeyID(hash));
}


// Helper to relay a transaction to peers
static void RelayBurnClaimTx(const uint256& hashTx)
{
    if (!g_connman) return;

    CInv inv(MSG_TX, hashTx);
    g_connman->ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

UniValue submitburnclaim(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 5 || request.params.size() > 6) {
        throw std::runtime_error(
            "submitburnclaim \"btc_raw_tx\" \"btc_block_hash\" height [\"merkle_proof\",...] tx_index (\"bathron_address\")\n"
            "\nSubmit a burn claim for M0BTC minting.\n"
            "\nArguments:\n"
            "1. btc_raw_tx      (string, required) Hex-encoded raw BTC transaction\n"
            "2. btc_block_hash  (string, required) BTC block hash containing the TX\n"
            "3. height          (numeric, required) BTC block height\n"
            "4. merkle_proof    (array, required) Array of hex hashes for merkle proof\n"
            "5. tx_index        (numeric, required) TX index in block\n"
            "6. bathron_address    (string, optional) BATHRON address to claim to (default: from burn metadata)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"...\",           (string) BATHRON claim transaction ID\n"
            "  \"btc_txid\": \"...\",       (string) BTC burn transaction ID\n"
            "  \"burned_sats\": n,          (numeric) Satoshis burned\n"
            "  \"bathron_dest\": \"...\",      (string) BATHRON destination address\n"
            "  \"status\": \"pending\"      (string) Claim status\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("submitburnclaim", "\"0100000001...\" \"00000000...\" 286000 '[\"abc...\",\"def...\"]' 5")
        );
    }

    // Parse arguments
    std::string btcRawTxHex = request.params[0].get_str();
    std::string btcBlockHashHex = request.params[1].get_str();
    uint32_t btcBlockHeight = request.params[2].get_int();
    UniValue proofArray = request.params[3].get_array();
    uint32_t txIndex = request.params[4].get_int();

    // Parse BTC raw TX
    std::vector<uint8_t> btcTxBytes = ParseHex(btcRawTxHex);
    if (btcTxBytes.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid BTC raw transaction hex");
    }

    // Parse and validate BTC TX
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(btcTxBytes, btcTx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse BTC transaction");
    }

    // Parse burn outputs to get destination
    BurnInfo burnInfo;
    if (!ParseBurnOutputs(btcTx, burnInfo)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC TX is not a valid burn (missing BATHRON metadata or burn output)");
    }

    // Verify network byte (accept both numeric and ASCII formats)
    bool networkOk = Params().IsTestnet()
        ? (burnInfo.network == 0x01 || burnInfo.network == 0x54)  // 0x01 or 'T'
        : (burnInfo.network == 0x00 || burnInfo.network == 0x4D); // 0x00 or 'M'
    if (!networkOk) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Burn network mismatch: got %d (0x%02x), expected %s",
                      burnInfo.network, burnInfo.network,
                      Params().IsTestnet() ? "0x01 or 'T'" : "0x00 or 'M'"));
    }

    // Parse block hash
    uint256 btcBlockHash = uint256S(btcBlockHashHex);
    if (btcBlockHash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid BTC block hash");
    }

    // Parse merkle proof
    std::vector<uint256> merkleProof;
    for (size_t i = 0; i < proofArray.size(); i++) {
        merkleProof.push_back(uint256S(proofArray[i].get_str()));
    }
    if (merkleProof.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Merkle proof is empty");
    }

    // Check SPV status
    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    // Verify block exists and is in best chain
    BtcHeaderIndex btcHeader;
    if (!g_btc_spv->GetHeader(btcBlockHash, btcHeader)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "BTC block not found in SPV chain. Use getbtcsyncstatus to check sync.");
    }
    if (!g_btc_spv->IsInBestChain(btcBlockHash)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC block not in best chain");
    }

    // Verify height matches
    if (btcHeader.height != btcBlockHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Height mismatch: provided %d, actual %d", btcBlockHeight, btcHeader.height));
    }

    // Compute BTC txid and verify merkle proof
    uint256 btcTxid = ComputeBtcTxid(btcTx);
    if (!g_btc_spv->VerifyMerkleProof(btcTxid, btcHeader.header.hashMerkleRoot, merkleProof, txIndex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Merkle proof verification failed");
    }

    // Check confirmations
    uint32_t confirmations = g_btc_spv->GetConfirmations(btcBlockHash);
    uint32_t requiredConf = GetRequiredConfirmations();
    if (confirmations < requiredConf) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Insufficient confirmations: %d < %d required", confirmations, requiredConf));
    }

    // Build payload - no signature needed!
    // The burn proof is self-authenticating:
    // - BTC tx is signed by the burner
    // - BATHRON metadata encodes the destination
    // - Merkle proof proves inclusion in block
    // - Confirmations prove finality
    // Anyone can submit a valid claim, M0BTC always goes to the encoded destination
    BurnClaimPayload payload;
    payload.nVersion = BURN_CLAIM_PAYLOAD_VERSION;
    payload.btcTxBytes = btcTxBytes;
    payload.btcBlockHash = btcBlockHash;
    payload.btcBlockHeight = btcBlockHeight;
    payload.merkleProof = merkleProof;
    payload.txIndex = txIndex;

    // Build TX_BURN_CLAIM transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BURN_CLAIM;

    // Serialize payload to extraPayload
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());

    // Create transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    uint256 hashTx = tx->GetHash();

    // Broadcast to mempool
    CValidationState state;
    bool fMissingInputs = false;

    {
        LOCK(cs_main);
        // ignoreFees=true because TX_BURN_CLAIM has no inputs (fee-less special TX)
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true)) {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                strprintf("TX rejected: %s", state.GetRejectReason()));
        }
    }

    // Relay to network
    RelayBurnClaimTx(hashTx);

    LogPrintf("BURNCLAIM-RPC: TX_BURN_CLAIM %s submitted for btc_txid %s\n",
              hashTx.ToString().substr(0, 16), btcTxid.ToString().substr(0, 16));

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("btc_txid", btcTxid.GetHex());
    result.pushKV("burned_sats", (int64_t)burnInfo.burnedSats);

    // Convert destination to address (from burn metadata)
    CTxDestination dest = BurnDestToTxDest(burnInfo.destType, burnInfo.bathronDest);
    result.pushKV("bathron_dest", EncodeDestination(dest));
    result.pushKV("dest_type", burnInfo.destType == BURN_DEST_P2SH ? "p2sh" : "p2pkh");

    result.pushKV("btc_confirmations", (int)confirmations);
    result.pushKV("status", "pending");
    result.pushKV("broadcast", true);

    return result;
}

UniValue submitburnclaimproof(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "submitburnclaimproof \"btc_raw_tx\" \"merkleblock_hex\"\n"
            "\nSubmit a burn claim using raw merkleblock proof from gettxoutproof.\n"
            "\nThis is the simplified version - no manual proof extraction needed.\n"
            "Just pass the BTC raw tx and the output from 'bitcoin-cli gettxoutproof'.\n"
            "\nArguments:\n"
            "1. btc_raw_tx       (string, required) Hex-encoded raw BTC transaction\n"
            "2. merkleblock_hex  (string, required) Hex output from 'gettxoutproof' (CMerkleBlock)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"...\",           (string) BATHRON claim transaction ID\n"
            "  \"btc_txid\": \"...\",       (string) BTC burn transaction ID\n"
            "  \"btc_block_hash\": \"...\", (string) BTC block hash\n"
            "  \"btc_height\": n,           (numeric) BTC block height\n"
            "  \"burned_sats\": n,          (numeric) Satoshis burned\n"
            "  \"bathron_dest\": \"...\",      (string) BATHRON destination address\n"
            "  \"status\": \"pending\"      (string) Claim status\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("submitburnclaimproof", "\"0100000001...\" \"0000002...\"")
        );
    }

    // Parse BTC raw TX
    std::string btcRawTxHex = request.params[0].get_str();
    std::vector<uint8_t> btcTxBytes = ParseHex(btcRawTxHex);
    if (btcTxBytes.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid BTC raw transaction hex");
    }

    // Parse and validate BTC TX
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(btcTxBytes, btcTx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse BTC transaction");
    }

    // Parse burn outputs to get destination
    BurnInfo burnInfo;
    if (!ParseBurnOutputs(btcTx, burnInfo)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC TX is not a valid burn (missing BATHRON metadata or burn output)");
    }

    // Verify network byte (accept both numeric and ASCII formats)
    bool networkOk2 = Params().IsTestnet()
        ? (burnInfo.network == 0x01 || burnInfo.network == 0x54)  // 0x01 or 'T'
        : (burnInfo.network == 0x00 || burnInfo.network == 0x4D); // 0x00 or 'M'
    if (!networkOk2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Burn network mismatch: got %d (0x%02x), expected %s",
                      burnInfo.network, burnInfo.network,
                      Params().IsTestnet() ? "0x01 or 'T'" : "0x00 or 'M'"));
    }

    // Compute BTC txid
    uint256 btcTxid = ComputeBtcTxid(btcTx);

    // Parse BTC CMerkleBlock from hex
    // NOTE: Can't use CMerkleBlock directly because BATHRON's CBlockHeader has
    // extra fields (hashFinalSaplingRoot) that don't exist in BTC headers.
    // We must parse BTC header (80 bytes) separately from the partial merkle tree.
    std::string merkleBlockHex = request.params[1].get_str();
    std::vector<uint8_t> merkleBlockBytes = ParseHex(merkleBlockHex);
    if (merkleBlockBytes.size() < 80) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Invalid merkleblock: too short (%zu bytes)", merkleBlockBytes.size()));
    }

    // Parse first 80 bytes as BTC header (same format as BtcBlockHeader)
    BtcBlockHeader btcHeader;
    CPartialMerkleTree pmt;
    try {
        CDataStream ss(merkleBlockBytes, SER_NETWORK, PROTOCOL_VERSION);
        ss >> btcHeader;  // Exactly 80 bytes
        ss >> pmt;        // Rest is partial merkle tree
        if (!ss.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Extra data after merkleblock");
        }
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Failed to parse merkleblock: %s", e.what()));
    }

    uint256 btcBlockHash = btcHeader.GetHash();

    // Extract proof using the correct PMT traversal method
    // This collects siblings in leaf-to-root order as required by VerifyMerkleProof
    uint256 extractedTxid;
    uint32_t txIndex;
    std::vector<uint256> merkleProof;

    uint256 extractedRoot = pmt.ExtractSingleMatchWithProof(
        extractedTxid, txIndex, merkleProof);

    if (extractedRoot.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Merkle proof extraction failed - invalid or malformed merkleblock");
    }

    // Verify merkle root matches header
    if (extractedRoot != btcHeader.hashMerkleRoot) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Merkle root mismatch: proof doesn't match header");
    }

    // Verify extracted txid matches our BTC TX
    if (extractedTxid != btcTxid) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Extracted txid %s doesn't match provided TX %s",
                      extractedTxid.GetHex(), btcTxid.GetHex()));
    }

    // Check SPV status
    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    // Get BTC block height from SPV (has hash→height index via BtcHeaderIndex)
    BtcHeaderIndex btcHeaderIndex;
    if (!g_btc_spv->GetHeader(btcBlockHash, btcHeaderIndex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("BTC block %s not found in SPV chain. Use getbtcsyncstatus to check sync.",
                      btcBlockHash.GetHex()));
    }
    if (!g_btc_spv->IsInBestChain(btcBlockHash)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "BTC block not in best chain");
    }

    uint32_t btcBlockHeight = btcHeaderIndex.height;

    // Check confirmations
    uint32_t confirmations = g_btc_spv->GetConfirmations(btcBlockHash);
    uint32_t requiredConf = GetRequiredConfirmations();
    if (confirmations < requiredConf) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Insufficient confirmations: %d < %d required", confirmations, requiredConf));
    }

    // Sanity check: verify extracted proof with SPV
    if (!g_btc_spv->VerifyMerkleProof(btcTxid, btcHeader.hashMerkleRoot, merkleProof, txIndex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
            "Internal error: extracted proof failed SPV verification");
    }

    // Build payload
    BurnClaimPayload payload;
    payload.nVersion = BURN_CLAIM_PAYLOAD_VERSION;
    payload.btcTxBytes = btcTxBytes;
    payload.btcBlockHash = btcBlockHash;
    payload.btcBlockHeight = btcBlockHeight;
    payload.merkleProof = merkleProof;
    payload.txIndex = txIndex;

    // Build TX_BURN_CLAIM transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BURN_CLAIM;

    // Serialize payload to extraPayload
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());

    // Create transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    uint256 hashTx = tx->GetHash();

    // Broadcast to mempool
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
    RelayBurnClaimTx(hashTx);

    LogPrintf("BURNCLAIM-RPC: TX_BURN_CLAIM %s submitted via proof for btc_txid %s\n",
              hashTx.ToString().substr(0, 16), btcTxid.ToString().substr(0, 16));

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", hashTx.GetHex());
    result.pushKV("btc_txid", btcTxid.GetHex());
    result.pushKV("btc_block_hash", btcBlockHash.GetHex());
    result.pushKV("btc_height", (int)btcBlockHeight);
    result.pushKV("burned_sats", (int64_t)burnInfo.burnedSats);

    CTxDestination dest = BurnDestToTxDest(burnInfo.destType, burnInfo.bathronDest);
    result.pushKV("bathron_dest", EncodeDestination(dest));
    result.pushKV("dest_type", burnInfo.destType == BURN_DEST_P2SH ? "p2sh" : "p2pkh");

    result.pushKV("btc_confirmations", (int)confirmations);
    result.pushKV("status", "pending");
    result.pushKV("broadcast", true);

    return result;
}

// Helper: convert BurnClaimRecord to UniValue
static UniValue BurnClaimToJSON(const BurnClaimRecord& record)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("btc_txid", record.btcTxid.GetHex());
    obj.pushKV("btc_block_hash", record.btcBlockHash.GetHex());
    obj.pushKV("btc_height", (int)record.btcHeight);
    obj.pushKV("burned_sats", (int64_t)record.burnedSats);
    obj.pushKV("burned_btc", ValueFromAmount(record.burnedSats));

    // Convert destination to address
    CTxDestination dest = BurnDestToTxDest(record.destType, record.bathronDest);
    obj.pushKV("bathron_dest", EncodeDestination(dest));
    obj.pushKV("dest_type", record.destType == BURN_DEST_P2SH ? "p2sh" : "p2pkh");

    obj.pushKV("claim_height", (int)record.claimHeight);

    // DB status
    std::string dbStatus = (record.status == BurnClaimStatus::PENDING) ? "pending" : "final";
    obj.pushKV("db_status", dbStatus);

    // Display status (derived - includes orphaned)
    std::string displayStatus = dbStatus;
    if (record.status == BurnClaimStatus::PENDING && record.IsOrphaned()) {
        displayStatus = "orphaned";
    }
    obj.pushKV("display_status", displayStatus);

    if (record.status == BurnClaimStatus::FINAL) {
        obj.pushKV("final_height", (int)record.finalHeight);
    }

    // BTC confirmations (if SPV available)
    if (g_btc_spv) {
        obj.pushKV("btc_block_in_best_chain", g_btc_spv->IsInBestChain(record.btcBlockHash));
        uint32_t conf = g_btc_spv->GetConfirmations(record.btcBlockHash);
        obj.pushKV("btc_confirmations", (int)conf);
        obj.pushKV("btc_required", (int)GetRequiredConfirmations());
    }

    // Blocks until final (for pending)
    if (record.status == BurnClaimStatus::PENDING) {
        // This is approximate - actual finalization depends on BTC validity
        uint32_t kFinality = GetKFinality();
        // We don't have current height here, so just show claim height + K_FINALITY
        obj.pushKV("finalize_at_height", (int)(record.claimHeight + kFinality));
    }

    return obj;
}

UniValue getburnclaim(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "getburnclaim \"btc_txid\"\n"
            "\nGet information about a burn claim by BTC txid.\n"
            "\nArguments:\n"
            "1. btc_txid    (string, required) BTC burn transaction ID\n"
            "\nResult:\n"
            "{\n"
            "  \"btc_txid\": \"...\",\n"
            "  \"db_status\": \"pending|final\",\n"
            "  \"display_status\": \"pending|final|orphaned\",\n"
            "  \"burned_sats\": n,\n"
            "  \"burned_btc\": n.nnnnnnnn,\n"
            "  \"bathron_dest\": \"...\",\n"
            "  \"claim_height\": n,\n"
            "  \"final_height\": n,       (if final)\n"
            "  \"btc_confirmations\": n,\n"
            "  \"btc_required\": n,\n"
            "  \"btc_block_in_best_chain\": true|false\n"
            "}\n"
        );
    }

    if (!g_burnclaimdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Burn claim database not initialized");
    }

    uint256 btcTxid = uint256S(request.params[0].get_str());
    if (btcTxid.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid BTC txid");
    }

    BurnClaimRecord record;
    if (!g_burnclaimdb->GetBurnClaim(btcTxid, record)) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("btc_txid", btcTxid.GetHex());
        result.pushKV("status", "not_found");
        return result;
    }

    return BurnClaimToJSON(record);
}

UniValue listburnclaims(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 3) {
        throw std::runtime_error(
            "listburnclaims (filter) (count) (skip)\n"
            "\nList burn claims.\n"
            "\nArguments:\n"
            "1. filter  (string, optional) \"pending\", \"final\", \"orphaned\", or \"all\" (default: \"all\")\n"
            "2. count   (numeric, optional) Max results (default: 10)\n"
            "3. skip    (numeric, optional) Skip first N (default: 0)\n"
            "\nResult:\n"
            "[{claim_object}, ...]\n"
        );
    }

    if (!g_burnclaimdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Burn claim database not initialized");
    }

    std::string filter = "all";
    int count = 10;
    int skip = 0;

    if (request.params.size() > 0 && !request.params[0].isNull()) {
        filter = request.params[0].get_str();
    }
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        count = request.params[1].get_int();
        if (count <= 0) count = 10;
        if (count > 1000) count = 1000;  // Hard cap
    }
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        skip = request.params[2].get_int();
        if (skip < 0) skip = 0;
    }

    UniValue result(UniValue::VARR);
    int skipped = 0;
    int added = 0;

    auto addClaim = [&](const BurnClaimRecord& record) -> bool {
        // Apply filter
        bool include = false;
        if (filter == "all") {
            include = true;
        } else if (filter == "pending") {
            include = (record.status == BurnClaimStatus::PENDING && !record.IsOrphaned());
        } else if (filter == "final") {
            include = (record.status == BurnClaimStatus::FINAL);
        } else if (filter == "orphaned") {
            include = (record.status == BurnClaimStatus::PENDING && record.IsOrphaned());
        }

        if (!include) return true;  // Continue

        if (skipped < skip) {
            skipped++;
            return true;  // Continue
        }

        if (added >= count) {
            return false;  // Stop
        }

        result.push_back(BurnClaimToJSON(record));
        added++;
        return true;  // Continue
    };

    // Iterate based on filter
    if (filter == "final") {
        g_burnclaimdb->ForEachFinalClaim(addClaim);
    } else {
        // For pending, orphaned, or all - iterate pending first
        g_burnclaimdb->ForEachPendingClaim(addClaim);
        if (filter == "all" && added < count) {
            g_burnclaimdb->ForEachFinalClaim(addClaim);
        }
    }

    return result;
}

UniValue getbtcburnstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "getbtcburnstats\n"
            "\nReturns aggregate statistics about BTC burns.\n"
            "\nResult:\n"
            "{\n"
            "  \"total_records\": n,\n"
            "  \"total_pending\": n,\n"
            "  \"total_final\": n,\n"
            "  \"total_orphaned\": n,\n"
            "  \"m0btc_supply\": n,         (satoshis, FINAL only)\n"
            "  \"m0btc_pending\": n,        (satoshis, PENDING not orphaned)\n"
            "  \"m0btc_supply_btc\": n.nn,\n"
            "  \"m0btc_pending_btc\": n.nn\n"
            "}\n"
        );
    }

    if (!g_burnclaimdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Burn claim database not initialized");
    }

    auto stats = g_burnclaimdb->GetStats();

    // Count orphaned separately
    size_t orphanedCount = 0;
    uint64_t orphanedAmount = 0;

    g_burnclaimdb->ForEachPendingClaim([&](const BurnClaimRecord& record) {
        if (record.IsOrphaned()) {
            orphanedCount++;
            orphanedAmount += record.burnedSats;
        }
        return true;
    });

    UniValue result(UniValue::VOBJ);
    result.pushKV("total_records", (int)stats.totalRecords);
    result.pushKV("total_pending", (int)(stats.pendingCount - orphanedCount));
    result.pushKV("total_final", (int)stats.finalCount);
    result.pushKV("total_orphaned", (int)orphanedCount);
    result.pushKV("m0btc_supply", (int64_t)stats.m0btcSupply);
    result.pushKV("m0btc_pending", (int64_t)(stats.pendingAmount - orphanedAmount));
    result.pushKV("m0btc_supply_btc", ValueFromAmount(stats.m0btcSupply));
    result.pushKV("m0btc_pending_btc", ValueFromAmount(stats.pendingAmount - orphanedAmount));

    // Network info
    result.pushKV("k_confirmations", (int)GetRequiredConfirmations());
    result.pushKV("k_finality", (int)GetKFinality());

    return result;
}

UniValue verifyburntx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "verifyburntx \"btc_raw_tx_hex\"\n"
            "\nVerify if a BTC transaction is a valid BATHRON burn.\n"
            "\nArguments:\n"
            "1. btc_raw_tx_hex    (string, required) Raw BTC transaction in hex\n"
            "\nResult:\n"
            "{\n"
            "  \"valid\": true|false,\n"
            "  \"btc_txid\": \"...\",\n"
            "  \"version\": n,\n"
            "  \"network\": n,\n"
            "  \"bathron_dest\": \"...\",\n"
            "  \"burned_sats\": n,\n"
            "  \"error\": \"...\"  (if invalid)\n"
            "}\n"
        );
    }

    std::string btcRawTxHex = request.params[0].get_str();
    std::vector<uint8_t> btcTxBytes = ParseHex(btcRawTxHex);

    UniValue result(UniValue::VOBJ);

    // Parse BTC TX
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(btcTxBytes, btcTx)) {
        result.pushKV("valid", false);
        result.pushKV("error", "Failed to parse BTC transaction");
        return result;
    }

    uint256 btcTxid = ComputeBtcTxid(btcTx);
    result.pushKV("btc_txid", btcTxid.GetHex());

    // Check for SegWit
    result.pushKV("has_witness", btcTx.hasWitness);
    result.pushKV("vin_count", (int)btcTx.vin.size());
    result.pushKV("vout_count", (int)btcTx.vout.size());

    // Parse burn outputs
    BurnInfo burnInfo;
    if (!ParseBurnOutputs(btcTx, burnInfo)) {
        result.pushKV("valid", false);
        result.pushKV("error", "Not a valid BATHRON burn (missing metadata or burn output)");
        return result;
    }

    result.pushKV("valid", true);
    result.pushKV("version", (int)burnInfo.version);
    result.pushKV("network", (int)burnInfo.network);
    result.pushKV("network_name", burnInfo.network == 0 ? "mainnet" : "testnet");

    // Convert destination to address
    CTxDestination dest = BurnDestToTxDest(burnInfo.destType, burnInfo.bathronDest);
    result.pushKV("bathron_dest", EncodeDestination(dest));
    result.pushKV("dest_type", burnInfo.destType == BURN_DEST_P2SH ? "p2sh" : "p2pkh");
    result.pushKV("bathron_dest_hash160", burnInfo.bathronDest.GetHex());

    result.pushKV("burned_sats", (int64_t)burnInfo.burnedSats);
    result.pushKV("burned_btc", ValueFromAmount(burnInfo.burnedSats));

    return result;
}

UniValue getgenesisburnstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "getgenesisburnstats\n"
            "\nReturns statistics about all burn claims from burnclaimdb.\n"
            "\nNote: All burns (including pre-launch) are now detected by burn_claim_daemon.\n"
            "This RPC returns data from burnclaimdb (the single source of truth).\n"
            "\nResult:\n"
            "{\n"
            "  \"network\": \"xxx\",        (string) Network name\n"
            "  \"burn_count\": n,           (numeric) Number of burn claims in db\n"
            "  \"total_sats\": n,           (numeric) Total satoshis from all burns\n"
            "  \"total_btc\": n.nn          (numeric) Total in BTC format\n"
            "  \"pending\": n,              (numeric) Claims awaiting K confirmations\n"
            "  \"final\": n                 (numeric) Finalized claims\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getgenesisburnstats", "")
            + HelpExampleRpc("getgenesisburnstats", "")
        );
    }

    // Determine network name
    const CChainParams& params = Params();
    std::string network;
    if (params.IsTestnet()) {
        network = "test";
    } else if (params.IsRegTestNet()) {
        network = "regtest";
    } else {
        network = "main";
    }

    // Query burnclaimdb for all claims
    size_t burnCount = 0;
    CAmount totalSats = 0;
    size_t pendingCount = 0;
    size_t finalCount = 0;

    if (g_burnclaimdb) {
        // Count pending claims
        g_burnclaimdb->ForEachPendingClaim([&](const BurnClaimRecord& claim) {
            burnCount++;
            totalSats += claim.burnedSats;
            pendingCount++;
            return true;  // continue
        });

        // Count final claims
        g_burnclaimdb->ForEachFinalClaim([&](const BurnClaimRecord& claim) {
            burnCount++;
            totalSats += claim.burnedSats;
            finalCount++;
            return true;  // continue
        });
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("network", network);
    result.pushKV("burn_count", (int)burnCount);
    result.pushKV("total_sats", (int64_t)totalSats);
    result.pushKV("total_btc", ValueFromAmount(totalSats));
    result.pushKV("pending", (int)pendingCount);
    result.pushKV("final", (int)finalCount);

    return result;
}

// =============================================================================
// F3 Burnscan - BTC block scanning for burn claims
// =============================================================================

UniValue getburnscanstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "getburnscanstatus\n"
            "\nReturns the current burnscan progress and status.\n"
            "\nResult:\n"
            "{\n"
            "  \"last_height\": n,              (numeric) Last processed BTC block height\n"
            "  \"last_hash\": \"...\",          (string) Last processed BTC block hash\n"
            "  \"spv_tip_height\": n,           (numeric) Current SPV tip height\n"
            "  \"spv_min_height\": n,           (numeric) Minimum SPV height (checkpoint)\n"
            "  \"blocks_behind\": n,            (numeric) Number of blocks behind SPV tip\n"
            "  \"synced\": true|false,          (bool) Whether burnscan is at SPV tip\n"
            "  \"status\": \"...\"              (string) \"synced\", \"behind\", or \"not_started\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getburnscanstatus", "")
        );
    }

    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not initialized");
    }
    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    uint32_t lastHeight = 0;
    uint256 lastHash;
    bool hasProgress = g_settlementdb->ReadBurnscanProgress(lastHeight, lastHash);

    uint32_t spvTipHeight = g_btc_spv->GetTipHeight();
    uint32_t spvMinHeight = g_btc_spv->GetMinSupportedHeight();

    UniValue result(UniValue::VOBJ);

    if (hasProgress) {
        result.pushKV("last_height", (int)lastHeight);
        result.pushKV("last_hash", lastHash.GetHex());
    } else {
        result.pushKV("last_height", UniValue(UniValue::VNULL));
        result.pushKV("last_hash", UniValue(UniValue::VNULL));
    }

    result.pushKV("spv_tip_height", (int)spvTipHeight);
    result.pushKV("spv_min_height", (int)spvMinHeight);

    if (!hasProgress) {
        result.pushKV("blocks_behind", (int)(spvTipHeight - spvMinHeight));
        result.pushKV("synced", false);
        result.pushKV("status", "not_started");
    } else if (lastHeight >= spvTipHeight) {
        result.pushKV("blocks_behind", 0);
        result.pushKV("synced", true);
        result.pushKV("status", "synced");
    } else {
        result.pushKV("blocks_behind", (int)(spvTipHeight - lastHeight));
        result.pushKV("synced", false);
        result.pushKV("status", "behind");
    }

    return result;
}

UniValue setburnscanprogress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "setburnscanprogress height \"block_hash\"\n"
            "\nSet the burnscan progress (last processed BTC block).\n"
            "\nUsed by external scripts to update progress after processing blocks.\n"
            "\nArguments:\n"
            "1. height       (numeric, required) BTC block height\n"
            "2. block_hash   (string, required) BTC block hash\n"
            "\nResult:\n"
            "{\n"
            "  \"success\": true|false,\n"
            "  \"height\": n,\n"
            "  \"hash\": \"...\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("setburnscanprogress", "287000 \"000000...\"")
        );
    }

    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not initialized");
    }
    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    uint32_t height = request.params[0].get_int();
    uint256 hash = uint256S(request.params[1].get_str());

    if (hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block hash");
    }

    // F3.4 Reorg detection: verify the hash is in the SPV best chain
    if (!g_btc_spv->IsInBestChain(hash)) {
        // Check if we have this header at all
        BtcHeaderIndex headerIndex;
        if (!g_btc_spv->GetHeader(hash, headerIndex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Block %s not found in SPV headers", hash.GetHex().substr(0, 16)));
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Block %s at height %d is not in the SPV best chain (possible reorg)",
                      hash.GetHex().substr(0, 16), height));
    }

    // Verify height matches
    BtcHeaderIndex headerIndex;
    if (!g_btc_spv->GetHeader(hash, headerIndex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to get header from SPV");
    }
    if (headerIndex.height != height) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Height mismatch: provided %d, actual %d", height, headerIndex.height));
    }

    // Check for reorg: if we had previous progress, verify hash at that height still matches
    uint32_t prevHeight = 0;
    uint256 prevHash;
    if (g_settlementdb->ReadBurnscanProgress(prevHeight, prevHash)) {
        // Only check if going forward from previous progress
        if (height > prevHeight) {
            BtcHeaderIndex prevHeaderNow;
            if (g_btc_spv->GetHeaderAtHeight(prevHeight, prevHeaderNow)) {
                if (prevHeaderNow.hash != prevHash) {
                    LogPrintf("BURNSCAN WARNING: Reorg detected! Previous height %d had hash %s, now has %s\n",
                              prevHeight, prevHash.GetHex().substr(0, 16),
                              prevHeaderNow.hash.GetHex().substr(0, 16));
                    // Allow the update but log warning - caller should handle rollback
                }
            }
        }
    }

    // Write progress
    if (!g_settlementdb->WriteBurnscanProgress(height, hash)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to write burnscan progress");
    }

    LogPrintf("BURNSCAN: Progress updated to height=%d hash=%s\n",
              height, hash.GetHex().substr(0, 16));

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    result.pushKV("height", (int)height);
    result.pushKV("hash", hash.GetHex());
    return result;
}

UniValue checkburnclaim(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "checkburnclaim \"btc_txid\"\n"
            "\nCheck if a burn claim already exists (idempotence check).\n"
            "\nUsed by external scripts to skip already-processed burns.\n"
            "\nArguments:\n"
            "1. btc_txid    (string, required) BTC burn transaction ID\n"
            "\nResult:\n"
            "{\n"
            "  \"exists\": true|false,\n"
            "  \"btc_txid\": \"...\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("checkburnclaim", "\"abc123...\"")
        );
    }

    if (!g_burnclaimdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Burn claim database not initialized");
    }

    uint256 btcTxid = uint256S(request.params[0].get_str());
    if (btcTxid.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid BTC txid");
    }

    bool exists = g_burnclaimdb->ExistsBurnClaim(btcTxid);

    UniValue result(UniValue::VOBJ);
    result.pushKV("exists", exists);
    result.pushKV("btc_txid", btcTxid.GetHex());
    return result;
}

UniValue getburnscanrange(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "getburnscanrange (max_blocks)\n"
            "\nGet the next range of BTC blocks to scan.\n"
            "\nReturns start/end heights for the next scan batch.\n"
            "\nArguments:\n"
            "1. max_blocks   (numeric, optional, default=100) Max blocks to scan in one batch\n"
            "\nResult:\n"
            "{\n"
            "  \"start_height\": n,        (numeric) First block to scan\n"
            "  \"end_height\": n,          (numeric) Last block to scan (inclusive)\n"
            "  \"count\": n,               (numeric) Number of blocks in range\n"
            "  \"at_tip\": true|false      (bool) Whether we're already at SPV tip\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getburnscanrange", "")
            + HelpExampleCli("getburnscanrange", "50")
        );
    }

    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not initialized");
    }
    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    int maxBlocks = 100;
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        maxBlocks = request.params[0].get_int();
        if (maxBlocks <= 0) maxBlocks = 100;
        if (maxBlocks > 1000) maxBlocks = 1000;  // Hard cap
    }

    uint32_t spvTipHeight = g_btc_spv->GetTipHeight();
    uint32_t spvMinHeight = g_btc_spv->GetMinSupportedHeight();

    // Determine start height
    uint32_t startHeight;
    uint32_t lastHeight = 0;
    uint256 lastHash;

    if (g_settlementdb->ReadBurnscanProgress(lastHeight, lastHash)) {
        startHeight = lastHeight + 1;  // Next block after last processed
    } else {
        startHeight = spvMinHeight;  // Start from SPV minimum
    }

    UniValue result(UniValue::VOBJ);

    if (startHeight > spvTipHeight) {
        // Already at tip
        result.pushKV("start_height", (int)spvTipHeight);
        result.pushKV("end_height", (int)spvTipHeight);
        result.pushKV("count", 0);
        result.pushKV("at_tip", true);
        return result;
    }

    uint32_t endHeight = std::min(startHeight + (uint32_t)maxBlocks - 1, spvTipHeight);

    result.pushKV("start_height", (int)startHeight);
    result.pushKV("end_height", (int)endHeight);
    result.pushKV("count", (int)(endHeight - startHeight + 1));
    result.pushKV("at_tip", endHeight >= spvTipHeight);

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BP12 - Kill Switch RPCs
// ═══════════════════════════════════════════════════════════════════════════════

UniValue getburnstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "getburnstatus\n"
            "\nGet the current BTC burns status (kill switch state).\n"
            "\nResult:\n"
            "{\n"
            "  \"burns_enabled\": true|false,  (bool) Whether BTC burns are currently enabled\n"
            "  \"kill_switch_active\": true|false, (bool) True if kill switch is active (burns disabled)\n"
            "  \"config_default\": true|false, (bool) Default from config file\n"
            "  \"last_changed\": n,            (numeric) Unix timestamp of last state change (0 if never)\n"
            "  \"note\": \"...\"               (string) Human-readable status\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getburnstatus", "")
        );
    }

    KillSwitchStatus status = GetKillSwitchStatus();

    UniValue result(UniValue::VOBJ);
    result.pushKV("burns_enabled", status.enabled);
    result.pushKV("kill_switch_active", !status.enabled);
    result.pushKV("config_default", status.configDefault);
    result.pushKV("last_changed", status.lastChanged);

    if (status.enabled) {
        result.pushKV("note", "BTC burns are enabled. New burn claims will be processed.");
    } else {
        result.pushKV("note", "BTC burns are DISABLED (kill switch active). New burn claims will be rejected.");
    }

    return result;
}

UniValue setbtcburnsenabled(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "setbtcburnsenabled enabled\n"
            "\nEnable or disable BTC burns (activate/deactivate kill switch).\n"
            "\nWARNING: This is an emergency control. Use with caution.\n"
            "\nArguments:\n"
            "1. enabled   (bool, required) true to enable burns, false to disable\n"
            "\nResult:\n"
            "{\n"
            "  \"burns_enabled\": true|false,  (bool) New state\n"
            "  \"changed\": true|false,        (bool) Whether state was changed\n"
            "  \"message\": \"...\"            (string) Status message\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("setbtcburnsenabled", "false")
            + HelpExampleCli("setbtcburnsenabled", "true")
        );
    }

    bool enabled = request.params[0].get_bool();
    bool changed = SetBtcBurnsEnabled(enabled);

    UniValue result(UniValue::VOBJ);
    result.pushKV("burns_enabled", AreBtcBurnsEnabled());
    result.pushKV("changed", changed);

    if (changed) {
        if (enabled) {
            result.pushKV("message", "BTC burns have been ENABLED. New burn claims will be processed.");
        } else {
            result.pushKV("message", "BTC burns have been DISABLED (kill switch activated). New burn claims will be rejected.");
        }
    } else {
        result.pushKV("message", strprintf("No change - BTC burns were already %s.", enabled ? "enabled" : "disabled"));
    }

    return result;
}

// Register commands
static const CRPCCommand commands[] = {
    //  category       name                     actor                  okSafeMode  argNames
    { "burnclaim",    "submitburnclaim",       &submitburnclaim,      true,       {"btc_raw_tx", "btc_block_hash", "height", "merkle_proof", "tx_index", "bathron_address"} },
    { "burnclaim",    "submitburnclaimproof",  &submitburnclaimproof, true,       {"btc_raw_tx", "merkleblock_hex"} },
    { "burnclaim",    "getburnclaim",          &getburnclaim,         true,       {"btc_txid"} },
    { "burnclaim",    "listburnclaims",        &listburnclaims,       true,       {"filter", "count", "skip"} },
    { "burnclaim",    "getbtcburnstats",       &getbtcburnstats,      true,       {} },
    { "burnclaim",    "getgenesisburnstats",   &getgenesisburnstats,  true,       {} },
    { "burnclaim",    "verifyburntx",          &verifyburntx,         true,       {"btc_raw_tx_hex"} },
    { "burnclaim",    "getburnscanstatus",     &getburnscanstatus,    true,       {} },
    { "burnclaim",    "setburnscanprogress",   &setburnscanprogress,  true,       {"height", "block_hash"} },
    { "burnclaim",    "checkburnclaim",        &checkburnclaim,       true,       {"btc_txid"} },
    { "burnclaim",    "getburnscanrange",      &getburnscanrange,     true,       {"max_blocks"} },
    { "burnclaim",    "getburnstatus",         &getburnstatus,        true,       {} },
    { "burnclaim",    "setbtcburnsenabled",    &setbtcburnsenabled,   true,       {"enabled"} },
};

void RegisterBurnClaimRPCCommands(CRPCTable& t)
{
    for (const auto& cmd : commands) {
        t.appendCommand(cmd.name, &cmd);
    }
}
