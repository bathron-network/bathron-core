// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "chainparams.h"
#include "logging.h"
#include "masternode/activemasternode.h"
#include "masternode/deterministicmns.h"
#include "masternode/specialtx_validation.h"
#include "net/net.h"
#include "rpc/server.h"
#include "streams.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <univalue.h>

// Helper to relay a transaction to peers
static void RelayBtcHeadersTx(const uint256& hashTx)
{
    if (!g_connman) return;

    CInv inv(MSG_TX, hashTx);
    g_connman->ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

// =============================================================================
// RPC: getbtcheaderstip
// =============================================================================

UniValue getbtcheaderstip(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "getbtcheaderstip\n"
            "\nReturns current BTC headers consensus tip from btcheadersdb.\n"
            "This is the on-chain consensus tip, NOT the btcspv sync tip.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\": n,          (numeric) BTC block height\n"
            "  \"hash\": \"hash\",     (string) BTC block hash\n"
            "  \"bestBlock\": \"hash\" (string) BATHRON block hash at last update\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getbtcheaderstip", "")
            + HelpExampleRpc("getbtcheaderstip", "")
        );
    }

    if (!g_btcheadersdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC headers database not initialized");
    }

    uint32_t height;
    uint256 hash;
    UniValue result(UniValue::VOBJ);

    if (g_btcheadersdb->GetTip(height, hash)) {
        result.pushKV("height", (int)height);
        result.pushKV("hash", hash.GetHex());
    } else {
        result.pushKV("height", 0);
        result.pushKV("hash", "");
    }

    uint256 bestBlock;
    if (g_btcheadersdb->ReadBestBlock(bestBlock)) {
        result.pushKV("bestBlock", bestBlock.GetHex());
    } else {
        result.pushKV("bestBlock", "");
    }

    return result;
}

// =============================================================================
// RPC: getbtcheadersheader
// =============================================================================

UniValue getbtcheadersheader(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "getbtcheadersheader height\n"
            "\nReturns BTC block header from consensus btcheadersdb at given height.\n"
            "\nArguments:\n"
            "1. height    (numeric, required) BTC block height\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\": \"hash\",         (string) Block hash\n"
            "  \"height\": n,              (numeric) Block height\n"
            "  \"version\": n,             (numeric) Block version\n"
            "  \"prevHash\": \"hash\",     (string) Previous block hash\n"
            "  \"merkleRoot\": \"hash\",   (string) Merkle root\n"
            "  \"time\": n,                (numeric) Block timestamp\n"
            "  \"nBits\": n,               (numeric) Difficulty bits\n"
            "  \"nonce\": n                (numeric) Nonce\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getbtcheadersheader", "800000")
        );
    }

    if (!g_btcheadersdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC headers database not initialized");
    }

    // Accept both string and integer arguments
    uint32_t height;
    if (request.params[0].isNum()) {
        height = request.params[0].get_int();
    } else {
        height = ParseOutpointVout(request.params[0].get_str());
    }

    BtcBlockHeader header;
    if (!g_btcheadersdb->GetHeaderByHeight(height, header)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Header not found at height %d", height));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", header.GetHash().GetHex());
    result.pushKV("height", (int)height);
    result.pushKV("version", header.nVersion);
    result.pushKV("prevHash", header.hashPrevBlock.GetHex());
    result.pushKV("merkleRoot", header.hashMerkleRoot.GetHex());
    result.pushKV("time", (int64_t)header.nTime);
    result.pushKV("nBits", (int64_t)header.nBits);
    result.pushKV("nonce", (int64_t)header.nNonce);

    return result;
}

// =============================================================================
// RPC: getbtcheadersstatus
// =============================================================================

UniValue getbtcheadersstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "getbtcheadersstatus\n"
            "\nReturns full status of the on-chain BTC headers system.\n"
            "\nResult:\n"
            "{\n"
            "  \"db_initialized\": true|false,    (boolean) Whether btcheadersdb is initialized\n"
            "  \"tip_height\": n,                 (numeric) Consensus tip height\n"
            "  \"tip_hash\": \"hash\",            (string) Consensus tip hash\n"
            "  \"header_count\": n,               (numeric) Total headers in DB\n"
            "  \"best_bathron_block\": \"hash\",     (string) Last BATHRON block that updated headers\n"
            "  \"spv_tip_height\": n,             (numeric) btcspv tip height (source)\n"
            "  \"headers_ahead\": n,              (numeric) Headers available in spv but not in consensus\n"
            "  \"can_publish\": true|false        (boolean) Whether we can publish more headers\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getbtcheadersstatus", "")
        );
    }

    UniValue result(UniValue::VOBJ);

    // Check btcheadersdb
    if (!g_btcheadersdb) {
        result.pushKV("db_initialized", false);
        result.pushKV("tip_height", 0);
        result.pushKV("tip_hash", "");
        result.pushKV("header_count", 0);
        result.pushKV("best_bathron_block", "");
        result.pushKV("spv_tip_height", 0);
        result.pushKV("headers_ahead", 0);
        result.pushKV("can_publish", false);
        return result;
    }

    result.pushKV("db_initialized", true);

    // Get btcheadersdb stats
    auto stats = g_btcheadersdb->GetStats();
    result.pushKV("tip_height", (int)stats.tipHeight);
    result.pushKV("tip_hash", stats.tipHash.GetHex());
    result.pushKV("header_count", (int)stats.headerCount);
    result.pushKV("best_bathron_block", stats.bestBathronBlock.GetHex());

    // Get btcspv tip
    uint32_t spvTipHeight = 0;
    int headersAhead = 0;
    bool canPublish = false;

    if (g_btc_spv) {
        spvTipHeight = g_btc_spv->GetTipHeight();
        if (spvTipHeight > stats.tipHeight) {
            headersAhead = spvTipHeight - stats.tipHeight;
            canPublish = true;
        }
    }

    result.pushKV("spv_tip_height", (int)spvTipHeight);
    result.pushKV("headers_ahead", headersAhead);
    result.pushKV("can_publish", canPublish);

    return result;
}

// =============================================================================
// RPC: publishbtcheaders
// =============================================================================

UniValue publishbtcheaders(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "publishbtcheaders ( count )\n"
            "\nPublish BTC headers from btcspv to the blockchain as TX_BTC_HEADERS.\n"
            "This command is for masternode operators to publish new BTC headers.\n"
            "Requires: active masternode with operator key configured.\n"
            "\nArguments:\n"
            "1. count    (numeric, optional, default=100) Number of headers to publish (1-1000, but 100 recommended)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hash\",       (string) Transaction ID\n"
            "  \"start_height\": n,      (numeric) Starting BTC height\n"
            "  \"count\": n,             (numeric) Number of headers published\n"
            "  \"publisher\": \"hash\"   (string) Publisher proTxHash\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("publishbtcheaders", "")
            + HelpExampleCli("publishbtcheaders", "50")
        );
    }

    // Check dependencies
    if (!g_btcheadersdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC headers database not initialized");
    }
    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized - cannot get source headers");
    }
    if (!activeMasternodeManager) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Active masternode manager not available");
    }

    // Get count parameter (accept both string and integer)
    uint16_t count = BTCHEADERS_DEFAULT_COUNT;  // Default to 100 (fits in 10KB limit)
    if (!request.params.empty()) {
        int reqCount;
        if (request.params[0].isNum()) {
            reqCount = request.params[0].get_int();
        } else {
            reqCount = std::stoi(request.params[0].get_str());
        }
        if (reqCount < 1 || reqCount > BTCHEADERS_MAX_COUNT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("count must be 1-%d", BTCHEADERS_MAX_COUNT));
        }
        count = static_cast<uint16_t>(reqCount);
    }

    // Get current consensus tip from btcheadersdb
    uint32_t consensusTipHeight = 0;
    uint256 consensusTipHash;
    uint32_t startHeight;
    if (g_btcheadersdb->GetTip(consensusTipHeight, consensusTipHash)) {
        // Have existing tip - continue from there
        startHeight = consensusTipHeight + 1;
    } else {
        // Empty DB - start from btcspv's min_supported_height + 1
        uint32_t minHeight = g_btc_spv->GetMinSupportedHeight();
        if (minHeight == UINT32_MAX) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "SPV not ready - min_supported_height not set");
        }
        startHeight = minHeight + 1;
        consensusTipHeight = startHeight - 1;
    }

    // Get SPV tip
    uint32_t spvTipHeight = g_btc_spv->GetTipHeight();
    if (spvTipHeight < startHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("No new headers to publish: spv=%u, start=%u", spvTipHeight, startHeight));
    }

    // Calculate how many headers we can publish
    uint32_t available = spvTipHeight - startHeight + 1;
    if (count > available) {
        count = static_cast<uint16_t>(available);
    }
    std::vector<BtcBlockHeader> headers;
    headers.reserve(count);

    for (uint32_t h = startHeight; h < startHeight + count; h++) {
        BtcHeaderIndex idx;
        if (!g_btc_spv->GetHeaderAtHeight(h, idx)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                strprintf("Failed to get header at height %u from btcspv", h));
        }
        headers.push_back(idx.header);
    }

    // Get operator key and proTxHash
    const CActiveMasternodeInfo* info = activeMasternodeManager->GetInfo();
    std::vector<uint256> managedProTxHashes;
    if (info) {
        managedProTxHashes = info->GetManagedProTxHashes();
    }
    if (!info || managedProTxHashes.empty()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No active masternode configured");
    }

    // Use first proTxHash and its operator key
    uint256 publisherProTxHash = managedProTxHashes[0];
    CKey operatorKey;

    // Find the operator key for this proTxHash
    auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(publisherProTxHash);
    if (!dmn) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Masternode not found in DMN list");
    }

    // Get the operator pubkey hash (uint256) to look up our key
    uint256 keyId = dmn->pdmnState->pubKeyOperator.GetHash();
    if (!info->GetKeyByPubKeyId(keyId, operatorKey)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Operator key not found for masternode");
    }

    // Build payload
    BtcHeadersPayload payload;
    payload.nVersion = BtcHeadersPayload::CURRENT_VERSION;
    payload.publisherProTxHash = publisherProTxHash;
    payload.startHeight = startHeight;
    payload.count = count;
    payload.headers = std::move(headers);

    // Sign payload
    uint256 sigHash = payload.GetSignatureHash();
    if (!operatorKey.Sign(sigHash, payload.sig)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign payload");
    }

    // Verify signature (sanity check)
    if (!payload.VerifySignature()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Signature verification failed (internal error)");
    }

    // Trivial validation
    std::string strError;
    if (!payload.IsTriviallyValid(strError)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Payload trivial validation failed: " + strError);
    }

    // Build transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;
    SetTxPayload(mtx, payload);

    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    uint256 txid = tx->GetHash();

    // Submit to mempool
    CValidationState state;
    bool fMissingInputs = false;

    {
        LOCK(cs_main);
        // ignoreFees=true because TX_BTC_HEADERS is fee-exempt
        if (!AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, true, true)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                strprintf("TX rejected: %s", state.GetRejectReason()));
        }
    }

    // Relay to network
    RelayBtcHeadersTx(txid);

    LogPrintf("BTC-HEADERS: Published TX %s (start=%u, count=%d, publisher=%s)\n",
              txid.ToString().substr(0, 16), startHeight, count,
              publisherProTxHash.ToString().substr(0, 16));

    // Return result
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", txid.GetHex());
    result.pushKV("start_height", (int)startHeight);
    result.pushKV("count", (int)count);
    result.pushKV("publisher", publisherProTxHash.GetHex());

    return result;
}

// =============================================================================
// Register commands
// =============================================================================

static const CRPCCommand commands[] = {
    //  category       name                    actor                okSafeMode  argNames
    { "btcheaders",   "getbtcheaderstip",     &getbtcheaderstip,    true,       {} },
    { "btcheaders",   "getbtcheadersheader",  &getbtcheadersheader, true,       {"height"} },
    { "btcheaders",   "getbtcheadersstatus",  &getbtcheadersstatus, true,       {} },
    { "btcheaders",   "publishbtcheaders",    &publishbtcheaders,   true,       {"count"} },
};

void RegisterBtcHeadersRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
