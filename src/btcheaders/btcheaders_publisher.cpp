// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btcheaders/btcheaders_publisher.h"
#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "chainparams.h"

#include "consensus/validation.h"
#include "logging.h"
#include "masternode/activemasternode.h"
#include "masternode/deterministicmns.h"
#include "net/net.h"
#include "primitives/transaction.h"
#include "scheduler.h"
#include "txmempool.h"
#include "util/system.h"
#include "validation.h"

#include <atomic>
#include <mutex>

// Publisher state
static std::mutex g_publisherMutex;
static std::atomic<bool> g_publisherEnabled{false};

// Default interval: 60 seconds
static const int DEFAULT_PUBLISH_INTERVAL = 60;

// Helper to relay transaction
static void RelayTransaction(const uint256& hashTx)
{
    if (!g_connman) return;
    CInv inv(MSG_TX, hashTx);
    g_connman->ForEachNode([&inv](CNode* pnode) {
        pnode->PushInventory(inv);
    });
}

/**
 * Attempt to publish BTC headers.
 * Returns true if published (or nothing to publish), false on error.
 */
static bool TryPublishHeaders()
{
    std::lock_guard<std::mutex> lock(g_publisherMutex);


    // Check dependencies
    if (!g_btcheadersdb) {
        return false;
    }
    if (!g_btc_spv) {
        return false;
    }
    if (!activeMasternodeManager) {
        return false;
    }

    // Get current consensus tip
    uint32_t consensusTipHeight = 0;
    uint256 consensusTipHash;
    uint32_t startHeight;

    if (g_btcheadersdb->GetTip(consensusTipHeight, consensusTipHash)) {
        startHeight = consensusTipHeight + 1;
    } else {
        // Empty DB - start from btcspv's min_supported_height + 1
        uint32_t minHeight = g_btc_spv->GetMinSupportedHeight();
        if (minHeight == UINT32_MAX) {
            return false;
        }
        startHeight = minHeight + 1;
        consensusTipHeight = startHeight - 1;
    }

    // BP-BTCHEADERS-REORG: when btcspv's active chain diverges from the consensus
    // tip (a BTC reorg below the published tip), publish from the FORK POINT so a
    // strictly-heavier branch can reorg the consensus chain. Gated by activation;
    // pre-activation this stays a no-op (V1 extend-only).
    if (consensusTipHeight > 0 && chainActive.Tip() &&
        Params().GetConsensus().IsBtcHeadersReorg(chainActive.Height())) {
        BtcHeaderIndex spvAtTip;
        if (g_btc_spv->GetHeaderAtHeight(consensusTipHeight, spvAtTip) &&
            spvAtTip.hash != consensusTipHash) {
            // Diverged: walk back to the highest common ancestor.
            uint32_t fork = consensusTipHeight;
            while (fork > 0) {
                uint256 consHash;
                BtcHeaderIndex spvIdx;
                if (g_btcheadersdb->GetHashAtHeight(fork, consHash) &&
                    g_btc_spv->GetHeaderAtHeight(fork, spvIdx) &&
                    consHash == spvIdx.hash) {
                    break; // common ancestor
                }
                fork--;
            }
            startHeight = fork + 1;
            LogPrintf("BTC-HEADERS-PUB: consensus diverged from SPV at tip %u; "
                      "republishing from fork point %u\n", consensusTipHeight, startHeight);
        }
    }

    // Check if we have headers to publish
    uint32_t spvTipHeight = g_btc_spv->GetTipHeight();
    if (spvTipHeight < startHeight) {
        // Nothing to publish - this is normal
        return true;
    }

    // Calculate how many headers to publish (max 100 to fit in 10KB payload limit)
    uint32_t available = spvTipHeight - startHeight + 1;
    uint16_t count = std::min(available, (uint32_t)BTCHEADERS_DEFAULT_COUNT);

    // Get operator info
    const CActiveMasternodeInfo* info = activeMasternodeManager->GetInfo();
    std::vector<uint256> managedProTxHashes;
    if (info) {
        managedProTxHashes = info->GetManagedProTxHashes();
    }
    if (!info || managedProTxHashes.empty()) {
        return false;
    }

    // Use first proTxHash
    uint256 publisherProTxHash = managedProTxHashes[0];

    // Get DMN and operator key
    auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(publisherProTxHash);
    if (!dmn) {
        return false;
    }

    CKey operatorKey;
    uint256 keyId = dmn->pdmnState->pubKeyOperator.GetHash();
    if (!info->GetKeyByPubKeyId(keyId, operatorKey)) {
        return false;
    }

    // Fetch headers from btcspv
    std::vector<BtcBlockHeader> headers;
    headers.reserve(count);

    for (uint32_t h = startHeight; h < startHeight + count; h++) {
        BtcHeaderIndex idx;
        if (!g_btc_spv->GetHeaderAtHeight(h, idx)) {
            return false;
        }
        headers.push_back(idx.header);
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
        return false;
    }

    // Verify signature
    if (!payload.VerifySignature()) {
        return false;
    }

    // Trivial validation
    std::string strError;
    if (!payload.IsTriviallyValid(strError)) {
        return false;
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
            // Not fatal - another MN might have published first
            LogPrint(BCLog::MASTERNODE, "BTC-HEADERS-PUB: TX rejected: %s\n", state.GetRejectReason());
            return true;  // Return true to not spam retries
        }
    }

    // Relay to network
    RelayTransaction(txid);


    LogPrintf("BTC-HEADERS-PUB: Published TX %s (start=%u, count=%d)\n",
              txid.ToString().substr(0, 16), startHeight, count);

    return true;
}

/**
 * Scheduler callback - checks and publishes headers.
 */
static void PublisherCallback()
{
    if (!g_publisherEnabled.load()) {
        return;
    }

    try {
        TryPublishHeaders();
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_publisherMutex);
        LogPrintf("BTC-HEADERS-PUB: Exception: %s\n", e.what());
    }
}

void InitBtcHeadersPublisher(CScheduler& scheduler)
{
    // Check if enabled
    if (!gArgs.GetBoolArg("-btcheaderspublish", false)) {
        LogPrintf("BTC-HEADERS-PUB: Disabled (btcheaderspublish=0)\n");
        return;
    }

    g_publisherEnabled.store(true);

    // Get interval
    int interval = gArgs.GetArg("-btcpublishinterval", DEFAULT_PUBLISH_INTERVAL);
    if (interval < 10) interval = 10;  // Minimum 10 seconds
    if (interval > 600) interval = 600;  // Maximum 10 minutes

    LogPrintf("BTC-HEADERS-PUB: Enabled, interval=%d seconds\n", interval);

    // Schedule periodic checks
    scheduler.scheduleEvery([]() {
        PublisherCallback();
    }, interval * 1000);
}

void ShutdownBtcHeadersPublisher()
{
    g_publisherEnabled.store(false);
    LogPrintf("BTC-HEADERS-PUB: Shutdown\n");
}

