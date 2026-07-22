// Copyright (c) 2021 The PIVX Core developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "masternode/tiertwo_sync_state.h"
#include "chain.h"
#include "chainparams.h"
#include "validation.h"
#include "utiltime.h"
#include "logging.h"
#include "net/net.h"

TierTwoSyncState g_tiertwo_sync_state;

// Tier-two sync bootstrap exemption: the first blocks (genesis, BTC headers,
// burn-backed mint, collateral funding, first ProRegTx) predate any HU quorum.
// NOTE: this local constant (5) is deliberately small and distinct from the
// consensus nDMMBootstrapHeight — it only gates the SYNC state machine.
static const int BATHRON_BOOTSTRAP_HEIGHT = 5;

// Maximum blocks behind best peer before we consider ourselves "behind"
// If a peer announces a height > localHeight + this tolerance, we're not synced
static const int BATHRON_PEER_HEIGHT_TOLERANCE = 2;

/**
 * BATHRON: Simplified sync check - DECOUPLED FROM HU FINALITY
 *
 * DESIGN PRINCIPLE:
 * - DMM (block production) must NOT be blocked because HU finality is late
 * - HU finality can catch up later - it should never prevent liveness
 * - IsBlockchainSynced() is a GUARD-FOO for IBD and real network lag only
 *
 * Logic (ordered by priority):
 * 1. Bootstrap phase (height <= 5): Always synced
 * 2. IBD (Initial Block Download): NOT synced
 * 3. Behind peers (bestHeaderHeight >> localHeight): NOT synced
 * 4. Cold start recovery (tip very old): SYNCED (to allow DMM to restart)
 * 5. At tip with recent activity: SYNCED (even if HU finality is stale)
 * 6. Recent finality (bonus case): SYNCED
 * 7. Ambiguous cases: conservative NOT synced
 *
 * KEY CHANGE from old logic:
 * - OLD: HU finality stale (> 120s) → IsBlockchainSynced = false → DMM blocked
 * - NEW: HU finality stale but at tip → IsBlockchainSynced = true → DMM continues
 *
 * This ensures 60s block times even when HU is temporarily slow.
 */
bool TierTwoSyncState::IsBlockchainSynced() const
{
    // Get current chain tip and headers
    const CBlockIndex* tip = nullptr;
    int bestHeaderHeight = 0;
    {
        LOCK(cs_main);
        tip = chainActive.Tip();
        bestHeaderHeight = pindexBestHeader ? pindexBestHeader->nHeight : (tip ? tip->nHeight : 0);
    }

    if (!tip) {
        LogPrint(BCLog::MASTERNODE, "IsBlockchainSynced: false (no tip)\n");
        return false;
    }

    int localHeight = tip->nHeight;
    int64_t tipTime = tip->GetBlockTime();
    int64_t now = GetTime();
    int64_t tipAge = now - tipTime;

    const Consensus::Params& consensus = Params().GetConsensus();
    int64_t targetSpacing = consensus.nTargetSpacing;
    int64_t staleTimeout = consensus.nStaleChainTimeout;

    // For logging
    int64_t lastFinalized = m_last_finalized_time.load();
    int64_t finalAge = lastFinalized > 0 ? now - lastFinalized : -1;

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 1: Bootstrap phase - blocks 0-5 are always considered synced
    // This allows DMM to start producing block 6 without waiting for HU signatures
    // ═══════════════════════════════════════════════════════════════════════════
    if (localHeight <= BATHRON_BOOTSTRAP_HEIGHT) {
        LogPrint(BCLog::MASTERNODE, "IsBlockchainSynced: true (bootstrap phase, height=%d)\n", localHeight);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 2: IBD (Initial Block Download) - NOT synced
    // This catches nodes that just started and are catching up
    // IMPORTANT: Check IBD BEFORE cold start, because IBD is based on nMaxTipAge
    // which is a LEGACY Bitcoin check that doesn't understand HU
    // ═══════════════════════════════════════════════════════════════════════════
    // NOTE: We check IBD here but will override it for cold start case below
    bool inIBD = IsInitialBlockDownload();

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 3: Really behind peers - NOT synced
    // If bestHeaderHeight is significantly ahead of us, we need to download blocks
    // This prevents a lagging node from producing blocks on a stale chain
    // ═══════════════════════════════════════════════════════════════════════════
    if (bestHeaderHeight > localHeight + BATHRON_PEER_HEIGHT_TOLERANCE) {
        LogPrint(BCLog::MASTERNODE, "IsBlockchainSynced: false (behind peers, local=%d, bestHeader=%d)\n",
                 localHeight, bestHeaderHeight);
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 4: Cold start recovery - tip is very old (network was stopped)
    // This MUST be checked BEFORE IBD check because IBD stays true on stale tips!
    // If tip is stale, we're on a dead network that needs restart.
    // We bypass IBD check to allow DMM to produce the next block.
    // SECURITY: Timeout is network-specific via consensus.nStaleChainTimeout
    // ═══════════════════════════════════════════════════════════════════════════
    if (tipAge > staleTimeout) {
        LogPrintf("IsBlockchainSynced: true (COLD START, tipAge=%ds, threshold=%ds)\n",
                 (int)tipAge, (int)staleTimeout);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 5: Node is AT TIP with recent activity - SYNCED
    // THIS IS THE KEY FIX: If we're at the tip and blocks are recent,
    // we're synced even if HU finality is lagging behind.
    // HU can catch up later - it should NOT block DMM production.
    //
    // Criteria:
    // - localHeight >= bestHeaderHeight - 1 (at tip, or 1 block behind at most)
    // - tipAge <= 2 * targetSpacing (last block was recent)
    // ═══════════════════════════════════════════════════════════════════════════
    if (bestHeaderHeight <= localHeight + 1 && tipAge <= 2 * targetSpacing) {
        LogPrint(BCLog::MASTERNODE,
                 "IsBlockchainSynced: true (at tip, recent activity, height=%d, tipAge=%ds, finalAge=%ds)\n",
                 localHeight, (int)tipAge, (int)finalAge);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 6: Recent HU finality - SYNCED (bonus case, kept for compatibility)
    // If we received a finalized block recently, we're definitely synced
    // ═══════════════════════════════════════════════════════════════════════════
    if (lastFinalized > 0 && finalAge <= BATHRON_SYNC_TIMEOUT) {
        LogPrint(BCLog::MASTERNODE,
                 "IsBlockchainSynced: true (recent finality, finalAge=%ds)\n",
                 (int)finalAge);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 7: IBD check - if still in IBD and none of the above, NOT synced
    // This is checked late because we want cold start and at-tip to override IBD
    // ═══════════════════════════════════════════════════════════════════════════
    if (inIBD) {
        LogPrint(BCLog::MASTERNODE, "IsBlockchainSynced: false (IBD in progress)\n");
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CASE 8: Ambiguous - conservative NOT synced
    // This catches edge cases where we're not clearly at tip but not in IBD either
    // Log detailed info for debugging
    // ═══════════════════════════════════════════════════════════════════════════
    LogPrint(BCLog::MASTERNODE,
             "IsBlockchainSynced: false (ambiguous, local=%d, bestHeader=%d, tipAge=%ds, finalAge=%ds)\n",
             localHeight, bestHeaderHeight, (int)tipAge, (int)finalAge);
    return false;
}

void TierTwoSyncState::OnFinalizedBlock(int64_t timestamp)
{
    m_last_finalized_time.store(timestamp);
    LogPrint(BCLog::MASTERNODE, "OnFinalizedBlock: timestamp=%d\n", (int)timestamp);
}
