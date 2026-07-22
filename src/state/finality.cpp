// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/finality.h"

#include "chain.h"
#include "chainparams.h"
#include "logging.h"
#include "masternode/deterministicmns.h"
#include "state/metrics.h"
#include "state/quorum.h"
#include "masternode/tiertwo_sync_state.h"
#include "utiltime.h"
#include "../validation.h"

#include <set>

namespace hu {

std::unique_ptr<CFinalityManagerHandler> finalityHandler;
std::unique_ptr<CFinalityManagerDB> pFinalityDB;

// DB key prefix for finality records
static const char DB_HU_FINALITY = 'F';

// ── Per-block finality operator context cache (off-cs_main counting) ────────────
// Precomputed once at block connect so the hot signature-counting path never blocks
// on cs_main (which is contended on loaded nodes → delayed finality observation).
static RecursiveMutex cs_finalityCtx;
static std::map<uint256, HuBlockFinalityContext> g_finalityCtx GUARDED_BY(cs_finalityCtx);

void CacheBlockFinalityContext(const CBlockIndex* pindex)
{
    // Caller holds cs_main (called at connect). Derives the SAME data the live path
    // uses (GetListForBlock(pprev) + bootstrap-aware eligibility) so counting off the
    // cache is byte-for-byte identical to counting under cs_main — deterministic.
    if (!pindex || !deterministicMNManager) return;
    const CBlockIndex* pprev = pindex->pprev ? pindex->pprev : pindex;
    const Consensus::Params& consensus = Params().GetConsensus();
    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pprev);

    HuBlockFinalityContext ctx;
    ctx.nHeight = pindex->nHeight;
    // VRF input (alpha) for this block — same derivation the verify path uses
    // (IsOperatorVrfSelected), precomputed so per-signature validation never has to
    // resolve the block index again.
    ctx.vrfSeed = GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
    mnList.ForEachMN(true /* onlyValid */, [&](const CDeterministicMNCPtr& dmn) {
        ctx.operatorByProTx[dmn->proTxHash] = dmn->pdmnState->pubKeyOperator;
        ctx.vrfByProTx[dmn->proTxHash] = dmn->pdmnState->pubKeyVRF;
        // Same bootstrap-aware eligibility as GetUniqueOperators (quorum.cpp).
        const bool isBootstrapMN = (dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight);
        if (!isBootstrapMN && dmn->pdmnState->confirmedHash.IsNull()) return;
        ctx.eligibleOperators.insert(dmn->pdmnState->pubKeyOperator);
    });
    ctx.valid = true;

    LOCK(cs_finalityCtx);
    g_finalityCtx[pindex->GetBlockHash()] = std::move(ctx);
}

bool GetCachedFinalityContext(const uint256& blockHash, HuBlockFinalityContext& out)
{
    LOCK(cs_finalityCtx);
    auto it = g_finalityCtx.find(blockHash);
    if (it == g_finalityCtx.end() || !it->second.valid) return false;
    out = it->second;
    return true;
}

bool GetOrBuildFinalityContext(const uint256& blockHash, HuBlockFinalityContext& out)
{
    if (GetCachedFinalityContext(blockHash, out)) return true;

    // Miss: the block either isn't connected yet (caller buffers the signature) or
    // was connected before this process started / beyond the prune window. Resolve
    // it ONCE under cs_main and cache the rebuilt context — subsequent signatures
    // for the same block hit the cache with no lock.
    const CBlockIndex* pindex = nullptr;
    {
        LOCK(cs_main);
        auto it = mapBlockIndex.find(blockHash);
        if (it != mapBlockIndex.end()) pindex = it->second;
    }
    if (!pindex) return false;
    CacheBlockFinalityContext(pindex);
    return GetCachedFinalityContext(blockHash, out);
}

void PruneFinalityContextsBelow(int nHeight)
{
    LOCK(cs_finalityCtx);
    for (auto it = g_finalityCtx.begin(); it != g_finalityCtx.end(); ) {
        if (it->second.nHeight < nHeight) it = g_finalityCtx.erase(it);
        else ++it;
    }
}

// ============================================================================
// CFinalityManager Implementation - OPERATOR-BASED QUORUM (2/3 of operators)
// ============================================================================
// Finality is based on UNIQUE OPERATOR COUNT, not raw signature count. A single
// operator running multiple MNs counts as ONE vote — this prevents one operator
// from reaching quorum alone. Matches the spec (doc/blueprints/done/03-CONSENSUS,
// doc/02-SPEC) and the quorum SELECTION (state/quorum.cpp, which is per-operator).
// GetSignatureCount() is defined inline in finality.h (raw proTxHash count).
// ============================================================================

/**
 * Count the unique OPERATORS that have signed (the finality quantity).
 * Resolves each signer's proTxHash to its operator key via the MN list.
 */
size_t CFinalityManager::GetUniqueOperatorCount() const
{
    if (mapSignatures.empty()) {
        return 0;
    }

    // Fast path: count against the block's context cached at connect — NO cs_main.
    // Identical to the deterministic fallback below (same GetListForBlock(pprev)
    // eligibility), so this only removes the contended lock from the hot path.
    {
        HuBlockFinalityContext ctx;
        if (GetCachedFinalityContext(blockHash, ctx)) {
            std::set<CPubKey> uniqueOperators;
            for (const auto& [proTxHash, sig] : mapSignatures) {
                auto itc = ctx.operatorByProTx.find(proTxHash);
                if (itc != ctx.operatorByProTx.end() && ctx.eligibleOperators.count(itc->second)) {
                    uniqueOperators.insert(itc->second);
                }
            }
            return uniqueOperators.size();
        }
    }

    // Without the MN manager we cannot resolve operators; treat as not-confirmed
    // (return 0) rather than trusting the raw signature count, which would let a
    // single operator's MNs reach quorum.
    if (!deterministicMNManager) {
        return 0;
    }

    // DETERMINISM (audit HIGH): resolve signers→operators against THIS BLOCK's own MN list
    // (GetListForBlock(pprev)) — the SAME population the VRF selection and the threshold
    // (HuFinalityOperatorCount) use — NOT GetListAtChainTip(), which is node-local mutable
    // state. With the tip list, two nodes at different tips (or after an operator-key
    // change / MN add-remove between this block and the tip) could count a different number
    // of operators for the same block → divergent HasFinality → split finality view.
    CDeterministicMNList mnList;
    {
        LOCK(cs_main);
        auto it = mapBlockIndex.find(blockHash);
        if (it == mapBlockIndex.end() || !it->second) {
            return 0;  // block not in index → cannot resolve deterministically → not confirmed
        }
        const CBlockIndex* pprev = it->second->pprev ? it->second->pprev : it->second;
        mnList = deterministicMNManager->GetListForBlock(pprev);
    }

    // Numerator/denominator symmetry: only count signers whose operator is in the
    // SAME bootstrap-aware eligible set that defines N (HuFinalityOperatorCount →
    // GetUniqueOperators). Otherwise a post-bootstrap, not-yet-confirmed MN could be
    // counted toward finality while being excluded from the threshold's N.
    const auto eligibleOps = GetUniqueOperators(mnList);  // bootstrap-aware, keyed by pubKeyOperator

    std::set<CPubKey> uniqueOperators;
    for (const auto& [proTxHash, sig] : mapSignatures) {
        auto dmn = mnList.GetMN(proTxHash);
        if (dmn && eligibleOps.count(dmn->pdmnState->pubKeyOperator)) {
            uniqueOperators.insert(dmn->pdmnState->pubKeyOperator);
        }
    }

    return uniqueOperators.size();
}

/**
 * Check if block has reached finality threshold.
 * Counts UNIQUE OPERATORS (one vote per operator), NOT raw signatures.
 *
 * @param nThreshold - operators required; callers derive it from
 *        HuActiveFinalityThreshold = ceil(2/3·min(E,N)) for the block
 * @return true if unique-operator count >= threshold
 */
bool CFinalityManager::HasFinality(int nThreshold) const
{
    return static_cast<int>(GetUniqueOperatorCount()) >= nThreshold;
}

// ============================================================================
// CFinalityManagerDB Implementation
// ============================================================================

CFinalityManagerDB::CFinalityManagerDB(size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(GetDataDir() / "finality", nCacheSize, fMemory, fWipe)
{
}

bool CFinalityManagerDB::WriteFinality(const CFinalityManager& finality)
{
    return Write(std::make_pair(DB_HU_FINALITY, finality.blockHash), finality);
}

bool CFinalityManagerDB::ReadFinality(const uint256& blockHash, CFinalityManager& finality) const
{
    return Read(std::make_pair(DB_HU_FINALITY, blockHash), finality);
}

bool CFinalityManagerDB::HasFinality(const uint256& blockHash) const
{
    return Exists(std::make_pair(DB_HU_FINALITY, blockHash));
}

bool CFinalityManagerDB::IsBlockFinal(const uint256& blockHash) const
{
    CFinalityManager finality;
    if (!ReadFinality(blockHash, finality)) {
        return false;
    }
    // The finality threshold is per-block (ceil(2/3·min(E,N)) over the block's own
    // operator population). Derive it from the finalized block's record — so every
    // caller is correct without threading a threshold/height through.
    const int nThreshold = hu::HuActiveFinalityThreshold(Params().GetConsensus(), HuFinalityOperatorCount(blockHash));
    return finality.HasFinality(nThreshold);
}

// ============================================================================
// Global Functions
// ============================================================================

void InitHuFinality(size_t nCacheSize, bool fWipe)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // Initialize in-memory handler
    finalityHandler = std::make_unique<CFinalityManagerHandler>();

    // Initialize LevelDB persistence
    pFinalityDB = std::make_unique<CFinalityManagerDB>(nCacheSize, false, fWipe);

    // ═══════════════════════════════════════════════════════════════════════════
    // I1: RESTORE FINALITY DATA FROM DB ON STARTUP
    // ═══════════════════════════════════════════════════════════════════════════
    // Critical for cold start recovery: reload persisted finality state so that
    // DMM can continue producing blocks without re-collecting all HU signatures.
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fWipe && pFinalityDB) {
        int restoredCount = 0;
        int lastFinalizedHeight = 0;
        uint256 lastFinalizedHash;

        // Iterate over all finality records in DB
        std::unique_ptr<CDBIterator> it(pFinalityDB->NewIterator());
        for (it->Seek(std::make_pair(DB_HU_FINALITY, uint256())); it->Valid(); it->Next()) {
            std::pair<char, uint256> key;
            if (!it->GetKey(key) || key.first != DB_HU_FINALITY) {
                break;
            }

            CFinalityManager finality;
            if (it->GetValue(finality)) {
                // Restore to in-memory handler
                finalityHandler->RestoreFinality(finality);
                restoredCount++;

                // Track the most recent finalized block
                if (finality.HasFinality(hu::HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(finality.blockHash))) &&
                    finality.nHeight > lastFinalizedHeight) {
                    lastFinalizedHeight = finality.nHeight;
                    lastFinalizedHash = finality.blockHash;
                }
            }
        }

        // Notify sync state of the last finalized block
        if (lastFinalizedHeight > 0) {
            g_tiertwo_sync_state.OnFinalizedBlock(GetTime());
            LogPrintf("Quorum Finality: Restored %d records from DB, lastFinalized=%d (%s)\n",
                     restoredCount, lastFinalizedHeight, lastFinalizedHash.ToString().substr(0, 16));
        } else if (restoredCount > 0) {
            LogPrintf("Quorum Finality: Restored %d records from DB (none finalized yet)\n", restoredCount);
        }
    }

    LogPrintf("Quorum Finality: Initialized (quorum floor=%d, E=%d, timeout=%ds, maxReorg=%d)\n",
              consensus.nHuQuorumSize,
              consensus.nHuExpectedCommitteeSize,
              consensus.nHuLeaderTimeoutSeconds,
              consensus.nHuMaxReorgDepth);
}

void ShutdownHuFinality()
{
    pFinalityDB.reset();
    finalityHandler.reset();
    LogPrintf("Quorum Finality: Shutdown\n");
}

int HuFinalityOperatorCount(const uint256& blockHash)
{
    // Deterministic per-block operator population, matching the VRF selection's N:
    // GetUniqueOperators over the block's parent MN list (GetListForBlock(pprev)).
    // Returns 0 if unresolved (caller falls back to E). cs_main is recursive, so taking
    // it here is safe even when a caller already holds it (e.g. the finality-handler cs).

    // Fast path: cached at connect (no cs_main) — same eligible-operator set.
    {
        HuBlockFinalityContext ctx;
        if (GetCachedFinalityContext(blockHash, ctx)) {
            return static_cast<int>(ctx.eligibleOperators.size());
        }
    }

    if (!deterministicMNManager) {
        return 0;
    }
    const CBlockIndex* pindex = nullptr;
    {
        LOCK(cs_main);
        auto it = mapBlockIndex.find(blockHash);
        if (it != mapBlockIndex.end()) {
            pindex = it->second;
        }
    }
    if (!pindex) {
        return 0;
    }
    const CBlockIndex* pprev = pindex->pprev ? pindex->pprev : pindex;
    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pprev);
    return static_cast<int>(GetUniqueOperators(mnList).size());
}

bool WouldViolateHuFinality(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork)
{
    if (!pindexNew || !pindexFork || !pFinalityDB) {
        return false;
    }

    // Walk from fork point to current tip, checking for finalized blocks
    const CBlockIndex* pindex = chainActive.Tip();
    while (pindex && pindex != pindexFork) {
        if (pFinalityDB->IsBlockFinal(pindex->GetBlockHash())) {
            LogPrint(BCLog::STATE, "Quorum Finality: Reorg blocked - block %s at height %d is finalized\n",
                     pindex->GetBlockHash().ToString().substr(0, 16), pindex->nHeight);
            return true;
        }
        pindex = pindex->pprev;
    }

    return false;
}

bool CFinalityManagerHandler::HasFinality(int nHeight, const uint256& blockHash) const
{
    LOCK(cs);

    // Check if we have finality data for this block
    auto it = mapFinality.find(blockHash);
    if (it == mapFinality.end()) {
        return false;
    }

    // Verify height matches
    if (it->second.nHeight != nHeight) {
        LogPrint(BCLog::STATE, "Quorum Finality: Height mismatch for %s (expected %d, got %d)\n",
                 blockHash.ToString().substr(0, 16), nHeight, it->second.nHeight);
        return false;
    }

    return it->second.HasFinality(hu::HuActiveFinalityThreshold(Params().GetConsensus(), HuFinalityOperatorCount(blockHash)));
}

bool CFinalityManagerHandler::HasConflictingFinality(int nHeight, const uint256& blockHash) const
{
    LOCK(cs);

    // Check if there's a different finalized block at this height
    auto heightIt = mapHeightToBlock.find(nHeight);
    if (heightIt == mapHeightToBlock.end()) {
        return false; // No finalized block at this height
    }

    // If same hash, no conflict
    if (heightIt->second == blockHash) {
        return false;
    }

    // Check if the other block actually has finality
    auto finalityIt = mapFinality.find(heightIt->second);
    if (finalityIt == mapFinality.end()) {
        return false;
    }

    if (finalityIt->second.HasFinality(hu::HuActiveFinalityThreshold(Params().GetConsensus(), HuFinalityOperatorCount(heightIt->second)))) {
        LogPrint(BCLog::STATE, "Quorum Finality: Conflicting block at height %d. Finalized: %s, Attempted: %s\n",
                 nHeight,
                 heightIt->second.ToString().substr(0, 16),
                 blockHash.ToString().substr(0, 16));
        return true;
    }

    return false;
}

bool CFinalityManagerHandler::AddSignature(const CHuSignature& sig)
{
    LOCK(cs);

    // Get or create finality entry
    auto& finality = mapFinality[sig.blockHash];
    if (finality.blockHash.IsNull()) {
        finality.blockHash = sig.blockHash;
        // Note: nHeight should be set by caller via MarkBlockFinal or separate method
    }

    // Check if we already have this signature
    if (finality.mapSignatures.count(sig.proTxHash)) {
        LogPrint(BCLog::STATE, "Quorum Finality: Duplicate signature from %s for block %s\n",
                 sig.proTxHash.ToString().substr(0, 16),
                 sig.blockHash.ToString().substr(0, 16));
        return false;
    }

    // Add signature
    finality.mapSignatures[sig.proTxHash] = sig.vchSig;

    const Consensus::Params& consensus = Params().GetConsensus();

    // Resolve the block height FIRST: the active finality threshold is height-gated
    // (VRF sortition vs legacy), so nHeight is needed before computing it. Use the
    // connect-time context (no cs_main — we HOLD this->cs here, and taking cs_main
    // under it inverts the UpdateTip lock order); fall back to cs_main only on a
    // genuine cache miss (restart boundary).
    int nHeight = finality.nHeight;
    if (nHeight <= 0) {
        HuBlockFinalityContext ctx;
        if (GetCachedFinalityContext(sig.blockHash, ctx)) {
            nHeight = ctx.nHeight;
            finality.nHeight = nHeight;
        } else {
            LOCK(cs_main);
            auto it = mapBlockIndex.find(sig.blockHash);
            if (it != mapBlockIndex.end()) {
                nHeight = it->second->nHeight;
                finality.nHeight = nHeight;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // OPERATOR-BASED QUORUM: finality = HuActiveFinalityThreshold UNIQUE OPERATORS
    // ═══════════════════════════════════════════════════════════════════════════
    // One vote per operator — a single operator's multiple MNs count once. The
    // threshold is ceil(2/3·min(E,N)) over the block's operator population.
    // sigCount is logging only.
    // ═══════════════════════════════════════════════════════════════════════════
    const int nThreshold = hu::HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(finality.blockHash));
    size_t sigCount = finality.GetSignatureCount();        // raw signatures (logging)
    size_t uniqueOps = finality.GetUniqueOperatorCount();  // the finality quantity

    LogPrint(BCLog::STATE, "Quorum Finality: Added signature %zu/%d (ops=%zu) from %s for block %s\n",
             sigCount, nThreshold, uniqueOps,
             sig.proTxHash.ToString().substr(0, 16),
             sig.blockHash.ToString().substr(0, 16));

    // ═══════════════════════════════════════════════════════════════════════════
    // I1: PERSIST SIGNATURE TO DB
    // ═══════════════════════════════════════════════════════════════════════════
    // Persist after each signature so we don't lose finality data on restart.
    // This is critical for network-wide restarts and cold start recovery.
    // ═══════════════════════════════════════════════════════════════════════════
    if (pFinalityDB) {
        pFinalityDB->WriteFinality(finality);
        LogPrint(BCLog::STATE, "Quorum Finality: Persisted signature to DB for block %s (height=%d, ops=%zu, sigs=%zu)\n",
                 sig.blockHash.ToString().substr(0, 16), nHeight, uniqueOps, finality.mapSignatures.size());
    }

    // Fire once, when the unique-operator count first reaches the threshold.
    // (A later signature from an already-counted operator must not re-notify.)
    const bool alreadyFinalAtHeight = (nHeight > 0 && mapHeightToBlock.count(nHeight) > 0);
    if (static_cast<int>(uniqueOps) >= nThreshold && !alreadyFinalAtHeight) {
        // ═══════════════════════════════════════════════════════════════════════════
        // FINALITY DELAY TRACKING (v4.0)
        // ═══════════════════════════════════════════════════════════════════════════
        int64_t blockReceivedTime = g_hu_metrics.lastBlockReceivedTime.load();
        int64_t finalityTime = GetTimeMicros();
        int64_t delayMs = 0;
        if (blockReceivedTime > 0) {
            delayMs = (finalityTime - blockReceivedTime) / 1000;  // Convert to ms
            g_hu_metrics.lastFinalityDelayMs.store(delayMs);
            g_hu_metrics.totalFinalityDelayMs.fetch_add(delayMs);
            g_hu_metrics.finalityDelayCount.fetch_add(1);
        }

        LogPrintf("Quorum Finality: Block %s at height %d reached finality (%zu/%d sigs, %zu ops, delay=%ldms)\n",
                  sig.blockHash.ToString().substr(0, 16), nHeight, sigCount, nThreshold,
                  uniqueOps, delayMs);

        // Update height->block mapping if we have the height
        if (nHeight > 0) {
            mapHeightToBlock[nHeight] = sig.blockHash;

            // BATHRON: Notify sync state that we have a finalized block
            // This is critical for DMM to know it can produce the next block
            g_tiertwo_sync_state.OnFinalizedBlock(GetTime());
            LogPrint(BCLog::STATE, "Quorum Finality: Notified sync state of finalized block at height %d\n",
                     nHeight);
        }
    }

    return true;
}

bool CFinalityManagerHandler::GetFinality(const uint256& blockHash, CFinalityManager& finalityOut) const
{
    LOCK(cs);

    auto it = mapFinality.find(blockHash);
    if (it == mapFinality.end()) {
        return false;
    }

    finalityOut = it->second;
    return true;
}

int CFinalityManagerHandler::GetSignatureCount(const uint256& blockHash) const
{
    LOCK(cs);

    auto it = mapFinality.find(blockHash);
    if (it == mapFinality.end()) {
        return 0;
    }

    return static_cast<int>(it->second.mapSignatures.size());
}

void CFinalityManagerHandler::RestoreFinality(const CFinalityManager& finality)
{
    LOCK(cs);

    // Restore finality entry
    mapFinality[finality.blockHash] = finality;

    // Update height mapping if finalized. Use the auto-scaled active threshold
    // (ceil(2/3·min(E,N))) keyed on the block's own operator population, so a
    // restored record is indexed exactly as the live reorg guards
    // (IsBlockFinal/HasConflictingFinality) judge it.
    if (finality.nHeight > 0) {
        const Consensus::Params& consensus = Params().GetConsensus();
        const int nThreshold = hu::HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(finality.blockHash));
        if (finality.HasFinality(nThreshold)) {
            mapHeightToBlock[finality.nHeight] = finality.blockHash;
        }
    }

    LogPrint(BCLog::STATE, "Quorum Finality: Restored block %s height=%d sigs=%zu\n",
             finality.blockHash.ToString().substr(0, 16),
             finality.nHeight,
             finality.mapSignatures.size());
}

bool CFinalityManagerHandler::GetLastFinalized(int& nHeightOut, uint256& hashOut) const
{
    LOCK(cs);

    // Every mapHeightToBlock entry was inserted at the moment its block CROSSED the
    // active finality threshold (AddSignature) or was restored as already-final
    // (RestoreFinality, gated by HasFinality) — and finality is irreversible. So the
    // highest key IS the last finalized block: O(1), no re-verification.
    //
    // The previous implementation re-verified EVERY entry on EVERY call via
    // HuFinalityOperatorCount + HasFinality — each a GetListForBlock/cs_main round for
    // blocks older than the context cache — an O(chain-length) scan that ran once per
    // UpdateTip (under cs_main) and once per getfinalitystatus poll (under this cs,
    // TAKING cs_main inside = lock-order inversion vs UpdateTip). Its cost grew with
    // every block produced: the network-wide finality delay crept from ~100ms to
    // multi-second "Connect postprocess" stalls as the chain got longer.
    if (mapHeightToBlock.empty()) {
        return false;
    }
    const auto& last = *mapHeightToBlock.rbegin();
    nHeightOut = last.first;
    hashOut = last.second;
    return true;
}

int CFinalityManagerHandler::GetFinalityLag(int tipHeight) const
{
    int lastFinalizedHeight = 0;
    uint256 lastFinalizedHash;

    if (GetLastFinalized(lastFinalizedHeight, lastFinalizedHash)) {
        return tipHeight - lastFinalizedHeight;
    }

    // No finalized blocks yet - return tip height as lag
    return tipHeight;
}

} // namespace hu
