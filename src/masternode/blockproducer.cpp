// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/blockproducer.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "logging.h"
#include "pubkey.h"

#include "consensus/params.h"
#include "masternode/deterministicmns.h"
#include "tinyformat.h"
#include "validation.h"   // chainActive — ONLY to tell DEFERRED from FATAL (O-1)

#include <algorithm>
#include <limits>
#include <map>

namespace mn_consensus {

// ═════════════════════════════════════════════════════════════════════════════
// LOT 9 M1 — non-grindable schedule (architecture B)
// ═════════════════════════════════════════════════════════════════════════════

const std::string DMM_SCHEDULE_DOMAIN = "BATHRON_DMM_SCHEDULE_V1";
const std::string DMM_RECOVERY_DOMAIN = "BATHRON_DMM_RECOVERY_V1";

uint32_t GetScheduleEpochIndex(int nHeight, int nActivationHeight, int nEpochLength)
{
    if (nEpochLength <= 0) return 0;
    if (nHeight < nActivationHeight) return 0;   // bootstrap mode: no epoch
    return (uint32_t)((nHeight - nActivationHeight) / nEpochLength);
}

int GetScheduleEpochStart(int nHeight, int nActivationHeight, int nEpochLength)
{
    if (nEpochLength <= 0) return nActivationHeight;
    if (nHeight < nActivationHeight) return nActivationHeight;
    return nActivationHeight
           + (int)GetScheduleEpochIndex(nHeight, nActivationHeight, nEpochLength) * nEpochLength;
}

int GetEpochSnapshotHeight(int nHeight, int nActivationHeight, int nEpochLength, int nSnapshotDepth)
{
    // The anchor: the last bootstrap block. No epoch may ever look below it — that
    // block is where the launch registrations become visible AND bootstrap-trusted.
    const int anchor = nActivationHeight - 1 > 0 ? nActivationHeight - 1 : 0;
    const int epochStart = GetScheduleEpochStart(nHeight, nActivationHeight, nEpochLength);
    if (nSnapshotDepth <= 0) return epochStart;
    const int h = epochStart - nSnapshotDepth;
    // First epoch falls out of the max(): epochStart == activation, so
    // epochStart - depth < anchor whenever depth >= 1. No special case exists,
    // and none may be added — a "first epoch" exception keyed on the current list
    // is exactly what M3.1 removed.
    return h > anchor ? h : anchor;
}

uint256 GetScheduleSeed(const std::string& strDomain, const uint256& genesisHash, uint32_t nEpochIndex)
{
    // Domain || genesisHash || epochIndex. Every term is either a network constant or a
    // pure function of the height: NOTHING a producer emits participates.
    CHashWriter ss(SER_GETHASH, 0);
    ss << strDomain;
    ss << genesisHash;
    ss << nEpochIndex;
    return ss.GetHash();
}

std::vector<uint256> ComputeSchedulePermutation(const uint256& seed, std::vector<uint256> ops)
{
    std::vector<std::pair<arith_uint256, uint256>> scored;
    scored.reserve(ops.size());
    for (const uint256& op : ops) {
        CHashWriter ss(SER_GETHASH, 0);
        ss << seed;
        ss << op;
        scored.emplace_back(UintToArith256(ss.GetHash()), op);
    }
    // Descending score; ties broken by proTxHash ascending. Total order ⇒ the result is
    // a BIJECTION of the input: one identity, exactly one position.
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        if (a.first == b.first) return a.second < b.second;
        return a.first > b.first;
    });

    std::vector<uint256> out;
    out.reserve(scored.size());
    for (const auto& s : scored) out.push_back(s.second);
    return out;
}

int64_t GetRawProducerSlot(const CBlockIndex* pindexPrev, int64_t nBlockTime)
{
    if (!pindexPrev) return 0;

    const Consensus::Params& consensus = Params().GetConsensus();
    const int64_t leaderTimeout = consensus.nHuLeaderTimeoutSeconds;
    const int64_t window = consensus.nHuFallbackRecoverySeconds;
    if (window <= 0) return 0;   // defensive: a zero window would divide by zero

    const int64_t minBlockTime = (int64_t)pindexPrev->GetBlockTime() + consensus.nTargetSpacing;
    const int64_t dt = nBlockTime - minBlockTime;

    // Early blocks (clock drift on the producer side) are treated as slot 0, exactly as
    // before. dt < 0 is folded into the same branch.
    if (dt < leaderTimeout) return 0;

    const int64_t extra = dt - leaderTimeout;
    // Header timestamps are uint32, so extra <= ~2^32 and extra/window can never approach
    // INT64_MAX. Guard anyway so a malformed index can never overflow the +1.
    if (extra > (std::numeric_limits<int64_t>::max() - 1)) return std::numeric_limits<int64_t>::max();
    return 1 + (extra / window);   // O(1): no loop, no allocation, no clamp
}

bool SelectScheduledLeader(const uint256& genesisHash,
                           int nHeight,
                           int nActivationHeight,
                           int nEpochLength,
                           int64_t nRawSlot,
                           const std::vector<uint256>& productionSet,
                           const std::vector<uint256>& recoverySet,
                           DMMScheduleResult& out)
{
    out = DMMScheduleResult();
    out.nRawSlot = nRawSlot;
    if (nRawSlot < 0) return false;

    const uint32_t epochIndex = GetScheduleEpochIndex(nHeight, nActivationHeight, nEpochLength);
    const int epochStart = GetScheduleEpochStart(nHeight, nActivationHeight, nEpochLength);
    const int64_t heightInEpoch = (int64_t)nHeight - (int64_t)epochStart;   // always >= 0

    const int64_t P = (int64_t)productionSet.size();

    // NORMAL MODE — lease-valid operators only. Expired identities are absent from this
    // set, so they can never insert an empty slot into the normal calendar.
    if (P > 0 && nRawSlot < P) {
        const auto perm = ComputeSchedulePermutation(
            GetScheduleSeed(DMM_SCHEDULE_DOMAIN, genesisHash, epochIndex), productionSet);
        const int64_t turn = heightInEpoch % P;
        out.nIndex = (size_t)((turn + nRawSlot) % P);
        out.proTxHash = perm[out.nIndex];
        out.fRecovery = false;
        out.fFound = true;
        return true;
    }

    // RECOVERY MODE — every confirmed identity, expired included. Reached only once every
    // lease-valid member has had its objective temporal window (rawSlot >= P), or
    // immediately when P == 0 (no special case: rawSlot >= 0 always holds).
    const int64_t R = (int64_t)recoverySet.size();
    if (R <= 0) {
        // No signer exists at all. Explicit stall — NOT a block-validity verdict.
        out.fRecovery = true;
        out.fFound = false;
        return false;
    }
    const auto perm = ComputeSchedulePermutation(
        GetScheduleSeed(DMM_RECOVERY_DOMAIN, genesisHash, epochIndex), recoverySet);
    const int64_t recoverySlot = nRawSlot - P;
    const int64_t turn = heightInEpoch % R;
    out.nIndex = (size_t)((turn + recoverySlot) % R);
    out.proTxHash = perm[out.nIndex];
    out.fRecovery = true;
    out.fFound = true;
    return true;
}

bool CheckDMMTimingInvariants(const Consensus::Params& consensus, std::string& strError)
{
    strError.clear();
    const int drift = consensus.FutureBlockTimeDrift(0);
    const int floor = drift + DMM_TIMING_SAFETY_MARGIN;

    // (I1) slot 0 -> 1 costs leaderTimeout. NOT redundant with I2: regtest shipped
    // leaderTimeout=5 against a 14 s drift, so slot 1 was free there even with a wide
    // recovery window.
    if (consensus.nHuLeaderTimeoutSeconds < floor) {
        strError = strprintf("DMM timing invariant I1 violated: nHuLeaderTimeoutSeconds=%d < "
                             "FutureBlockTimeDrift(%d) + margin(%d) = %d — a producer could "
                             "cross the first slot boundary for free by publishing into the "
                             "accepted future drift",
                             consensus.nHuLeaderTimeoutSeconds, drift, DMM_TIMING_SAFETY_MARGIN, floor);
        return false;
    }
    // (I2) slot k -> k+1 costs the recovery window.
    if (consensus.nHuFallbackRecoverySeconds < floor) {
        strError = strprintf("DMM timing invariant I2 violated: nHuFallbackRecoverySeconds=%d < "
                             "FutureBlockTimeDrift(%d) + margin(%d) = %d — a producer could "
                             "advance %d slot(s) for free",
                             consensus.nHuFallbackRecoverySeconds, drift, DMM_TIMING_SAFETY_MARGIN, floor,
                             consensus.nHuFallbackRecoverySeconds > 0 ? drift / consensus.nHuFallbackRecoverySeconds : 0);
        return false;
    }
    return true;
}

ScheduleStatus ResolveEpochOperatorSets(const CBlockIndex* pindexPrev, EpochOperatorSets& out)
{
    out = EpochOperatorSets();

    // chainActive.Contains() below requires cs_main; every caller (ConnectBlock,
    // AcceptBlock, the local scheduler, the display RPC, the finality population)
    // already holds it. The resolver adds NO lock of its own and touches NO
    // finality lock; the only nested lock is GetListForBlock's own cs, taken UNDER
    // cs_main exactly as the legacy engine did — no new AB/BA order exists.
    AssertLockHeld(cs_main);

    if (!pindexPrev || !deterministicMNManager) {
        return ScheduleStatus::DEFERRED;
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const int nHeight = pindexPrev->nHeight + 1;

    // ── Snapshot resolved from the PARENT alone, ANCHORED at the activation height
    // (LOT 9 M3.1). The block's context is invariant because its parent is invariant:
    // two branches sharing this ancestor compute the same schedule, and a reorg that
    // does not move the ancestor changes nothing. Every block of an epoch resolves the
    // SAME snapshot height, so a registration/renewal/expiry included during an epoch
    // can only take effect through a FUTURE snapshot — never the current calendar.
    //
    // Below the activation height the chain is in BOOTSTRAP MODE and this resolver is
    // not consulted for production at all (CheckBlockMNOnly returns before it).
    const int snapshotHeight = GetEpochSnapshotHeight(nHeight,
                                                      consensus.DMMScheduleActivationHeight(),
                                                      consensus.nDMMScheduleEpochLength,
                                                      consensus.nDMMSetSnapshotDepth);

    out.nSnapshotHeight = snapshotHeight;
    // NULL-SAFE ancestor walk. CBlockIndex::GetAncestor ABORTS (assert(pprev)) when
    // the index chain is broken — acceptable for a fully-linked chainstate, NOT for
    // a resolver that also runs on gossip/finality paths and on transient indexes:
    // an unlinked ancestor is exactly the "local state missing" condition the O-1
    // statuses classify, never a reason to kill the process. The walk is bounded by
    // epochLength + snapshotDepth (~90 steps) since snapshotHeight is at most that
    // far below the parent.
    // A snapshot height ABOVE the parent is NOT corruption: it is a height that
    // PRECEDES the schedule. Every height below the activation anchors on epoch 0,
    // whose snapshot is activation-1 — necessarily in the future while the chain is
    // still inside the bootstrap window. MEASURED LIVE (M4-BIS PHASE 1): classifying
    // this as FATAL made every operator daemon fire the LOT 1 latch and shut itself
    // down on its first scheduler tick during bootstrap, and -reindex could never
    // repair it because nothing was corrupt. DEFERRED is the correct O-1 class —
    // "not judgeable here and now": no verdict on the block, no latch, no shutdown.
    if (snapshotHeight > pindexPrev->nHeight) {
        return ScheduleStatus::DEFERRED;
    }

    const CBlockIndex* pindexSnapshot = nullptr;
    if (snapshotHeight >= 0) {
        const CBlockIndex* walk = pindexPrev;
        while (walk && walk->nHeight > snapshotHeight) walk = walk->pprev;
        pindexSnapshot = (walk && walk->nHeight == snapshotHeight) ? walk : nullptr;
    }
    if (!pindexSnapshot) {
        // The parent cannot reach its own ancestor: our index is broken, and the block
        // is not to blame. Classify like any missing local state.
        return chainActive.Contains(pindexPrev) ? ScheduleStatus::LOCAL_STATE_MISSING_FATAL
                                                : ScheduleStatus::DEFERRED;
    }

    CDeterministicMNList snapshotList;
    try {
        snapshotList = deterministicMNManager->GetListForBlock(pindexSnapshot);
    } catch (const std::runtime_error&) {
        // The EXPECTED missing-local-data failures and nothing broader:
        // GetListForBlock's own throw ("No masternode list data found for connected
        // block …") is a std::runtime_error, and so is the dbwrapper read-failure
        // class — both mean OUR store cannot produce the list. Never let them escape
        // into ProcessMessages (a peer could then kill the node by referencing an
        // unknown ancestor). Anything else (bad_alloc, logic_error) is NOT a
        // missing-list condition and must propagate — silently classifying it would
        // turn an unknown bug into a quiet DEFERRED.
        return chainActive.Contains(pindexSnapshot) ? ScheduleStatus::LOCAL_STATE_MISSING_FATAL
                                                    : ScheduleStatus::DEFERRED;
    }

    // Eligible identities at the snapshot: same predicate the legacy draw used
    // (valid, plus bootstrap-trust for MNs registered <= nDMMBootstrapHeight).
    // M3 split: the lease decides PRODUCTION membership; recovery keeps everyone.
    // The lease is judged ON THE SNAPSHOT STATE at the SNAPSHOT HEIGHT
    // (snapshotHeight < nLeaseExpiryHeight; equality = expired) — never on the
    // tip, never on the parent list: a mid-epoch renewal or expiry has NO effect
    // before the next epoch's snapshot (spec §B.5).
    snapshotList.ForEachMN(true /* onlyValid */, [&](const CDeterministicMNCPtr& dmn) {
        const bool isBootstrapMN = (dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight);
        if (!isBootstrapMN && dmn->pdmnState->confirmedHash.IsNull()) return;
        out.recovery.push_back(dmn->proTxHash);
        out.byProTx.emplace(dmn->proTxHash, dmn);
        if (snapshotHeight < dmn->pdmnState->nLeaseExpiryHeight) {
            out.production.push_back(dmn->proTxHash);
        }
    });

    if (out.recovery.empty()) {
        // An EMPTY list is ambiguous: either the snapshot genuinely has no operator
        // (early chain / genesis window), or we have not connected that branch. Only the
        // second case may be deferred; the first is a chain fact.
        if (!chainActive.Contains(pindexSnapshot)) {
            return ScheduleStatus::DEFERRED;
        }
        // Authoritative snapshot with no signer at all -> objective consensus stall.
        // NEVER converted from a local gap: that path returned DEFERRED/FATAL above.
        return ScheduleStatus::NO_SIGNER;
    }

    return ScheduleStatus::OK;
}

ScheduleStatus ResolveScheduledProducer(const CBlockIndex* pindexPrev,
                                        int64_t nBlockTime,
                                        CDeterministicMNCPtr& outMn,
                                        DMMScheduleResult& outRes)
{
    outMn = nullptr;
    outRes = DMMScheduleResult();

    EpochOperatorSets sets;
    const ScheduleStatus status = ResolveEpochOperatorSets(pindexPrev, sets);
    if (status != ScheduleStatus::OK) {
        return status;
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const int nHeight = pindexPrev->nHeight + 1;

    const int64_t rawSlot = GetRawProducerSlot(pindexPrev, nBlockTime);
    if (!SelectScheduledLeader(consensus.hashGenesisBlock, nHeight,
                               consensus.DMMScheduleActivationHeight(),
                               consensus.nDMMScheduleEpochLength, rawSlot,
                               sets.production, sets.recovery, outRes)) {
        return ScheduleStatus::NO_SIGNER;
    }

    auto it = sets.byProTx.find(outRes.proTxHash);
    if (it == sets.byProTx.end()) {
        return ScheduleStatus::LOCAL_STATE_MISSING_FATAL;   // unreachable: elected from the sets
    }
    outMn = it->second;
    return ScheduleStatus::OK;
}

const char* ScheduleStatusName(ScheduleStatus status)
{
    switch (status) {
        case ScheduleStatus::OK: return "ok";
        case ScheduleStatus::NO_SIGNER: return "no_signer";
        case ScheduleStatus::DEFERRED: return "deferred";
        case ScheduleStatus::LOCAL_STATE_MISSING_FATAL: return "local_state_missing_fatal";
    }
    return "unknown";
}

bool HandleFatalScheduleResolution(int nHeight, const uint256& parentHash, CValidationState* state)
{
    LogPrintf("LOT9(DMM): epoch snapshot for height %d (parent %s) is on our active chain "
              "but its masternode list is absent or unreadable — LOCAL state corruption, "
              "node must -reindex. The block is NOT judged.\n",
              nHeight, parentHash.ToString().substr(0, 16));
    // LOT 1 shared latch: controlled shutdown once, REINDEX_REQUIRED at the next
    // startup gate, `state` (when present) carries a NON-invalid Error(). No caller
    // may derive DoS/ban/BLOCK_FAILED_* from this return.
    AbortConsensusDBState(/*fConnect=*/true, /*nStep=*/0, "dmm-schedule-snapshot",
                          /*fPartial=*/false, nHeight, parentHash, state);
    return false;
}

bool SignBlockMNOnly(CBlock& block, const CKey& operatorKey)
{
    if (!operatorKey.IsValid()) {
        return error("%s: Invalid ECDSA operator key\n", __func__);
    }

    // Sign the block hash with ECDSA
    uint256 hashToSign = block.GetHash();
    std::vector<unsigned char> vchSig;
    if (!operatorKey.Sign(hashToSign, vchSig)) {
        return error("%s: ECDSA signing failed\n", __func__);
    }

    block.vchBlockSig = vchSig;

    // Debug: verify signature immediately
    CPubKey pubKey = operatorKey.GetPubKey();
    bool verified = pubKey.Verify(hashToSign, vchSig);

    LogPrintf("%s: Block %s signed with ECDSA (sig size: %d, pubkey: %s, verified: %d)\n",
             __func__, hashToSign.ToString().substr(0, 16), vchSig.size(),
             HexStr(pubKey).substr(0, 32), verified);

    return true;
}

bool VerifyScheduledProducerSignature(const CBlock& block,
                                      const CDeterministicMNCPtr& expectedMn,
                                      CValidationState& state)
{
    if (!expectedMn) {
        // Defensive: callers only reach this with ScheduleStatus::OK, which always
        // carries a non-null MN. A null here is a caller bug, not a block fault.
        return state.Error("dmm-schedule-null-producer");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AUD-005 (LOT 3) — THE RAW WALL-CLOCK GATE THAT USED TO SIT HERE IS REMOVED.
    //
    // It was:
    //     const int64_t MAX_FUTURE_TIME = 120;
    //     int64_t currentTime = GetTime();            // RAW local clock
    //     if (block.nTime > currentTime + MAX_FUTURE_TIME)
    //         return state.DoS(10, …, "bad-mn-time-future", …);
    //
    // Why it had to go. This function is reached from ConnectBlock (validation.cpp
    // -> CheckBlockMNOnly -> here), so `GetTime()` — a value that differs between
    // nodes and even between two runs on ONE node across an NTP step — decided
    // BLOCK VALIDITY. A 121-second skew was enough to change which rule a block was
    // judged against (reproduced by consensus_audit_review_rev005). Worse, because
    // the verdict was a state.DoS it reached InvalidBlockFound and PERSISTED
    // BLOCK_FAILED_VALID: fixing the clock did not recover the block, only
    // reconsiderblock did. A transient local condition became permanent consensus
    // state — the amplifier that made this HIGH.
    //
    // What still bounds a far-future timestamp (the threat this gate named):
    //   1. CheckBlockTime's `time-too-new` (validation.cpp) rejects
    //      blockTime > pindexPrev->MaxFutureBlockTime() = GetAdjustedTime() +
    //      FutureBlockTimeDrift = adjusted time + 14 s. That is TIGHTER than the
    //      120 s removed here by 106 s, and it runs on the header-acceptance path
    //      BEFORE AddToBlockIndex — so it is NOT persisted and self-heals once the
    //      clock or the peer median catches up.
    //   2. The slot arithmetic itself is bounded by chain data only:
    //      GetRawProducerSlot derives dt from pindexPrev->GetBlockTime() and the
    //      block's own nTime. No local clock participates in producer selection.
    //
    // Deliberately NOT done: replacing GetTime() with GetAdjustedTime() here. The
    // peer median is also node-local — merely less so — and it would keep a
    // node-local value inside a PERSISTED consensus verdict, which is the actual
    // defect. Deliberately NOT done either: inventing a chain-derived replacement
    // bound. The CONSENSUS FREEZE RULE puts the burden of proof on the addition,
    // and (1) already provides the bound in a higher layer.
    //
    // Consequence, stated plainly: blocks that a clock-skewed node previously
    // rejected are now accepted, which is the point. On REGTEST CheckBlockTime
    // returns early, so no future-time bound applies to the producer path there —
    // acceptable because regtest block times are fully controlled by the harness.
    // During bootstrap (height <= nDMMBootstrapHeight) CheckBlockMNOnly returns
    // before ever reaching this function, so the bootstrap relaxation in
    // CheckBlockTime is not a gap here.
    // ═══════════════════════════════════════════════════════════════════════════

    // Check signature exists
    if (block.vchBlockSig.empty()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-empty");
    }

    // BATHRON v1: Verify ECDSA signature (typically 70-72 bytes DER encoded)
    if (block.vchBlockSig.size() < 64 || block.vchBlockSig.size() > 73) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-size", false,
                         strprintf("Bad ECDSA sig size: %d", block.vchBlockSig.size()));
    }

    // Operator pubkey (ECDSA) of the SCHEDULED leader — production, AcceptBlock and
    // ConnectBlock resolved it through ResolveScheduledProducer from the same parent,
    // so all three judge against the same identity.
    const CPubKey& pubKey = expectedMn->pdmnState->pubKeyOperator;
    if (!pubKey.IsValid()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-invalid-key", false,
                         strprintf("Invalid operator key for expected producer %s",
                                   expectedMn->proTxHash.ToString().substr(0, 16)));
    }

    // Verify signature against the scheduled producer
    uint256 hashToVerify = block.GetHash();
    if (!pubKey.Verify(hashToVerify, block.vchBlockSig)) {
        LogPrintf("%s: Signature verification FAILED: block %s (nTime=%d), scheduled producer %s, sig size %d\n",
                  __func__, hashToVerify.ToString().substr(0, 16), block.nTime,
                  expectedMn->proTxHash.ToString().substr(0, 16), block.vchBlockSig.size());
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-verify", false,
                         strprintf("ECDSA sig verification failed - scheduled producer: %s",
                                   expectedMn->proTxHash.ToString().substr(0, 16)));
    }

    LogPrint(BCLog::MASTERNODE, "%s: Block %s verified (ECDSA), scheduled producer: %s\n",
             __func__, block.GetHash().ToString().substr(0, 16),
             expectedMn->proTxHash.ToString().substr(0, 16));
    return true;
}

} // namespace mn_consensus
