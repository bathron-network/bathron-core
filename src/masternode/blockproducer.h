// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_EVO_BLOCKPRODUCER_H
#define BATHRON_EVO_BLOCKPRODUCER_H

#include "masternode/deterministicmns.h"
#include "key.h"
#include "primitives/block.h"
#include "uint256.h"

#include <string>
#include <vector>

class CBlockIndex;
class CValidationState;
namespace Consensus { struct Params; }

namespace mn_consensus {

/**
 * MN-only block production for BATHRON chain.
 *
 * BATHRON uses pure MN-only consensus from genesis - NO PoS.
 * Masternodes produce all blocks. Block signatures use ECDSA with the operator
 * key (~72 bytes DER encoded).
 *
 * Since LOT 9 M1+M2 the ONLY selection engine is the non-grindable epoch
 * schedule below (ResolveScheduledProducer). The legacy per-block draw
 * score = H(prevBlockHash || height || proTxHash) has been REMOVED from the
 * tree: its parent-hash input was producer-chosen and re-rollable for free.
 */

// ═════════════════════════════════════════════════════════════════════════════
// LOT 9 M1 — NON-GRINDABLE SCHEDULE (architecture B)
// ═════════════════════════════════════════════════════════════════════════════
//
// The legacy draw (removed in M1+M2) was a PUBLIC hash of PUBLIC inputs, one of
// which — the parent hash — was chosen by the previous producer, who could re-roll
// it for free (no proof-of-work). LOT 9 measured the consequence: with 5 operators,
// at most 9 re-rolls elect ANY chosen successor, and chaining that gives one
// operator a permanent hold on the schedule. The delayed-ancestor variant hash(H-k)
// was REFUTED: it only moves the grinding k blocks earlier and still hands a single
// operator a guaranteed 1/k share, independent of the population size.
//
// The schedule below removes producer-controlled entropy entirely: the seed is
// derived from the genesis hash and the epoch index — one constant and one pure
// function of the height. Nothing a producer emits can move it. The price is that
// the schedule is fully PREDICTABLE (a known leader can be targeted); that trade is
// deliberate — manipulation is silent, free and permanent, while targeted DoS is
// noisy, costly and absorbed by the fallback. Finality keeps its ECVRF, so the
// committee stays unpredictable where safety actually lives.

/** Domain separators. Distinct seeds ⇒ the recovery order is not a rotation of the
 *  normal one, so an expired operator cannot infer its recovery rank from the
 *  normal permutation. */
extern const std::string DMM_SCHEDULE_DOMAIN;   //!< "BATHRON_DMM_SCHEDULE_V1"
extern const std::string DMM_RECOVERY_DOMAIN;   //!< "BATHRON_DMM_RECOVERY_V1"

/** Safety margin of the two timing invariants (seconds). */
static const int DMM_TIMING_SAFETY_MARGIN = 15;

// ─────────────────────────────────────────────────────────────────────────────
// LOT 9 M3.1 — ANCHORED ACTIVATION.
//
// The schedule starts at an explicit frontier, `activation`
// (= Consensus::Params::DMMScheduleActivationHeight()). Below it the chain is in
// BOOTSTRAP MODE; from it on, EVERY epoch has ONE immutable snapshot:
//
//   epochIndex     = (height - activation) / epochLength
//   epochStart     = activation + epochIndex * epochLength
//   snapshotHeight = max(activation - 1, epochStart - snapshotDepth)
//
// The first epoch needs no special case: its epochStart IS activation, so
// `epochStart - snapshotDepth` sits below `activation - 1` and the max() picks
// the anchor. Every block of an epoch therefore resolves the SAME snapshot
// height, fixed by one ancestor block hash — a registration, renewal or expiry
// included during an epoch can only take effect through a FUTURE snapshot.
//
// The REJECTED alternative (measured and reverted in M3.1): resolving the
// operator set from the parent list during the first epoch. That made the set
// mutable at every height, so a producer could include or censor a registration
// and move the very next calendar — a violation of snapshot immutability.
// ─────────────────────────────────────────────────────────────────────────────

/** epochIndex = (height - activation) / epochLength (pure, no chain data).
 *  Returns 0 below the activation height (bootstrap mode: undefined, unused). */
uint32_t GetScheduleEpochIndex(int nHeight, int nActivationHeight, int nEpochLength);

/** First height of the epoch containing nHeight (>= activation). */
int GetScheduleEpochStart(int nHeight, int nActivationHeight, int nEpochLength);

/** Height whose MN list freezes the epoch's operator set:
 *  max(activation - 1, epochStart - snapshotDepth). Resolved by the caller through
 *  the parent's ancestors — NEVER chainActive, finalitydb or a local cache. */
int GetEpochSnapshotHeight(int nHeight, int nActivationHeight, int nEpochLength, int nSnapshotDepth);

/** seed = SHA256d(domain || genesisHash || epochIndex). No producer input. */
uint256 GetScheduleSeed(const std::string& strDomain, const uint256& genesisHash, uint32_t nEpochIndex);

/** Deterministic BIJECTIVE permutation of `ops`: sort by SHA256d(seed || proTxHash)
 *  descending, ties broken by proTxHash ascending. Being a bijection is what bounds
 *  proTxHash grinding: an identity may buy a POSITION, never a second slot. */
std::vector<uint256> ComputeSchedulePermutation(const uint256& seed, std::vector<uint256> ops);

/**
 * rawSlot — 64-bit, UNCLAMPED, computed in O(1) with no iteration.
 *
 * The legacy MAX_FALLBACK_SLOTS=360 clamp must NOT reach leader selection: with
 * P=361 lease-valid operators, `min(slot,360) < P` would hold forever and the
 * recovery mode could never be entered — a permanent wedge. M2 removed the clamp
 * (and the temporal-PoSe path that carried it) from the tree entirely.
 *
 *   dt < leaderTimeout          -> 0
 *   otherwise                   -> 1 + (dt - leaderTimeout) / recoveryWindow
 *
 * Pure function of two CHAIN timestamps (parent's and the block's own). No local
 * clock. Block times are uint32 in the header, so dt <= ~2^32 and no overflow is
 * reachable; the computation is still written defensively.
 */
int64_t GetRawProducerSlot(const CBlockIndex* pindexPrev, int64_t nBlockTime);

/** Outcome of the two-level schedule. */
struct DMMScheduleResult {
    bool fFound{false};        //!< false = no signer available at all (explicit stall)
    bool fRecovery{false};     //!< true = the recovery permutation was used
    int64_t nRawSlot{0};
    size_t nIndex{0};          //!< index inside the permutation that was used
    uint256 proTxHash;         //!< the elected identity
};

/**
 * Two-level leader selection.
 *
 *   rawSlot <  P : NORMAL   — lease-valid operators only, so expired identities can
 *                             never slow the normal calendar (1000 dead operators
 *                             would otherwise mean 1000 empty slots to wait out).
 *   rawSlot >= P : RECOVERY — every confirmed identity, expired included, may produce
 *                             a block carrying renewals and registrations.
 *
 * `rawSlot >= P` IS the bounded objective delay: reaching slot P costs
 * leaderTimeout + (P-1)*recoveryWindow of CHAIN time, so every lease-valid member has
 * had its window before an expired one may produce.
 *
 * P == 0 needs no special case (rawSlot >= 0 always holds) — recovery is then
 * AVAILABLE from slot 0. That does not mean instant resumption: production restarts at
 * the first slot whose expired identity can still sign. If every key is lost and every
 * operator offline, no protocol can recreate a signer; R == 0 is reported as an
 * explicit stall (fFound = false), never as a block-validity verdict.
 */
bool SelectScheduledLeader(const uint256& genesisHash,
                           int nHeight,
                           int nActivationHeight,
                           int nEpochLength,
                           int64_t nRawSlot,
                           const std::vector<uint256>& productionSet,
                           const std::vector<uint256>& recoverySet,
                           DMMScheduleResult& out);

/**
 * The two timing invariants. A free clock advance crosses a slot boundary whenever the
 * window preceding it is shorter than the accepted future drift, letting a producer
 * steal another's turn without waiting:
 *
 *   (I1) leaderTimeout      >= FutureBlockTimeDrift + DMM_TIMING_SAFETY_MARGIN   slot 0 -> 1
 *   (I2) recoveryWindow     >= FutureBlockTimeDrift + DMM_TIMING_SAFETY_MARGIN   slot k -> k+1
 *
 * I1 is NOT redundant: crossing the FIRST boundary costs leaderTimeout, not the
 * recovery window, so fixing only the window would leave slot 1 free wherever
 * leaderTimeout <= drift (regtest shipped leaderTimeout=5 against a 14 s drift).
 *
 * @return false and fills strError when either invariant is violated.
 */
bool CheckDMMTimingInvariants(const Consensus::Params& consensus, std::string& strError);

/**
 * Outcome of resolving the scheduled producer for the block extending `pindexPrev`.
 *
 * The four values keep two things that must never be confused strictly apart: what the
 * CHAIN says (OK / NO_SIGNER) and what OUR NODE is missing (DEFERRED /
 * LOCAL_STATE_MISSING_FATAL). A local gap is never reported as a chain fact.
 */
enum class ScheduleStatus {
    //! A leader is elected. Normal validation continues.
    OK,
    //! The snapshot ancestor is authoritative (on our active chain) and its list is
    //! readable, but NO deterministic signer exists. This is an objective consensus
    //! stall: the local producer emits nothing, and a block claiming a producer is
    //! rejected with a precise reason. It is a CHAIN fact, identical on every node.
    NO_SIGNER,
    //! The snapshot ancestor is NOT on our active chain: we simply have not connected
    //! that branch yet. Validation is DEFERRED — state.Error, no fatal latch, no
    //! invalidity, no ban, and never a fallback onto an empty list or the tip.
    DEFERRED,
    //! The snapshot ancestor IS on our active chain but its deterministic list is
    //! absent or unreadable: genuine corruption of OUR reconstructible state. Fatal
    //! latch (LOT 1) + REINDEX_REQUIRED. Never Invalid/DoS/ban/BLOCK_FAILED_*.
    LOCAL_STATE_MISSING_FATAL,
};

/**
 * LOT 9 M3 — the two-level operator sets of the epoch containing pindexPrev+1,
 * resolved from the PARENT alone (same snapshot discipline as the leader
 * election, same O-1 status classification):
 *
 *   production = eligible identities whose lease is VALID at the snapshot
 *                (snapshotHeight < nLeaseExpiryHeight; EQUALITY = EXPIRED);
 *   recovery   = every eligible identity, expired leases included.
 *
 * Eligible = valid (not banned) + bootstrap-trust or confirmedHash — unchanged.
 * finalitySet == production (spec O-2): the finality population and threshold N
 * come from GetEpochFinalityOperators (quorum.h), which wraps this.
 */
struct EpochOperatorSets {
    int nSnapshotHeight{0};
    std::vector<uint256> production;
    std::vector<uint256> recovery;
    std::map<uint256, CDeterministicMNCPtr> byProTx;   //!< every recovery member
};

ScheduleStatus ResolveEpochOperatorSets(const CBlockIndex* pindexPrev, EpochOperatorSets& out);

/**
 * Resolve the epoch snapshot from `pindexPrev` ALONE and elect the scheduled leader.
 *
 *   nHeight        = pindexPrev->nHeight + 1
 *   snapshotHeight = max(0, epochStart(nHeight) - nDMMSetSnapshotDepth)
 *   pindexSnapshot = pindexPrev->GetAncestor(snapshotHeight)
 *
 * NEVER chainActive.Tip(), never finalitydb, never a cache keyed on the local view.
 * `chainActive.Contains(pindexSnapshot)` is consulted for ONE purpose only —
 * telling DEFERRED from LOCAL_STATE_MISSING_FATAL — and never enters the election.
 *
 * Same parent ⇒ same snapshot ⇒ same permutation ⇒ same leader, on every node, across
 * restart, -reindex and reorg.
 *
 * @param outMn  [out] elected masternode (null unless OK)
 * @param outRes [out] the raw schedule result (slot, mode, index)
 */
ScheduleStatus ResolveScheduledProducer(const CBlockIndex* pindexPrev,
                                        int64_t nBlockTime,
                                        CDeterministicMNCPtr& outMn,
                                        DMMScheduleResult& outRes);

/** Stable lowercase name of a ScheduleStatus (for RPC display and logs). */
const char* ScheduleStatusName(ScheduleStatus status);

/**
 * THE single handler for ScheduleStatus::LOCAL_STATE_MISSING_FATAL on a
 * consensus/production path: logs, fires the LOT 1 shared fatal latch
 * (AbortConsensusDBState -> controlled shutdown + REINDEX_REQUIRED at the next
 * startup gate) and returns false with `state` carrying a NON-invalid Error().
 * A local gap is never block invalidity: no DoS, no ban, no BLOCK_FAILED_*.
 * `state` may be null (paths that carry no CValidationState, e.g. the scheduler).
 */
bool HandleFatalScheduleResolution(int nHeight, const uint256& parentHash, CValidationState* state);

/**
 * Sign block with MN operator ECDSA key.
 *
 * @param block          Block to sign
 * @param operatorKey    ECDSA private key (operator)
 * @return               true if signed
 */
bool SignBlockMNOnly(CBlock& block, const CKey& operatorKey);

/**
 * Verify that `block` is signed by the SCHEDULED producer `expectedMn` (the
 * identity elected by ResolveScheduledProducer for this parent and nTime).
 *
 * This is the only signature check of the producer path: production, AcceptBlock
 * and ConnectBlock all resolve the leader through the same engine from the same
 * parent, so a signature that verifies here verifies everywhere. A failure IS a
 * genuine block invalidity (state.DoS) — by the time this runs, every local-state
 * condition has already been classified by ResolveScheduledProducer.
 */
bool VerifyScheduledProducerSignature(const CBlock& block,
                                      const CDeterministicMNCPtr& expectedMn,
                                      CValidationState& state);

} // namespace mn_consensus

#endif // BATHRON_EVO_BLOCKPRODUCER_H
