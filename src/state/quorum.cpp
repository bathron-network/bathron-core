// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/quorum.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "masternode/blockproducer.h"   // LOT 9 M3: ResolveEpochOperatorSets
#include "validation.h"                 // cs_main (epoch resolution asserts it)

#include <algorithm>
#include <map>

namespace hu {

// NOTE: ComputeHuQuorumSeed removed as dead legacy — it seeded the top-N cycle
// selection (now gone). The VRF path uses GetHuFinalitySeedHash(pindex, k) directly.

uint256 GetHuFinalitySeedHash(const CBlockIndex* pindex, int nSeedOffset)
{
    // See quorum.h for the rationale (anti double-lever, deterministic, bootstrap).
    if (!pindex) {
        return uint256();
    }
    int seedHeight = pindex->nHeight - nSeedOffset;
    if (seedHeight < 0) {
        seedHeight = 0;  // bootstrap fallback: genesis
    }
    const CBlockIndex* seedIndex = pindex->GetAncestor(seedHeight);
    if (!seedIndex) {
        // Defensive: for an in-chain pindex this cannot happen. Fall back to the
        // immediate parent (legacy seed) rather than returning a null seed.
        return pindex->pprev ? pindex->pprev->GetBlockHash() : pindex->GetBlockHash();
    }
    return seedIndex->GetBlockHash();
}

// NOTE: the per-MN quorum helpers (ComputeHuQuorumMemberScore, GetHuQuorum,
// IsInHuQuorum) were removed as dead legacy — they predate the operator-based model
// and the GetFinalityCommittee seam, and had no callers. The live path is
// operator-based (GetUniqueOperators + per-block ECVRF sortition).

// ═══════════════════════════════════════════════════════════════════════════════
// OPERATOR-BASED QUORUM (v3.0)
// ═══════════════════════════════════════════════════════════════════════════════

std::map<CPubKey, CDeterministicMNCPtr> GetEpochFinalityOperators(const CBlockIndex* pindexPrev)
{
    // LOT 9 M3 (spec O-2): finalitySet == productionSet of the epoch snapshot —
    // confirmed/bootstrap identities whose lease is VALID at the snapshot height.
    // N (and therefore the threshold) tracks THIS set: leases expiring drop N at
    // the next epoch boundary; if N falls below nHuQuorumSize finality STALLS
    // fail-closed while production continues through the recovery permutation,
    // and it restarts automatically once renewals bring N back to the floor.
    std::map<CPubKey, CDeterministicMNCPtr> operators;
    if (!pindexPrev || !deterministicMNManager) {
        return operators;
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const int nHeight = pindexPrev->nHeight + 1;
    if (nHeight < consensus.DMMScheduleActivationHeight()) {
        // BOOTSTRAP MODE (LOT 9 M3.1) — the explicitly-defined regime below the
        // activation height, where production itself is exempt from the schedule.
        // The population is the legacy bootstrap-aware parent-list set, so a fresh
        // chain finalizes from its first blocks. This is NOT a "first epoch"
        // exception to the schedule: above the activation height the anchored
        // snapshot is the ONLY source, with no fallback of any kind.
        return GetUniqueOperators(deterministicMNManager->GetListForBlock(pindexPrev));
    }

    mn_consensus::EpochOperatorSets sets;
    mn_consensus::ScheduleStatus status;
    {
        // cs_main is recursive; several callers (context build at connect, cold
        // paths) already hold it, gossip-side cold paths do not.
        LOCK(cs_main);
        status = mn_consensus::ResolveEpochOperatorSets(pindexPrev, sets);
    }
    if (status != mn_consensus::ScheduleStatus::OK) {
        // DEFERRED / NO_SIGNER / FATAL-shaped local gaps: FAIL-CLOSED (empty set →
        // threshold falls back to ceil(2/3·E), unreachable). A finality/gossip read
        // must never fire the fatal latch — only the consensus validation sites do.
        return operators;
    }

    for (const uint256& proTxHash : sets.production) {
        auto it = sets.byProTx.find(proTxHash);
        if (it == sets.byProTx.end()) continue;
        const CPubKey& opKey = it->second->pdmnState->pubKeyOperator;
        if (operators.find(opKey) == operators.end()) {
            operators[opKey] = it->second;
        }
    }
    return operators;
}

std::map<CPubKey, CDeterministicMNCPtr> GetUniqueOperators(const CDeterministicMNList& mnList)
{
    std::map<CPubKey, CDeterministicMNCPtr> operators;
    const Consensus::Params& consensus = Params().GetConsensus();

    mnList.ForEachMN(true /* onlyValid */, [&](const CDeterministicMNCPtr& dmn) {
        // Mirror the block-producer trust model (blockproducer.cpp): MNs registered during
        // the bootstrap phase are trusted WITHOUT confirmedHash. Chicken-and-egg — a fresh
        // network must finalize before its MNs can reach collateral confirmation
        // (nMasternodeCollateralMinConf = 60 testnet / 1440 ≈ 24h mainnet). Without this,
        // production runs but finality is dead for that whole window. Deterministic:
        // nRegisteredHeight + nDMMBootstrapHeight, so signer and verifier compute the same N.
        const bool isBootstrapMN = (dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight);
        if (!isBootstrapMN && dmn->pdmnState->confirmedHash.IsNull()) {
            return;  // post-bootstrap MN not yet collateral-confirmed → excluded
        }

        const CPubKey& opKey = dmn->pdmnState->pubKeyOperator;
        // Keep first MN per operator (for signing purposes)
        if (operators.find(opKey) == operators.end()) {
            operators[opKey] = dmn;
        }
    });

    return operators;
}

// NOTE: the top-N committee machinery (ComputeOperatorScore, GetHuQuorumOperators,
// GetFinalityCommittee, IsInFinalityCommittee — plus IsOperatorInHuQuorum earlier) was
// removed: finality is VRF-only. Committee membership is decided per-block by ECVRF
// sortition (IsOperatorVrfSelected); the eligible set is GetUniqueOperators(mnList).

// ───────────────────────────────────────────────────────────────────────────────
// VRF SORTITION (roadmap étape 3.2)
// ───────────────────────────────────────────────────────────────────────────────

bool IsVrfSelected(const vrf::Output& vrfOutput, int E, int N)
{
    if (N <= 0 || E <= 0) {
        return false;
    }
    if (E >= N) {
        return true;  // expected size >= population → everyone is drawn
    }
    // threshold = floor((2^256 - 1) / N) * E  ≈ floor(2^256 · E / N), deterministic.
    // With E < N (and N >= 2 here), (max/N) <= max/2 and *E < max → no overflow.
    const arith_uint256 threshold = (~arith_uint256(0) / arith_uint256(N)) * arith_uint256(E);

    uint256 outBlob(std::vector<unsigned char>(vrfOutput.begin(), vrfOutput.end()));
    return UintToArith256(outBlob) <= threshold;
}

int HuVrfFinalityThreshold(int E)
{
    if (E <= 0) {
        return 0;  // degenerate: no expected committee → can never finalize
    }
    // ceil(2E/3) with pure integer math (no floating point in consensus).
    return (2 * E + 2) / 3;
}

int HuActiveFinalityThreshold(const Consensus::Params& consensus, int nOperators)
{
    // Auto-scaling committee: the EFFECTIVE committee is min(E, N), where E is the fixed
    // EXPECTED committee size (nHuExpectedCommitteeSize — a target, not a hard cap: when
    // N > E each operator is drawn with p = E/N, so the realised size varies around E) and
    // N = nOperators is the unique
    // operator count AT the block (resolved deterministically by the caller from that
    // block's MN list — the same N the VRF selection uses, see GetUniqueOperators).
    //   N <= E → the whole operator population participates (small / bootstrap network);
    //   N >  E → VRF sortition samples ~E operators (large network).
    // The threshold stays ceil(2/3 · min(E,N)), so ONE fixed E scales from a few operators
    // to thousands with no retuning. nOperators<=0 (block unresolved) falls back to E
    // (conservative: a high threshold that is never trivially met — never 0).
    const int E = consensus.nHuExpectedCommitteeSize;

    // ═══════════════════════════════════════════════════════════════════════════
    // AUD-002 (LOT 4) — SYBIL FLOOR, applied HERE and only here.
    //
    // Before this lot `nHuQuorumSize` had exactly ONE non-logging use in the whole
    // tree (state/signaling.cpp inside HasQuorum), which is on no block-validity
    // path and is OR-bypassed by two floor-free fallbacks. Every finality predicate
    // that DOES gate validity derived its bar from this function, which had no
    // floor — so a population below the 3f+1 floor could finalize. At N=1 the
    // threshold is 1: a single operator finalizes alone, and its equivocation
    // finalizes two conflicting blocks on two honest nodes — a permanent fork.
    //
    // The floor is placed in the THRESHOLD DERIVATION (remediation option 1)
    // rather than at the call sites because BOTH the write side
    // (CFinalityManagerHandler::AddSignature) and the read side
    // (CFinalityManagerDB::IsBlockFinal, HasFinality) re-derive through here. A
    // guard on one side alone would leave historical records honoured on read —
    // exactly the grandfathering hole the finding warns about.
    //
    // Semantics below the floor: NOT "threshold 0" and NOT "threshold = N" but
    // UNREACHABLE — no achievable unique-operator count can satisfy it, so such a
    // block is simply never final. That is the intended consequence: a network
    // legitimately running below the floor STOPS FINALIZING (it keeps producing;
    // liveness of block production is untouched). Deploy only with a confirmed
    // >= nHuQuorumSize operator population.
    // ═══════════════════════════════════════════════════════════════════════════
    if (nOperators > 0 && nOperators < consensus.nHuQuorumSize) {
        return HU_FINALITY_THRESHOLD_UNREACHABLE;
    }
    // DELIBERATE, AND A KNOWN RESIDUAL: the guard is `nOperators > 0`, so an
    // UNRESOLVED block (HuFinalityOperatorCount returns 0 when the block is absent
    // from mapBlockIndex or has no cached context) does NOT get the floor — it falls
    // through to the pre-existing conservative fallback of ceil(2/3·E). AUD-002 names
    // this fail-open ("an unknown block skips the floor check"). It is not closed
    // here because at shipped params the fallback threshold is ceil(2/3·128) = 86,
    // far ABOVE nHuQuorumSize = 4, so an unresolved block is harder to finalize than
    // a resolved one, not easier. That safety comes from E, not from the floor — if
    // E were ever lowered near nHuQuorumSize this must be revisited. Recorded as a
    // follow-up rather than silently relied upon.

    int eff = (nOperators > 0) ? std::min(E, nOperators) : E;
    if (eff < 1) eff = 1;
    return HuVrfFinalityThreshold(eff);
}

bool IsOperatorVrfSelected(
    const CDeterministicMNList& mnList,
    const CBlockIndex* pindex,
    const CPubKey& vrfPubKey,
    const vrf::Proof& proof)
{
    // LOT 9 M3: N no longer comes from the caller's list — the epoch snapshot is
    // the single source (below). The list parameter is kept for interface
    // stability of existing callers/tests; it carries no authority here.
    (void)mnList;
    if (!pindex || !vrfPubKey.IsValid() || vrfPubKey.size() != vrf::PUBKEY_SIZE) {
        return false;
    }
    const Consensus::Params& consensus = Params().GetConsensus();

    // VRF input (alpha) = the finality seed hash(H-k); identical for all nodes.
    uint256 seed = GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
    std::vector<unsigned char> msg(seed.begin(), seed.end());

    vrf::Output output;
    if (!vrf::Verify(output, proof, vrfPubKey.begin(), msg)) {
        return false;  // unverifiable claim → never selected
    }

    // LOT 9 M3: N = the epoch snapshot's lease-valid population — identical to the
    // context-based verify path (ValidateSignatureFromContext) and the signer side.
    const int N = static_cast<int>(GetEpochFinalityOperators(pindex->pprev).size());
    const int E = consensus.nHuExpectedCommitteeSize;
    return IsVrfSelected(output, E, N);
}

} // namespace hu
