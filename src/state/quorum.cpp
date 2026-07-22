// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/quorum.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"

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
    // expected-committee CAP (nHuExpectedCommitteeSize) and N = nOperators is the unique
    // operator count AT the block (resolved deterministically by the caller from that
    // block's MN list — the same N the VRF selection uses, see GetUniqueOperators).
    //   N <= E → the whole operator population participates (small / bootstrap network);
    //   N >  E → VRF sortition samples ~E operators (large network).
    // The threshold stays ceil(2/3 · min(E,N)), so ONE fixed E scales from a few operators
    // to thousands with no retuning. nOperators<=0 (block unresolved) falls back to E
    // (conservative: a high threshold that is never trivially met — never 0).
    const int E = consensus.nHuExpectedCommitteeSize;
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

    const int N = static_cast<int>(GetUniqueOperators(mnList).size());
    const int E = consensus.nHuExpectedCommitteeSize;
    return IsVrfSelected(output, E, N);
}

} // namespace hu
