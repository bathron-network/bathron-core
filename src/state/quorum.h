// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_HU_QUORUM_H
#define BATHRON_HU_QUORUM_H

#include "masternode/deterministicmns.h"
#include "state/finality.h"
#include "uint256.h"
#include "vrf.h"

#include <vector>

class CBlockIndex;
namespace Consensus { struct Params; }

namespace hu {

/**
 * HU Quorum System - OPERATOR-BASED Finality
 *
 * DESIGN PRINCIPLE:
 * - DMM (Production): ALL MNs participate, scored by proTxHash
 * - FINALITY (Signatures): OPERATORS vote, one vote per operator
 *
 * This ensures:
 * - Maximum availability for block production (all MNs compete)
 * - Economic decentralization for finality (operators, not MNs)
 *
 * COMMITTEE SELECTION (VRF-only, re-drawn EVERY block):
 * 1. Seed = hash of the ancestor at fixed offset k (anti double-lever)
 * 2. Each operator computes ECVRF(sk, seed); selected if output < (E/N)·2^256
 * 3. One vote per unique operator — the producer's operator votes like any other
 *    (producer-exclusion was removed 2026-06-30: excluding it broke 3f+1 at
 *     small N, and a self-vote is harmless at the 2/3 threshold)
 * 4. Finality threshold: ceil(2/3 · min(E, N)) via HuActiveFinalityThreshold
 */

/**
 * Compute the finality-committee SEED BLOCK HASH for the block at `pindex`.
 *
 * Returns the hash of the ancestor at height (pindex->nHeight - nSeedOffset).
 * Using a FIXED backward offset k (instead of pprev = H-1) breaks the
 * production/finality "double lever": the producer of block H-1 controls H-1's
 * hash and thus DMM production at H, but no longer ALSO controls H's finality
 * committee, which now keys off H-k — an older block that is, in practice,
 * already HU-finalized and therefore immutable.
 *
 * Computed PURELY from chain structure (height + ancestor hash) => fully
 * deterministic across nodes. Runtime finalization status is intentionally NOT
 * consulted (that would make validation non-deterministic). The "is finalized"
 * property is obtained by choosing k >= practical finality depth, not by a check.
 *
 * Bootstrap: if H - nSeedOffset < 0, the height is clamped to 0 (genesis). The
 * permissioned bootstrap has no adversary, so an early predictable seed is harmless.
 *
 * @param pindex      Block whose finality committee is being selected (height H)
 * @param nSeedOffset Fixed backward offset k (consensus.nHuFinalitySeedOffset)
 * @return Hash of the seed block (null only if pindex is null)
 */
uint256 GetHuFinalitySeedHash(const CBlockIndex* pindex, int nSeedOffset);

// NOTE: per-MN quorum helpers (GetHuQuorum / IsInHuQuorum / ComputeHuQuorumMemberScore)
// removed as dead legacy — superseded by the operator-based path below + the
// GetFinalityCommittee seam.

// ═══════════════════════════════════════════════════════════════════════════════
// OPERATOR-BASED QUORUM (v3.0)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get unique operators from MN list
 * @param mnList Deterministic MN list
 * @return Map of operator pubkey -> one representative MN (for signing)
 */
std::map<CPubKey, CDeterministicMNCPtr> GetUniqueOperators(const CDeterministicMNList& mnList);

// NOTE: the top-N committee machinery (GetHuQuorumOperators, ComputeOperatorScore,
// GetFinalityCommittee, IsInFinalityCommittee, IsOperatorInHuQuorum) was removed —
// finality is VRF-only. Committee membership is decided per-block by ECVRF sortition
// (IsOperatorVrfSelected below); the eligible set is GetUniqueOperators(mnList).

// ───────────────────────────────────────────────────────────────────────────────
// VRF SORTITION — the sole finality-committee selection (VRF-only, no legacy path).
// Each operator is independently drawn with probability p = E/N (1-operator-1-vote)
// from its VRF output. The signing node self-selects its own operators (it holds
// their VRF secret keys); everyone else verifies via the published proof.
// ───────────────────────────────────────────────────────────────────────────────

/**
 * Pure 1-operator-1-vote sortition decision. Selected iff the VRF output, read as a
 * big integer in [0, 2^256), falls under threshold = floor(2^256·E/N). Deterministic
 * integer math (no floating point). E>=N → always selected; E<=0 or N<=0 → never.
 *
 * @param vrfOutput The 32-byte VRF output (beta).
 * @param E         Expected committee size (consensus.nHuExpectedCommitteeSize).
 * @param N         Number of unique operators eligible.
 */
bool IsVrfSelected(const vrf::Output& vrfOutput, int E, int N);

/**
 * Finality threshold under VRF sortition = ceil(2/3 · E), in UNIQUE OPERATOR votes.
 *
 * The fixed "8 of 12" couple disappears (roadmap §3): only the ⅔ BFT ratio survives,
 * applied to the EXPECTED committee size E (consensus.nHuExpectedCommitteeSize). The
 * number actually drawn per block is binomial(N, E/N) and varies; this threshold is a
 * fixed integer derived from E, NOT from the per-block draw. If fewer than this many
 * eligible operators are drawn (or are online), the block does not finalize and finality
 * lags to a later block with a fresh seed (liveness fallback, §11.3 — no re-seed).
 *
 * Integer math, deterministic: ceil(2E/3) == (2*E + 2) / 3. Reproduces the legacy fixed
 * thresholds exactly when E equals today's committee size (E=12→8, E=3→2, E=1→1), so
 * activation is threshold-neutral on a network whose E matches its old nHuQuorumSize.
 *
 * @param E Expected committee size (>0). Returns 0 for E<=0 (degenerate, never finalizes).
 */
int HuVrfFinalityThreshold(int E);

/**
 * The finality threshold (in unique-operator votes) for a block with `nOperators`
 * unique operators in its MN list.
 *
 * Single source of truth: threshold = ceil(2/3 · min(E, nOperators)), where E =
 * consensus.nHuExpectedCommitteeSize is the fixed expected-committee CAP. The min()
 * makes ONE fixed E auto-scale across network sizes:
 *   - nOperators <= E → whole population (small / bootstrap network);
 *   - nOperators >  E → VRF sortition samples ~E (large network), threshold ~2/3·E.
 * So a network can grow from a handful of operators to thousands with no retuning.
 *
 * `nOperators` MUST be resolved by the caller from the block's OWN MN list
 * (GetUniqueOperators over GetListForBlock(pindex->pprev)) — the same population the
 * VRF selection uses — so signer, verifier and threshold all agree deterministically.
 * nOperators<=0 falls back to E (conservative high threshold, never trivially met).
 */
int HuActiveFinalityThreshold(const Consensus::Params& consensus, int nOperators);

/**
 * Verify a VRF proof for the block at `pindex` and decide committee membership.
 * Internally: seed = GetHuFinalitySeedHash(pindex, k); output = ECVRF_verify(
 * vrfPubKey, seed, proof); return IsVrfSelected(output, E=consensus, N=|operators|).
 * Returns false if the proof is invalid (so an unverifiable claim is never counted).
 *
 * @param mnList    MN list for the block (gives N = unique operators).
 * @param pindex    Block whose committee membership is being checked.
 * @param vrfPubKey The operator's registered VRF public key (33-byte compressed).
 * @param proof     The 81-byte VRF proof the operator published.
 */
bool IsOperatorVrfSelected(
    const CDeterministicMNList& mnList,
    const CBlockIndex* pindex,
    const CPubKey& vrfPubKey,
    const vrf::Proof& proof);

} // namespace hu

#endif // BATHRON_HU_QUORUM_H
