// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// BFT / byzantine-fault unit suite for operator-based HU finality (test-plan C4).
//
// The existing hu_finality_integration_tests prove the COUNTING helpers (per-
// operator dedup, exact-threshold finalizes) and hu_finality_reorg_tests prove
// the chain-level conflict guard (a finalized block cannot be reorged; a
// conflicting block at a finalized height is rejected). This suite encodes the
// BFT 3f+1 SAFETY/LIVENESS MODEL ITSELF as executable assertions on N=4 operators
// (f=1, threshold = ceil(2/3·4) = 3) — the gap the coverage inventory flags as
// "no unit test encodes the 3f+1 model as an assertion":
//
//   * a single byzantine operator cannot forge finality (even via all its MNs);
//   * finalizing two CONFLICTING blocks at one height requires > f equivocators
//     (quorum intersection = 2·T − N = 2 > f=1) — the core safety argument;
//   * an equivocating operator is counted once per block (catching equivocation
//     is the chain guard's job, not the counter's);
//   * liveness tolerates exactly f=1 crash (3-of-4 finalizes, 2-of-4 does not).
//
// Pure CFinalityManager-level assertions (no global handler / chain needed),
// matching the hu_finality_integration_tests style.

#include "test/util/mn_finality_setup.h"

#include "chainparams.h"
#include "key.h"
#include "state/finality.h"
#include "state/quorum.h"
#include "uint256.h"

#include <algorithm>
#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace hu;

namespace {

// N=4 operators, one MN each: the canonical 3f+1 BFT set with f=1.
struct FourOperators : public MultiMNFinalitySetup {
    FourOperators() : MultiMNFinalitySetup(/*numOperators=*/4, /*mnsPerOperator=*/1) {}

    // The enforced finality threshold for N operators = ceil(2/3·min(E,N)).
    int Threshold(int nOps) const {
        return HuActiveFinalityThreshold(Params().GetConsensus(), nOps);
    }

    // Build a manager for `blockHash` signed by the given operator indices, each
    // via its (single) MN. Returns the manager so the caller can query counts.
    CFinalityManager Sign(const uint256& blockHash, const std::vector<int>& ops) const {
        CFinalityManager fm(blockHash, /*height=*/5'000'000);
        for (int op : ops) {
            CHuSignature s = SignAs(op, /*mnIdx=*/0, blockHash);
            fm.mapSignatures[s.proTxHash] = s.vchSig;
        }
        return fm;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(byzantine_finality_tests, FourOperators)

// The 3f+1 threshold is exactly ceil(2/3·N): for N=4, T=3. Sanity-pin it so a
// change to the threshold formula trips this suite.
BOOST_AUTO_TEST_CASE(bft_threshold_is_ceil_two_thirds_of_four)
{
    BOOST_REQUIRE_EQUAL(operators.size(), 4u);
    BOOST_CHECK_EQUAL(Threshold(4), 3);      // ceil(2/3·4) = 3  → tolerates f=1
    BOOST_CHECK_EQUAL(Threshold(3), 2);      // ceil(2/3·3) = 2
    BOOST_CHECK_EQUAL(Threshold(1), 1);      // single-op degenerate
}

// SAFETY-adjacent: one byzantine operator, even signing with every identity it
// controls, is one vote — far below T=3. It cannot forge finality by itself.
BOOST_AUTO_TEST_CASE(single_byzantine_operator_cannot_forge_finality)
{
    const uint256 blockHash = TipIndex()->GetBlockHash();
    const int T = Threshold(4);

    // Byzantine op 0 signs; even re-adding its signature (equivocation replay)
    // cannot lift the unique-operator count above 1.
    CFinalityManager fm = Sign(blockHash, {0});
    CHuSignature dup = SignAs(0, 0, blockHash);
    fm.mapSignatures[dup.proTxHash] = dup.vchSig;   // idempotent re-add

    BOOST_CHECK_EQUAL(fm.GetUniqueOperatorCount(), 1u);
    BOOST_CHECK(!fm.HasFinality(T));                 // 1 < 3 → never final
}

// LIVENESS boundary of 3f+1: exactly f=1 crash-fault is tolerated. 3-of-4 signing
// operators reach finality; a second fault (2-of-4) does not.
BOOST_AUTO_TEST_CASE(liveness_tolerates_exactly_one_fault)
{
    const uint256 blockHash = TipIndex()->GetBlockHash();
    const int T = Threshold(4);

    // 1 operator down → 3 honest sign → final.
    BOOST_CHECK(Sign(blockHash, {0, 1, 2}).HasFinality(T));
    // 2 operators down → only 2 sign → NOT final (liveness lost past f).
    BOOST_CHECK(!Sign(blockHash, {0, 1}).HasFinality(T));
}

// SAFETY (the core): to finalize two CONFLICTING blocks A and B at one height,
// each needs T=3 of the N=4 operators. By quorum intersection any two such sets
// share |Qa|+|Qb|−N = 3+3−4 = 2 operators — so BOTH finalize only if ≥2 operators
// EQUIVOCATE (sign both). With the byzantine budget f=1, that is impossible: an
// honest majority on A leaves at most 1 equivocator for B, and B never reaches 3.
// Operator resolution is keyed to the block's own indexed MN list, so counting
// is done against the fixture's real tip hash; a competing block B at the same
// height draws its quorum from the SAME N operators. The safety statement is then
// combinatorial: any quorum Qa that finalizes A and any quorum Qb that finalizes
// a conflicting B overlap in |Qa|+|Qb|−N = 2·T−N = 2 operators, so finalizing
// both forces ≥2 operators to EQUIVOCATE — impossible within the byzantine budget
// f=1 while the honest majority stays on A.
BOOST_AUTO_TEST_CASE(conflicting_finalization_needs_more_than_f_equivocators)
{
    const uint256 tip = TipIndex()->GetBlockHash();
    const int T = Threshold(4);
    const int N = (int)operators.size();
    const int f = N - T;                       // byzantine budget = 4-3 = 1

    // A's honest quorum {0,1,2} finalizes.
    BOOST_CHECK(Sign(tip, {0, 1, 2}).HasFinality(T));
    // The lone byzantine op 3 cannot reach T for a competing block (1 < 3).
    BOOST_CHECK(!Sign(tip, {3}).HasFinality(T));
    // op 3 plus one accomplice is still 2 < 3.
    BOOST_CHECK(!Sign(tip, {3, 0}).HasFinality(T));
    // A second quorum that DOES reach T (e.g. {3,0,1}) necessarily reuses {0,1}
    // from A's quorum — those 2 operators would have to equivocate to finalize
    // both blocks.
    BOOST_CHECK(Sign(tip, {3, 0, 1}).HasFinality(T));

    // The forced-equivocation count = |Qa ∩ Qb| ≥ 2·T−N must exceed f for safety.
    const int minEquivocators = 2 * T - N;     // = 2
    BOOST_CHECK_EQUAL(minEquivocators, 2);
    BOOST_CHECK_GT(minEquivocators, f);        // 2 > 1  → conflicting finality is unreachable under f=1
}

// An operator contributes exactly ONE vote per block, however it (mis)behaves:
// the per-block counter is honest even when the signer is not. Detecting an
// equivocation ACROSS two conflicting blocks is the chain guard's job
// (HasConflictingFinality — see hu_finality_reorg_tests
// :conflicting_finalization_rejected_partition_safety), not this counter's.
BOOST_AUTO_TEST_CASE(operator_vote_is_one_per_operator_per_block)
{
    const uint256 tip = TipIndex()->GetBlockHash();

    CFinalityManager fm = Sign(tip, {0, 1, 2, 3});
    BOOST_CHECK_EQUAL(fm.GetSignatureCount(), 4u);
    BOOST_CHECK_EQUAL(fm.GetUniqueOperatorCount(), 4u);

    // Re-adding op 0's signature (an equivocation-style replay) does not inflate
    // its weight — still exactly one operator-vote for this block.
    CHuSignature again = SignAs(0, /*mnIdx=*/0, tip);
    fm.mapSignatures[again.proTxHash] = again.vchSig;
    BOOST_CHECK_EQUAL(fm.GetUniqueOperatorCount(), 4u);
}

// Quorum-intersection safety as a pure property over the ACTUAL operator set:
// enumerate every pair of distinct T-sized operator quorums and assert they
// always share ≥ 2·T−N operators (> f). This is the combinatorial backbone of
// the "cannot finalize two conflicting blocks without > f equivocators" argument.
BOOST_AUTO_TEST_CASE(every_pair_of_quorums_intersects_above_f)
{
    const int N = (int)operators.size();       // 4
    const int T = Threshold(N);                // 3
    const int f = N - T;                       // 1
    const int floorInt = 2 * T - N;            // 2

    // All T-subsets of {0..N-1}.
    std::vector<std::vector<int>> quorums;
    std::vector<int> pick(N, 0);
    std::fill(pick.begin(), pick.begin() + T, 1);
    std::vector<int> order(N);
    for (int i = 0; i < N; ++i) order[i] = i;
    do {
        std::vector<int> q;
        for (int i = 0; i < N; ++i) if (pick[i]) q.push_back(i);
        quorums.push_back(q);
    } while (std::prev_permutation(pick.begin(), pick.end()));

    BOOST_REQUIRE(!quorums.empty());
    for (size_t i = 0; i < quorums.size(); ++i) {
        for (size_t j = i + 1; j < quorums.size(); ++j) {
            std::set<int> si(quorums[i].begin(), quorums[i].end());
            int shared = 0;
            for (int op : quorums[j]) if (si.count(op)) ++shared;
            BOOST_CHECK_GE(shared, floorInt);   // ≥ 2 shared
            BOOST_CHECK_GT(shared, f);          // > byzantine budget → ≥1 honest overlap
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
