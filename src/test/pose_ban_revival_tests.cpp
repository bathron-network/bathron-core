// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * PoSe ban -> revival state machine (test-plan B7, tier 1).
 *
 * 3 missed production slots -> ban from the active set; a ProUpServ resets the
 * penalty and revives. The pure anti-cascade predicate (ShouldSkipPoSePunishment)
 * and the missed-index math are already covered by bathron_dmm_finality_tests;
 * what had no coverage is the LIST-STATE machine those decisions drive: that a
 * banned MN leaves BOTH the block-producer scoring and the finality operator
 * set, and that revival puts it back. Asserted on nPoSePenalty / nPoSeBanHeight /
 * IsPoSeBanned / GetValidMNsCount / GetUniqueOperators — never on log strings
 * (the ban/revival emit no reject codes, only LogPrintf markers).
 *
 * POSE_BAN_THRESHOLD = 3 (deterministicmns.cpp).
 */

#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "state/quorum.h"
#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include <boost/test/unit_test.hpp>

namespace {

// Clone a MN's state, mutate it via `f`, and write it back.
template <typename F>
void MutateState(CDeterministicMNList& list, const uint256& proTx, F f)
{
    auto dmn = list.GetMN(proTx);
    BOOST_REQUIRE(dmn);
    auto st = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
    f(*st);
    list.UpdateMN(proTx, st);
}

bool ScoresContain(const CBlockIndex* prev, const CDeterministicMNList& list,
                   const uint256& proTx)
{
    for (const auto& s : mn_consensus::CalculateBlockProducerScores(prev, list)) {
        if (s.second->proTxHash == proTx) return true;
    }
    return false;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pose_ban_revival_tests, MultiMNFinalitySetup)

// Penalty 1 and 2 are not a ban; the 3rd strike (penalty 3 + banHeight set) is.
BOOST_AUTO_TEST_CASE(ban_only_on_third_strike)
{
    CDeterministicMNList list = BuildTestMNList(4, 1, operators);
    const uint256 proTx = operators[0].mns[0].proTxHash;
    BOOST_REQUIRE_EQUAL(list.GetValidMNsCount(), 4U);

    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 1; });
    BOOST_CHECK(!list.GetMN(proTx)->IsPoSeBanned());
    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 2; });
    BOOST_CHECK(!list.GetMN(proTx)->IsPoSeBanned());

    // 3rd strike bans (the BuildNewListFromBlock loop sets nPoSeBanHeight=height
    // once penalty reaches POSE_BAN_THRESHOLD).
    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 3; s.nPoSeBanHeight = 500; });
    BOOST_CHECK(list.GetMN(proTx)->IsPoSeBanned());
    BOOST_CHECK_EQUAL(list.GetValidMNsCount(), 3U);
}

// A banned MN leaves BOTH the block-producer scoring and the finality operator
// set — that is what "ban from the active set" means.
BOOST_AUTO_TEST_CASE(banned_mn_excluded_from_active_set)
{
    CDeterministicMNList list = BuildTestMNList(4, 1, operators);
    const uint256 proTx = operators[0].mns[0].proTxHash;

    BOOST_CHECK(ScoresContain(TipIndex(), list, proTx));
    BOOST_CHECK_EQUAL(hu::GetUniqueOperators(list).size(), 4U);

    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 3; s.nPoSeBanHeight = 500; });

    BOOST_CHECK(!ScoresContain(TipIndex(), list, proTx));            // out of production
    BOOST_CHECK_EQUAL(hu::GetUniqueOperators(list).size(), 3U);      // out of finality
}

// A ProUpServ revival resets the penalty and clears the ban -> back in the set.
BOOST_AUTO_TEST_CASE(revival_resets_penalty_and_restores)
{
    CDeterministicMNList list = BuildTestMNList(4, 1, operators);
    const uint256 proTx = operators[0].mns[0].proTxHash;
    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 3; s.nPoSeBanHeight = 500; });
    BOOST_REQUIRE(list.GetMN(proTx)->IsPoSeBanned());

    // Revival (the ProUpServ handler: penalty=0, banHeight=-1, revivedHeight set).
    MutateState(list, proTx, [](CDeterministicMNState& s){
        s.nPoSePenalty = 0; s.nPoSeBanHeight = -1; s.nPoSeRevivedHeight = 600;
    });
    BOOST_CHECK(!list.GetMN(proTx)->IsPoSeBanned());
    BOOST_CHECK_EQUAL(list.GetValidMNsCount(), 4U);
    BOOST_CHECK(ScoresContain(TipIndex(), list, proTx));
    BOOST_CHECK_EQUAL(hu::GetUniqueOperators(list).size(), 4U);
}

// BanIfNotBanned is idempotent: a later ban does not re-stamp the height.
BOOST_AUTO_TEST_CASE(ban_height_not_restamped)
{
    CDeterministicMNState st;
    st.BanIfNotBanned(100);
    BOOST_CHECK_EQUAL(st.nPoSeBanHeight, 100);
    st.BanIfNotBanned(200);
    BOOST_CHECK_EQUAL(st.nPoSeBanHeight, 100);   // unchanged
}

// PoSeDecrease models the -1 when an MN produces successfully; it requires a
// positive, un-banned penalty (never called on a banned MN).
BOOST_AUTO_TEST_CASE(producer_success_decays_penalty)
{
    CDeterministicMNList list = BuildTestMNList(4, 1, operators);
    const uint256 proTx = operators[0].mns[0].proTxHash;
    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 2; });

    list.PoSeDecrease(proTx);
    BOOST_CHECK_EQUAL(list.GetMN(proTx)->pdmnState->nPoSePenalty, 1);
    BOOST_CHECK(!list.GetMN(proTx)->IsPoSeBanned());
}

BOOST_AUTO_TEST_SUITE_END()
