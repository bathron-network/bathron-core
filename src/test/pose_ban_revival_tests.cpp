// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * PoSe ban -> revival state machine — NON-TEMPORAL transitions only.
 *
 * LOT 9 M2 removed the TEMPORAL PoSe system (missed-slot penalty/ban derived
 * from block.nTime, its decay rules, and PoSeDecrease). What remains — and what
 * this file covers — is the ban/revival LIST-STATE machine driven by the
 * non-temporal transitions that still exist: ProRegTx with an empty service
 * starts banned, an operator-key change or a ProUpRevTx bans, a ProUpServTx
 * revives. The invariant under test: a banned MN leaves BOTH the schedule's
 * eligible set and the finality operator set, and revival puts it back.
 * Asserted on nPoSePenalty / nPoSeBanHeight / IsPoSeBanned / GetValidMNsCount /
 * GetUniqueOperators — never on log strings.
 */

#include "chainparams.h"
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

// Membership in the schedule's eligible set — the same predicate
// ResolveScheduledProducer applies to the epoch snapshot (valid = not banned,
// plus bootstrap-trust or confirmedHash).
bool EligibleContains(const CDeterministicMNList& list, const uint256& proTx)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    bool found = false;
    list.ForEachMN(true /* onlyValid */, [&](const CDeterministicMNCPtr& dmn) {
        const bool boot = dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight;
        if (!boot && dmn->pdmnState->confirmedHash.IsNull()) return;
        if (dmn->proTxHash == proTx) found = true;
    });
    return found;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pose_ban_revival_tests, MultiMNFinalitySetup)

// A ban is the FIELD state (nPoSeBanHeight set), not a penalty count — LOT 9 M2
// removed every temporal path that used to move the penalty, so the penalty
// value alone never bans.
BOOST_AUTO_TEST_CASE(penalty_alone_is_not_a_ban)
{
    CDeterministicMNList list = BuildTestMNList(4, 1, operators);
    const uint256 proTx = operators[0].mns[0].proTxHash;
    BOOST_REQUIRE_EQUAL(list.GetValidMNsCount(), 4U);

    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 1; });
    BOOST_CHECK(!list.GetMN(proTx)->IsPoSeBanned());
    MutateState(list, proTx, [](CDeterministicMNState& s){ s.nPoSePenalty = 2; });
    BOOST_CHECK(!list.GetMN(proTx)->IsPoSeBanned());

    // The ban is the banHeight stamp (BanIfNotBanned — key change / revocation /
    // empty-service registration), never a timestamp-derived strike count.
    MutateState(list, proTx, [](CDeterministicMNState& s){ s.BanIfNotBanned(500); });
    BOOST_CHECK(list.GetMN(proTx)->IsPoSeBanned());
    BOOST_CHECK_EQUAL(list.GetValidMNsCount(), 3U);
}

// A banned MN leaves BOTH the schedule's eligible set and the finality operator
// set — that is what "ban from the active set" means.
BOOST_AUTO_TEST_CASE(banned_mn_excluded_from_active_set)
{
    CDeterministicMNList list = BuildTestMNList(4, 1, operators);
    const uint256 proTx = operators[0].mns[0].proTxHash;

    BOOST_CHECK(EligibleContains(list, proTx));
    BOOST_CHECK_EQUAL(hu::GetUniqueOperators(list).size(), 4U);

    MutateState(list, proTx, [](CDeterministicMNState& s){ s.BanIfNotBanned(500); });

    BOOST_CHECK(!EligibleContains(list, proTx));                     // out of production
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
    BOOST_CHECK(EligibleContains(list, proTx));
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

BOOST_AUTO_TEST_SUITE_END()
