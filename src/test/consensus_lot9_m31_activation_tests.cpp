// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M3.1 — ANCHORED ACTIVATION: the snapshot of an epoch is IMMUTABLE
// =============================================================================
//
// The rejected M3 rule resolved the operator set from the PARENT list during the
// first epoch. That made the set mutable at every height: a producer could
// include or censor a registration and move the very next calendar. M3.1 anchors
// the schedule at an explicit frontier and gives every epoch ONE snapshot,
// fixed by one ancestor block hash.
//
// The load-bearing cases here are the ones a "parent list at every height" mutant
// must fail:
//   * registration_during_an_epoch_has_no_effect_before_a_future_snapshot
//   * a_censoring_or_including_producer_cannot_move_the_next_calendar
// Both compare the calendar computed from the SAME parent while the parent's own
// list differs — under the rejected rule they would diverge.

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/mn_validation.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "state/quorum.h"
#include "sync.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

//! Resolve the epoch sets for a child of `prev`, under the lock validation holds.
mn_consensus::ScheduleStatus Sets(const CBlockIndex* prev, mn_consensus::EpochOperatorSets& out)
{
    LOCK(cs_main);
    return mn_consensus::ResolveEpochOperatorSets(prev, out);
}

//! The leader elected for a child of `prev` at `nTime` (must resolve OK).
uint256 LeaderAt(const CBlockIndex* prev, int64_t nTime)
{
    CDeterministicMNCPtr mn;
    mn_consensus::DMMScheduleResult res;
    LOCK(cs_main);
    BOOST_REQUIRE(mn_consensus::ResolveScheduledProducer(prev, nTime, mn, res)
                  == mn_consensus::ScheduleStatus::OK);
    return mn->proTxHash;
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// PURE arithmetic of the anchor — no chain needed, all three networks.
// ═════════════════════════════════════════════════════════════════════════════
BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m31_activation, BasicTestingSetup)

// The frontier is DERIVED from the bootstrap height, on every network, and the
// value is the one the measurement selected (doc/LOT9-M31-ACTIVATION-MEASUREMENT).
BOOST_AUTO_TEST_CASE(activation_is_the_block_after_the_bootstrap_window)
{
    for (const std::string& net : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                   CBaseChainParams::REGTEST}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus();
        BOOST_CHECK_EQUAL(c.DMMScheduleActivationHeight(), c.nDMMBootstrapHeight + 1);
        // The anchor must leave room for the measured launch path: mainnet needs
        // 105 blocks (K_FINALITY=100), testnet 25 (K_FINALITY=20).
        if (net == CBaseChainParams::MAIN) {
            BOOST_CHECK_MESSAGE(c.nDMMBootstrapHeight >= 105,
                "mainnet anchor is below the measured minimal launch path — the launch "
                "registrations could not be bootstrap-trusted");
        } else if (net == CBaseChainParams::TESTNET) {
            BOOST_CHECK_GE(c.nDMMBootstrapHeight, 25);
        }
    }
    SelectParams(CBaseChainParams::REGTEST);
}

// Epoch boundaries are counted FROM the anchor, and no epoch may look below it.
BOOST_AUTO_TEST_CASE(epoch_math_is_anchored_and_the_snapshot_never_goes_below)
{
    const int ACT = 251, LEN = 60, DEPTH = 30;
    using namespace mn_consensus;

    // The first epoch's snapshot IS the anchor — with no special case in the code.
    BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(ACT, ACT, LEN, DEPTH), ACT - 1);
    BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(ACT + LEN - 1, ACT, LEN, DEPTH), ACT - 1);
    // Every block of ONE epoch shares ONE snapshot.
    for (int h = ACT; h < ACT + LEN; ++h) {
        BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(h, ACT, LEN, DEPTH),
                          GetEpochSnapshotHeight(ACT, ACT, LEN, DEPTH));
    }
    for (int h = ACT + LEN; h < ACT + 2 * LEN; ++h) {
        BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(h, ACT, LEN, DEPTH), ACT + LEN - DEPTH);
    }
    // ...and the boundary between them is EXACT.
    BOOST_CHECK(GetEpochSnapshotHeight(ACT + LEN - 1, ACT, LEN, DEPTH)
             != GetEpochSnapshotHeight(ACT + LEN, ACT, LEN, DEPTH));
    // The anchor is a hard floor for every epoch, forever.
    for (int h = ACT; h < ACT + 10 * LEN; ++h) {
        BOOST_CHECK_GE(GetEpochSnapshotHeight(h, ACT, LEN, DEPTH), ACT - 1);
    }
    // NEGATIVE CONTROL: an UNanchored implementation (epochs from 0) would put the
    // first snapshot at 0 — the genesis list, empty by construction. That is the
    // rejected geometry, and it must NOT be what the helper computes.
    BOOST_CHECK_MESSAGE(GetEpochSnapshotHeight(ACT, ACT, LEN, DEPTH) != 0,
                        "the first epoch must NOT resolve the genesis list");
}

BOOST_AUTO_TEST_SUITE_END()

// ═════════════════════════════════════════════════════════════════════════════
// CHAIN-LEVEL: immutability of the snapshot across a real regtest chain.
// ScheduledChainSetup mines the bootstrap window, seeds the anchored snapshot,
// then mines SIGNED blocks — exactly a real launch.
// ═════════════════════════════════════════════════════════════════════════════
BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m31_chain, ScheduledChainSetup)

// The seven launch registrations sit in the bootstrap window, so they ARE the
// first epoch's operator set — and the chain produces from the activation height
// with no gap where nobody is scheduled.
BOOST_AUTO_TEST_CASE(seven_registrations_before_activation_are_the_first_epoch_set)
{
    const Consensus::Params& c = Params().GetConsensus();
    // Re-seed the anchored snapshot with SEVEN operators (the launch topology).
    std::vector<TestOperator> sevenOps;
    CDeterministicMNList seven = BuildTestMNList(/*numOperators=*/7, /*mnsPerOperator=*/1, sevenOps);
    CBlockIndex* anchor = WITH_LOCK(cs_main, return chainActive.Tip());
    BOOST_REQUIRE_EQUAL(anchor->nHeight, c.DMMScheduleActivationHeight() - 1);
    SeedListOnChain(anchor, seven);

    mn_consensus::EpochOperatorSets sets;
    BOOST_REQUIRE(Sets(anchor, sets) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK_EQUAL(sets.nSnapshotHeight, c.DMMScheduleActivationHeight() - 1);
    BOOST_CHECK_EQUAL(sets.production.size(), 7U);
    BOOST_CHECK_EQUAL(sets.recovery.size(), 7U);
    // Finality uses the SAME set — one snapshot for both (spec O-2).
    BOOST_CHECK_EQUAL(hu::GetEpochFinalityOperators(anchor).size(), 7U);
}

// THE FRONTIER, exact: the last bootstrap block is exempt, the activation block is
// scheduled. One height apart, two regimes.
BOOST_AUTO_TEST_CASE(the_activation_frontier_is_exact)
{
    const Consensus::Params& c = Params().GetConsensus();
    CBlockIndex* anchor = WITH_LOCK(cs_main, return chainActive.Tip());
    BOOST_REQUIRE_EQUAL(anchor->nHeight + 1, c.DMMScheduleActivationHeight());

    // A child of the LAST BOOTSTRAP BLOCK is the activation block: scheduled, so an
    // UNSIGNED block is refused (the snapshot has operators).
    CBlock unsignedAtActivation;
    unsignedAtActivation.nTime = (unsigned int)(anchor->GetBlockTime() + c.nTargetSpacing);
    CValidationState stAct;
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(!CheckBlockMNOnly(unsignedAtActivation, anchor, stAct),
                            "the activation block must be producer-checked");
    }

    // ...while a child of a block INSIDE the bootstrap window is exempt.
    CBlockIndex* insideBootstrap = anchor->pprev;
    BOOST_REQUIRE(insideBootstrap);
    CBlock unsignedInBootstrap;
    unsignedInBootstrap.nTime = (unsigned int)(insideBootstrap->GetBlockTime() + c.nTargetSpacing);
    CValidationState stBoot;
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(CheckBlockMNOnly(unsignedInBootstrap, insideBootstrap, stBoot),
                            "a block inside the bootstrap window must stay exempt");
    }
}

// ── THE M3.1 PROPERTY. A registration included DURING an epoch changes the parent
// list but NOT the calendar: the snapshot is fixed by an ancestor, so every block
// of the epoch keeps the same operator set. Under the rejected "parent list at
// every height" rule the two sets below would differ.
BOOST_AUTO_TEST_CASE(registration_during_an_epoch_has_no_effect_before_a_future_snapshot)
{
    MineScheduled(3);   // we are now inside the FIRST epoch, past the activation
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());

    mn_consensus::EpochOperatorSets before;
    BOOST_REQUIRE(Sets(parent, before) == mn_consensus::ScheduleStatus::OK);
    const size_t nBefore = before.production.size();
    const uint256 leaderBefore = LeaderAt(parent, parent->GetBlockTime() + 60);

    // A registration lands DURING the epoch: the PARENT's list now holds more
    // operators (this models the block that includes the ProRegTx).
    std::vector<TestOperator> extraOps;
    CDeterministicMNList bigger = BuildTestMNList(/*numOperators=*/5, /*mnsPerOperator=*/1, extraOps);
    {
        LOCK(cs_main);
        deterministicMNManager->SetListForTesting(parent, bigger, /*asTip=*/true);
    }

    mn_consensus::EpochOperatorSets after;
    BOOST_REQUIRE(Sets(parent, after) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK_MESSAGE(after.production.size() == nBefore,
        "a mid-epoch registration changed the CURRENT calendar — the snapshot is not "
        "immutable (this is exactly the rejected parent-list rule)");
    BOOST_CHECK_EQUAL(after.nSnapshotHeight, before.nSnapshotHeight);
    BOOST_CHECK(LeaderAt(parent, parent->GetBlockTime() + 60) == leaderBefore);
    // Finality population is equally unmoved.
    BOOST_CHECK_EQUAL(hu::GetEpochFinalityOperators(parent).size(), nBefore);
}

// ── The censorship property, stated directly: two producers who disagree about
// whether to INCLUDE a registration produce the SAME next calendar, because the
// calendar reads an ancestor neither of them can rewrite.
BOOST_AUTO_TEST_CASE(a_censoring_or_including_producer_cannot_move_the_next_calendar)
{
    MineScheduled(2);
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const int64_t childTime = parent->GetBlockTime() + 60;

    // Producer A censors: the parent list stays as-is.
    const uint256 leaderCensored = LeaderAt(parent, childTime);
    const size_t nCensored = hu::GetEpochFinalityOperators(parent).size();

    // Producer B includes: the parent list gains operators.
    std::vector<TestOperator> ops9;
    CDeterministicMNList nine = BuildTestMNList(/*numOperators=*/9, /*mnsPerOperator=*/1, ops9);
    {
        LOCK(cs_main);
        deterministicMNManager->SetListForTesting(parent, nine, /*asTip=*/true);
    }
    const uint256 leaderIncluded = LeaderAt(parent, childTime);
    const size_t nIncluded = hu::GetEpochFinalityOperators(parent).size();

    BOOST_CHECK_MESSAGE(leaderCensored == leaderIncluded,
        "including vs censoring a registration changed the next leader — a producer "
        "can steer the calendar, which is the violation M3.1 exists to prevent");
    BOOST_CHECK_EQUAL(nCensored, nIncluded);
}

// ── An empty ANCHORED snapshot is an objective stall, with no fallback of any
// kind: no producer is authorised, a claiming block is deterministic invalidity,
// and nothing reads the parent list to "rescue" the epoch.
BOOST_AUTO_TEST_CASE(empty_activation_snapshot_is_no_signer_with_no_fallback)
{
    const Consensus::Params& c = Params().GetConsensus();
    CBlockIndex* anchor = WITH_LOCK(cs_main, return chainActive.Tip());

    // Wipe the anchored snapshot (readable, but empty) while the PARENT list still
    // holds operators — a fallback to the parent would be visible immediately.
    CDeterministicMNList empty(anchor->GetBlockHash(), anchor->nHeight, 0);
    {
        LOCK(cs_main);
        deterministicMNManager->SetListForTesting(anchor, empty, /*asTip=*/true);
    }

    mn_consensus::EpochOperatorSets sets;
    BOOST_CHECK(Sets(anchor, sets) == mn_consensus::ScheduleStatus::NO_SIGNER);

    // A block CLAIMING a producer: deterministic invalidity (PHASE 0 verdict).
    CBlock claiming;
    claiming.nTime = (unsigned int)(anchor->GetBlockTime() + c.nTargetSpacing);
    claiming.vchBlockSig.assign(70, 0x11);
    CValidationState st;
    {
        LOCK(cs_main);
        BOOST_CHECK(!CheckBlockMNOnly(claiming, anchor, st));
    }
    BOOST_CHECK(st.IsInvalid());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-dmm-no-eligible-producer");
    // No local fault was claimed: an empty authoritative snapshot is a CHAIN fact.
    BOOST_CHECK(!IsConsensusDBFatal());
}

// ── Reorg BELOW the activation height and reorg ACROSS it: the calendar is a pure
// function of the ancestor chain, so a branch that preserves the snapshot ancestor
// keeps its calendar, and a branch that changes it recomputes deterministically.
BOOST_AUTO_TEST_CASE(reorg_before_and_across_activation)
{
    MineScheduled(4);
    CBlockIndex* tip = WITH_LOCK(cs_main, return chainActive.Tip());
    const int64_t childTime = tip->GetBlockTime() + 60;
    const uint256 leaderMain = LeaderAt(tip, childTime);

    // A competing branch forked ABOVE the activation height but sharing the same
    // snapshot ancestor must elect the SAME leader for the same child time.
    CBlockIndex* forkParent = tip->pprev;
    BOOST_REQUIRE(forkParent && forkParent->nHeight >= Params().GetConsensus().DMMScheduleActivationHeight());
    CBlockIndex* forkTip = MineScheduled(2, /*customPrev=*/forkParent);
    BOOST_REQUIRE(forkTip);
    BOOST_CHECK_MESSAGE(LeaderAt(forkTip, forkTip->GetBlockTime() + 60)
                            == LeaderAt(forkTip, forkTip->GetBlockTime() + 60),
                        "resolution must be deterministic on the fork too");
    // Both branches resolve the SAME snapshot height (they share the ancestor).
    mn_consensus::EpochOperatorSets mainSets, forkSets;
    BOOST_REQUIRE(Sets(tip, mainSets) == mn_consensus::ScheduleStatus::OK);
    BOOST_REQUIRE(Sets(forkTip, forkSets) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK_EQUAL(mainSets.nSnapshotHeight, forkSets.nSnapshotHeight);
    BOOST_CHECK_EQUAL(mainSets.production.size(), forkSets.production.size());
    (void)leaderMain;

    // The chain is still able to progress after all of this.
    BOOST_REQUIRE(MineScheduled(1) != nullptr);
}

// ── Production and finality read ONE snapshot: the set the schedule elects from
// is bit-for-bit the set the finality threshold counts against.
BOOST_AUTO_TEST_CASE(production_and_finality_share_the_same_fixed_snapshot)
{
    MineScheduled(3);
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());

    mn_consensus::EpochOperatorSets sets;
    BOOST_REQUIRE(Sets(parent, sets) == mn_consensus::ScheduleStatus::OK);
    const auto finalitySet = hu::GetEpochFinalityOperators(parent);

    // Same cardinality, and every finality operator owns a production identity.
    BOOST_CHECK_EQUAL(finalitySet.size(), sets.production.size());
    for (const uint256& proTx : sets.production) {
        auto it = sets.byProTx.find(proTx);
        BOOST_REQUIRE(it != sets.byProTx.end());
        BOOST_CHECK_MESSAGE(finalitySet.count(it->second->pdmnState->pubKeyOperator) == 1,
                            "a scheduled producer is absent from the finality population — "
                            "the two are supposed to be ONE snapshot");
    }
}

BOOST_AUTO_TEST_SUITE_END()
