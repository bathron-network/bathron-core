// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M4-BIS PHASE 1 — the BOOTSTRAP WINDOW must never fire the fatal latch
// =============================================================================
//
// Found by running the 7-operator laboratory FROM GENESIS with the operator keys
// already loaded — the real launch order, which the M4 run never exercised
// because it distributed the keys after the bootstrap window had been mined.
//
// Every height below the activation anchors on epoch 0, whose snapshot is
// activation-1. While the chain is still inside the bootstrap window that height
// is IN THE FUTURE, and the resolver classified "snapshot above the parent" as
// LOCAL_STATE_MISSING_FATAL — local corruption. It is not corruption: nothing is
// missing, the height simply precedes the schedule. The consequence was measured
// live: every operator daemon fired the LOT 1 latch and shut itself down on its
// first scheduler tick, and -reindex could not repair it because there was
// nothing to rebuild. A launcher would have watched its whole fleet die at
// genesis.
//
// Two levels are pinned here, and a mutant on EITHER must turn this suite red:
//   1. the resolver classifies "snapshot above parent" as DEFERRED, never FATAL;
//   2. the classification still reaches FATAL for a genuinely broken index, so
//      the fix did not neuter the LOT 1 detection it sits next to.

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "sync.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

//! A synthetic chain of `n` linked indexes ending at `topHeight`.
struct SyntheticChain {
    std::vector<CBlockIndex> idx;
    std::vector<uint256> hashes;

    SyntheticChain(int topHeight, int n, uint32_t salt)
    {
        idx.resize(n);
        hashes.resize(n);
        const int bottom = topHeight - n + 1;
        for (int i = 0; i < n; ++i) {
            hashes[i] = ArithToUint256(arith_uint256(salt) + (uint32_t)i);
            idx[i].nHeight = bottom + i;
            idx[i].phashBlock = &hashes[i];
            idx[i].nTime = (unsigned int)(1800000000 + i * 60);
            idx[i].pprev = (i > 0) ? &idx[i - 1] : nullptr;
        }
    }
    CBlockIndex* Top() { return &idx.back(); }
};

mn_consensus::ScheduleStatus Resolve(const CBlockIndex* prev)
{
    mn_consensus::EpochOperatorSets sets;
    LOCK(cs_main);
    return mn_consensus::ResolveEpochOperatorSets(prev, sets);
}

//! Take over chainActive for the duration of a case, restoring the old tip.
struct ActiveChainGuard {
    CBlockIndex* saved{nullptr};
    explicit ActiveChainGuard(CBlockIndex* tip)
    {
        LOCK(cs_main);
        saved = chainActive.Tip();
        chainActive.SetTip(tip);
    }
    ~ActiveChainGuard()
    {
        LOCK(cs_main);
        chainActive.SetTip(saved);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m4bis_bootstrap, TestnetSetup)

// ── The exact live condition: a chain still inside the bootstrap window, its
// parent ON the active chain (the branch that used to select FATAL over
// DEFERRED). The verdict must be DEFERRED — "not judgeable here and now".
BOOST_AUTO_TEST_CASE(inside_the_bootstrap_window_the_resolver_never_fires_the_latch)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int activation = c.DMMScheduleActivationHeight();
    BOOST_REQUIRE_GT(activation, 10);   // testnet ships 251; the case needs room below it

    // Heights 0..8, exactly the laboratory's state after seven registrations.
    SyntheticChain chain(/*topHeight=*/8, /*n=*/9, 0xB00A0000u);
    ActiveChainGuard guard(chain.Top());

    const mn_consensus::ScheduleStatus st = Resolve(chain.Top());
    BOOST_CHECK_MESSAGE(st != mn_consensus::ScheduleStatus::LOCAL_STATE_MISSING_FATAL,
        "a height inside the bootstrap window classified as LOCAL corruption — this is "
        "the defect that shut down every operator daemon at genesis");
    BOOST_CHECK_EQUAL((int)st, (int)mn_consensus::ScheduleStatus::DEFERRED);
}

// ── Every height in the window, not just one sample: the whole bootstrap range
// must be latch-free. A mutant restoring the FATAL branch fails on the first.
BOOST_AUTO_TEST_CASE(the_whole_bootstrap_window_is_latch_free)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int activation = c.DMMScheduleActivationHeight();

    for (int parentHeight : {0, 1, 7, activation / 2, activation - 3, activation - 2}) {
        if (parentHeight < 0) continue;
        SyntheticChain chain(parentHeight, parentHeight + 1, 0xB00B0000u + (uint32_t)parentHeight);
        ActiveChainGuard guard(chain.Top());
        const mn_consensus::ScheduleStatus st = Resolve(chain.Top());
        BOOST_CHECK_MESSAGE(st != mn_consensus::ScheduleStatus::LOCAL_STATE_MISSING_FATAL,
            "parent height " << parentHeight << " (child " << (parentHeight + 1)
            << ", activation " << activation << ") fired the fatal latch");
    }
}

// ── THE FRONTIER. The first scheduled block (height == activation) anchors on
// activation-1 — the LAST BOOTSTRAP BLOCK. So the frontier is exactly reachable:
// one block earlier the snapshot is in the future (DEFERRED above), and here it
// is the parent itself. This is the geometric fact PHASE 1 attacks.
BOOST_AUTO_TEST_CASE(the_first_scheduled_block_anchors_on_the_last_bootstrap_block)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int activation = c.DMMScheduleActivationHeight();

    BOOST_CHECK_EQUAL(mn_consensus::GetEpochSnapshotHeight(activation, activation,
                                                           c.nDMMScheduleEpochLength,
                                                           c.nDMMSetSnapshotDepth),
                      activation - 1);
    // ...and it is the SAME snapshot for every height of the first epoch, which is
    // what makes the set immutable across it (M3.1).
    for (int h : {activation, activation + 1, activation + c.nDMMScheduleEpochLength - 1}) {
        BOOST_CHECK_EQUAL(mn_consensus::GetEpochSnapshotHeight(h, activation,
                                                               c.nDMMScheduleEpochLength,
                                                               c.nDMMSetSnapshotDepth),
                          activation - 1);
    }
}

// ── The LOT 1 detection must still work. A parent above the activation whose
// snapshot ancestor is genuinely unreachable (broken index) is REAL local
// corruption and must still be FATAL. Without this, a mutant that returns
// DEFERRED unconditionally would pass the cases above.
BOOST_AUTO_TEST_CASE(a_genuinely_unreachable_snapshot_is_still_fatal)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int activation = c.DMMScheduleActivationHeight();
    const int parentHeight = activation + 3 * c.nDMMScheduleEpochLength;
    const int snapshot = mn_consensus::GetEpochSnapshotHeight(parentHeight + 1, activation,
                                                              c.nDMMScheduleEpochLength,
                                                              c.nDMMSetSnapshotDepth);
    BOOST_REQUIRE_LT(snapshot, parentHeight);

    // Chain stops ABOVE the snapshot height: the walk runs off a null pprev.
    const int n = parentHeight - snapshot;      // bottom = snapshot + 1
    SyntheticChain chain(parentHeight, n, 0xB00C0000u);
    BOOST_REQUIRE_GT(chain.idx.front().nHeight, snapshot);
    ActiveChainGuard guard(chain.Top());

    BOOST_CHECK_EQUAL((int)Resolve(chain.Top()),
                      (int)mn_consensus::ScheduleStatus::LOCAL_STATE_MISSING_FATAL);
}

BOOST_AUTO_TEST_SUITE_END()
