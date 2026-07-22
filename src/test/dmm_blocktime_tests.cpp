// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// dmm-production-1: CheckBlockTime must enforce a lower bound on the block
// timestamp (median-time-past), so a producer cannot sign a non-monotonic /
// backdated block that all nodes would accept (which corrupts the DMM slot math
// and time-based locks). The old "time-too-old" check was dropped for DMM; this
// verifies the BIP113-style median-time-past replacement.

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>
#include <vector>

// CheckBlockTime has external linkage but is not declared in validation.h.
bool CheckBlockTime(const CBlockHeader& block, CValidationState& state, CBlockIndex* const pindexPrev);

BOOST_FIXTURE_TEST_SUITE(dmm_blocktime_tests, TestnetSetup)

BOOST_AUTO_TEST_CASE(block_time_must_exceed_median_time_past)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int64_t slot = consensus.nTimeSlotLength > 0 ? (int64_t)consensus.nTimeSlotLength : 60;

    // Heights well past the bootstrap phase so the relaxed bootstrap branch is not
    // taken; slot-aligned times in the past so the future-drift and time-mask
    // checks both pass and only the median-time-past lower bound is exercised.
    const int baseHeight = 1'000'000;
    const int64_t baseTime = (1700000000 / slot) * slot;

    std::vector<CBlockIndex> chain(12);
    for (int i = 0; i < 12; ++i) {
        chain[i].nHeight = baseHeight + i;
        chain[i].nTime = (uint32_t)(baseTime + (int64_t)i * slot);
        chain[i].pprev = (i == 0) ? nullptr : &chain[i - 1];
    }
    CBlockIndex* prev = &chain[11];
    const int64_t mtp = prev->GetMedianTimePast();

    auto makeBlock = [](int64_t t) {
        CBlockHeader b;
        b.nTime = (uint32_t)t;
        return b;
    };

    // A timestamp at or below median-time-past is rejected.
    {
        CValidationState st;
        BOOST_CHECK(!CheckBlockTime(makeBlock(mtp), st, prev));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "time-too-old");
    }
    // A forward-moving, slot-aligned timestamp (in the past, so not future) passes.
    {
        CValidationState st;
        BOOST_CHECK(CheckBlockTime(makeBlock((int64_t)prev->nTime + slot), st, prev));
    }
}

BOOST_AUTO_TEST_SUITE_END()
