// Copyright (c) 2014 The Bitcoin Core developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2021 The BATHRON Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bathron.h"

#include "net/net.h"         // CombinerAll
#include "validation.h"  // GetBlockValue

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

// =============================================================================
// REMOVED: block_signature_test (legacy PoS staking signature test)
// HU Chain uses DMM (Deterministic Masternode Mining), not PoS
// =============================================================================

// =============================================================================
// HU Chain: Block Reward Test
// =============================================================================
// HU economics: No block rewards on mainnet. Economy via BTC burn-to-mint.
// GetBlockValue() returns 0 for mainnet (this test uses mainnet params by default)

BOOST_AUTO_TEST_CASE(hu_block_reward_zero_test)
{
    // HU Chain: Block reward = 0 for all heights on mainnet
    // TestingSetup uses CBaseChainParams::MAIN by default

    // Block 0 (genesis) has no reward
    BOOST_CHECK_EQUAL(GetBlockValue(0), 0);

    // All blocks have 0 reward on mainnet
    for (int nHeight = 1; nHeight <= 1000; nHeight++) {
        CAmount nSubsidy = GetBlockValue(nHeight);
        BOOST_CHECK_EQUAL(nSubsidy, 0);
    }

    // Very high blocks also have 0 reward
    BOOST_CHECK_EQUAL(GetBlockValue(100000), 0);
    BOOST_CHECK_EQUAL(GetBlockValue(1000000), 0);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool(), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}

BOOST_AUTO_TEST_SUITE_END()
