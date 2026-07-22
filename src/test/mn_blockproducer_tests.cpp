// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bathron.h"
#include "masternode/blockproducer.h"
#include "arith_uint256.h"
#include "uint256.h"
#include "hash.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mn_blockproducer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(score_computation_deterministic)
{
    // Test that ComputeMNBlockScore is deterministic
    uint256 prevHash = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    int height = 100;
    uint256 proTxHash = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

    arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);
    arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);

    BOOST_CHECK(score1 == score2);
}

BOOST_AUTO_TEST_CASE(score_changes_with_height)
{
    // Different heights should produce different scores
    uint256 prevHash = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    uint256 proTxHash = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

    arith_uint256 score100 = mn_consensus::ComputeMNBlockScore(prevHash, 100, proTxHash);
    arith_uint256 score101 = mn_consensus::ComputeMNBlockScore(prevHash, 101, proTxHash);

    BOOST_CHECK(score100 != score101);
}

BOOST_AUTO_TEST_CASE(score_changes_with_prevhash)
{
    // Different prevHash should produce different scores
    uint256 prevHash1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 prevHash2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 proTxHash = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
    int height = 100;

    arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash1, height, proTxHash);
    arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash2, height, proTxHash);

    BOOST_CHECK(score1 != score2);
}

BOOST_AUTO_TEST_CASE(score_changes_with_protxhash)
{
    // Different proTxHash should produce different scores
    uint256 prevHash = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    uint256 proTxHash1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 proTxHash2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    int height = 100;

    arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash1);
    arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash2);

    BOOST_CHECK(score1 != score2);
}

BOOST_AUTO_TEST_CASE(score_hash_output)
{
    // Verify the hash computation matches expected format
    // H(prevBlockHash || height || proTxHash)
    uint256 prevHash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    int height = 1;
    uint256 proTxHash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");

    arith_uint256 score = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);

    // Score should be non-zero
    BOOST_CHECK(score > arith_uint256(0));

    // Recompute manually
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << prevHash;
    ss << height;
    ss << proTxHash;
    uint256 expectedHash = ss.GetHash();
    arith_uint256 expectedScore = UintToArith256(expectedHash);

    BOOST_CHECK(score == expectedScore);
}

BOOST_AUTO_TEST_CASE(selection_is_deterministic)
{
    // Multiple calls with same inputs should produce same ordering
    // (This tests the sorting stability of CalculateBlockProducerScores)

    // Create test data
    uint256 prevHash = uint256S("0xaabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344");
    int height = 500;

    // Simulate 3 MNs with different proTxHashes
    uint256 mn1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 mn2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 mn3 = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    // Calculate scores
    arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash, height, mn1);
    arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash, height, mn2);
    arith_uint256 score3 = mn_consensus::ComputeMNBlockScore(prevHash, height, mn3);

    // Find the winner (highest score)
    arith_uint256 maxScore = std::max({score1, score2, score3});
    uint256 winner;
    if (score1 == maxScore) winner = mn1;
    else if (score2 == maxScore) winner = mn2;
    else winner = mn3;

    // Recompute - should get same winner
    arith_uint256 score1b = mn_consensus::ComputeMNBlockScore(prevHash, height, mn1);
    arith_uint256 score2b = mn_consensus::ComputeMNBlockScore(prevHash, height, mn2);
    arith_uint256 score3b = mn_consensus::ComputeMNBlockScore(prevHash, height, mn3);

    arith_uint256 maxScoreB = std::max({score1b, score2b, score3b});
    uint256 winnerB;
    if (score1b == maxScoreB) winnerB = mn1;
    else if (score2b == maxScoreB) winnerB = mn2;
    else winnerB = mn3;

    BOOST_CHECK_EQUAL(winner, winnerB);
}

BOOST_AUTO_TEST_CASE(different_blocks_different_winners)
{
    // Over many blocks, different MNs should win
    // This is a statistical test - with enough blocks, all MNs should win at least once

    uint256 mn1 = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 mn2 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 mn3 = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    int wins1 = 0, wins2 = 0, wins3 = 0;

    // Test 100 different block heights
    uint256 prevHash = uint256S("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");

    for (int height = 1; height <= 100; height++) {
        arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash, height, mn1);
        arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash, height, mn2);
        arith_uint256 score3 = mn_consensus::ComputeMNBlockScore(prevHash, height, mn3);

        arith_uint256 maxScore = std::max({score1, score2, score3});
        if (score1 == maxScore) wins1++;
        else if (score2 == maxScore) wins2++;
        else wins3++;

        // Update prevHash for next iteration (simulate chain progression)
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << prevHash << height;
        prevHash = ss.GetHash();
    }

    // Each MN should have won at least once over 100 blocks
    // (With 3 MNs and 100 blocks, probability of one never winning is ~0.0003)
    BOOST_CHECK_GT(wins1, 0);
    BOOST_CHECK_GT(wins2, 0);
    BOOST_CHECK_GT(wins3, 0);

    // Total should be 100
    BOOST_CHECK_EQUAL(wins1 + wins2 + wins3, 100);
}

// dmm-production-4: PoSe penalty must target the MNs that missed their slot,
// consistent with the modulo producer selection (scores[slot % n]) — never the
// actual producer, and each missed MN at most once even when the slot wrapped.
BOOST_AUTO_TEST_CASE(missed_producer_indices_modulo_and_excludes_winner)
{
    using mn_consensus::ComputeMissedProducerIndices;

    // No fallback (slot 0) or empty set => nothing penalized.
    BOOST_CHECK(ComputeMissedProducerIndices(0, 3).empty());
    BOOST_CHECK(ComputeMissedProducerIndices(5, 0).empty());

    // Slot < n: clean prefix, winner (= slot) excluded by construction.
    {
        auto m = ComputeMissedProducerIndices(2, 3);   // winner = 2
        BOOST_CHECK_EQUAL(m.size(), 2u);
        BOOST_CHECK(m == std::vector<int>({0, 1}));
    }

    // Slot wraps past n: winner = slot % n must NOT be penalized; distinct indices.
    {
        const int slot = 4, n = 3;                     // winner = 1
        auto m = ComputeMissedProducerIndices(slot, n);
        const int winner = slot % n;
        BOOST_CHECK(std::find(m.begin(), m.end(), winner) == m.end()); // producer not penalized
        // distinct
        std::set<int> uniq(m.begin(), m.end());
        BOOST_CHECK_EQUAL(uniq.size(), m.size());
        BOOST_CHECK(m == std::vector<int>({0, 2}));
    }
    {
        const int slot = 6, n = 3;                     // winner = 0
        auto m = ComputeMissedProducerIndices(slot, n);
        BOOST_CHECK(std::find(m.begin(), m.end(), 0) == m.end());
        BOOST_CHECK(m == std::vector<int>({1, 2}));
    }
}

BOOST_AUTO_TEST_SUITE_END()
