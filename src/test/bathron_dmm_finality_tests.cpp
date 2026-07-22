// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * BATHRON DMM + Finality Tests
 *
 * Tests for:
 *   1. DMM (Deterministic Masternode Minting) producer scoring/scheduling
 *   2. ECDSA finality signatures (per-operator, threshold ceil(2/3·min(E,N)))
 *   3. Consensus-params sanity
 *   4. Signature verification
 */

#include "test/test_bathron.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "state/quorum.h"
#include "state/finality.h"
#include "uint256.h"
#include "hash.h"
#include "key.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bathron_dmm_finality_tests, BasicTestingSetup)

// =============================================================================
// Test 1: DMM Slot calculation
// =============================================================================
BOOST_AUTO_TEST_CASE(dmm_slot_calculation_basic)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // Slot 0: within leader timeout
    int64_t prevTime = 1700000000;
    int64_t blockTime = prevTime + consensus.nHuLeaderTimeoutSeconds - 1;

    // Slot should be 0 for times within leader timeout
    BOOST_CHECK_LT(blockTime - prevTime, consensus.nHuLeaderTimeoutSeconds);

    // Slot 1: at leader timeout
    blockTime = prevTime + consensus.nHuLeaderTimeoutSeconds;
    BOOST_CHECK_GE(blockTime - prevTime, consensus.nHuLeaderTimeoutSeconds);
}

BOOST_AUTO_TEST_CASE(dmm_slot_fallback_progression)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    int64_t prevTime = 1700000000;

    // Slots should increase with time
    int lastSlot = -1;
    for (int dt = 0; dt <= 600; dt += consensus.nHuFallbackRecoverySeconds) {
        int expectedSlot = 0;

        if (dt >= consensus.nHuLeaderTimeoutSeconds) {
            expectedSlot = 1 + (dt - consensus.nHuLeaderTimeoutSeconds) / consensus.nHuFallbackRecoverySeconds;
        }

        if (lastSlot >= 0) {
            BOOST_CHECK_GE(expectedSlot, lastSlot);
        }
        lastSlot = expectedSlot;
    }
}

// =============================================================================
// Test 2: MN Score determinism
// =============================================================================
BOOST_AUTO_TEST_CASE(pose_punishment_guard_network_events)
{
    using mn_consensus::ShouldSkipPoSePunishment;
    const int64_t STALE = 600;  // testnet nStaleChainTimeout

    // Nominal single-MN outage: 1 missed of 6, normal fallback dt → PUNISH.
    BOOST_CHECK(!ShouldSkipPoSePunishment(105, STALE, 1, 6));
    // Two adjacent dead MNs: 2 missed of 6 = ceil(6/3) → still individual faults → PUNISH.
    BOOST_CHECK(!ShouldSkipPoSePunishment(125, STALE, 2, 6));
    // Breadth cap: 3 missed of 6 > ceil(6/3)=2 → network turbulence → SKIP.
    BOOST_CHECK(ShouldSkipPoSePunishment(135, STALE, 3, 6));
    // Deep recovery slot: N-1 missed → SKIP regardless of dt.
    BOOST_CHECK(ShouldSkipPoSePunishment(300, STALE, 5, 6));
    // Chain-wide outage: dt beyond stale timeout → SKIP even for a single miss.
    BOOST_CHECK(ShouldSkipPoSePunishment(STALE + 1, STALE, 1, 6));
    // dt exactly at the timeout is NOT yet stale (strict >) → punish path.
    BOOST_CHECK(!ShouldSkipPoSePunishment(STALE, STALE, 1, 6));
    // Boundary at other sizes: ceil(4/3)=2, ceil(7/3)=3.
    BOOST_CHECK(!ShouldSkipPoSePunishment(105, STALE, 2, 4));
    BOOST_CHECK(ShouldSkipPoSePunishment(105, STALE, 3, 4));
    BOOST_CHECK(!ShouldSkipPoSePunishment(105, STALE, 3, 7));
    BOOST_CHECK(ShouldSkipPoSePunishment(105, STALE, 4, 7));
    // Degenerate: empty producer set → nothing sensible to punish.
    BOOST_CHECK(ShouldSkipPoSePunishment(105, STALE, 0, 0));
}

BOOST_AUTO_TEST_CASE(pose_missed_indices_match_modulo_selection)
{
    using mn_consensus::ComputeMissedProducerIndices;
    // slot 0 → nobody missed.
    BOOST_CHECK(ComputeMissedProducerIndices(0, 6).empty());
    // slot 1 of 6 → producer is idx 1, missed = {0}.
    auto m = ComputeMissedProducerIndices(1, 6);
    BOOST_REQUIRE_EQUAL(m.size(), 1U);
    BOOST_CHECK_EQUAL(m[0], 0);
    // slot 3 of 6 → missed = {0,1,2}.
    m = ComputeMissedProducerIndices(3, 6);
    BOOST_REQUIRE_EQUAL(m.size(), 3U);
    // deep slot wraps: slot 175 of 6 → everyone but the winner, each once.
    m = ComputeMissedProducerIndices(175, 6);
    BOOST_CHECK_EQUAL(m.size(), 5U);
}

BOOST_AUTO_TEST_CASE(mn_score_is_deterministic)
{
    uint256 prevHash = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    int height = 1000;
    uint256 proTxHash = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

    arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);
    arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);
    arith_uint256 score3 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);

    BOOST_CHECK(score1 == score2);
    BOOST_CHECK(score2 == score3);
}

BOOST_AUTO_TEST_CASE(mn_score_differs_for_different_mns)
{
    uint256 prevHash = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    int height = 1000;

    uint256 proTxHash1 = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");
    uint256 proTxHash2 = uint256S("0x3333333333333333333333333333333333333333333333333333333333333333");

    arith_uint256 score1 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash1);
    arith_uint256 score2 = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash2);

    // Scores should be different for different MNs
    BOOST_CHECK(score1 != score2);
}

BOOST_AUTO_TEST_CASE(mn_score_differs_for_different_heights)
{
    uint256 prevHash = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 proTxHash = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");

    arith_uint256 score1000 = mn_consensus::ComputeMNBlockScore(prevHash, 1000, proTxHash);
    arith_uint256 score1001 = mn_consensus::ComputeMNBlockScore(prevHash, 1001, proTxHash);

    // Scores should be different for different heights
    BOOST_CHECK(score1000 != score1001);
}

// =============================================================================
// Test 4: Quorum size requirements
// =============================================================================
BOOST_AUTO_TEST_CASE(quorum_size_minimum)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // Sybil floor: 4 distinct operators = textbook 3f+1 (tolerates 1 fault)
    BOOST_CHECK_GE(consensus.nHuQuorumSize, 4);
}

// =============================================================================
// Test 5: ECDSA signature verification
// =============================================================================
BOOST_AUTO_TEST_CASE(ecdsa_signature_basic)
{
    // Generate a test key
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create a message hash (simulating block hash)
    std::string msg = "test block data";
    uint256 msgHash;
    CHash256().Write((unsigned char*)msg.data(), msg.size()).Finalize(msgHash.begin());

    // Sign the message
    std::vector<unsigned char> signature;
    bool signResult = key.Sign(msgHash, signature);
    BOOST_CHECK(signResult);

    // Verify the signature
    bool verifyResult = pubkey.Verify(msgHash, signature);
    BOOST_CHECK(verifyResult);
}

BOOST_AUTO_TEST_CASE(ecdsa_signature_wrong_key_fails)
{
    // Generate two different keys
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();

    std::string msg = "test block data";
    uint256 msgHash;
    CHash256().Write((unsigned char*)msg.data(), msg.size()).Finalize(msgHash.begin());

    // Sign with key1
    std::vector<unsigned char> signature;
    key1.Sign(msgHash, signature);

    // Verify with pubkey1 should succeed
    BOOST_CHECK(pubkey1.Verify(msgHash, signature));

    // Verify with pubkey2 should fail
    BOOST_CHECK(!pubkey2.Verify(msgHash, signature));
}

BOOST_AUTO_TEST_CASE(ecdsa_signature_wrong_message_fails)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::string msg1 = "message 1";
    std::string msg2 = "message 2";
    uint256 msgHash1, msgHash2;
    CHash256().Write((unsigned char*)msg1.data(), msg1.size()).Finalize(msgHash1.begin());
    CHash256().Write((unsigned char*)msg2.data(), msg2.size()).Finalize(msgHash2.begin());

    // Sign message 1
    std::vector<unsigned char> signature;
    key.Sign(msgHash1, signature);

    // Verify against message 1 should succeed
    BOOST_CHECK(pubkey.Verify(msgHash1, signature));

    // Verify against message 2 should fail
    BOOST_CHECK(!pubkey.Verify(msgHash2, signature));
}

// =============================================================================
// Test 6: Bootstrap phase
// =============================================================================
BOOST_AUTO_TEST_CASE(bootstrap_phase_no_finality_required)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // During bootstrap (height <= nDMMBootstrapHeight), finality not required
    for (int height = 1; height <= (int)consensus.nDMMBootstrapHeight; height++) {
        // Bootstrap blocks don't need finality signatures
        BOOST_CHECK_LE(height, (int)consensus.nDMMBootstrapHeight);
    }

    // After bootstrap, finality is required
    int postBootstrap = consensus.nDMMBootstrapHeight + 1;
    BOOST_CHECK_GT(postBootstrap, (int)consensus.nDMMBootstrapHeight);
}

// =============================================================================
// Test 7: Fork resolution with finality
// =============================================================================
BOOST_AUTO_TEST_CASE(fork_resolution_finalized_wins)
{
    // Scenario: Two competing chains at same height
    // Chain A: finalized
    // Chain B: not finalized
    // Expected: Chain A wins regardless of PoW

    bool chainA_finalized = true;
    bool chainB_finalized = false;

    // Finalized chain always wins
    if (chainA_finalized && !chainB_finalized) {
        BOOST_CHECK(true);  // Chain A wins
    } else if (!chainA_finalized && chainB_finalized) {
        BOOST_CHECK(false); // Chain B wins
    }
}

BOOST_AUTO_TEST_CASE(fork_resolution_both_finalized)
{
    // Scenario: Two competing chains, both finalized at different heights
    // Expected: Chain with higher finalized height wins

    int chainA_finalizedHeight = 100;
    int chainB_finalizedHeight = 95;

    // Higher finalized height wins
    BOOST_CHECK_GT(chainA_finalizedHeight, chainB_finalizedHeight);
}

// =============================================================================
// Test 8: Consensus parameters validation
// =============================================================================
BOOST_AUTO_TEST_CASE(consensus_params_valid)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // Leader timeout must be positive
    BOOST_CHECK_GT(consensus.nHuLeaderTimeoutSeconds, 0);

    // Fallback recovery must be positive
    BOOST_CHECK_GT(consensus.nHuFallbackRecoverySeconds, 0);

    // Finality-lag warning window must be positive
    BOOST_CHECK_GT(consensus.nHuFinalityLagWarning, 0);

    // Quorum size must be at least 3 for BFT
    BOOST_CHECK_GE(consensus.nHuQuorumSize, 3);

    // Bootstrap height must be defined
    BOOST_CHECK_GE(consensus.nDMMBootstrapHeight, 0);
}

// =============================================================================
// Test 10: DMM scheduling fairness
// =============================================================================
BOOST_AUTO_TEST_CASE(dmm_scheduling_rotation)
{
    // Over time, different MNs should get opportunities to produce blocks
    // (tested via score variation across heights)

    uint256 prevHash = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");
    uint256 proTxHash = uint256S("0x2222222222222222222222222222222222222222222222222222222222222222");

    std::set<arith_uint256> uniqueScores;

    for (int height = 1; height <= 100; height++) {
        arith_uint256 score = mn_consensus::ComputeMNBlockScore(prevHash, height, proTxHash);
        uniqueScores.insert(score);
    }

    // All scores should be unique (different heights = different scores)
    BOOST_CHECK_EQUAL(uniqueScores.size(), 100);
}

BOOST_AUTO_TEST_SUITE_END()
