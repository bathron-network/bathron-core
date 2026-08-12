// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M1 — non-grindable DMM schedule: proofs
// =============================================================================
//
// HARD RULE observed here: no consensus test depends on a real sleep. Time is an
// INPUT to pure functions, so every temporal boundary is asserted exactly rather
// than waited for.
//
// Every case carries a negative control or a named mutant, so a case that stopped
// biting fails loudly instead of passing vacuously.

#include "test/test_bathron.h"

#include "chainparams.h"
#include "consensus/params.h"
#include "hash.h"
#include "masternode/blockproducer.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using namespace mn_consensus;

namespace {

std::vector<uint256> MakeOps(size_t n, const char* tag = "op")
{
    std::vector<uint256> ops;
    ops.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string(tag);
        ss << (uint32_t)i;
        ops.push_back(ss.GetHash());
    }
    return ops;
}

const uint256 GENESIS = uint256S("0x00000000000000000000000000000000000000000000000000000000deadbeef");
const int EPOCH = 60;
//! LOT 9 M3.1 — the schedule anchor these pure cases run against. A non-trivial
//! value (not 0, not 1) so an implementation that ignored the activation would
//! give visibly different epoch/snapshot arithmetic.
const int ACTIVATION = 251;

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m1_schedule, BasicTestingSetup)

// ── D.16b — the TWO timing invariants, per network. I1 is not redundant with I2:
// crossing the FIRST boundary costs leaderTimeout, not the recovery window.
BOOST_AUTO_TEST_CASE(timing_invariants_hold_on_every_network)
{
    for (const std::string& net : {std::string(CBaseChainParams::MAIN),
                                   std::string(CBaseChainParams::TESTNET),
                                   std::string(CBaseChainParams::REGTEST)}) {
        SelectParams(net);
        const Consensus::Params& c = Params().GetConsensus();
        std::string err;
        BOOST_CHECK_MESSAGE(CheckDMMTimingInvariants(c, err),
                            "network " << net << " violates a DMM timing invariant: " << err);
        // D.16e — the CANONICAL values are read from chainparams, never copied as a
        // literal from a comment. Editing only a stale comment can therefore never be
        // mistaken for changing the value.
        BOOST_CHECK_EQUAL(c.nHuLeaderTimeoutSeconds, 45);
        BOOST_CHECK_EQUAL(c.nHuFallbackRecoverySeconds, 30);
        BOOST_CHECK_EQUAL(c.FutureBlockTimeDrift(0), 14);
        BOOST_CHECK_GE(c.nHuLeaderTimeoutSeconds, c.FutureBlockTimeDrift(0) + DMM_TIMING_SAFETY_MARGIN);
        BOOST_CHECK_GE(c.nHuFallbackRecoverySeconds, c.FutureBlockTimeDrift(0) + DMM_TIMING_SAFETY_MARGIN);
    }
    SelectParams(CBaseChainParams::TESTNET);
}

// The three declared mutants MUST turn the invariant red. Applied to a COPY of the
// params, so nothing global is disturbed.
BOOST_AUTO_TEST_CASE(timing_invariant_mutants_are_all_killed)
{
    Consensus::Params c = Params().GetConsensus();
    std::string err;
    BOOST_REQUIRE(CheckDMMTimingInvariants(c, err));

    // mutant 45 -> 5 (the old regtest leaderTimeout): slot 0 -> 1 becomes free.
    Consensus::Params m1 = c; m1.nHuLeaderTimeoutSeconds = 5;
    BOOST_CHECK_MESSAGE(!CheckDMMTimingInvariants(m1, err), "mutant 45->5 SURVIVED: I1 is not enforced");
    BOOST_CHECK(err.find("I1") != std::string::npos);

    // mutant 30 -> 14 (window at the drift): a full slot becomes free.
    Consensus::Params m2 = c; m2.nHuFallbackRecoverySeconds = 14;
    BOOST_CHECK_MESSAGE(!CheckDMMTimingInvariants(m2, err), "mutant 30->14 SURVIVED: I2 is not enforced");
    BOOST_CHECK(err.find("I2") != std::string::npos);

    // mutant 30 -> 15 (the previous value): margin of ONE second, still below drift+15.
    Consensus::Params m3 = c; m3.nHuFallbackRecoverySeconds = 15;
    BOOST_CHECK_MESSAGE(!CheckDMMTimingInvariants(m3, err),
                        "the old 15 s window must NOT satisfy the hardened invariant");
}

// ── D.1 — the schedule is immune to everything a producer emits. The old draw fed on
// the parent hash; this one has no producer-controlled input at all.
BOOST_AUTO_TEST_CASE(schedule_is_immune_to_producer_grinding)
{
    const auto ops = MakeOps(7);
    const int height = 5000;
    const uint32_t epoch = GetScheduleEpochIndex(height, ACTIVATION, EPOCH);
    const auto reference = ComputeSchedulePermutation(
        GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS, epoch), ops);

    // 10 000 candidate blocks: nonce, nTime, coinbase, tx order — all of it is absent
    // from the seed, so not one of them can move the permutation.
    for (uint64_t attempt = 0; attempt < 10000; ++attempt) {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("candidate-block");
        ss << attempt;
        const uint256 groundParentHash = ss.GetHash();   // whatever the producer re-rolls
        (void)groundParentHash;                          // it is NOT an input — that is the point
        const auto again = ComputeSchedulePermutation(
            GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS, epoch), ops);
        if (again != reference) {
            BOOST_FAIL("the schedule moved under a re-rolled candidate block at attempt " << attempt);
        }
    }
    BOOST_TEST_MESSAGE("LOT9/M1: 10 000 re-rolls, permutation byte-identical");

    // NEGATIVE CONTROLS — the three real inputs must each be decisive, otherwise the
    // immunity above would be the trivial immunity of a constant.
    const uint256 otherGenesis = uint256S("0x0000000000000000000000000000000000000000000000000000000012345678");
    BOOST_CHECK_MESSAGE(ComputeSchedulePermutation(
        GetScheduleSeed(DMM_SCHEDULE_DOMAIN, otherGenesis, epoch), ops) != reference,
        "genesisHash MUST be decisive");
    BOOST_CHECK_MESSAGE(ComputeSchedulePermutation(
        GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS, epoch + 1), ops) != reference,
        "epochIndex MUST be decisive");
    auto fewer = ops; fewer.pop_back();
    BOOST_CHECK_MESSAGE(ComputeSchedulePermutation(
        GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS, epoch), fewer) != reference,
        "the operator set MUST be decisive");
    // And the two domains must not produce the same order.
    BOOST_CHECK_MESSAGE(ComputeSchedulePermutation(
        GetScheduleSeed(DMM_RECOVERY_DOMAIN, GENESIS, epoch), ops) != reference,
        "normal and recovery permutations MUST differ (domain separation)");
}

// ── D.2 — proTxHash grinding buys a POSITION, never a second slot: the permutation is
// a bijection, so each identity appears exactly once in the base calendar.
BOOST_AUTO_TEST_CASE(protxhash_grinding_never_buys_a_second_slot)
{
    const auto ops = MakeOps(7);
    const uint256 seed = GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS, 42);

    for (uint32_t g = 0; g < 10000; ++g) {
        auto candidate = ops;
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("ground-identity");
        ss << g;
        candidate.push_back(ss.GetHash());               // an entrant grinding its identity
        const auto perm = ComputeSchedulePermutation(seed, candidate);

        BOOST_REQUIRE_EQUAL(perm.size(), candidate.size());
        std::set<uint256> uniq(perm.begin(), perm.end());
        if (uniq.size() != perm.size()) {
            BOOST_FAIL("grinding attempt " << g << " produced a duplicated position");
        }
    }
    BOOST_TEST_MESSAGE("LOT9/M1: 10 000 ground identities, permutation stayed bijective");

    // NEGATIVE CONTROL: a permutation that is NOT a bijection must be detectable by the
    // very check above — feed it a set containing a duplicate and confirm it shows.
    auto dup = ops; dup.push_back(ops.front());
    const auto permDup = ComputeSchedulePermutation(seed, dup);
    std::set<uint256> uniqDup(permDup.begin(), permDup.end());
    BOOST_CHECK_MESSAGE(uniqDup.size() < permDup.size(),
                        "the duplicate detector itself must bite");
}

// ── D.3 — same inputs, byte-identical result, whatever the caller's enumeration order.
BOOST_AUTO_TEST_CASE(same_inputs_give_byte_identical_schedule)
{
    const auto ops = MakeOps(9);
    const uint256 seed = GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS, 7);
    auto reversed = ops; std::reverse(reversed.begin(), reversed.end());
    BOOST_CHECK(ComputeSchedulePermutation(seed, ops) == ComputeSchedulePermutation(seed, reversed));
}

// ── D.4 — the epoch boundary, and the snapshot height derived from it.
BOOST_AUTO_TEST_CASE(epoch_boundary_and_snapshot_height)
{
    // LOT 9 M3.1 — epochs are counted FROM THE ACTIVATION HEIGHT, not from 0.
    BOOST_CHECK_EQUAL(GetScheduleEpochIndex(ACTIVATION - 1, ACTIVATION, EPOCH), 0u);   // bootstrap
    BOOST_CHECK_EQUAL(GetScheduleEpochIndex(ACTIVATION, ACTIVATION, EPOCH), 0u);
    BOOST_CHECK_EQUAL(GetScheduleEpochIndex(ACTIVATION + EPOCH - 1, ACTIVATION, EPOCH), 0u);
    BOOST_CHECK_EQUAL(GetScheduleEpochIndex(ACTIVATION + EPOCH, ACTIVATION, EPOCH), 1u);  // boundary bites
    BOOST_CHECK_EQUAL(GetScheduleEpochStart(ACTIVATION + EPOCH - 1, ACTIVATION, EPOCH), ACTIVATION);
    BOOST_CHECK_EQUAL(GetScheduleEpochStart(ACTIVATION + EPOCH, ACTIVATION, EPOCH), ACTIVATION + EPOCH);
    BOOST_CHECK_EQUAL(GetScheduleEpochStart(ACTIVATION + 2 * EPOCH - 1, ACTIVATION, EPOCH), ACTIVATION + EPOCH);

    // snapshot = max(activation - 1, epochStart - depth). The FIRST epoch needs no
    // special case: its epochStart IS the activation, so the anchor wins.
    BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(ACTIVATION, ACTIVATION, EPOCH, 30), ACTIVATION - 1);
    BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(ACTIVATION + EPOCH - 1, ACTIVATION, EPOCH, 30), ACTIVATION - 1);
    // Second epoch: epochStart - depth == activation + 30 > anchor, so it wins.
    BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(ACTIVATION + EPOCH, ACTIVATION, EPOCH, 30),
                      ACTIVATION + EPOCH - 30);
    BOOST_CHECK_EQUAL(GetEpochSnapshotHeight(ACTIVATION + 2 * EPOCH, ACTIVATION, EPOCH, 30),
                      ACTIVATION + 2 * EPOCH - 30);
    // The anchor is a HARD floor: no epoch may look below the last bootstrap block.
    for (int h = ACTIVATION; h < ACTIVATION + 4 * EPOCH; ++h) {
        BOOST_CHECK_GE(GetEpochSnapshotHeight(h, ACTIVATION, EPOCH, 30), ACTIVATION - 1);
    }

    // NEGATIVE CONTROL: the permutation really does change across the boundary.
    const auto ops = MakeOps(5);
    BOOST_CHECK(ComputeSchedulePermutation(GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS,
                                       GetScheduleEpochIndex(ACTIVATION + EPOCH - 1, ACTIVATION, EPOCH)), ops)
             != ComputeSchedulePermutation(GetScheduleSeed(DMM_SCHEDULE_DOMAIN, GENESIS,
                                       GetScheduleEpochIndex(ACTIVATION + EPOCH, ACTIVATION, EPOCH)), ops));
}

// ── rawSlot: unclamped, O(1), and exactly the declared arithmetic.
BOOST_AUTO_TEST_CASE(raw_slot_is_unclamped_and_exact)
{
    const Consensus::Params& c = Params().GetConsensus();
    CBlockIndex prev; prev.nTime = 1750000000; prev.nHeight = 1000;
    const int64_t minBlockTime = (int64_t)prev.nTime + c.nTargetSpacing;

    BOOST_CHECK_EQUAL(GetRawProducerSlot(&prev, minBlockTime), 0);
    BOOST_CHECK_EQUAL(GetRawProducerSlot(&prev, minBlockTime - 1000), 0);   // early ⇒ slot 0
    BOOST_CHECK_EQUAL(GetRawProducerSlot(&prev, minBlockTime + c.nHuLeaderTimeoutSeconds - 1), 0);
    BOOST_CHECK_EQUAL(GetRawProducerSlot(&prev, minBlockTime + c.nHuLeaderTimeoutSeconds), 1);
    BOOST_CHECK_EQUAL(GetRawProducerSlot(&prev, minBlockTime + c.nHuLeaderTimeoutSeconds
                                                + c.nHuFallbackRecoverySeconds), 2);

    // ── THE CLAMP MUST BE GONE. min(rawSlot,360) would wedge a 361-operator network in
    // normal mode forever, because rawSlot < P would hold at every timestamp.
    const int64_t far = minBlockTime + c.nHuLeaderTimeoutSeconds
                      + (int64_t)1000 * c.nHuFallbackRecoverySeconds;
    BOOST_CHECK_EQUAL(GetRawProducerSlot(&prev, far), 1001);
    BOOST_CHECK_MESSAGE(GetRawProducerSlot(&prev, far) > 360,
                        "MUTANT CHECK: reintroducing min(rawSlot,360) must fail here");

    // Largest slot reachable from a representable header timestamp (nTime is uint32).
    const int64_t maxHeaderTime = 0xffffffffLL;
    const int64_t slotMax = GetRawProducerSlot(&prev, maxHeaderTime);
    BOOST_CHECK(slotMax > 0);
    BOOST_TEST_MESSAGE("LOT9/M1: max rawSlot from a valid uint32 timestamp = " << slotMax);
}

// ── D.16c — the EXACT recovery boundary, read from the implementation so the P-1 vs P
// question can never resurface. minimum_effective_wait = leaderTimeout
// + (P-1)*window - drift; with P=7, 45 + 6*30 - 14 = 211 s.
BOOST_AUTO_TEST_CASE(recovery_boundary_is_exact_and_arithmetic_is_locked)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int64_t P = 7;
    const int64_t effective = c.nHuLeaderTimeoutSeconds
                            + (P - 1) * c.nHuFallbackRecoverySeconds
                            - c.FutureBlockTimeDrift(0);
    BOOST_CHECK_EQUAL(effective, 211);          // 45 + 180 - 14 — the figure, pinned

    CBlockIndex prev; prev.nTime = 1750000000; prev.nHeight = 500;
    const int64_t minBlockTime = (int64_t)prev.nTime + c.nTargetSpacing;
    // The chain-time cost of reaching slot P (before subtracting the accepted drift).
    const int64_t tAtP = minBlockTime + c.nHuLeaderTimeoutSeconds
                       + (P - 1) * c.nHuFallbackRecoverySeconds;

    const auto prodSet = MakeOps((size_t)P, "prod");
    auto recSet = prodSet;
    for (const auto& e : MakeOps(3, "expired")) recSet.push_back(e);

    DMMScheduleResult before, at;
    // One second before the boundary: still NORMAL mode — an expired identity is not yet
    // eligible. Refusal is temporal, never a persisted verdict.
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 500, ACTIVATION, EPOCH,
                  GetRawProducerSlot(&prev, tAtP - 1), prodSet, recSet, before));
    BOOST_CHECK_MESSAGE(!before.fRecovery, "one second before the boundary must stay NORMAL");
    BOOST_CHECK_EQUAL(before.nRawSlot, P - 1);

    // Exactly at the boundary: RECOVERY becomes reachable.
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 500, ACTIVATION, EPOCH,
                  GetRawProducerSlot(&prev, tAtP), prodSet, recSet, at));
    BOOST_CHECK_MESSAGE(at.fRecovery, "at the boundary the recovery permutation must be used");
    BOOST_CHECK_EQUAL(at.nRawSlot, P);
}

// ── D.13 — 1000 expired identities must NOT slow the normal calendar.
BOOST_AUTO_TEST_CASE(a_thousand_expired_do_not_slow_the_normal_calendar)
{
    const auto live = MakeOps(4, "live");
    auto recSet = live;
    for (const auto& d : MakeOps(1000, "dead")) recSet.push_back(d);

    // Normal mode ranges over the 4 lease-valid identities ONLY: every slot below P=4 is
    // held by a live operator, so no empty slot is ever waited out.
    for (int64_t slot = 0; slot < 4; ++slot) {
        DMMScheduleResult r;
        BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 300, ACTIVATION, EPOCH, slot, live, recSet, r));
        BOOST_CHECK_MESSAGE(!r.fRecovery, "slot " << slot << " must stay in normal mode");
        BOOST_CHECK_MESSAGE(std::find(live.begin(), live.end(), r.proTxHash) != live.end(),
                            "a dead identity leaked into the normal calendar");
    }
    // MUTANT: putting the expired ones in the production set collapses throughput —
    // the same loop then elects dead identities.
    DMMScheduleResult bad;
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 300, ACTIVATION, EPOCH, 3, recSet, recSet, bad));
    BOOST_CHECK_MESSAGE(std::find(live.begin(), live.end(), bad.proTxHash) == live.end(),
                        "the mutant control must elect a DEAD identity, proving the check bites");
}

// ── D.14 — every lease expired ⇒ no brick. P=0 makes recovery AVAILABLE at slot 0.
// Honest scope: availability is not instant resumption — production restarts at the
// first slot whose expired identity can still sign.
BOOST_AUTO_TEST_CASE(all_leases_expired_does_not_brick_the_chain)
{
    const std::vector<uint256> empty;
    const auto recSet = MakeOps(7, "expired");

    DMMScheduleResult r;
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 900, ACTIVATION, EPOCH, /*rawSlot=*/0, empty, recSet, r));
    BOOST_CHECK_MESSAGE(r.fRecovery, "P=0 must enter recovery mode at slot 0 with no special case");
    BOOST_CHECK(r.fFound);

    // Successive slots walk the recovery permutation, so a dead first leader is passed.
    std::set<uint256> reached;
    for (int64_t slot = 0; slot < 7; ++slot) {
        DMMScheduleResult s;
        BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 900, ACTIVATION, EPOCH, slot, empty, recSet, s));
        reached.insert(s.proTxHash);
    }
    BOOST_CHECK_MESSAGE(reached.size() == recSet.size(),
                        "seven successive slots must reach all seven identities");

    // The honest limit, asserted rather than hidden: no signer at all ⇒ explicit stall,
    // NOT a block-validity verdict.
    DMMScheduleResult dead;
    BOOST_CHECK(!SelectScheduledLeader(GENESIS, 900, ACTIVATION, EPOCH, 0, empty, empty, dead));
    BOOST_CHECK(!dead.fFound);
    BOOST_CHECK_MESSAGE(dead.fRecovery, "the stall must be reported from the recovery branch");
}

// ── D.19 — 1000 dead + ONE live expired identity: normal mode is clean (P=0 ⇒ recovery),
// and the recovery latency is QUANTIFIED rather than dressed up.
BOOST_AUTO_TEST_CASE(one_live_identity_among_a_thousand_dead_is_quantified)
{
    const std::vector<uint256> noneValid;
    auto recSet = MakeOps(1000, "dead");
    const auto live = MakeOps(1, "onlySurvivor");
    recSet.push_back(live.front());

    int64_t slotOfSurvivor = -1;
    for (int64_t slot = 0; slot < (int64_t)recSet.size(); ++slot) {
        DMMScheduleResult r;
        BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 1200, ACTIVATION, EPOCH, slot, noneValid, recSet, r));
        if (r.proTxHash == live.front()) { slotOfSurvivor = slot; break; }
    }
    BOOST_REQUIRE_MESSAGE(slotOfSurvivor >= 0, "the survivor must eventually be scheduled");

    const Consensus::Params& c = Params().GetConsensus();
    const int64_t waitSeconds = c.nHuLeaderTimeoutSeconds
                              + slotOfSurvivor * c.nHuFallbackRecoverySeconds;
    BOOST_TEST_MESSAGE("LOT9/M1 D.19: lone survivor among 1000 dead is reached at recovery slot "
                       << slotOfSurvivor << " => ~" << waitSeconds << " s ("
                       << (waitSeconds / 3600.0) << " h) before the chain restarts. "
                       "SLOW BY DESIGN — an accepted, measured limit, not a proof of liveness.");
    BOOST_CHECK(waitSeconds > 0);
}

// ── P=361: the recovery mode must stay reachable. Under the old clamp it never was.
BOOST_AUTO_TEST_CASE(recovery_stays_reachable_beyond_the_legacy_clamp)
{
    const auto prodSet = MakeOps(361, "p361");
    auto recSet = prodSet;
    for (const auto& e : MakeOps(2, "exp361")) recSet.push_back(e);

    DMMScheduleResult atClamp;
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 4000, ACTIVATION, EPOCH, 360, prodSet, recSet, atClamp));
    BOOST_CHECK_MESSAGE(!atClamp.fRecovery, "slot 360 < P=361 is still normal mode");

    DMMScheduleResult past;
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 4000, ACTIVATION, EPOCH, 361, prodSet, recSet, past));
    BOOST_CHECK_MESSAGE(past.fRecovery,
        "slot 361 MUST enter recovery — with min(rawSlot,360) it never could, and a "
        "361-operator network whose actives all went silent would be wedged forever");

    DMMScheduleResult farPast;
    BOOST_REQUIRE(SelectScheduledLeader(GENESIS, 4000, ACTIVATION, EPOCH, 5000, prodSet, recSet, farPast));
    BOOST_CHECK(farPast.fRecovery);
}

BOOST_AUTO_TEST_SUITE_END()
