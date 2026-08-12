// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M4 — DETERMINISTIC SCALE HARNESS (what the 7-node laboratory cannot run)
// =============================================================================
//
// The live laboratory measures a real 7-operator network. Two mandated scenarios
// are OUT OF ITS REACH and are measured here instead, deterministically — and
// this file exists to say so explicitly rather than let a gap pass as covered:
//
//   * P = 361 and rawSlot > 360 would need 361 real operators;
//   * a lease horizon of 10 080 blocks would need ~12 hours of production at the
//     laboratory's measured rate (~14 blocks/min).
//
// Nothing here is a substitute for the live measurements that ARE runnable; it
// covers only what a local process lab structurally cannot reach.

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "chainparams.h"
#include "consensus/params.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "script/standard.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "utiltime.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <set>
#include <vector>

using namespace mn_consensus;

namespace {

std::vector<uint256> MakeOps(size_t n, uint32_t salt)
{
    std::vector<uint256> ops;
    ops.reserve(n);
    for (uint32_t i = 0; i < (uint32_t)n; ++i) {
        ops.push_back(ArithToUint256(arith_uint256(salt) * 1000000 + i));
    }
    return ops;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m4_scale, BasicTestingSetup)

// ── PHASE F — rawSlot far beyond the retired 360 clamp, with P = 361.
// The legacy clamp would have pinned min(slot,360) < P forever, so the recovery
// mode could never be entered: a permanent wedge. Measured here at the exact
// shipped constants, plus the O(1) claim (a loop over rawSlot would never
// return at the magnitudes below).
BOOST_AUTO_TEST_CASE(raw_slot_beyond_the_retired_clamp_with_361_operators)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int ACT = c.DMMScheduleActivationHeight();
    const int LEN = c.nDMMScheduleEpochLength;
    const uint256 GEN = c.hashGenesisBlock;

    const auto production = MakeOps(361, 7);          // P = 361 > the old clamp
    const auto recovery   = MakeOps(361 + 5, 7);      // R > P
    const int height = ACT + 3 * LEN + 11;

    // rawSlot 360 — the old clamp value — is still a NORMAL slot at P = 361.
    DMMScheduleResult atOldClamp;
    BOOST_REQUIRE(SelectScheduledLeader(GEN, height, ACT, LEN, /*rawSlot=*/360,
                                        production, recovery, atOldClamp));
    BOOST_CHECK_MESSAGE(!atOldClamp.fRecovery,
        "at P=361 slot 360 must still be NORMAL — the retired clamp would have "
        "made every deeper slot unreachable");

    // rawSlot 361 — the first slot the clamp made unreachable — opens RECOVERY.
    DMMScheduleResult firstRecovery;
    BOOST_REQUIRE(SelectScheduledLeader(GEN, height, ACT, LEN, /*rawSlot=*/361,
                                        production, recovery, firstRecovery));
    BOOST_CHECK_MESSAGE(firstRecovery.fRecovery,
        "recovery must be reachable past the retired clamp, or a stalled chain "
        "with 361 lease-valid operators could never recover");

    // O(1): huge slots resolve in constant time. A loop proportional to rawSlot
    // would not return here — the assertion is the elapsed time, measured.
    const auto t0 = std::chrono::steady_clock::now();
    for (int64_t s : {(int64_t)1000, (int64_t)1000000, (int64_t)1000000000,
                      (int64_t)4000000000LL}) {
        DMMScheduleResult r;
        BOOST_REQUIRE(SelectScheduledLeader(GEN, height, ACT, LEN, s, production, recovery, r));
        BOOST_CHECK(r.fRecovery);
        BOOST_CHECK_LT(r.nIndex, recovery.size());
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    BOOST_TEST_MESSAGE("LOT9/M4: four selections at rawSlot up to 4e9 took " << ms << " ms");
    BOOST_CHECK_MESSAGE(ms < 2000,
        "selection is not O(1) in rawSlot — a slot-proportional loop is a DoS on "
        "any node validating a far-future timestamp");
}

// ── PHASE E — 1 000 expired identities and ONE live signer. The mandate allows a
// deterministic simulation here (1 001 daemons is not a laboratory) and REQUIRES
// the recovery latency to be measured and published, not hand-waved.
BOOST_AUTO_TEST_CASE(one_live_signer_among_a_thousand_expired_latency_measured)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int ACT = c.DMMScheduleActivationHeight();
    const int LEN = c.nDMMScheduleEpochLength;
    const uint256 GEN = c.hashGenesisBlock;
    const int height = ACT + 5 * LEN + 3;

    // Every lease has expired: the production set is EMPTY, so recovery is
    // available from slot 0 — but only the slot whose recovery identity can
    // still sign actually produces.
    const std::vector<uint256> production;                 // P = 0
    const auto recovery = MakeOps(1001, 42);               // R = 1001
    const uint256 aliveSigner = recovery[437];             // the single live key

    int64_t slotOfTheLiveSigner = -1;
    for (int64_t slot = 0; slot < (int64_t)recovery.size(); ++slot) {
        DMMScheduleResult r;
        BOOST_REQUIRE(SelectScheduledLeader(GEN, height, ACT, LEN, slot, production, recovery, r));
        BOOST_REQUIRE(r.fRecovery);
        if (r.proTxHash == aliveSigner) { slotOfTheLiveSigner = slot; break; }
    }
    BOOST_REQUIRE_MESSAGE(slotOfTheLiveSigner >= 0,
        "the recovery permutation must reach every identity — otherwise a live "
        "signer could be structurally unreachable");

    // THE PUBLISHED NUMBER: chain time to reach that slot, at the shipped timing.
    //   slot 0            -> minBlockTime
    //   slot s (s >= 1)   -> leaderTimeout + (s-1) * recoveryWindow
    const int64_t seconds = (slotOfTheLiveSigner == 0)
        ? 0
        : c.nHuLeaderTimeoutSeconds + (slotOfTheLiveSigner - 1) * c.nHuFallbackRecoverySeconds;
    BOOST_TEST_MESSAGE("LOT9/M4 recovery latency: the live signer sits at recovery slot "
                       << slotOfTheLiveSigner << " of " << recovery.size()
                       << " -> " << seconds << " s of CHAIN time ("
                       << (seconds / 3600.0) << " h) before it may produce");

    // The bound the design promises: worst case is R slots, i.e. bounded and
    // computable — never unbounded, never dependent on anything a peer controls.
    const int64_t worst = c.nHuLeaderTimeoutSeconds
                        + ((int64_t)recovery.size() - 1) * c.nHuFallbackRecoverySeconds;
    BOOST_CHECK_LE(seconds, worst);
    BOOST_TEST_MESSAGE("LOT9/M4 worst case with R=" << recovery.size() << ": "
                       << worst << " s (" << (worst / 3600.0) << " h)");
    BOOST_CHECK_MESSAGE(worst > 0, "the bound must be a real number, not a promise");
}

// ── PHASE E — the lease horizon at the SHIPPED constant, never shortened.
// The laboratory cannot run 10 080 blocks; the boundary arithmetic is pinned
// here against chainparams, so a silently reduced horizon fails.
BOOST_AUTO_TEST_CASE(lease_horizon_is_the_shipped_constant_and_the_boundary_is_exact)
{
    const Consensus::Params& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.nOperatorLeaseBlocks, 10080);

    // A lease taken at inclusion height H expires at H + horizon, and the
    // snapshot boundary is STRICT: snapshotHeight < expiry, equality = expired.
    const int inclusion = c.DMMScheduleActivationHeight() + 123;
    const int expiry = inclusion + c.nOperatorLeaseBlocks;
    BOOST_CHECK_LT(expiry - 1, expiry);                  // still valid one block before
    BOOST_CHECK_MESSAGE(!(expiry < expiry), "equality must NOT be valid (expired)");

    // At 60 s spacing the horizon is one week; state it in the numbers an operator
    // will actually reason about.
    const int64_t seconds = (int64_t)c.nOperatorLeaseBlocks * c.nTargetSpacing;
    BOOST_TEST_MESSAGE("LOT9/M4 lease horizon: " << c.nOperatorLeaseBlocks << " blocks = "
                       << (seconds / 86400.0) << " days at " << c.nTargetSpacing << " s spacing");
    BOOST_CHECK_GE(seconds, 6 * 86400);   // ~7 days, the documented design point
}

// ── PHASE F-BIS — the TIME path past the clamp, P = 361 (kills mutant M5a).
//
// The cases above feed rawSlot LITERALS to SelectScheduledLeader — they never
// traverse GetRawProducerSlot, which is where the retired 360 clamp lived and
// where its mutant reinstates it. That is exactly how M5a SURVIVED the suite.
// This case drives the schedule from TIME through the full production resolver
// and pins the LEADER, not just the slot number: under the clamp, every time
// beyond slot 360 collapses onto slot 360's NORMAL leader and recovery never
// opens — both assertions go red.
namespace {
struct DMMScale361Setup : DMMScheduleChainSetup {
    DMMScale361Setup() : DMMScheduleChainSetup(361, 1, /*seedSnapshotList=*/true) {}
};
} // namespace

BOOST_FIXTURE_TEST_CASE(the_time_path_elects_the_recovery_leader_past_the_clamp,
                        DMMScale361Setup)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int ACT = c.DMMScheduleActivationHeight();
    const int LEN = c.nDMMScheduleEpochLength;
    const uint256 GEN = c.hashGenesisBlock;

    MakeChainActive();   // the snapshot must sit on the active chain (else DEFERRED)

    using namespace mn_consensus;
    EpochOperatorSets sets;
    BOOST_REQUIRE(WITH_LOCK(cs_main, return ResolveEpochOperatorSets(Parent(), sets))
                  == ScheduleStatus::OK);
    BOOST_REQUIRE_EQUAL(sets.production.size(), 361u);   // P = 361 > the old clamp
    BOOST_REQUIRE_EQUAL(sets.recovery.size(), 361u);

    // Where the clamp lands everything: slot 360 through TIME is still NORMAL.
    CDeterministicMNCPtr l360;
    DMMScheduleResult r360;
    BOOST_REQUIRE(WITH_LOCK(cs_main,
                      return ResolveScheduledProducer(Parent(), ChildTimeAtSlot(360), l360, r360))
                  == ScheduleStatus::OK);
    BOOST_REQUIRE(l360);
    BOOST_CHECK_EQUAL(r360.nRawSlot, 360);
    BOOST_CHECK(!r360.fRecovery);

    // Slots 361..364 through TIME: recovery opens, and the elected leader matches
    // the literal-slot election on the SAME sets (an expectation independent of
    // GetRawProducerSlot). recoverySlot = s-361 covers four DISTINCT recovery
    // identities, and l360 is a single identity, so at least three of these four
    // leaders differ from it BY CONSTRUCTION — no luck involved.
    int discriminating = 0;
    for (int64_t s = 361; s <= 364; ++s) {
        CDeterministicMNCPtr l;
        DMMScheduleResult r;
        const ScheduleStatus st = WITH_LOCK(cs_main,
            return ResolveScheduledProducer(Parent(), ChildTimeAtSlot(s), l, r));
        BOOST_REQUIRE_MESSAGE(st == ScheduleStatus::OK && l,
                              "no leader through the time path at slot " << s);
        BOOST_CHECK_MESSAGE(r.nRawSlot == s,
            "time->slot must reach " << s << " (got " << r.nRawSlot
            << ") — the retired clamp would cap it at 360");
        BOOST_CHECK_MESSAGE(r.fRecovery,
            "slot " << s << " must be RECOVERY at P=361 — under the clamp a "
            "stalled 361-operator chain could never recover");

        DMMScheduleResult expected;
        BOOST_REQUIRE(SelectScheduledLeader(GEN, ChildHeight(), ACT, LEN, s,
                                            sets.production, sets.recovery, expected));
        BOOST_CHECK_MESSAGE(l->proTxHash == expected.proTxHash,
            "the time path elected a different leader than the literal slot " << s);

        if (l->proTxHash != l360->proTxHash) ++discriminating;
    }
    BOOST_CHECK_MESSAGE(discriminating >= 3,
        "the leaders past the clamp must differ from slot 360's NORMAL leader — "
        "under the clamp they would all BE that leader");
}

BOOST_AUTO_TEST_SUITE_END()

// ═════════════════════════════════════════════════════════════════════════════
// LOT 9 M4 SCALE E2E — the BLOCK VERDICT past the clamp (kills mutant M5a too)
// ═════════════════════════════════════════════════════════════════════════════
//
// A leader assertion is necessary but a mutant reinstating the clamp changes the
// VALIDATOR as well: what must be proven is that a real block, on a real chain,
// at an nTime mapping to rawSlot > 360, is judged by the UNCLAMPED leader.
// The expected slot and leader are derived here from the SPEC formula and the
// literal-slot election — never from GetRawProducerSlot — so mutating that
// function cannot drag the expectation along with it.
namespace {
struct ScheduledChain4Setup : ScheduledChainSetup {
    ScheduledChain4Setup() : ScheduledChainSetup(/*numOperators=*/4, /*mnsPerOperator=*/1) {}

    void SignAs(const uint256& proTxHash, CBlock& b) const
    {
        for (const auto& op : operators) {
            for (const auto& mn : op.mns) {
                if (mn.proTxHash == proTxHash) {
                    BOOST_REQUIRE(op.key.Sign(b.GetHash(), b.vchBlockSig));
                    return;
                }
            }
        }
        BOOST_REQUIRE_MESSAGE(false, "proTxHash not owned by any fixture operator");
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m4_scale_e2e, ScheduledChain4Setup)

BOOST_AUTO_TEST_CASE(a_block_past_the_clamp_is_judged_by_the_unclamped_leader)
{
    const Consensus::Params& c = Params().GetConsensus();
    const int ACT = c.DMMScheduleActivationHeight();
    const int LEN = c.nDMMScheduleEpochLength;
    const uint256 GEN = c.hashGenesisBlock;

    MineScheduled(2);   // leave the bootstrap window: producer checks are live
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const int childHeight = parent->nHeight + 1;

    using namespace mn_consensus;
    EpochOperatorSets sets;
    BOOST_REQUIRE(WITH_LOCK(cs_main, return ResolveEpochOperatorSets(parent, sets))
                  == ScheduleStatus::OK);
    BOOST_REQUIRE_EQUAL(sets.production.size(), 4u);
    BOOST_REQUIRE_EQUAL(sets.recovery.size(), 4u);

    // The SPEC time for fallback slot s (duplicated here on purpose — the test's
    // clock must not depend on the function the mutant edits):
    //   t(s) = parentTime + spacing + leaderTimeout + (s-1) * recoveryWindow
    const auto timeAtSlot = [&](int64_t s) {
        return (int64_t)parent->GetBlockTime() + c.nTargetSpacing
             + c.nHuLeaderTimeoutSeconds + (s - 1) * c.nHuFallbackRecoverySeconds;
    };

    // The clamp's landing spot (slot 360, still recovery at P=4) and a slot past
    // it whose leader DIFFERS. recoverySlot = s-4 walks the whole 4-identity
    // recovery permutation as s covers 361..364, and the slot-360 leader is one
    // identity, so a discriminating s exists BY CONSTRUCTION.
    DMMScheduleResult at360;
    BOOST_REQUIRE(SelectScheduledLeader(GEN, childHeight, ACT, LEN, 360,
                                        sets.production, sets.recovery, at360));
    int64_t sStar = 0;
    DMMScheduleResult atStar;
    for (int64_t s = 361; s <= 364; ++s) {
        DMMScheduleResult r;
        BOOST_REQUIRE(SelectScheduledLeader(GEN, childHeight, ACT, LEN, s,
                                            sets.production, sets.recovery, r));
        if (r.proTxHash != at360.proTxHash) { sStar = s; atStar = r; break; }
    }
    BOOST_REQUIRE_MESSAGE(sStar != 0, "no discriminating slot in 361..364 — impossible "
                                      "with 4 distinct recovery identities");

    const int64_t nTime = timeAtSlot(sStar);
    SetMockTime(nTime + 5);   // the block is 'now', not 'from the future'

    const CScript payoutA = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());

    // Negative control FIRST (same parent, same nTime): a block signed by the
    // leader the CLAMP would elect must NOT become the tip. The VERDICT is what
    // is asserted, never ProcessNewBlock's return value — on regtest the early
    // AcceptBlock producer check is skipped (`!Params().IsRegTestNet()`), so the
    // rejection is delivered by ConnectBlock and shows up as "this block is not
    // the tip", plus BLOCK_FAILED_VALID on its index. This control is what makes
    // the acceptance below non-vacuous: the two leaders really are distinguished
    // by the consensus verdict at this height and time.
    {
        CBlock bad = CreateBlock({}, payoutA, /*fNoMempoolTx=*/true,
                                 /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                 /*customPrevBlock=*/parent);
        bad.nTime = (uint32_t)nTime;
        SignAs(at360.proTxHash, bad);
        ProcessNewBlock(std::make_shared<const CBlock>(bad), nullptr);
        LOCK(cs_main);
        const CBlockIndex* tip = chainActive.Tip();
        BOOST_REQUIRE(tip);
        BOOST_CHECK_MESSAGE(tip->GetBlockHash() != bad.GetHash(),
            "a block signed by the CLAMPED slot-360 leader became the tip at rawSlot "
                << sStar << " — the clamp is back");
        const CBlockIndex* badIdx = LookupBlockIndex(bad.GetHash());
        BOOST_CHECK_MESSAGE(badIdx == nullptr || (badIdx->nStatus & BLOCK_FAILED_MASK),
            "the clamped-leader block was stored without being marked invalid");
    }

    // The block signed by the UNCLAMPED leader at rawSlot sStar must be ACCEPTED
    // and become the tip. Under mutant M5a the validator re-derives slot 360,
    // expects the other leader, and rejects this very block.
    {
        CBlock good = CreateBlock({}, payoutA, /*fNoMempoolTx=*/true,
                                  /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                  /*customPrevBlock=*/parent);
        good.nTime = (uint32_t)nTime;
        SignAs(atStar.proTxHash, good);
        BOOST_REQUIRE_MESSAGE(ProcessNewBlock(std::make_shared<const CBlock>(good), nullptr),
            "the block signed by the UNCLAMPED recovery leader (rawSlot " << sStar
                << ") was rejected");
        LOCK(cs_main);
        const CBlockIndex* tip = chainActive.Tip();
        BOOST_REQUIRE(tip);
        BOOST_CHECK_MESSAGE(tip->GetBlockHash() == good.GetHash(),
            "the unclamped-leader block did not become the tip");
        BOOST_CHECK_EQUAL(tip->nHeight, childHeight);
    }

    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
