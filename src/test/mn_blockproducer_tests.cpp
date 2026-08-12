// Copyright (c) 2025-2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M1+M2 — WIRING of the non-grindable epoch schedule (end-to-end)
// =============================================================================
//
// The pure schedule engine is proven in consensus_lot9_m1_schedule_tests. This
// file proves the WIRING: ConnectBlock's CheckBlockMNOnly, the AcceptBlock-side
// verifier and the local scheduler all resolve the leader through
// ResolveScheduledProducer from the parent alone, the four O-1 statuses map to
// exactly the mandated verdicts, and the two REMOVED systems (the grindable
// per-block score, the temporal PoSe) stay removed:
//
//   * old_engine_leader_is_rejected_and_new_leader_accepted is the MUTANT GUARD
//     for the legacy engine — re-wiring the old GetExpectedProducer draw into
//     validation flips its accept/reject pair and turns it red;
//   * temporal_pose_stays_removed is the MUTANT GUARD for the PoSe path —
//     restoring the missed-slot penalty/decay changes the penalties it pins.
//
// Every case that asserts a rejection also carries an acceptance (and vice
// versa), so none of them can pass vacuously.

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "arith_uint256.h"
#include "chainparams.h"
#include "consensus/mn_validation.h"
#include "consensus/validation.h"
#include "hash.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "primitives/block.h"
#include "rpc/server.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

UniValue getquorum(const JSONRPCRequest& request);

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Test-local replica of the REMOVED legacy engine (score + slot + modulo pick).
// It exists so the divergence test can compute what the OLD engine would have
// elected without the old engine existing anywhere in production code.
// ─────────────────────────────────────────────────────────────────────────────
arith_uint256 LegacyScore(const uint256& prevBlockHash, int nHeight, const uint256& proTxHash)
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << prevBlockHash;
    ss << nHeight;
    ss << proTxHash;
    return UintToArith256(ss.GetHash());
}

int LegacySlot(const CBlockIndex* prev, int64_t nBlockTime)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int64_t dt = nBlockTime - ((int64_t)prev->GetBlockTime() + consensus.nTargetSpacing);
    if (dt < consensus.nHuLeaderTimeoutSeconds) return 0;
    int slot = 1 + (int)((dt - consensus.nHuLeaderTimeoutSeconds) / consensus.nHuFallbackRecoverySeconds);
    return std::min(slot, 360);
}

uint256 LegacyLeader(const CBlockIndex* prev, int64_t nBlockTime, const CDeterministicMNList& list)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    std::vector<std::pair<arith_uint256, uint256>> scored;
    list.ForEachMN(true, [&](const CDeterministicMNCPtr& dmn) {
        const bool boot = dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight;
        if (!boot && dmn->pdmnState->confirmedHash.IsNull()) return;
        scored.emplace_back(LegacyScore(prev->GetBlockHash(), prev->nHeight + 1, dmn->proTxHash), dmn->proTxHash);
    });
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        if (a.first == b.first) return a.second < b.second;
        return a.first > b.first;
    });
    BOOST_REQUIRE(!scored.empty());
    return scored[LegacySlot(prev, nBlockTime) % (int)scored.size()].second;
}

//! Resolve through the production engine under the lock validation holds.
mn_consensus::ScheduleStatus Resolve(const CBlockIndex* prev, int64_t nTime,
                                     CDeterministicMNCPtr& outMn,
                                     mn_consensus::DMMScheduleResult& outRes)
{
    LOCK(cs_main);
    return mn_consensus::ResolveScheduledProducer(prev, nTime, outMn, outRes);
}

//! Run the ConnectBlock-side entry point exactly as ConnectBlock does.
bool ConnectSide(const CBlock& block, const CBlockIndex* prev, CValidationState& state)
{
    LOCK(cs_main);
    return CheckBlockMNOnly(block, prev, state);
}

//! What the AcceptBlock early check decides for a resolved-OK block.
bool AcceptSide(const CBlock& block, const CBlockIndex* prev, CValidationState& state)
{
    CDeterministicMNCPtr mn;
    mn_consensus::DMMScheduleResult res;
    if (Resolve(prev, block.nTime, mn, res) != mn_consensus::ScheduleStatus::OK) return false;
    return mn_consensus::VerifyScheduledProducerSignature(block, mn, state);
}

//! Regtest chain of 10 real blocks for the PHASE 0 NO_SIGNER end-to-end suite.
struct TestChainSetup10 : public TestChainSetup {
    TestChainSetup10() : TestChainSetup(10) {}
};

} // namespace

BOOST_AUTO_TEST_SUITE(mn_blockproducer_tests)

// ─────────────────────────────────────────────────────────────────────────────
// Family 1 + mutant 2 + family 7 — the schedules DIVERGE and only the NEW leader
// is accepted; the block the scheduler would produce is exactly the block both
// verifiers accept. Re-wiring the legacy engine turns this red.
// ─────────────────────────────────────────────────────────────────────────────
BOOST_FIXTURE_TEST_CASE(old_engine_leader_is_rejected_and_new_leader_accepted, DMMScheduleChainSetup)
{
    // Find a slot where the two engines elect DIFFERENT identities. With 4
    // operators and independent permutations this exists within a few slots;
    // REQUIRE makes the search's success part of the proof.
    int64_t divergentTime = -1;
    uint256 oldLeader, newLeader;
    for (int64_t s = 0; s <= 20 && divergentTime < 0; ++s) {
        const int64_t t = (s == 0) ? MinChildTime() : ChildTimeAtSlot(s);
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        BOOST_REQUIRE(Resolve(Parent(), t, mn, res) == mn_consensus::ScheduleStatus::OK);
        const uint256 oldL = LegacyLeader(Parent(), t, mnList);
        if (oldL != mn->proTxHash) {
            divergentTime = t;
            oldLeader = oldL;
            newLeader = mn->proTxHash;
        }
    }
    BOOST_REQUIRE_MESSAGE(divergentTime >= 0,
        "no divergent slot in 21 tries — the engines agree suspiciously often; "
        "either the fixture is degenerate or the new engine was replaced by the old one");

    // The OLD engine's leader signs: REJECTED as a genuine signature invalidity
    // (this is a chain fact, so DoS/Invalid is correct here — unlike DEFERRED/FATAL).
    {
        CBlock b;
        b.nTime = (unsigned int)divergentTime;
        SignBlockAs(oldLeader, b);
        CValidationState st;
        BOOST_CHECK(!ConnectSide(b, Parent(), st));
        BOOST_CHECK(st.IsInvalid());
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-mn-sig-verify");

        // The AcceptBlock-side verifier agrees (same engine, same parent).
        CValidationState st2;
        BOOST_CHECK(!AcceptSide(b, Parent(), st2));
        BOOST_CHECK_EQUAL(st2.GetRejectReason(), "bad-mn-sig-verify");
    }

    // The NEW engine's leader signs the same nTime: ACCEPTED on both paths.
    // This is also family 7: the producer path resolves through the same engine,
    // so the block "the scheduler would make" is exactly this one.
    {
        CBlock b;
        b.nTime = (unsigned int)divergentTime;
        SignBlockAs(newLeader, b);
        CValidationState st;
        BOOST_CHECK_MESSAGE(ConnectSide(b, Parent(), st),
                            "scheduled leader rejected: " << st.GetRejectReason());
        CValidationState st2;
        BOOST_CHECK(AcceptSide(b, Parent(), st2));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mutant 3 — TEMPORAL PoSe STAYS REMOVED. A deep-fallback nTime (which used to
// manufacture "missed slot" victims) leaves every penalty and ban byte-identical
// through BuildNewListFromBlock; a pre-existing penalty is neither decayed nor
// escalated. Restoring the missed-slot loop or either decay rule turns this red.
// ─────────────────────────────────────────────────────────────────────────────
BOOST_FIXTURE_TEST_CASE(temporal_pose_stays_removed, DMMScheduleChainSetup)
{
    // Seed the PARENT list with one MN carrying penalty 2 (one strike from the
    // removed ban threshold) — the exact state the old engine would have moved.
    CDeterministicMNList parentList = mnList;
    const uint256 marked = operators[1].mns[0].proTxHash;
    {
        auto dmn = parentList.GetMN(marked);
        BOOST_REQUIRE(dmn);
        auto st = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
        st->nPoSePenalty = 2;
        parentList.UpdateMN(marked, st);
    }
    deterministicMNManager->SetListForTesting(Parent(), parentList, /*asTip=*/false);

    // A block published FIVE fallback windows late — the old engine punished the
    // "victims" ranked before the winner for exactly this shape.
    CBlock lateBlock;
    lateBlock.nTime = (unsigned int)ChildTimeAtSlot(5);

    CValidationState state;
    CDeterministicMNList newList;
    {
        LOCK2(cs_main, deterministicMNManager->cs);
        BOOST_REQUIRE(deterministicMNManager->BuildNewListFromBlock(
            lateBlock, Parent(), state, newList, /*debugLogs=*/false));
    }

    // NOTHING temporal happened: the marked penalty is still exactly 2 (no decay,
    // no escalation), everyone else is untouched, nobody was banned.
    parentList.ForEachMN(false, [&](const CDeterministicMNCPtr& before) {
        auto after = newList.GetMN(before->proTxHash);
        BOOST_REQUIRE(after);
        BOOST_CHECK_EQUAL(after->pdmnState->nPoSePenalty, before->pdmnState->nPoSePenalty);
        BOOST_CHECK_EQUAL(after->pdmnState->nPoSeBanHeight, before->pdmnState->nPoSeBanHeight);
    });
    BOOST_CHECK_EQUAL(newList.GetMN(marked)->pdmnState->nPoSePenalty, 2);
    BOOST_CHECK(!newList.GetMN(marked)->IsPoSeBanned());
}

// ─────────────────────────────────────────────────────────────────────────────
// Family 4 — snapshot ON the active chain, list ABSENT: fatal latch + controlled
// shutdown + non-invalid Error. The block is never marked.
// ─────────────────────────────────────────────────────────────────────────────
struct UnseededChainSetup : public DMMScheduleChainSetup {
    UnseededChainSetup() : DMMScheduleChainSetup(4, 1, /*seedSnapshotList=*/false) {}
};

BOOST_FIXTURE_TEST_CASE(missing_snapshot_on_active_chain_is_fatal_never_invalid, UnseededChainSetup)
{
    MakeChainActive();   // the snapshot ancestor IS our chain -> a gap is OUR corruption

    CBlock b;
    b.nTime = (unsigned int)MinChildTime();
    SignBlockAs(operators[0].mns[0].proTxHash, b);   // signature must not matter

    CValidationState st;
    BOOST_CHECK(!ConnectSide(b, Parent(), st));
    BOOST_CHECK_MESSAGE(!st.IsInvalid(), "a local gap must NEVER become block invalidity");
    BOOST_CHECK_MESSAGE(st.IsError(), "the fatal path reports a non-invalid Error");

    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(), "the LOT 1 shared latch must be set");
    ConsensusDBFatalContext ctx;
    BOOST_REQUIRE(GetConsensusDBFatalContext(ctx));
    BOOST_CHECK_EQUAL(ctx.strDB, "dmm-schedule-snapshot");
    BOOST_CHECK_EQUAL(ctx.nHeight, ChildHeight());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 1);   // controlled shutdown, exactly once

    test_shutdown::Reset();
    ResetConsensusDBFatalForTests();
}

// ─────────────────────────────────────────────────────────────────────────────
// Family 5 — snapshot NOT on the active chain: DEFERRED. Never fatal, never
// invalid, no latch, no shutdown; and the SAME resolver returns OK once the
// missing list appears (the deferral is about data, not about the block).
// ─────────────────────────────────────────────────────────────────────────────
BOOST_FIXTURE_TEST_CASE(snapshot_off_active_chain_is_deferred_never_fatal, UnseededChainSetup)
{
    // NOT MakeChainActive(): the branch is unconnected here.
    CBlock b;
    b.nTime = (unsigned int)MinChildTime();
    SignBlockAs(operators[0].mns[0].proTxHash, b);

    CValidationState st;
    BOOST_CHECK(!ConnectSide(b, Parent(), st));
    BOOST_CHECK(!st.IsInvalid());
    BOOST_CHECK(st.IsError());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "dmm-schedule-deferred");
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(), "DEFERRED must never latch the fatal");
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);

    // Re-evaluation: seed the list (the branch data arrives) -> the same parent now
    // resolves and blocks are judged on their signature alone.
    SeedListAt(SnapshotIndex());
    CDeterministicMNCPtr mn;
    mn_consensus::DMMScheduleResult res;
    BOOST_REQUIRE(Resolve(Parent(), b.nTime, mn, res) == mn_consensus::ScheduleStatus::OK);
    CBlock good;
    good.nTime = b.nTime;
    SignBlockAs(mn->proTxHash, good);
    CValidationState st2;
    BOOST_CHECK(ConnectSide(good, Parent(), st2));
}

// ─────────────────────────────────────────────────────────────────────────────
// NO_SIGNER — an authoritative empty snapshot is a deterministic CHAIN fact. A
// block CLAIMING a producer is INVALID (bad-dmm-no-eligible-producer, M3 PHASE 0
// — the state.Error variant was refuted by the dmm_no_signer_e2e wedge
// reproducer); the local producer path elects nobody; unsigned blocks pass. The
// negative control shows the SAME empty list, when the snapshot is NOT ours,
// classifies as DEFERRED instead — invalidity can never come from missing local
// data.
// ─────────────────────────────────────────────────────────────────────────────
BOOST_FIXTURE_TEST_CASE(no_signer_is_a_stall_and_never_a_local_gap_verdict, UnseededChainSetup)
{
    // Seed an authoritative EMPTY list at the snapshot.
    CDeterministicMNList empty(SnapshotIndex()->GetBlockHash(), SnapshotIndex()->nHeight, 0);
    deterministicMNManager->SetListForTesting(SnapshotIndex(), empty, /*asTip=*/false);

    CBlock claiming;
    claiming.nTime = (unsigned int)MinChildTime();
    SignBlockAs(operators[0].mns[0].proTxHash, claiming);

    // NEGATIVE CONTROL first — snapshot not on our chain: the SAME inputs defer,
    // and the ConnectBlock entry point refuses WITHOUT invalidity.
    {
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        BOOST_CHECK(Resolve(Parent(), claiming.nTime, mn, res)
                    == mn_consensus::ScheduleStatus::DEFERRED);
        CValidationState stDef;
        BOOST_CHECK(!ConnectSide(claiming, Parent(), stDef));
        BOOST_CHECK_MESSAGE(!stDef.IsInvalid(),
                            "a local gap must NEVER yield the NO_SIGNER invalidity");
    }

    MakeChainActive();   // now the empty snapshot is an authoritative CHAIN fact

    {
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        BOOST_CHECK(Resolve(Parent(), claiming.nTime, mn, res)
                    == mn_consensus::ScheduleStatus::NO_SIGNER);
    }

    // A signed block (claims a producer) is DETERMINISTICALLY INVALID — a chain
    // fact, identical on every node; never a latch, never a shutdown.
    CValidationState st;
    BOOST_CHECK(!ConnectSide(claiming, Parent(), st));
    BOOST_CHECK(st.IsInvalid());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-dmm-no-eligible-producer");
    BOOST_CHECK(!IsConsensusDBFatal());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);

    // An unsigned block claims nothing — the pre-LOT-9 empty-set allowance, now
    // scoped to the authoritative-snapshot case only.
    CBlock unsignedBlock;
    unsignedBlock.nTime = claiming.nTime;
    CValidationState st2;
    BOOST_CHECK(ConnectSide(unsignedBlock, Parent(), st2));
}

// ─────────────────────────────────────────────────────────────────────────────
// Family 6 + family 9 (fork leg) — same parent ⇒ byte-identical resolution, and
// a FORK parent sharing the snapshot ancestor elects the same leader: the
// schedule depends on the parent's ancestry and timestamps, never on its hash.
// The negative control moves the timestamps and demands the slot move with them.
// ─────────────────────────────────────────────────────────────────────────────
BOOST_FIXTURE_TEST_CASE(same_parent_and_forks_sharing_the_snapshot_elect_the_same_leader, DMMScheduleChainSetup)
{
    const int64_t t = MinChildTime();

    CDeterministicMNCPtr mnA1, mnA2;
    mn_consensus::DMMScheduleResult r1, r2;
    BOOST_REQUIRE(Resolve(Parent(), t, mnA1, r1) == mn_consensus::ScheduleStatus::OK);
    BOOST_REQUIRE(Resolve(Parent(), t, mnA2, r2) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK(mnA1->proTxHash == mnA2->proTxHash);
    BOOST_CHECK_EQUAL(r1.nRawSlot, r2.nRawSlot);
    BOOST_CHECK_EQUAL(r1.nIndex, r2.nIndex);
    BOOST_CHECK_EQUAL(r1.fRecovery, r2.fRecovery);

    // A fork block at the SAME height with a DIFFERENT hash but the same ancestry
    // and timestamp resolves to the same leader — the parent hash contributes
    // NOTHING (that was the grindable input of the removed engine).
    uint256 forkHash = ArithToUint256(arith_uint256(0xF0F0F0F0));
    CBlockIndex forkParent;
    forkParent.nHeight = Parent()->nHeight;
    forkParent.phashBlock = &forkHash;
    forkParent.nTime = Parent()->nTime;
    forkParent.pprev = Parent()->pprev;

    CDeterministicMNCPtr mnB;
    mn_consensus::DMMScheduleResult rB;
    BOOST_REQUIRE(Resolve(&forkParent, t, mnB, rB) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK_MESSAGE(mnB->proTxHash == mnA1->proTxHash,
                        "a fork parent sharing the snapshot must elect the SAME leader");

    // NEGATIVE CONTROL: the chain TIMESTAMPS are decisive for the slot — the same
    // child time against a later parent keeps dt (same slot); against the original
    // parent time a +600 s child moves the slot.
    forkParent.nTime = Parent()->nTime + 600;
    CDeterministicMNCPtr mnC;
    mn_consensus::DMMScheduleResult rC;
    BOOST_REQUIRE(Resolve(&forkParent, t + 600, mnC, rC) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK_EQUAL(rC.nRawSlot, r1.nRawSlot);   // same relative dt -> same slot
    forkParent.nTime = Parent()->nTime;
    CDeterministicMNCPtr mnD;
    mn_consensus::DMMScheduleResult rD;
    BOOST_REQUIRE(Resolve(&forkParent, t + 600, mnD, rD) == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK_MESSAGE(rD.nRawSlot != r1.nRawSlot,
                        "the block/parent timestamps must be decisive for the slot");
}

// ─────────────────────────────────────────────────────────────────────────────
// Family 8 — the display RPC shows EXACTLY the consensus schedule: same engine,
// same parent, same nTime. The producer_operator it prints is the operator key
// of the leader ResolveScheduledProducer elects.
// ─────────────────────────────────────────────────────────────────────────────
BOOST_FIXTURE_TEST_CASE(getquorum_displays_the_consensus_schedule, DMMScheduleChainSetup)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    MakeChainActive();
    const int displayHeight = Parent()->nHeight;          // a block INSIDE the chain
    CBlockIndex* pindex = IndexAt(displayHeight);
    // The resolver reads the epoch snapshot of displayHeight — computed by the
    // PRODUCTION helper (LOT 9 M3.1 anchors epochs at the activation height, so a
    // re-derived "multiple of the epoch length" would point at the wrong block).
    SeedListAt(IndexAt(mn_consensus::GetEpochSnapshotHeight(displayHeight,
                                                            consensus.DMMScheduleActivationHeight(),
                                                            consensus.nDMMScheduleEpochLength,
                                                            consensus.nDMMSetSnapshotDepth)));
    SeedListAt(pindex->pprev);   // getquorum also reads the parent list for the table

    // What consensus says for this block:
    CDeterministicMNCPtr expectedMn;
    mn_consensus::DMMScheduleResult expectedRes;
    BOOST_REQUIRE(Resolve(pindex->pprev, pindex->GetBlockTime(), expectedMn, expectedRes)
                  == mn_consensus::ScheduleStatus::OK);

    JSONRPCRequest req;
    req.fHelp = false;
    req.params = UniValue(UniValue::VARR);
    req.params.push_back(displayHeight);
    const UniValue result = getquorum(req);

    BOOST_CHECK_EQUAL(result["schedule_status"].get_str(), "ok");
    BOOST_CHECK_EQUAL(result["schedule_raw_slot"].get_int64(), expectedRes.nRawSlot);
    BOOST_CHECK_EQUAL(result["schedule_recovery_mode"].get_bool(), expectedRes.fRecovery);
    BOOST_CHECK_EQUAL(result["producer_operator"].get_str(),
                      HexStr(expectedMn->pdmnState->pubKeyOperator));
}

BOOST_AUTO_TEST_SUITE_END()

// ═════════════════════════════════════════════════════════════════════════════
// LOT 9 M3 PHASE 0 — NO_SIGNER qualified END-TO-END (real chain, real blocks)
// ═════════════════════════════════════════════════════════════════════════════
//
// Regtest with no registered MN: every post-bootstrap block resolves an
// AUTHORITATIVE empty snapshot (genesis list, valid-empty, on the active chain),
// i.e. productionSet == recoverySet == ∅. This is the exact NO_SIGNER geometry,
// exercised through the REAL pipeline: ProcessNewBlock -> AcceptBlock (stores) ->
// ActivateBestChain -> ConnectTip -> CheckBlockMNOnly.
//
// MEASURED REFUTATION OF THE state.Error VARIANT (behaviour A, ran once against
// it before the fix): the claiming block stayed a BLOCK_VALID_TRANSACTIONS
// candidate; ActivateBestChainStep kept electing it (earlier nSequenceId wins the
// work tie), ConnectTip kept failing non-invalidly, ABC aborted — and the honest
// unsigned sibling at the same height could NEVER activate. A deterministic chain
// fact expressed as a local Error is a self-inflicted wedge.
//
// DECISION (mandated, confirmed by the reproducer): a block CLAIMING a producer
// against an authoritative empty snapshot is DETERMINISTIC INVALIDITY —
// bad-dmm-no-eligible-producer, BLOCK_FAILED_VALID allowed in this sole objective
// case. DEFERRED / LOCAL_STATE_MISSING_FATAL remain strictly non-invalidating
// (proven by the suite above).
BOOST_FIXTURE_TEST_SUITE(dmm_no_signer_e2e, TestChainSetup10)

BOOST_AUTO_TEST_CASE(claiming_block_is_invalid_and_never_wedges_the_node)
{
    CBlockIndex* tipBefore = WITH_LOCK(cs_main, return chainActive.Tip());
    BOOST_REQUIRE(tipBefore && tipBefore->nHeight == 10);

    // A block "claiming" a producer: real template, then a signature is attached.
    // (vchBlockSig is not part of the header hash, so no re-finalisation needed.)
    CBlock claiming = CreateBlock({}, coinbaseKey, /*fTestBlockValidity=*/false);
    claiming.vchBlockSig.assign(70, 0x42);
    const uint256 claimingHash = claiming.GetHash();

    // First attempt through the full pipeline.
    ProcessNewBlock(std::make_shared<const CBlock>(claiming), nullptr);

    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(chainActive.Tip() == tipBefore, "the claiming block must not activate");
        auto it = mapBlockIndex.find(claimingHash);
        BOOST_REQUIRE_MESSAGE(it != mapBlockIndex.end(), "AcceptBlock must have stored the block");
        BOOST_CHECK_MESSAGE(it->second->nStatus & BLOCK_FAILED_MASK,
            "an authoritative no-signer snapshot is a CHAIN fact: the claiming block "
            "must be marked invalid (bad-dmm-no-eligible-producer), not left as a "
            "retryable candidate");
    }

    // Second attempt of the SAME candidate: no crash, no loop, verdict unchanged.
    ProcessNewBlock(std::make_shared<const CBlock>(claiming), nullptr);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip() == tipBefore);
        BOOST_CHECK(mapBlockIndex[claimingHash]->nStatus & BLOCK_FAILED_MASK);
#ifdef BATHRON_ENABLE_LAB_FINALITY_HOOK
        // The invalid block must not survive in the candidate set the next
        // ActivateBestChain will scan — that persistence was behaviour A's wedge.
        for (const uint256& h : LabGetBlockIndexCandidates()) {
            BOOST_CHECK_MESSAGE(h != claimingHash,
                                "invalid claiming block still in setBlockIndexCandidates");
        }
#endif
    }

    // PROGRESSION: an honest (unsigned — no signer exists) sibling at the same
    // height must still activate. Under behaviour A this is exactly what wedged:
    // the claiming block, received first, won the work tie forever.
    CKey siblingKey;
    siblingKey.MakeNewKey(true);
    CBlock sibling = CreateAndProcessBlock({}, siblingKey);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(chainActive.Tip()->GetBlockHash() == sibling.GetHash(),
            "the node must remain able to progress past a rejected claiming block");
        BOOST_CHECK_EQUAL(chainActive.Height(), 11);
    }

    // And the chain keeps growing normally afterwards (no residual ABC damage).
    CreateAndProcessBlock({}, coinbaseKey);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainActive.Height()), 12);
}

BOOST_AUTO_TEST_SUITE_END()
