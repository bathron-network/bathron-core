// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// INDEPENDENT REVIEW of the consensus adversarial audit (f10c9bc).
//
// These cases exist to answer two objections raised against that audit:
//
//  (1) Its AUD-002 reproducer drove signatures straight into
//      CFinalityManagerHandler::AddSignature, bypassing the network receive path
//      (CHuSignalingManager::ProcessHuSignature -> ValidateSignatureFromContext),
//      which requires a COMPACT ECDSA signature over "HUSIG"||blockHash AND a
//      verifying ECVRF sortition proof. That proved an ACCOUNTING property but not
//      that a real peer could ever drive a node into the sub-floor-final state.
//      REV-002 below closes that gap: every signature here is built exactly as
//      SignBlockWithMN + OnNewBlock build one, and is fed through the real
//      ProcessHuSignature entry point.
//
//  (2) AUD-005 (raw GetTime() on a block-validity path) was recorded as TRACE.
//      REV-005 makes it a differential: same block, same parent, same MN list —
//      only the node's wall clock differs, and the validation outcome changes.
//
// Still DESCRIPTIVE of current behaviour. No consensus code is modified.

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/mn_validation.h"
#include "consensus/validation.h"
#include "hash.h"
#include "key.h"
#include "masternode/blockproducer.h"
#include "primitives/block.h"
#include "state/finality.h"
#include "state/quorum.h"
#include "state/signaling.h"
#include "sync.h"
#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"
#include "uint256.h"
#include "utiltime.h"
#include "validation.h"
#include "vrf.h"

#include <vector>

#include <boost/test/unit_test.hpp>

// ═══════════════════════════════════════════════════════════════════════════════
// REV-002 — sub-floor finality reached through the REAL network receive path
// ═══════════════════════════════════════════════════════════════════════════════

//! Same shape as the audit's FloorBypassSetup, but every signature is delivered via
//! ProcessHuSignature with a genuine compact-ECDSA signature and a genuine ECVRF
//! sortition proof — i.e. exactly what an honest remote operator would put on the
//! wire. Distinct hash space (0xREV0…) so the process-global g_finalityCtx cache
//! cannot be shared with any other suite.
struct NetworkPathFloorSetup : public TestnetSetup {
    // > nHuFinalitySeedOffset (testnet 3), AND >= one epoch + snapshot depth so the
    // LOT 9 M3 epoch snapshot (which defines the finality population) resolves
    // inside this synthetic chain, exactly as on a real node.
    static const int NBLOCKS = 95;

    int numOps;
    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> idx;

    explicit NetworkPathFloorSetup(int numOps_ = 3)
        : numOps(numOps_), hashes(NBLOCKS), idx(NBLOCKS)
    {
        // REV-FINDING-A: g_finalityCtx (state/finality.cpp:31) is a PROCESS-GLOBAL
        // std::map keyed only by block hash, with no fixture-scoped reset and no
        // teardown hook. Every test case in a BOOST_FIXTURE_TEST_SUITE re-runs the
        // constructor — with FRESH RANDOM operator keys from BuildTestMNList — but a
        // fixture that derives its synthetic hashes from constants alone reuses the
        // SAME keys into that map. Case 2 onward then validates against case 1's
        // cached operator pubkeys and every signature is rejected as an unknown MN.
        // Varying the hash by numOps (as the audit fixtures do) separates the 3-op
        // from the 4-op fixture but NOT successive instantiations of the same one.
        // A per-instance counter is required.
        static uint32_t s_instance = 0;
        const uint32_t nonce = ++s_instance;
        mnList = BuildTestMNList(numOps, /*mnsPerOperator=*/1, operators);
        {
            LOCK(cs_main);
            for (int h = 0; h < NBLOCKS; ++h) {
                hashes[h] = ArithToUint256(arith_uint256(0x5E100000u + nonce * 0x1000u
                                                         + numOps * 0x100u + h));
                idx[h].nHeight = 7'000'000 + h;
                idx[h].phashBlock = &hashes[h];
                idx[h].pprev = (h == 0) ? nullptr : &idx[h - 1];
                idx[h].nTime = static_cast<unsigned int>(GetTime());
                deterministicMNManager->SetListForTesting(&idx[h], mnList,
                                                          /*asTip=*/(h == NBLOCKS - 1));
                mapBlockIndex[hashes[h]] = &idx[h];
            }
        }
        hu::InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
        hu::huSignalingManager = std::make_unique<hu::CHuSignalingManager>();
    }

    ~NetworkPathFloorSetup()
    {
        hu::huSignalingManager.reset();
        hu::finalityHandler.reset();
        hu::pFinalityDB.reset();
        LOCK(cs_main);
        for (int h = 0; h < NBLOCKS; ++h) mapBlockIndex.erase(hashes[h]);
        if (deterministicMNManager) deterministicMNManager->SetTipIndex(nullptr);
    }

    const CBlockIndex* Tip() const { return &idx[NBLOCKS - 1]; }

    //! Build the signature exactly as production does:
    //!   vchSig      = SignCompact(SHA256d("HUSIG" || blockHash))   [SignBlockWithMN]
    //!   vchVrfProof = ECVRF_prove(vrfKey, hash(H-k))               [OnNewBlock]
    hu::CHuSignature WireSignature(int opIdx, const CBlockIndex* pindex) const
    {
        const Consensus::Params& consensus = Params().GetConsensus();
        hu::CHuSignature sig;
        sig.blockHash = pindex->GetBlockHash();
        sig.proTxHash = operators.at(opIdx).mns.at(0).proTxHash;

        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("HUSIG");
        ss << sig.blockHash;
        BOOST_REQUIRE(operators.at(opIdx).key.SignCompact(ss.GetHash(), sig.vchSig));

        const uint256 seed = hu::GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
        const std::vector<unsigned char> msg(seed.begin(), seed.end());
        vrf::Proof proof{};
        BOOST_REQUIRE(vrf::Prove(proof, operators.at(opIdx).vrfKey.begin(), msg));
        sig.vchVrfProof.assign(proof.begin(), proof.end());
        return sig;
    }

    bool DeliverOverNetwork(int opIdx, const CBlockIndex* pindex) const
    {
        // pfrom = nullptr  -> skip the per-peer rate limit (as ProcessPendingSigs does)
        // connman = nullptr -> BroadcastSignature returns early (signaling.cpp:448)
        return hu::huSignalingManager->ProcessHuSignature(WireSignature(opIdx, pindex),
                                                          nullptr, nullptr);
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_audit_review_rev002, NetworkPathFloorSetup)

// The wire-format signatures really are accepted by the full validation path — if
// this fails, everything below is vacuous.
BOOST_AUTO_TEST_CASE(wire_signatures_pass_real_validation)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(consensus.nHuQuorumSize, 4);
        BOOST_REQUIRE_EQUAL(hu::HuFinalityOperatorCount(Tip()->GetBlockHash()), 3);
    }
    // Every operator is VRF-selected here because E (128) >= N (3) short-circuits
    // IsVrfSelected (quorum.cpp:88-90) — so sub-floor populations are FULLY drawn.
    BOOST_CHECK(DeliverOverNetwork(0, Tip()));
    BOOST_CHECK(DeliverOverNetwork(1, Tip()));
}

// A tampered signature must be REJECTED by the same path — proves the path is
// really validating and not just accepting anything handed to it.
BOOST_AUTO_TEST_CASE(control_forged_signature_is_rejected)
{
    hu::CHuSignature bad = WireSignature(0, Tip());
    bad.vchSig[10] ^= 0xff;                       // break the ECDSA recovery
    bool misbehave = false;
    BOOST_CHECK(!hu::huSignalingManager->ProcessHuSignature(bad, nullptr, nullptr, &misbehave));
    BOOST_CHECK(misbehave);

    hu::CHuSignature noVrf = WireSignature(1, Tip());
    noVrf.vchVrfProof.clear();                    // strip the sortition proof
    BOOST_CHECK(!hu::huSignalingManager->ProcessHuSignature(noVrf, nullptr, nullptr));

    // Neither forgery moved the needle.
    BOOST_CHECK(!hu::pFinalityDB->IsBlockFinal(Tip()->GetBlockHash()));
}

// LOT 4 — THE INVERSION the remediation matrix demands ("REV-002 must invert:
// sub-floor never final via the network path").
//
// This case USED TO PROVE the defect: two honest remote operators, signing over the
// wire with valid ECDSA + valid ECVRF proofs, drove a population of N=3 (< floor 4)
// to FINAL. The signatures are still genuine and still accepted — what changed is
// that the Sybil floor is now applied in HuActiveFinalityThreshold, so no achievable
// count finalizes a sub-floor population. Emission and irreversibility now AGREE.
BOOST_AUTO_TEST_CASE(subfloor_population_never_finalizes_over_the_wire)
{
    const uint256 blockHash = Tip()->GetBlockHash();
    const int height = Tip()->nHeight;

    // Precondition: the population really is below the floor, and the threshold is
    // therefore unreachable — otherwise the case would pass for the wrong reason.
    const Consensus::Params& consensus = Params().GetConsensus();
    BOOST_REQUIRE_EQUAL(hu::HuFinalityOperatorCount(blockHash), 3);
    BOOST_REQUIRE_EQUAL(consensus.nHuQuorumSize, 4);
    BOOST_REQUIRE(!hu::HuFinalityFloorMet(consensus, 3));

    // The wire path still ACCEPTS the signatures — the fix is not "reject honest
    // operators", it is "do not call a sub-floor population final".
    BOOST_REQUIRE(DeliverOverNetwork(0, Tip()));
    BOOST_CHECK(!hu::pFinalityDB->IsBlockFinal(blockHash));

    BOOST_REQUIRE(DeliverOverNetwork(1, Tip()));   // 2 of 3 — the OLD threshold
    BOOST_CHECK_MESSAGE(!hu::pFinalityDB->IsBlockFinal(blockHash),
                        "AUD-002: a sub-floor population must NEVER be final");
    BOOST_CHECK_MESSAGE(!hu::finalityHandler->HasFinality(height, blockHash),
                        "AUD-002: HasFinality must honour the floor");

    // Even with EVERY operator signing, the floor still refuses.
    BOOST_REQUIRE(DeliverOverNetwork(2, Tip()));   // 3 of 3 — unanimous, still < floor
    BOOST_CHECK_MESSAGE(!hu::pFinalityDB->IsBlockFinal(blockHash),
                        "AUD-002: unanimity below the floor is still not finality");

    // Emission and irreversibility now agree: HasQuorum refused all along.
    BOOST_CHECK(!hu::huSignalingManager->HasQuorum(blockHash));

    // ...and the chain-level guard consulted by ConnectBlock/AcceptBlockHeader is no
    // longer driven by a sub-floor record.
    uint256 conflicting = blockHash;
    *conflicting.begin() ^= 0xff;
    BOOST_CHECK_MESSAGE(!hu::finalityHandler->HasConflictingFinality(height, conflicting),
                        "AUD-002: a sub-floor record must not drive HasConflictingFinality");
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// REV-005 — HISTORICAL: the node's wall clock changed a ConnectBlock outcome.
// **FIXED IN LOT 3 (AUD-005). These cases are INVERTED and now guard the fix.**
// ═══════════════════════════════════════════════════════════════════════════════
//
// What the defect WAS (the code below no longer exists):
//   ConnectBlock -> CheckBlockMNOnly -> VerifyBlockProducerSignature
//         -> int64_t currentTime = GetTime();                 // RAW local clock
//            if (block.nTime > currentTime + 120) DoS(10, "bad-mn-time-future")
// GetTime() is the raw local clock; block.nTime is fixed, the comparand was not —
// and because the verdict was a state.DoS it PERSISTED BLOCK_FAILED_VALID.
//
// LOT 3 removed the gate outright (the remediation the finding itself prescribes).
// The surviving future-time bound is CheckBlockTime's `time-too-new`
// (GetAdjustedTime() + 14 s) — tighter, and non-persisting because it runs before
// AddToBlockIndex. The cases below now assert clock INVARIANCE at both producer
// verifiers and at the CheckBlockMNOnly entry point; the suite
// consensus_lot3_future_time_bound covers the surviving bound itself.

// LOT 9 M1+M2 NOTE: the fixture now builds a REAL ancestor chain (the schedule
// engine resolves the epoch snapshot through pindexPrev->GetAncestor), and the
// per-block producer verifier is VerifyScheduledProducerSignature judging against
// the leader ResolveScheduledProducer elects. The clock-invariance claims are
// unchanged — neither the resolver nor the verifier may consult a local clock.
struct ProducerClockSetup : public DMMScheduleChainSetup {
    ProducerClockSetup() : DMMScheduleChainSetup(/*numOperators=*/3, /*mnsPerOperator=*/1) {}

    ~ProducerClockSetup()
    {
        SetMockTime(0);                   // never leak a frozen clock into another suite
    }

    //! Resolve the scheduled leader for a child of Parent() at `nTime` (must be OK).
    CDeterministicMNCPtr LeaderAt(int64_t nTime)
    {
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        LOCK(cs_main);
        BOOST_REQUIRE(mn_consensus::ResolveScheduledProducer(Parent(), nTime, mn, res)
                      == mn_consensus::ScheduleStatus::OK);
        return mn;
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_audit_review_rev005, ProducerClockSetup)

// LOT 3 — THE INVERSION. This case used to PROVE the defect: the same block, judged
// under two different local clocks, was rejected for two different reasons, and the
// 120 s boundary was exact. AUD-005 is fixed by REMOVING that gate, so the case now
// asserts the opposite: the verdict is INVARIANT under the local clock.
//
// The sweep deliberately includes the old boundary (−120/−121) and values far beyond
// it in both directions: if anyone reintroduces a wall-clock gate at any threshold,
// one of these points diverges and this test fails.
BOOST_AUTO_TEST_CASE(local_clock_no_longer_changes_the_validation_outcome)
{
    const int64_t blockTime = MinChildTime();     // fixed, well-defined block timestamp

    CBlock block;
    block.nTime = static_cast<unsigned int>(blockTime);
    block.vchBlockSig.clear();                    // empty -> "bad-mn-sig-empty" if reached

    const CDeterministicMNCPtr leader = LeaderAt(blockTime);

    // Reference verdict, clock exactly at the block's own time.
    SetMockTime(blockTime);
    CValidationState ref;
    BOOST_REQUIRE(!mn_consensus::VerifyScheduledProducerSignature(block, leader, ref));
    const std::string refReason = ref.GetRejectReason();
    BOOST_CHECK_EQUAL(refReason, "bad-mn-sig-empty");   // reached the signature checks

    // Every one of these offsets used to change the answer; none may now. −600 and
    // −121 previously returned "bad-mn-time-future".
    const std::vector<int64_t> offsets = {
        -100000, -3600, -600, -121, -120, -119, -1, 0, +1, +120, +600, +3600, +100000
    };
    for (int64_t off : offsets) {
        SetMockTime(blockTime + off);
        CValidationState st;
        const bool ok = mn_consensus::VerifyScheduledProducerSignature(block, LeaderAt(blockTime), st);
        BOOST_CHECK_MESSAGE(!ok, "offset " << off << ": unexpected acceptance");
        BOOST_CHECK_MESSAGE(st.GetRejectReason() == refReason,
                            "AUD-005: local clock offset " << off << " changed the verdict ('"
                            << st.GetRejectReason() << "' vs '" << refReason << "')");
        BOOST_CHECK_MESSAGE(st.GetRejectReason() != "bad-mn-time-future",
                            "offset " << off << ": the removed wall-clock gate is back");
    }

    // And with NO mock clock at all (real system time), the verdict is still the same.
    SetMockTime(0);
    CValidationState live;
    BOOST_CHECK(!mn_consensus::VerifyScheduledProducerSignature(block, LeaderAt(blockTime), live));
    BOOST_CHECK_EQUAL(live.GetRejectReason(), refReason);
}

// LOT 3 follow-up #1 (a reviewer's surviving mutant M7). The sweep above calls the
// producer verifier DIRECTLY, so a wall-clock gate planted ONE LAYER UP — in
// CheckBlockMNOnly, the sole ConnectBlock caller — was equally persisted as
// BLOCK_FAILED_VALID and passed the entire suite. The earlier comment claiming the
// sweep catches a gate "at any threshold" was therefore false for that layer.
// This case closes it at the real ConnectBlock entry point (which now resolves the
// schedule too — so it also guards the RESOLVER's clock-independence).
BOOST_AUTO_TEST_CASE(check_block_mn_only_is_clock_invariant)
{
    const int64_t blockTime = MinChildTime();
    CBlock block;
    block.nTime = static_cast<unsigned int>(blockTime);
    block.vchBlockSig.clear();

    auto entryPoint = [&](int64_t mockNow) {
        SetMockTime(mockNow);
        CValidationState st;
        LOCK(cs_main);
        CheckBlockMNOnly(block, Parent(), st);
        return st.GetRejectReason();
    };

    const std::string ref = entryPoint(blockTime);
    // Anti-vacuity: the entry point must actually reach the producer verifier here,
    // otherwise every comparison below is "" == "".
    BOOST_REQUIRE_MESSAGE(!ref.empty(),
                          "CheckBlockMNOnly returned no reason — it did not reach the verifier, "
                          "so this guard would be vacuous");
    BOOST_CHECK_EQUAL(ref, "bad-mn-sig-empty");

    for (int64_t off : {-100000, -3600, -600, -121, -120, -1, +1, +120, +121, +3600, +100000}) {
        const std::string got = entryPoint(blockTime + off);
        BOOST_CHECK_MESSAGE(got == ref,
                            "AUD-005: a clock gate at the CheckBlockMNOnly layer — offset "
                            << off << " gave '" << got << "' vs '" << ref << "'");
        BOOST_CHECK_MESSAGE(got != "bad-mn-time-future",
                            "offset " << off << ": the removed wall-clock gate is back one layer up");
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 3 follow-up #2 (a reviewer's surviving mutant M8) — the bound LOT 3 now
// RELIES ON had zero test coverage anywhere in the tree.
// ═══════════════════════════════════════════════════════════════════════════════
//
// Removing the producer-side wall-clock gate is only safe because CheckBlockTime
// already rejects `time-too-new` at GetAdjustedTime() + FutureBlockTimeDrift (14 s),
// earlier on the same path and — crucially — WITHOUT persisting BLOCK_FAILED_VALID.
// Disabling that check left the whole suite green, i.e. LOT 3 leaned on an untested
// guarantee. It is tested here.
//
// CheckBlockTime has external linkage but no header declaration; declared locally so
// no production file is touched.
bool CheckBlockTime(const CBlockHeader& block, CValidationState& state, CBlockIndex* const pindexPrev);

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 3 pre-acceptance — L3-F2 / L3-F3 QUALIFICATION (executable)
// ═══════════════════════════════════════════════════════════════════════════════
//
// L3-F3: AcceptBlock (validation.cpp:3929-3956) runs a producer check ONLY when
//   `!IsRegTestNet() && pindexPrev && !IsInitialBlockDownload() && !blockAheadOfTip`,
// and on failure does `pindex->nStatus |= BLOCK_FAILED_VALID` + setDirtyBlockIndex
// — i.e. a PERSISTED verdict behind a node-local, clock-derived guard
// (IsInitialBlockDownload reads GetTime() at validation.cpp:1290).
//
// The question that decides whether this is a defect: does the guard change the
// VERDICT, or only WHERE/WHEN the same verdict is rendered? A node that skips the
// AcceptBlock check still reaches ConnectBlock -> CheckBlockMNOnly ->
// VerifyBlockProducerSignature. So divergence is possible ONLY IF the two producer
// verifiers can disagree on accept/reject for the same (block, parent, mnList) —
// which is exactly L3-F2.
//
// These cases answer that mechanically, including a REALLY SIGNED block so the
// "accept" outcome is exercised and the agreement is not trivially reject==reject.

// LOT 9 M1+M2 NOTE: both verifiers now judge against the SAME resolved leader
// (ResolveScheduledProducer + VerifyScheduledProducerSignature) — the agreement
// property below is what the wiring must preserve, and this suite would catch a
// re-divergence (e.g. one path re-wired onto a different engine).
struct TwoVerifierSetup : public DMMScheduleChainSetup {
    TwoVerifierSetup() : DMMScheduleChainSetup(/*numOperators=*/3, /*mnsPerOperator=*/1) {}
    ~TwoVerifierSetup() { SetMockTime(0); }

    //! What the AcceptBlock-side check (run only by a NON-IBD node) would decide.
    bool AcceptSide(const CBlock& b, std::string& reason) const
    {
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        CValidationState st;
        bool ok;
        {
            LOCK(cs_main);
            ok = mn_consensus::ResolveScheduledProducer(
                     const_cast<TwoVerifierSetup*>(this)->Parent(), b.nTime, mn, res)
                     == mn_consensus::ScheduleStatus::OK
                 && mn_consensus::VerifyScheduledProducerSignature(b, mn, st);
        }
        reason = st.GetRejectReason();
        return ok;
    }
    //! What the ConnectBlock-side check decides — reached by EVERY node, including
    //! one that skipped the AcceptBlock check because it believed itself in IBD.
    bool ConnectSide(const CBlock& b, std::string& reason) const
    {
        CValidationState st;
        bool ok;
        {
            LOCK(cs_main);
            ok = CheckBlockMNOnly(b, const_cast<TwoVerifierSetup*>(this)->Parent(), st);
        }
        reason = st.GetRejectReason();
        return ok;
    }

    //! A block whose signature is genuinely produced by the SCHEDULED producer, so
    //! both verifiers must ACCEPT it.
    CBlock ValidlySignedBlock()
    {
        CBlock b;
        b.nTime = static_cast<unsigned int>(MinChildTime());

        CDeterministicMNCPtr expected;
        mn_consensus::DMMScheduleResult res;
        {
            LOCK(cs_main);
            BOOST_REQUIRE(mn_consensus::ResolveScheduledProducer(Parent(), b.nTime, expected, res)
                          == mn_consensus::ScheduleStatus::OK);
        }
        SignBlockAs(expected->proTxHash, b);
        return b;
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_lot3_two_verifier_agreement, TwoVerifierSetup)

// L3-F2 — the two producer verifiers must never DISAGREE on accept/reject for the
// same (block, parent, MN list). They may differ on the reject REASON string; that
// is cosmetic. This is the property L3-F3 depends on.
BOOST_AUTO_TEST_CASE(the_two_verifiers_never_disagree_on_accept_or_reject)
{
    struct Shape { const char* name; CBlock block; };
    std::vector<Shape> shapes;

    // 1. genuinely valid: both must ACCEPT (this is what makes the test non-trivial)
    shapes.push_back({"validly signed", ValidlySignedBlock()});

    // 2. empty signature — the one shape where the REASONS differ by design
    {
        CBlock b = ValidlySignedBlock(); b.vchBlockSig.clear();
        shapes.push_back({"empty signature", b});
    }
    // 3. wrong size
    {
        CBlock b = ValidlySignedBlock(); b.vchBlockSig.assign(10, 0x01);
        shapes.push_back({"undersized signature", b});
    }
    // 4. right size, garbage content -> signature verification fails
    {
        CBlock b = ValidlySignedBlock(); b.vchBlockSig.assign(70, 0x7F);
        shapes.push_back({"garbage signature", b});
    }
    // 5. valid signature but a DIFFERENT nTime, so the expected producer changes
    {
        CBlock b = ValidlySignedBlock();
        b.nTime += 15 * 40;                 // walk far into the fallback slots
        shapes.push_back({"signature bound to another slot", b});
    }

    bool sawAccept = false, sawReject = false;
    for (auto& s : shapes) {
        std::string ra, rc;
        const bool acc = AcceptSide(s.block, ra);
        const bool con = ConnectSide(s.block, rc);
        BOOST_CHECK_MESSAGE(acc == con,
            "L3-F2: the two producer verifiers DISAGREE on '" << s.name << "' — "
            "AcceptBlock side=" << acc << " ('" << ra << "'), ConnectBlock side="
            << con << " ('" << rc << "')");
        acc ? sawAccept = true : sawReject = true;
    }
    // Anti-vacuity: the matrix must contain at least one ACCEPT and one REJECT,
    // otherwise "they agree" would be a tautology.
    BOOST_CHECK_MESSAGE(sawAccept, "no shape was accepted — agreement would be trivial");
    BOOST_CHECK_MESSAGE(sawReject, "no shape was rejected — agreement would be trivial");
}

// L3-F3 REPRODUCER — same parent, same signed block, same chain state; one node
// behaves as IBD (skips the AcceptBlock producer check) and the other as non-IBD
// (runs it). What is ASSERTED equal is the VERDICT (accept/reject) and therefore the
// resulting BLOCK_FAILED_VALID. The reject-reason strings are captured only to make
// a failure message readable — they are NOT asserted equal and may legitimately
// differ between the two paths (an empty signature yields bad-mn-sig-size on the
// AcceptBlock side and bad-mn-sig-empty on the ConnectBlock side). Consensus depends
// on the verdict and the persisted status, not on the diagnostic text.
//
// The AcceptBlock branch is regtest-exempt and needs a full chain, so the two node
// behaviours are reproduced at the decision level: the IBD node evaluates ONLY the
// ConnectBlock-side check (which every node always reaches), the non-IBD node
// evaluates the AcceptBlock-side check first and then the ConnectBlock one.
BOOST_AUTO_TEST_CASE(ibd_and_non_ibd_nodes_reach_the_same_persisted_verdict)
{
    // Model the persisted outcome: BLOCK_FAILED_VALID is set when a producer check
    // fails — at AcceptBlock (validation.cpp:3949) or, later, via ConnectBlock ->
    // InvalidBlockFound. Either way the trigger is `state.IsInvalid()`.
    auto nodeInIBD = [&](const CBlock& b, std::string& reason) {
        return ConnectSide(b, reason);                       // AcceptBlock check skipped
    };
    auto nodeNotInIBD = [&](const CBlock& b, std::string& reason) {
        std::string ra;
        if (!AcceptSide(b, ra)) { reason = ra; return false; }   // rejected before storage
        return ConnectSide(b, reason);
    };

    const CBlock good = ValidlySignedBlock();
    CBlock bad = ValidlySignedBlock();
    bad.vchBlockSig.assign(70, 0x7F);                        // valid size, bad content

    for (const auto& pair : {std::make_pair("valid block", good),
                             std::make_pair("invalid block", bad)}) {
        // Clock is varied too: IBD is itself clock-derived, so the reproducer must
        // show the verdict is invariant under BOTH.
        for (int64_t off : {-100000, 0, +100000}) {
            SetMockTime(1'900'000'000 + off);
            std::string rIbd, rLive;
            const bool okIbd  = nodeInIBD(pair.second, rIbd);
            const bool okLive = nodeNotInIBD(pair.second, rLive);
            BOOST_CHECK_MESSAGE(okIbd == okLive,
                "L3-F3: IBD and non-IBD nodes disagree on '" << pair.first
                << "' at clock offset " << off << " (IBD=" << okIbd << " '" << rIbd
                << "' vs non-IBD=" << okLive << " '" << rLive << "')");
            // The persisted marking follows the verdict, so identical verdicts mean
            // identical BLOCK_FAILED_VALID outcomes.
            BOOST_CHECK_EQUAL(!okIbd, !okLive);
        }
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(consensus_lot3_future_time_bound, TestnetSetup)

BOOST_AUTO_TEST_CASE(check_block_time_still_bounds_far_future_blocks)
{
    // Parent well past nDMMBootstrapHeight (testnet 250), so the bootstrap
    // relaxation inside CheckBlockTime does not apply.
    uint256 prevHash = ArithToUint256(arith_uint256(0xC10C0777));
    CBlockIndex prevIdx;
    prevIdx.nHeight = 5'000'000;
    prevIdx.phashBlock = &prevHash;
    const int64_t now = 1'900'000'000;
    prevIdx.nTime = static_cast<unsigned int>(now - 600);   // parent safely in the past
    SetMockTime(now);

    const int slot = 15;                       // nTimeSlotLength; timestamps must align
    auto headerAt = [&](int64_t t) {
        CBlockHeader h;
        h.nTime = static_cast<unsigned int>(t - (t % slot));   // satisfy the time mask
        return h;
    };

    // A block ~1 hour in the future MUST still be rejected, and with the
    // non-persisting reason (time-too-new), not the removed producer gate.
    {
        CValidationState st;
        CBlockHeader far = headerAt(now + 3600);
        BOOST_CHECK_MESSAGE(!CheckBlockTime(far, st, &prevIdx),
                            "a far-future block must still be rejected after LOT 3");
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "time-too-new");
    }

    // The bound is TIGHTER than the 120 s gate LOT 3 removed: a block 120 s ahead
    // (which the old gate accepted) is rejected by this one.
    {
        CValidationState st;
        CBlockHeader oldGateWouldAccept = headerAt(now + 120);
        BOOST_CHECK_MESSAGE(!CheckBlockTime(oldGateWouldAccept, st, &prevIdx),
                            "the surviving bound must be tighter than the removed 120s gate");
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "time-too-new");
    }

    // ...and a block inside the drift window is accepted (so the check is a real
    // boundary, not a blanket reject that would make the two cases above trivial).
    {
        CValidationState st;
        CBlockHeader ok = headerAt(now);      // aligned down: <= now+14 and > parent
        BOOST_CHECK_MESSAGE(CheckBlockTime(ok, st, &prevIdx),
                            "a near-present block must be accepted: " << st.GetRejectReason());
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
