// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// CONSENSUS ADVERSARIAL AUDIT 2026-07 — differential reproducers.
//
// Every case here answers ONE question: can two honest nodes running THIS code,
// fed the SAME block with the SAME deterministic parent context, reach DIFFERENT
// verdicts because of node-local state?
//
// The suites are DESCRIPTIVE of current behaviour. Where current behaviour is the
// defect, the assertion records the defect and a comment states what the correct
// behaviour would be. NO consensus code is modified by this commit.
//
//   AUD-001  CheckBtcHeadersTx resolves the publisher (R1) and the operator key
//            (R2) from the node-local chain TIP instead of the block's parent.
//            Two nodes at different tips → different verdicts on the same tx.
//   AUD-002  The Sybil floor nHuQuorumSize is enforced only inside
//            CHuSignalingManager::HasQuorum, and its sole consensus-side caller
//            PreviousBlockHasQuorum immediately OR-s past it via two floor-free
//            fallbacks. The floor is therefore not load-bearing anywhere.
//   AUD-003  The BTC-burn kill switch (a process-local, RPC-mutable atomic) is
//            read inside CreateMintM0BTC, which ProcessSpecialTxsInBlock uses as
//            the ORACLE for the expected mint. Flipping it changes the expected
//            mint for an already-produced block.

#include "arith_uint256.h"
#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "burnclaim/burnclaim.h"
#include "burnclaim/burnclaimdb.h"
#include "burnclaim/killswitch.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "htlc/htlcdb.h"        // g_htlcdb — fixture hygiene (see KillSwitchOracleSetup)
#include "key.h"
#include "primitives/transaction.h"
#include "state/finality.h"
#include "state/settlementdb.h" // g_settlementdb — fixture hygiene
#include "state/quorum.h"
#include "state/signaling.h"
#include "sync.h"
#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"
#include "uint256.h"
#include "util/system.h"   // LOT 2: gArgs — exercise the -enablemint producer policy
#include "utiltime.h"
#include "validation.h"

#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

BtcBlockHeader AuditDummyHeader(uint32_t nonce)
{
    BtcBlockHeader h;
    h.nVersion = 4;
    h.hashPrevBlock = ArithToUint256(arith_uint256(0x5EED) + nonce);
    h.hashMerkleRoot = ArithToUint256(arith_uint256(nonce) + 7);
    h.nTime = 2000 + nonce;
    h.nBits = 0x1d00ffff;
    h.nNonce = nonce;
    return h;
}

BtcHeadersPayload AuditPayload(const uint256& publisher, uint32_t startHeight)
{
    BtcHeadersPayload p;
    p.nVersion = BTCHEADERS_VERSION;
    p.publisherProTxHash = publisher;
    p.startHeight = startHeight;
    p.headers = {AuditDummyHeader(startHeight)};
    p.count = 1;
    return p;
}

CTransactionRef AuditToTx(const BtcHeadersPayload& p)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;
    SetTxPayload(mtx, p);
    return MakeTransactionRef(std::move(mtx));
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════════
// AUD-001 — TX_BTC_HEADERS publisher and operator key: PARENT, never the local tip
// ═══════════════════════════════════════════════════════════════════════════════
//
// ✅ CORRIGÉ — LOT 5, branche claude/fix-aud001-parent-context.
//
// THIS SUITE WAS INVERTED. It previously asserted the DEFECT: same tx, same parent,
// verdict flipping with the local tip. The audit's own text flagged it FLIP-ON-FIX
// ("whoever lands the fix must rewrite this case, not just delete a line"), and the
// independent review (C-b) warned that even `acceptedA != acceptedB` is not
// fix-stable — a correct fix makes them EQUAL. So every case below now asserts the
// FIXED property, and each carries the pre-fix observation it replaced, so the
// inversion is auditable without git archaeology.
//
// CheckBtcHeadersTx(tx, pindexPrev, state) is reached from
//   ConnectBlock (validation.cpp)
//     -> ProcessSpecialTxsInBlock(block, pindex, ...)
//        -> CheckSpecialTx(*tx, pindex->pprev, view, state)     <-- parent IS passed
//           -> CheckBtcHeadersTx(tx, pindexPrev, state)
// and the two MN lookups inside it now USE pindexPrev:
//   btcheaders.cpp  R1  deterministicMNManager->GetListForBlock(pindexPrev).GetMN(...)
//   btcheaders.cpp  R2  verified inline against the dmn R1 already resolved
//
// The fixture pins the parent context and varies ONLY the local tip. The verdict
// must not move. Note the direction that matters most: it is not enough for the tip
// to be "no longer consulted" — the PARENT must be authoritative, which the
// fail-closed cases below pin from the other side (publisher present at the tip,
// absent from the parent => still rejected).
//
// SCOPE (independent review, C-d): TestnetSetup leaves g_btcheadersdb null, so the
// whole `if (pindexPrev && g_btcheadersdb)` block — R3/R3', R4, F5 checkpoint, R5
// PoW, R6 difficulty — is skipped. On a real node this payload is rejected by R3 at
// every tip. What is proven here is the R1/R2 VERDICT, which is the finding.

//! Two synthetic blocks with DIFFERENT injected MN lists: PARENT (the block's real
//! deterministic context) and OTHER (some other chain position a node's tip may sit
//! at). Both are registered so GetListForBlock resolves either one.
struct TipVsParentSetup : public TestnetSetup {
    std::vector<TestOperator> parentOps;   // 3 operators: proTxHash 1,2,3
    std::vector<TestOperator> otherOps;    // 1 operator : proTxHash 1 (different key)
    CDeterministicMNList parentList;
    CDeterministicMNList otherList;

    // AUD-001 (LOT 5): a REAL grandparent, with its own list, chained under the
    // parent. Without it `parentIdx.pprev` is null and an off-by-one mutation
    // (grandparent instead of parent — the classic slip in this codebase, where
    // pindex vs pindex->pprev is one character) degenerates to a no-op and SURVIVES.
    // A surviving mutant is what put this here.
    std::vector<TestOperator> grandOps;
    CDeterministicMNList grandList;

    uint256 parentHash;
    uint256 otherHash;
    uint256 grandHash;
    CBlockIndex parentIdx;
    CBlockIndex otherIdx;
    CBlockIndex grandIdx;

    TipVsParentSetup()
    {
        // BuildTestMNList restarts its proTxHash counter at 1 on every call, so the
        // 3-operator list holds proTxHash {1,2,3} and the 1-operator list holds {1}
        // with a DIFFERENT operator key. That gives us both divergence shapes:
        //   proTxHash 3 -> present in parent, ABSENT from other  (R1 membership)
        //   proTxHash 1 -> present in both, DIFFERENT key        (R2 signature)
        parentList = BuildTestMNList(/*numOperators=*/3, /*mnsPerOperator=*/1, parentOps);
        otherList = BuildTestMNList(/*numOperators=*/1, /*mnsPerOperator=*/1, otherOps);
        // 2 operators: proTxHash {1,2}. proTxHash 3 (the publisher used below) is
        // registered in the PARENT and absent from the GRANDPARENT, which is what
        // makes the off-by-one observable.
        grandList = BuildTestMNList(/*numOperators=*/2, /*mnsPerOperator=*/1, grandOps);

        parentHash = ArithToUint256(arith_uint256(0xADD00001));
        otherHash = ArithToUint256(arith_uint256(0xADD00002));

        // Heights well past nDMMBootstrapHeight (testnet 250) so skipMNChecks is
        // false and R1/R2 actually run, and in the UPGRADE_V6_0-active range so
        // GetListForBlock does not early-return empty.
        grandHash = ArithToUint256(arith_uint256(0xADD00003));

        grandIdx.nHeight = 4'999'999;
        grandIdx.phashBlock = &grandHash;
        parentIdx.nHeight = 5'000'000;
        parentIdx.phashBlock = &parentHash;
        parentIdx.pprev = &grandIdx;                 // real chain link
        otherIdx.nHeight = 5'000'100;
        otherIdx.phashBlock = &otherHash;

        LOCK(cs_main);
        deterministicMNManager->SetListForTesting(&grandIdx, grandList, /*asTip=*/false);
        deterministicMNManager->SetListForTesting(&parentIdx, parentList, /*asTip=*/false);
        deterministicMNManager->SetListForTesting(&otherIdx, otherList, /*asTip=*/false);
        mapBlockIndex[grandHash] = &grandIdx;
        mapBlockIndex[parentHash] = &parentIdx;
        mapBlockIndex[otherHash] = &otherIdx;
    }

    ~TipVsParentSetup()
    {
        LOCK(cs_main);
        mapBlockIndex.erase(grandHash);
        mapBlockIndex.erase(parentHash);
        mapBlockIndex.erase(otherHash);
        if (deterministicMNManager) deterministicMNManager->SetTipIndex(nullptr);
    }

    void SetLocalTip(const CBlockIndex* pindex)
    {
        deterministicMNManager->SetTipIndex(pindex);
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_divergence_aud001, TipVsParentSetup)

// Control: the parent list really does contain the publisher, so the ONLY thing
// that can make the verdict differ below is where the local tip points.
BOOST_AUTO_TEST_CASE(precondition_publisher_is_in_parent_list_only)
{
    const uint256 proTx3 = parentOps[2].mns[0].proTxHash;
    BOOST_REQUIRE(parentList.GetMN(proTx3) != nullptr);   // in the block's own context
    BOOST_REQUIRE(otherList.GetMN(proTx3) == nullptr);    // not at the other tip
}

// PREUVE 2 — R1 membership. SAME tx, SAME parent, local tip moved across every
// position a node can be in: at the parent, at an unrelated block whose list does
// NOT contain the publisher, and NULL (the ReplayBlocks state). The publisher is a
// registered MN in the block's own context, so all three must ACCEPT.
//
// PRE-FIX OBSERVATION (this case asserted it): accepted with tip==parent, rejected
// `bad-btcheaders-unknown-mn` with the tip elsewhere.
BOOST_AUTO_TEST_CASE(r1_membership_verdict_is_parent_decided)
{
    const uint256 proTx3 = parentOps[2].mns[0].proTxHash;
    BtcHeadersPayload p = AuditPayload(proTx3, 300000);
    BOOST_REQUIRE(parentOps[2].key.Sign(p.GetSignatureHash(), p.sig));
    const CTransactionRef tx = AuditToTx(p);

    // The reachable windows are startup-only (independent review, C-c): ReplayBlocks
    // (tip pointer still null) and VerifyDB at -checklevel=4 (pindex walks forward
    // while tipIndex stays at the real tip, judging replayed blocks against a FUTURE
    // list). Throughout ActivateBestChainStep the DMN tip equals pindex->pprev, which
    // is why this was never a live fork — an incidental ordering invariant in an
    // unrelated file, which is exactly what the fix removes reliance on.
    SetLocalTip(&parentIdx);
    CValidationState stateAtParent;
    const bool acceptedAtParent = CheckBtcHeadersTx(*tx, &parentIdx, stateAtParent);

    SetLocalTip(&otherIdx);                       // VerifyDB -checklevel=4 window
    CValidationState stateAtOther;
    const bool acceptedAtOther = CheckBtcHeadersTx(*tx, &parentIdx, stateAtOther);

    SetLocalTip(nullptr);                          // ReplayBlocks window
    CValidationState stateAtNull;
    const bool acceptedAtNull = CheckBtcHeadersTx(*tx, &parentIdx, stateAtNull);

    BOOST_CHECK_MESSAGE(acceptedAtParent, "publisher is in the parent list: must accept");
    BOOST_CHECK_MESSAGE(acceptedAtOther,
                        "AUD-001: same tx + same parent must not be rejected because the tip moved");
    BOOST_CHECK_MESSAGE(acceptedAtNull,
                        "AUD-001: ReplayBlocks (null tip) must not reject every publisher");
    // Stated as an equality, not as `a != b`: the property is agreement, and it must
    // keep holding if all three verdicts ever become reject for some other reason.
    BOOST_CHECK_EQUAL(acceptedAtParent, acceptedAtOther);
    BOOST_CHECK_EQUAL(acceptedAtParent, acceptedAtNull);
    BOOST_CHECK_EQUAL(stateAtParent.GetRejectReason(), stateAtOther.GetRejectReason());
    BOOST_CHECK_EQUAL(stateAtParent.GetRejectReason(), stateAtNull.GetRejectReason());
}

// PREUVE 2 — R2 operator key. proTxHash 1 exists in BOTH lists but under a DIFFERENT
// operator key. Pre-fix, VerifySignature() took the key from the tip, so a signature
// valid in the block's own context failed once the tip moved past a ProUpRegTx that
// rotated that operator's key — `bad-btcheaders-sig`. The key must come from the
// parent, so the verdict must not move.
BOOST_AUTO_TEST_CASE(r2_operator_key_is_parent_decided)
{
    const uint256 proTx1 = parentOps[0].mns[0].proTxHash;
    BOOST_REQUIRE(otherList.GetMN(proTx1) != nullptr);   // same proTxHash present
    BOOST_REQUIRE(parentOps[0].key.GetPubKey() != otherOps[0].key.GetPubKey());

    BtcHeadersPayload p = AuditPayload(proTx1, 300000);
    BOOST_REQUIRE(parentOps[0].key.Sign(p.GetSignatureHash(), p.sig));
    const CTransactionRef tx = AuditToTx(p);

    SetLocalTip(&parentIdx);
    CValidationState stateAtParent;
    const bool acceptedAtParent = CheckBtcHeadersTx(*tx, &parentIdx, stateAtParent);

    SetLocalTip(&otherIdx);                        // rotated key at the tip
    CValidationState stateAtOther;
    const bool acceptedAtOther = CheckBtcHeadersTx(*tx, &parentIdx, stateAtOther);

    BOOST_CHECK(acceptedAtParent);
    BOOST_CHECK_MESSAGE(acceptedAtOther,
                        "AUD-001: R2 must verify against the PARENT's operator key, not the tip's");
    BOOST_CHECK_EQUAL(acceptedAtParent, acceptedAtOther);
    BOOST_CHECK_EQUAL(stateAtParent.GetRejectReason(), stateAtOther.GetRejectReason());
}

// FAIL-CLOSED, THE DIRECTION THAT MATTERS. Everything above would also pass if the
// fix had simply stopped rejecting. These pin the converse: the PARENT is
// authoritative, so a publisher the parent does not know is refused EVEN WHEN the
// local tip does know it. Without this pair, a "fix" that consulted the union of
// both lists, or that dropped R1 entirely, would go green.
BOOST_AUTO_TEST_CASE(publisher_absent_from_parent_is_rejected_at_every_tip)
{
    // otherOps[0] is a DIFFERENT key under proTxHash 1. Build a publisher that only
    // the OTHER list would vouch for by signing with the other operator's key: in the
    // parent context proTxHash 1 exists but with a different key (=> R2 fails), and
    // we also cover a proTxHash absent from the parent entirely below.
    const uint256 proTx1 = parentOps[0].mns[0].proTxHash;
    BtcHeadersPayload p = AuditPayload(proTx1, 300000);
    BOOST_REQUIRE(otherOps[0].key.Sign(p.GetSignatureHash(), p.sig));   // wrong key for the PARENT
    const CTransactionRef tx = AuditToTx(p);

    for (const CBlockIndex* tip : {(const CBlockIndex*)&parentIdx, (const CBlockIndex*)&otherIdx,
                                   (const CBlockIndex*)nullptr}) {
        SetLocalTip(tip);
        CValidationState state;
        BOOST_CHECK_MESSAGE(!CheckBtcHeadersTx(*tx, &parentIdx, state),
                            "signature valid only under the TIP's key must be refused");
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-sig");
    }
}

BOOST_AUTO_TEST_CASE(unknown_publisher_is_rejected_even_when_the_tip_knows_it)
{
    // A proTxHash that exists in NEITHER list: the parent must refuse it whatever the
    // tip is, and the rejection reason must be identical across tips (no divergence
    // in the diagnostic either, which is what a two-node comparison would see).
    const uint256 ghost = ArithToUint256(arith_uint256(0xDEADBEEF));
    BOOST_REQUIRE(parentList.GetMN(ghost) == nullptr);
    BOOST_REQUIRE(otherList.GetMN(ghost) == nullptr);

    BtcHeadersPayload p = AuditPayload(ghost, 300000);
    BOOST_REQUIRE(parentOps[0].key.Sign(p.GetSignatureHash(), p.sig));
    const CTransactionRef tx = AuditToTx(p);

    std::string reasonAtParent;
    for (const CBlockIndex* tip : {(const CBlockIndex*)&parentIdx, (const CBlockIndex*)&otherIdx,
                                   (const CBlockIndex*)nullptr}) {
        SetLocalTip(tip);
        CValidationState state;
        BOOST_CHECK(!CheckBtcHeadersTx(*tx, &parentIdx, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-unknown-mn");
        if (reasonAtParent.empty()) reasonAtParent = state.GetRejectReason();
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reasonAtParent);
    }
}

// PREUVE 3 — two concurrent forks. The SAME publisher tx is judged against two
// DIFFERENT parents (one per branch) while the tip is parked on each branch in turn,
// including the reversed order after a chain switch. The verdict must be a function
// of the parent alone: accepted under the parent that registered the publisher,
// refused under the parent that did not — and never a function of which branch the
// node currently considers active.
BOOST_AUTO_TEST_CASE(sibling_branches_are_judged_by_their_own_parent)
{
    const uint256 proTx3 = parentOps[2].mns[0].proTxHash;   // parent list only
    BtcHeadersPayload p = AuditPayload(proTx3, 300000);
    BOOST_REQUIRE(parentOps[2].key.Sign(p.GetSignatureHash(), p.sig));
    const CTransactionRef tx = AuditToTx(p);

    // Active branch = parentIdx, side branch = otherIdx. Judge a child of each.
    struct Obs { bool accepted; std::string reason; };
    auto judge = [&](const CBlockIndex* parent, const CBlockIndex* tip) {
        SetLocalTip(tip);
        CValidationState st;
        const bool ok = CheckBtcHeadersTx(*tx, parent, st);
        return Obs{ok, st.GetRejectReason()};
    };

    // Order A: tip on the active branch.
    const Obs childOfActive_A = judge(&parentIdx, &parentIdx);
    const Obs childOfSide_A   = judge(&otherIdx, &parentIdx);
    // Order B: chain switched — tip now on the former side branch, reversed order.
    const Obs childOfSide_B   = judge(&otherIdx, &otherIdx);
    const Obs childOfActive_B = judge(&parentIdx, &otherIdx);

    // Same parent => same verdict, whichever branch is active and whatever the order.
    BOOST_CHECK_EQUAL(childOfActive_A.accepted, childOfActive_B.accepted);
    BOOST_CHECK_EQUAL(childOfActive_A.reason, childOfActive_B.reason);
    BOOST_CHECK_EQUAL(childOfSide_A.accepted, childOfSide_B.accepted);
    BOOST_CHECK_EQUAL(childOfSide_A.reason, childOfSide_B.reason);

    // And the two parents genuinely disagree — otherwise the equalities above would
    // be vacuous (both branches accepting everything proves nothing).
    BOOST_CHECK_MESSAGE(childOfActive_A.accepted,
                        "publisher registered in the active branch's parent: accept");
    BOOST_CHECK_MESSAGE(!childOfSide_A.accepted,
                        "publisher NOT in the side branch's parent: refuse, on both orders");
    BOOST_CHECK_EQUAL(childOfSide_A.reason, "bad-btcheaders-unknown-mn");
}

// THE PARENT, NOT AN ANCESTOR. `pindex` vs `pindex->pprev` is a one-character slip
// and the rest of this suite could not see it: with a null `parentIdx.pprev` a
// grandparent mutation degenerates to a no-op and goes green. proTxHash 3 is
// registered in the parent and ABSENT from the grandparent, so resolving one block
// too far back flips the verdict to `bad-btcheaders-unknown-mn`.
BOOST_AUTO_TEST_CASE(context_is_the_parent_not_an_earlier_ancestor)
{
    const uint256 proTx3 = parentOps[2].mns[0].proTxHash;
    BOOST_REQUIRE(parentList.GetMN(proTx3) != nullptr);   // in the parent
    BOOST_REQUIRE(grandList.GetMN(proTx3) == nullptr);    // NOT one block earlier
    BOOST_REQUIRE(parentIdx.pprev == &grandIdx);          // the link the mutant needs

    BtcHeadersPayload p = AuditPayload(proTx3, 300000);
    BOOST_REQUIRE(parentOps[2].key.Sign(p.GetSignatureHash(), p.sig));
    const CTransactionRef tx = AuditToTx(p);

    for (const CBlockIndex* tip : {(const CBlockIndex*)&parentIdx, (const CBlockIndex*)&otherIdx,
                                   (const CBlockIndex*)nullptr}) {
        SetLocalTip(tip);
        CValidationState state;
        BOOST_CHECK_MESSAGE(CheckBtcHeadersTx(*tx, &parentIdx, state),
                            "resolved one block too far back: publisher unknown in the grandparent");
    }

    // And the converse, so the case cannot pass by accepting everything: a publisher
    // known ONLY to the grandparent must be refused when judging a child of parentIdx.
    const uint256 grandOnly = grandOps[0].mns[0].proTxHash;
    if (parentList.GetMN(grandOnly) == nullptr) {
        BtcHeadersPayload g = AuditPayload(grandOnly, 300000);
        BOOST_REQUIRE(grandOps[0].key.Sign(g.GetSignatureHash(), g.sig));
        const CTransactionRef gtx = AuditToTx(g);
        SetLocalTip(&parentIdx);
        CValidationState gstate;
        BOOST_CHECK(!CheckBtcHeadersTx(*gtx, &parentIdx, gstate));
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// AUD-002 — the Sybil floor is not load-bearing
// ═══════════════════════════════════════════════════════════════════════════════
//
// nHuQuorumSize appears on exactly ONE non-logging code path in the whole tree:
//   signaling.cpp:517-525, inside CHuSignalingManager::HasQuorum.
// Its only consensus-side caller is PreviousBlockHasQuorum (signaling.cpp:717),
// which is a DISJUNCTION:
//   760  if (HasQuorum(prevHash)) return true;                  <-- floor enforced
//   765  if (finalityHandler->...HasFinality(threshold)) return true;   <-- NO floor
//   775  if (pFinalityDB->IsBlockFinal(prevHash)) return true;          <-- NO floor
// so a sub-floor population that HasQuorum explicitly refuses is admitted two
// lines later. This suite pins that.

struct FloorBypassSetup : public TestnetSetup {
    // > nHuFinalitySeedOffset (testnet 3), AND >= one epoch + snapshot depth so the
    // LOT 9 M3 epoch snapshot (which defines the finality population) resolves
    // inside this synthetic chain, exactly as on a real node.
    static const int NBLOCKS = 95;

    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> idx;

    explicit FloorBypassSetup(int numOps = 3)
        : hashes(NBLOCKS), idx(NBLOCKS)
    {
        mnList = BuildTestMNList(numOps, /*mnsPerOperator=*/1, operators);
        {
            LOCK(cs_main);
            for (int h = 0; h < NBLOCKS; ++h) {
                // g_finalityCtx is a process-global keyed by block hash that
                // survives fixture teardown, so this suite MUST NOT collide with
                // the hashes any other suite injects.
                hashes[h] = ArithToUint256(arith_uint256(0xB10C0000u + numOps * 0x10000u + h));
                idx[h].nHeight = 6'000'000 + h;
                idx[h].phashBlock = &hashes[h];
                idx[h].pprev = (h == 0) ? nullptr : &idx[h - 1];
                // Fresh timestamp: PreviousBlockHasQuorum bypasses the whole check
                // when GetTime() - blockTime > nStaleChainTimeout (testnet 600s).
                idx[h].nTime = static_cast<unsigned int>(GetTime());
                deterministicMNManager->SetListForTesting(&idx[h], mnList,
                                                          /*asTip=*/(h == NBLOCKS - 1));
                mapBlockIndex[hashes[h]] = &idx[h];
            }
        }
        hu::InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
        hu::huSignalingManager = std::make_unique<hu::CHuSignalingManager>();
    }

    ~FloorBypassSetup()
    {
        hu::huSignalingManager.reset();
        hu::finalityHandler.reset();
        hu::pFinalityDB.reset();
        LOCK(cs_main);
        for (int h = 0; h < NBLOCKS; ++h) mapBlockIndex.erase(hashes[h]);
        if (deterministicMNManager) deterministicMNManager->SetTipIndex(nullptr);
    }

    const CBlockIndex* Tip() const { return &idx[NBLOCKS - 1]; }

    void AddSig(int opIdx, const uint256& blockHash)
    {
        hu::CHuSignature s;
        s.blockHash = blockHash;
        s.proTxHash = operators.at(opIdx).mns.at(0).proTxHash;
        operators.at(opIdx).key.Sign(blockHash, s.vchSig);
        hu::finalityHandler->AddSignature(s);
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_divergence_aud002, FloorBypassSetup)

// The floor is above the population, and the fixture is NOT in the two blanket
// bypasses (bootstrap height, stale tip) — so the floor check is live.
BOOST_AUTO_TEST_CASE(precondition_subfloor_and_bypasses_inactive)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(consensus.nHuQuorumSize, 4);
    BOOST_CHECK_EQUAL(hu::HuFinalityOperatorCount(Tip()->GetBlockHash()), 3);
    BOOST_CHECK_GT(Tip()->nHeight, consensus.nDMMBootstrapHeight);
    BOOST_CHECK_LE(GetTime() - Tip()->GetBlockTime(), consensus.nStaleChainTimeout);
}

// LOT 4 — INVERTED. This USED TO BE the finding: HasQuorum said NO (floor) while
// PreviousBlockHasQuorum said YES through two floor-free OR-fallbacks, so the floor
// was decorative. The floor now lives in HuActiveFinalityThreshold, which BOTH
// fallbacks derive from — so all three answers agree.
BOOST_AUTO_TEST_CASE(floor_is_no_longer_overridden_by_the_or_fallbacks)
{
    const uint256 blockHash = Tip()->GetBlockHash();

    AddSig(0, blockHash);
    AddSig(1, blockHash);   // 2 of 3 — what USED TO be the met threshold

    // The floor still refuses: 3 operators < nHuQuorumSize 4.
    BOOST_REQUIRE(!hu::huSignalingManager->HasQuorum(blockHash));

    // ...and the fallbacks no longer contradict it.
    BOOST_CHECK_MESSAGE(!hu::finalityHandler->HasFinality(Tip()->nHeight, blockHash),
                        "AUD-002: HasFinality fallback must honour the floor");
    BOOST_CHECK_MESSAGE(!hu::pFinalityDB->IsBlockFinal(blockHash),
                        "AUD-002: IsBlockFinal fallback must honour the floor");
    BOOST_CHECK_MESSAGE(!hu::PreviousBlockHasQuorum(Tip()),
                        "AUD-002: the disjunction must no longer admit a sub-floor population");
}

// The wall clock is an input to PreviousBlockHasQuorum: a tip older than
// nStaleChainTimeout returns true unconditionally (signaling.cpp:750-755). Two
// nodes evaluating the same block seconds apart across that boundary — or with
// skewed clocks — disagree. Not a block-validity path today (the only callers are
// UpdateTip's sync-state notification and the local production gate), which is
// exactly why this is recorded as liveness/production, NOT as a fork vector.
BOOST_AUTO_TEST_CASE(wall_clock_decides_the_cold_start_bypass)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    CBlockIndex stale = idx[NBLOCKS - 1];
    uint256 staleHash = ArithToUint256(arith_uint256(0xB10CDEAD));
    stale.phashBlock = &staleHash;
    stale.nTime = static_cast<unsigned int>(GetTime() - consensus.nStaleChainTimeout - 1);

    // F5 (independent review): a STACK-allocated CBlockIndex must be removed from the
    // global mapBlockIndex on EVERY exit path. If a BOOST_REQUIRE throws past a bare
    // erase, ~TestingSetup -> UnloadBlockIndex (validation.cpp:4446-4448) calls delete
    // on a stack pointer. RAII, not a trailing statement.
    struct MapGuard {
        uint256 h;
        explicit MapGuard(const uint256& hh, CBlockIndex* p) : h(hh)
        {
            LOCK(cs_main);
            mapBlockIndex[h] = p;
        }
        ~MapGuard()
        {
            LOCK(cs_main);
            mapBlockIndex.erase(h);
        }
    } guard(staleHash, &stale);

    // No signatures at all for this block, yet the check passes purely on tip age.
    // NOTE (independent review): this is the DOCUMENTED cold-start bypass
    // (signaling.cpp:750-755) on a NON-validity path. It is recorded as evidence that
    // wall-clock time reaches PreviousBlockHasQuorum, not as a fork vector — the fork
    // vector on a clock is AUD-005 / REV-005 (blockproducer.cpp:302, in ConnectBlock).
    BOOST_CHECK(hu::PreviousBlockHasQuorum(&stale));
    BOOST_CHECK(!hu::pFinalityDB->IsBlockFinal(staleHash));
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// AUD-003 — the BTC-burn kill switch changes the EXPECTED mint
// ═══════════════════════════════════════════════════════════════════════════════
//
// HISTORICAL FINDING (AUD-003), **FIXED BY LOT 2 — this suite is now INVERTED**.
//
// g_btc_burns_enabled (killswitch.cpp:12) is a process-local atomic, seeded from
// -btcburnsenabled and flipped at runtime by the setbtcburnsenabled RPC. It USED to
// be read inside the mint oracle, and ProcessSpecialTxsInBlock used that same
// function as the ORACLE for the mint a block must contain — so the same block was
// valid or invalid according to a node-local flag:
//
//   (before) expectedMint non-null + block has no mint -> "Missing required TX_MINT_M0BTC"
//   (before) expectedMint NULL     + block has a mint  -> "Unexpected TX_MINT_M0BTC"
//
// LOT 2 split the two roles:
//   * CreateExpectedMintM0BTC — CONSENSUS oracle, reads consensus state ONLY;
//   * CreateMintM0BTC        — PRODUCER policy wrapper (kill switch / -enablemint).
// The cases below now assert the FIX: the consensus oracle is flag-invariant, while
// the producer wrapper still honours local policy.

struct KillSwitchOracleSetup : public BasicTestingSetup {
    KillSwitchOracleSetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        // FIXTURE HYGIENE (found while writing the LOT 2 inversions): this fixture
        // used to leave g_settlementdb / g_htlcdb owned by whatever suite ran
        // before it — objects whose on-disk datadir BasicTestingSetup's destructor
        // has already deleted. The next fixture's assignment then destroyed those
        // stale LevelDB handles and threw `dbwrapper_error: Database I/O error`,
        // aborting unrelated cases. Reset them on entry AND exit so this suite
        // neither inherits nor exports DB state.
        g_settlementdb.reset();
        g_htlcdb.reset();
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
        g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, true, true);
        SetBtcBurnsEnabled(true);
    }
    ~KillSwitchOracleSetup()
    {
        SetBtcBurnsEnabled(true);   // never leak the flag into another suite
        g_burnclaimdb.reset();
        g_btc_spv.reset();
        g_btcheadersdb.reset();
        g_settlementdb.reset();
        g_htlcdb.reset();
    }

    //! Seed a BTC header and advance the btcheadersdb tip far enough that a burn at
    //! `burnHeight` clears GetRequiredConfirmations().
    uint256 SeedHeaderAt(uint32_t height)
    {
        BtcBlockHeader hdr;
        hdr.nVersion = 4;
        hdr.hashPrevBlock = ArithToUint256(arith_uint256(0xB0DE) + height);
        hdr.hashMerkleRoot = ArithToUint256(arith_uint256(height) + 3);
        hdr.nTime = 1000 + height;
        hdr.nBits = 0x1d00ffff;
        hdr.nNonce = height;
        const uint256 hash = hdr.GetHash();
        auto batch = g_btcheadersdb->CreateBatch();
        batch.WriteHeader(height, hdr);
        batch.WriteTip(height, hash);
        BOOST_REQUIRE(batch.Commit());
        return hash;
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_divergence_aud003, KillSwitchOracleSetup)

BOOST_AUTO_TEST_CASE(killswitch_flips_the_expected_mint_for_identical_state)
{
    const uint32_t burnHeight = 300000;
    const uint256 blockHash = SeedHeaderAt(burnHeight);
    // Move the BTC tip past the confirmation requirement (headers at intermediate
    // heights are not needed: IsBtcBurnStillValidConsensus only reads the hash at
    // the burn height and the tip height).
    SeedHeaderAt(burnHeight + GetRequiredConfirmations() + 10);

    BurnClaimRecord rec;
    rec.btcTxid = ArithToUint256(arith_uint256(0xA11DEC0DE));
    rec.btcBlockHash = blockHash;
    rec.btcHeight = burnHeight;
    rec.burnedSats = 123456;
    rec.bathronDest = uint160(std::vector<unsigned char>(20, 0x42));
    rec.destType = BURN_DEST_P2PKH;
    rec.claimHeight = 1000;
    rec.status = BurnClaimStatus::PENDING;
    {
        auto batch = g_burnclaimdb->CreateBatch();
        batch.StoreBurnClaim(rec);
        BOOST_REQUIRE(batch.Commit());
    }

    // Height at which the claim is eligible: blockHeight > claimHeight + K.
    const uint32_t mintHeight = rec.claimHeight + GetKFinality() + 1;

    // Node A — burns enabled (the default). The consensus oracle produces the mint.
    BOOST_REQUIRE(AreBtcBurnsEnabled());
    const CTransaction expectedA = CreateExpectedMintM0BTC(mintHeight);
    BOOST_REQUIRE_MESSAGE(!expectedA.IsNull(),
                          "precondition: the claim must be mint-eligible");
    BOOST_CHECK_EQUAL(expectedA.vout.size(), 1U);
    BOOST_CHECK_EQUAL(expectedA.vout[0].nValue, CAmount(rec.burnedSats));

    // Node B — same DB, same height, same claim; only the local flag differs.
    SetBtcBurnsEnabled(false);
    const CTransaction expectedB = CreateExpectedMintM0BTC(mintHeight);

    // LOT 2 FIX (was: expectedB.IsNull(), i.e. the flag decided block validity).
    BOOST_CHECK_MESSAGE(!expectedB.IsNull(),
                        "LOT 2: the consensus oracle must NOT be silenced by a node-local flag");
    BOOST_CHECK_MESSAGE(expectedB.GetHash() == expectedA.GetHash(),
                        "LOT 2: the expected mint must be byte-identical regardless of "
                        "the kill switch — otherwise the same block is 'Missing required "
                        "TX_MINT_M0BTC' on one node and valid on another");

    // The POLICY wrapper, in contrast, still refuses to BUILD while burns are off —
    // that is the legitimate local brake, and it never touches block validity.
    BOOST_CHECK_MESSAGE(CreateMintM0BTC(mintHeight).IsNull(),
                        "the producer wrapper must still honour the kill switch");

    // -enablemint=0 is likewise producer-only: oracle unchanged, wrapper silent.
    SetBtcBurnsEnabled(true);
    gArgs.ForceSetArg("-enablemint", "0");
    const CTransaction expectedD = CreateExpectedMintM0BTC(mintHeight);
    const bool wrapperSilent = CreateMintM0BTC(mintHeight).IsNull();
    gArgs.ForceSetArg("-enablemint", "1");
    BOOST_CHECK(!expectedD.IsNull());
    BOOST_CHECK(expectedD.GetHash() == expectedA.GetHash());
    BOOST_CHECK_MESSAGE(wrapperSilent, "-enablemint=0 must stop production, not validation");

    // Symmetry on re-enable.
    const CTransaction expectedC = CreateExpectedMintM0BTC(mintHeight);
    BOOST_CHECK(!expectedC.IsNull());
    BOOST_CHECK(expectedC.GetHash() == expectedA.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
