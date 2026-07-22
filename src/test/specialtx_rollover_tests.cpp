// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ============================================================================
// F-HTLC-2 rollover-liveness regression suite.
//
// A special-tx consensus rule that is HEIGHT-MONOTONIC-TIGHTENING (R2
// "child-underlife", companion "expired-at-creation") can make a tx that was
// valid for block N become permanently invalid for N+1 as the tip advances.
// Before the fix such a tx lingered in the mempool and, because the DMM
// producer assembles with fTestValidity=false, was included in a template that
// ConnectBlock then rejected — a block-production liveness/griefing vector.
//
// Two defenses (defense in depth), both exercised here against PRODUCTION code:
//   1. CTxMemPool::removeForSpecialTxHeightChange — evicts permanently-invalid
//      special txs (and descendants) on tip change; keeps premature/loosening.
//   2. BlockAssembler::TestPackageSpecialHeight — skips (never throws) a package
//      whose special tx is permanently invalid at the block's own height, so a
//      template can never contain what ConnectBlock would reject at that height.
//
// The rule itself is NOT re-encoded here — the guard re-runs the real Check*
// and only interprets its reject reason (IsSpecialTxHeightPermanentlyInvalid).
// ============================================================================

#include "amount.h"
#include "blockassembler.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "masternode/specialtx_validation.h"
#include "primitives/transaction.h"
#include "script/conditional.h"
#include "script/script.h"
#include "script/standard.h"
#include "state/settlement.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"
#include "htlc/htlc.h"
#include "htlc/htlcdb.h"
#include "txmempool.h"
#include "validation.h"
#include "crypto/sha256.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(specialtx_rollover_tests, TestingSetup)

namespace {

CScript OpTrue() { CScript s; s << OP_TRUE; return s; }

CKeyID NewKeyID() { CKey k; k.MakeNewKey(true); return k.GetPubKey().GetID(); }

struct Fx {
    CCoinsView coinsDummy;
    CCoinsViewCache view{&coinsDummy};
    CKey key;
    CKeyID keyID;
    std::vector<unsigned char> secret = std::vector<unsigned char>(32, 0x7A);
    uint256 hashlock;
    CAmount P = 100000;
    CAmount fee = CTV_FIXED_FEE;

    Fx() {
        BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
        BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true));
        key.MakeNewKey(true);
        keyID = key.GetPubKey().GetID();
        CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());
    }

    // ACTIVE covenant parent HTLC keyed on `htlcOut`, child expiry = childExpiry.
    void writeCovenantParent(const COutPoint& htlcOut, uint32_t parentExpiry, uint32_t childExpiry) {
        CScript redeem = CreateConditionalWithCovenantScript(hashlock, parentExpiry, keyID, keyID, uint256S("22"));
        HTLCRecord rec;
        rec.htlcOutpoint = htlcOut;
        rec.amount = P;
        rec.hashlock = hashlock;
        rec.status = HTLCStatus::ACTIVE;
        rec.claimKeyID = keyID;
        rec.refundKeyID = keyID;
        rec.createHeight = 10;
        rec.expiryHeight = parentExpiry;
        rec.covenantFee = fee;
        rec.templateCommitment = uint256S("22");
        rec.htlc3ClaimKeyID = keyID;
        rec.htlc3RefundKeyID = keyID;
        rec.htlc3ExpiryHeight = childExpiry;
        rec.redeemScript = redeem;
        BOOST_REQUIRE(g_htlcdb->WriteHTLC(rec));
    }

    CTransaction makeCovenantClaim(const COutPoint& htlcOut) {
        // The Check reads the record's redeemScript; build the scriptSig from it.
        HTLCRecord rec; BOOST_REQUIRE(g_htlcdb->ReadHTLC(htlcOut, rec));
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::HTLC_CLAIM;
        CTxIn in(htlcOut);
        in.scriptSig = CreateConditionalSpendA(std::vector<unsigned char>(72, 0x30),
                                               key.GetPubKey(), secret, rec.redeemScript);
        mtx.vin.push_back(in);
        mtx.vout.emplace_back(CTxOut(P - fee, GetScriptForDestination(CScriptID(OpTrue()))));
        mtx.vout.emplace_back(CTxOut(fee, OpTrue()));
        return CTransaction(mtx);
    }

    // Fund an M1 receipt and build a well-formed covenant HTLC_CREATE_M1 tx.
    CTransaction makeCovenantCreate(const COutPoint& receiptOut, uint32_t parentExpiry, uint32_t childExpiry) {
        M1Receipt r; r.outpoint = receiptOut; r.amount = P; r.nCreateHeight = 1;
        auto sb = g_settlementdb->CreateBatch(); sb.WriteReceipt(r); BOOST_REQUIRE(sb.Commit());
        HTLCCreatePayload p;
        p.nVersion = HTLC_CREATE_PAYLOAD_VERSION_CTV;
        p.hashlock = hashlock;
        p.expiryHeight = parentExpiry;
        p.claimKeyID = keyID; p.refundKeyID = keyID;
        p.templateCommitment = uint256S("22");
        p.htlc3ExpiryHeight = childExpiry;
        p.htlc3ClaimKeyID = keyID; p.htlc3RefundKeyID = keyID;
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::HTLC_CREATE_M1;
        mtx.vin.emplace_back(CTxIn(receiptOut));
        mtx.vout.emplace_back(CTxOut(P, GetScriptForDestination(CScriptID(OpTrue()))));
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << p;
        mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());
        return CTransaction(mtx);
    }
};

} // namespace

// ---- Classifier: the primitive both defenses share -------------------------

// #13 exact R2 boundary + #2 rollover: valid at N, permanently invalid at N+1.
BOOST_AUTO_TEST_CASE(classifier_r2_boundary_and_rollover)
{
    LOCK(cs_main); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    const uint32_t childExpiry = 302;  // record pre-exists; R1 not re-checked at claim
    f.writeCovenantParent(htlcOut, /*parentExpiry=*/500, childExpiry);
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    std::string reason;
    // Exact R2 boundary: block 300 is the last valid height (child 302 >= 300+2).
    BOOST_CHECK(!IsSpecialTxHeightPermanentlyInvalid(claim, f.view, 300, reason));
    // Block 301: 302 >= 303 is false -> permanently invalid (child-underlife).
    BOOST_CHECK(IsSpecialTxHeightPermanentlyInvalid(claim, f.view, 301, reason));
    BOOST_CHECK_EQUAL(reason, "bad-htlcclaim-child-underlife");
}

// #12 a premature/loosening reject is NOT flagged permanently invalid.
BOOST_AUTO_TEST_CASE(classifier_ignores_non_tightening_rejects)
{
    LOCK(cs_main); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, 100000);
    // Same-block-pending style: point the claim at an outpoint with no record.
    CTransaction orphanClaim = f.makeCovenantClaim(htlcOut);  // record exists; tweak to a missing one:
    CMutableTransaction m(orphanClaim);
    m.vin[0].prevout = COutPoint(uint256S("ee"), 7);  // not an HTLC -> bad-htlcclaim-not-htlc
    std::string reason;
    BOOST_CHECK(!IsSpecialTxHeightPermanentlyInvalid(CTransaction(m), f.view, 900000, reason));
    BOOST_CHECK(reason.empty());
}

// #11 an unrelated (normal) tx is never flagged.
BOOST_AUTO_TEST_CASE(classifier_ignores_normal_tx)
{
    LOCK(cs_main); Fx f;
    CMutableTransaction normal;
    normal.nVersion = CTransaction::TxVersion::SAPLING;
    normal.nType = CTransaction::TxType::NORMAL;
    normal.vin.emplace_back(CTxIn(COutPoint(uint256S("01"), 0)));
    normal.vout.emplace_back(CTxOut(1000, OpTrue()));
    std::string reason;
    BOOST_CHECK(!IsSpecialTxHeightPermanentlyInvalid(CTransaction(normal), f.view, 1000000, reason));
}

// Companion: a create that becomes born-expired as height passes parentExpiry.
BOOST_AUTO_TEST_CASE(classifier_companion_parent_expired)
{
    LOCK(cs_main); Fx f;
    CTransaction create = f.makeCovenantCreate(COutPoint(uint256S("cc"), 0), /*parentExpiry=*/500, /*childExpiry=*/700);
    std::string reason;
    BOOST_CHECK(!IsSpecialTxHeightPermanentlyInvalid(create, f.view, 499, reason));  // still valid
    BOOST_CHECK(IsSpecialTxHeightPermanentlyInvalid(create, f.view, 500, reason));   // expiry<=height
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expired-at-creation");
}

// ---- Mempool sweep ---------------------------------------------------------

// #3 invalid tx removed + #9 does not reappear; #15 no height divergence.
BOOST_AUTO_TEST_CASE(mempool_sweep_evicts_rolled_over_claim)
{
    LOCK2(cs_main, mempool.cs); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, /*childExpiry=*/302);
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(claim.GetHash(), entry.FromTx(claim));
    BOOST_REQUIRE(mempool.exists(claim.GetHash()));

    // Tip at 300 -> next block 301 (valid). Sweep must NOT evict.
    mempool.removeForSpecialTxHeightChange(f.view, 300);
    BOOST_CHECK(mempool.exists(claim.GetHash()));

    // Tip advanced to 301 -> next block 302 (child 302 >= 304? no) -> evict.
    mempool.removeForSpecialTxHeightChange(f.view, 302);
    BOOST_CHECK(!mempool.exists(claim.GetHash()));

    // #9 does not reappear on a second sweep.
    mempool.removeForSpecialTxHeightChange(f.view, 303);
    BOOST_CHECK(!mempool.exists(claim.GetHash()));
}

// #12 a refund-style loosening special tx is NOT swept (kept until valid).
BOOST_AUTO_TEST_CASE(mempool_sweep_keeps_premature_refund)
{
    LOCK2(cs_main, mempool.cs); Fx f;
    // Active HTLC3S with a future expiry; a refund is premature but only ever
    // enters the mempool once valid — here we assert the sweep classifier does
    // not treat a refund tx as permanently invalid regardless of height.
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, 100000);
    CMutableTransaction refund;
    refund.nVersion = CTransaction::TxVersion::SAPLING;
    refund.nType = CTransaction::TxType::HTLC_REFUND;
    refund.vin.emplace_back(CTxIn(htlcOut));
    refund.vout.emplace_back(CTxOut(f.P, GetScriptForDestination(CScriptID(OpTrue()))));
    CTransaction rtx(refund);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(rtx.GetHash(), entry.FromTx(rtx));
    mempool.removeForSpecialTxHeightChange(f.view, 200);   // well before expiry
    BOOST_CHECK(mempool.exists(rtx.GetHash()));            // refund not our concern -> kept
}

// #4 descendants of an evicted tx are removed too; #14 only the invalid one goes.
BOOST_AUTO_TEST_CASE(mempool_sweep_removes_descendants_only)
{
    LOCK2(cs_main, mempool.cs); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, /*childExpiry=*/302);
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(claim.GetHash(), entry.FromTx(claim));

    // A child normal tx spending the claim's output.
    CMutableTransaction child;
    child.nVersion = CTransaction::TxVersion::SAPLING;
    child.vin.emplace_back(CTxIn(COutPoint(claim.GetHash(), 0)));
    child.vout.emplace_back(CTxOut(f.P - 1000, OpTrue()));
    CTransaction ctx(child);
    mempool.addUnchecked(ctx.GetHash(), entry.FromTx(ctx));

    // An unrelated normal tx that must survive.
    CMutableTransaction other;
    other.nVersion = CTransaction::TxVersion::SAPLING;
    other.vin.emplace_back(CTxIn(COutPoint(uint256S("f00d"), 3)));
    other.vout.emplace_back(CTxOut(500, OpTrue()));
    CTransaction otx(other);
    mempool.addUnchecked(otx.GetHash(), entry.FromTx(otx));

    mempool.removeForSpecialTxHeightChange(f.view, 302);   // evict claim
    BOOST_CHECK(!mempool.exists(claim.GetHash()));
    BOOST_CHECK(!mempool.exists(ctx.GetHash()));           // descendant gone
    BOOST_CHECK(mempool.exists(otx.GetHash()));            // unrelated kept
}

// ---- Assembler backstop ----------------------------------------------------

// #5 assembler skips invalid special tx; #6 template stays valid; #1 valid mined.
BOOST_AUTO_TEST_CASE(assembler_skips_rolled_over_claim)
{
    // Build directly on the tip that TestingSetup left (regtest genesis).
    LOCK2(cs_main, mempool.cs); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    // Child expiry just above genesis+1 so it is valid now but not far.
    const int tipH = chainActive.Height();
    f.writeCovenantParent(htlcOut, tipH + 500, /*childExpiry=*/(uint32_t)(tipH + 1));  // underlife for block tipH+1
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(claim.GetHash(), entry.FromTx(claim));

    // Assemble the next block (height tipH+1) WITHOUT final ConnectBlock test —
    // the DMM-realistic path. The claim (child tipH+1 < (tipH+1)+2) must be
    // skipped by TestPackageSpecialHeight, so it is absent from the template.
    CScript spk = CScript() << OP_TRUE;
    std::unique_ptr<CBlockTemplate> tmpl =
        BlockAssembler(Params(), false).CreateNewBlock(spk, nullptr, false, nullptr,
                                                       /*fNoMempoolTx=*/false, /*fTestValidity=*/false);
    BOOST_REQUIRE(tmpl != nullptr);
    bool included = false;
    for (const auto& txr : tmpl->block.vtx)
        if (txr->GetHash() == claim.GetHash()) included = true;
    BOOST_CHECK_MESSAGE(!included, "rolled-over claim must be skipped by the assembler");

    // Positive control: an otherwise-identical claim on a HEALTHY-margin parent
    // (child expiry far above the target height) IS selected — proving the skip
    // above is caused by the height guard, not some unrelated exclusion.
    COutPoint htlcOut2(uint256S("cd"), 0);
    f.writeCovenantParent(htlcOut2, tipH + 500, /*childExpiry=*/(uint32_t)(tipH + 1000));
    CTransaction goodClaim = f.makeCovenantClaim(htlcOut2);
    mempool.addUnchecked(goodClaim.GetHash(), entry.FromTx(goodClaim));
    std::unique_ptr<CBlockTemplate> tmpl2 =
        BlockAssembler(Params(), false).CreateNewBlock(spk, nullptr, false, nullptr,
                                                       /*fNoMempoolTx=*/false, /*fTestValidity=*/false);
    BOOST_REQUIRE(tmpl2 != nullptr);
    bool goodIncluded = false, badIncluded = false;
    for (const auto& txr : tmpl2->block.vtx) {
        if (txr->GetHash() == goodClaim.GetHash()) goodIncluded = true;
        if (txr->GetHash() == claim.GetHash()) badIncluded = true;
    }
    BOOST_CHECK_MESSAGE(goodIncluded, "healthy-margin claim must be included");
    BOOST_CHECK_MESSAGE(!badIncluded, "rolled-over claim must still be skipped");
}

// ---- PHASE B: package parent/child + the not-htlc bypass is unreachable -----
//
// CheckSpecialTx (what AcceptToMemoryPool calls at admission) reads the HTLC
// record from g_htlcdb, which is written ONLY by ApplyHTLCCreate at
// ConnectBlock. So a covenant claim can be admitted ONLY once its parent HTLC
// is CONFIRMED (in a prior block). A claim on an unconfirmed (in-mempool)
// parent is rejected at admission with bad-htlcclaim-not-htlc. Therefore a
// parent+claim package in the SAME block cannot form for covenant HTLCs, and
// the "not-htlc temporarily -> later violates a height rule" bypass is
// structurally impossible for the height-tightening rules (which apply only to
// HTLC_CLAIM/CREATE). These tests drive the REAL admission decision
// (CheckSpecialTx), not addUnchecked.

// Claim on an UNCONFIRMED parent (record absent from g_htlcdb) is rejected at
// admission: no same-block parent+claim package can exist.
BOOST_AUTO_TEST_CASE(admission_rejects_claim_on_unconfirmed_parent)
{
    LOCK(cs_main); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, 100000);
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    // Now simulate "parent not yet confirmed": erase the record, keep the tx.
    BOOST_REQUIRE(g_htlcdb->EraseHTLC(htlcOut));
    CBlockIndex idxPrev; idxPrev.nHeight = 300;
    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(claim, &idxPrev, &f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-not-htlc");
}

// Confirmed parent, R2 satisfied: admission ACCEPTS (positive control).
BOOST_AUTO_TEST_CASE(admission_accepts_confirmed_parent_r2_ok)
{
    LOCK(cs_main); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, /*childExpiry=*/100000);
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    CBlockIndex idxPrev; idxPrev.nHeight = 300;   // next block 301, child huge -> ok
    CValidationState st;
    BOOST_CHECK_MESSAGE(CheckSpecialTx(claim, &idxPrev, &f.view, st),
                        "R2-ok claim on confirmed parent rejected: " + st.GetRejectReason());
}

// Confirmed parent, R2 violated at the admission height: rejected at admission
// (same rule, same height context as ConnectBlock) — child-underlife, NOT a
// non-tightening reason, so the guard/sweep would also catch it.
BOOST_AUTO_TEST_CASE(admission_rejects_confirmed_parent_r2_underlife)
{
    LOCK(cs_main); Fx f;
    COutPoint htlcOut(uint256S("bb"), 0);
    f.writeCovenantParent(htlcOut, 500, /*childExpiry=*/302);
    CTransaction claim = f.makeCovenantClaim(htlcOut);
    CBlockIndex idxPrev; idxPrev.nHeight = 301;   // next block 302, child 302 < 304
    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(claim, &idxPrev, &f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-child-underlife");
    // The classifier agrees it is permanently invalid at that height.
    std::string reason;
    BOOST_CHECK(IsSpecialTxHeightPermanentlyInvalid(claim, f.view, 302, reason));
    BOOST_CHECK_EQUAL(reason, "bad-htlcclaim-child-underlife");
}

// NOTE on "template passes TestBlockValidity": running CreateNewBlock with
// fTestValidity=true (which invokes ConnectBlock on the assembled block) is not
// feasible at unit level for BATHRON's genesis-adjacent block 1 — it is the
// special BTC-headers genesis block and a literal ConnectBlock there needs
// btcheaders + MN/finality state (same harness limitation settlement_tests
// documents). The achievable, non-vacuous proof is above: with
// fTestValidity=false the assembler INCLUDES a healthy-margin claim (positive
// control) and SKIPS the rolled-over one via TestPackageSpecialHeight — i.e.
// the template never carries a tx ConnectBlock would reject for the height
// rule. Full-suite validation_block_tests covers ConnectBlock validity of
// normal blocks separately.

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// PHASE C (operational lab): TestBlockValidity on a NORMAL block via the REAL
// BlockAssembler. TestChainSetup mines 10 regtest blocks, so the next block
// (height 11) is a NORMAL block — past the special genesis header (block 1) and
// ProReg (block 2) blocks. This closes the "template passes TestBlockValidity"
// check the unit-level TestingSetup harness could not (block 1 special path).
// No mock: the real CreateNewBlock(..., fTestValidity=true) runs TestBlockValidity
// -> ConnectBlock on the assembled block.
// ============================================================================

struct RolloverChainSetup : public TestChainSetup {
    RolloverChainSetup() : TestChainSetup(/*blockCount=*/10) {
        // Empty-block mining does not touch the HTLC DB (its uses are guarded by
        // `g_htlcdb &&`), so it can be null here — init a fresh in-memory one.
        // Only init the settlement DB if the chain build did not already (do NOT
        // wipe an existing one: the mined chain's A5/A6 state lives there).
        if (!g_htlcdb) BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
        if (!g_settlementdb) BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true));
    }
};

BOOST_FIXTURE_TEST_SUITE(specialtx_rollover_blockvalidity_tests, RolloverChainSetup)

namespace {
CScript OpTrueC() { CScript s; s << OP_TRUE; return s; }
} // namespace

BOOST_AUTO_TEST_CASE(normal_block_template_passes_testblockvalidity_with_poison_skipped)
{
    LOCK2(cs_main, mempool.cs);
    BOOST_REQUIRE(g_htlcdb != nullptr);
    const int tipH = chainActive.Height();
    BOOST_REQUIRE(tipH >= 3);   // past special blocks 1-2

    // Real preimage/hashlock + covenant parent record in g_htlcdb, with a child
    // expiry that is UNDER-LIFE for the next block (tipH+1): htlc3Expiry < (tipH+1)+2.
    CKey key; key.MakeNewKey(true);
    const CKeyID keyID = key.GetPubKey().GetID();
    std::vector<unsigned char> secret(32, 0x5C);
    uint256 hashlock; CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());
    const COutPoint htlcOut(uint256S("c0ffee"), 0);
    const CAmount P = 100000, fee = CTV_FIXED_FEE;
    CScript redeem = CreateConditionalWithCovenantScript(hashlock, tipH + 500, keyID, keyID, uint256S("22"));
    {
        HTLCRecord rec;
        rec.htlcOutpoint = htlcOut; rec.amount = P; rec.hashlock = hashlock;
        rec.status = HTLCStatus::ACTIVE; rec.claimKeyID = keyID; rec.refundKeyID = keyID;
        rec.createHeight = 3; rec.expiryHeight = tipH + 500; rec.covenantFee = fee;
        rec.templateCommitment = uint256S("22"); rec.htlc3ClaimKeyID = keyID;
        rec.htlc3RefundKeyID = keyID; rec.htlc3ExpiryHeight = (uint32_t)(tipH + 1);  // under-life
        rec.redeemScript = redeem;
        BOOST_REQUIRE(g_htlcdb->WriteHTLC(rec));
    }

    // The rolled-over covenant claim, injected into the mempool.
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CLAIM;
    CTxIn in(htlcOut);
    in.scriptSig = CreateConditionalSpendA(std::vector<unsigned char>(72, 0x30), key.GetPubKey(), secret, redeem);
    mtx.vin.push_back(in);
    mtx.vout.emplace_back(CTxOut(P - fee, GetScriptForDestination(CScriptID(OpTrueC()))));
    mtx.vout.emplace_back(CTxOut(fee, OpTrueC()));
    CTransaction claim(mtx);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(claim.GetHash(), entry.FromTx(claim));
    BOOST_REQUIRE(mempool.exists(claim.GetHash()));

    // Build the NEXT (normal, height tipH+1) block with the harness's proven
    // block path — the SAME real BlockAssembler used to mine blocks 1..10 — but
    // WITH the mempool included (fNoMempoolTx=false) and fTestBlockValidity=true,
    // which runs TestBlockValidity -> ConnectBlock on the assembled block. If the
    // poison were included, ConnectBlock would reject it (R2) and CreateBlock
    // would throw. It must NOT throw, and the poison must be absent from the
    // validated block. (No mock: this is the real assembler + real ConnectBlock.)
    CScript spk = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CBlock block;
    BOOST_REQUIRE_NO_THROW(
        block = CreateBlock(/*txns=*/{}, spk, /*fNoMempoolTx=*/false, /*fTestBlockValidity=*/true));
    bool poisonIncluded = false;
    for (const auto& txr : block.vtx)
        if (txr->GetHash() == claim.GetHash()) poisonIncluded = true;
    BOOST_CHECK_MESSAGE(!poisonIncluded, "rolled-over claim must be absent from the validated block");
    // Coinbase present -> valid txs remain; TestBlockValidity above already ran
    // ConnectBlock on this normal block and accepted it.
    BOOST_REQUIRE(!block.vtx.empty());
    BOOST_CHECK(block.vtx[0]->IsCoinBase());

    // Connect it for real and verify the tip advances and invariants hold.
    BOOST_REQUIRE(ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr));
    BOOST_CHECK_EQUAL(chainActive.Height(), tipH + 1);
    // The poison is still in the mempool (not mined) but permanently invalid at
    // the new height — the sweep evicts it, proving no lingering poison.
    mempool.removeForSpecialTxHeightChange(*pcoinsTip, (unsigned)(tipH + 2));
    BOOST_CHECK(!mempool.exists(claim.GetHash()));
}

BOOST_AUTO_TEST_SUITE_END()
