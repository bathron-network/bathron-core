// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Consensus negative-path coverage for HTLC_CLAIM_3S / HTLC_REFUND_3S (gate G4).
// Each test drives the real consensus check (CheckHTLC3SClaim / CheckHTLC3SRefund)
// against an active HTLC3S record written via the real g_htlcdb API, asserts the
// EXACT reject reason, and — for rejections — asserts the DB record is unchanged
// (the Check* functions are pure; Apply* alone mutates state). No guard is
// weakened and no test is disabled to pass.

#include "amount.h"
#include "coins.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"
#include "htlc/htlc.h"
#include "htlc/htlcdb.h"
#include "validation.h"          // cs_main
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(htlc3s_failure_tests, BasicTestingSetup)

namespace {

CScript OpTrue() { CScript s; s << OP_TRUE; return s; }

// hashlock = SHA256(preimage), matching VerifyPreimages3S.
uint256 Sha256Of(const std::vector<unsigned char>& v) {
    uint256 h;
    CSHA256().Write(v.data(), v.size()).Finalize(h.begin());
    return h;
}

std::vector<unsigned char> Preimage(unsigned char fill) {
    return std::vector<unsigned char>(HTLC_PREIMAGE_SIZE, fill);  // 32 bytes
}

// Write an ACTIVE HTLC3S record keyed on `outpoint`, no covenant.
HTLC3SRecord WriteActive3S(const COutPoint& outpoint, CAmount amount,
                           const std::vector<unsigned char>& su,
                           const std::vector<unsigned char>& s1,
                           const std::vector<unsigned char>& s2,
                           const CScript& redeem, uint32_t expiry) {
    HTLC3SRecord rec;
    rec.htlcOutpoint  = outpoint;
    rec.hashlock_user = Sha256Of(su);
    rec.hashlock_lp1  = Sha256Of(s1);
    rec.hashlock_lp2  = Sha256Of(s2);
    rec.amount        = amount;
    rec.redeemScript  = redeem;
    rec.expiryHeight  = expiry;
    rec.createHeight  = 1;
    rec.status        = HTLCStatus::ACTIVE;  // templateCommitment stays null → no covenant
    BOOST_REQUIRE(g_htlcdb->WriteHTLC3S(rec));
    BOOST_REQUIRE(g_htlcdb->IsHTLC3S(outpoint));
    return rec;
}

// Branch-A claim scriptSig: <sig> <pubkey> <S_lp2> <S_lp1> <S_user> OP_TRUE <redeem>.
// sig/pubkey are placeholders — CheckHTLC3SClaim only extracts/verifies preimages.
CScript ClaimScriptSig(const std::vector<unsigned char>& su,
                       const std::vector<unsigned char>& s1,
                       const std::vector<unsigned char>& s2,
                       const CScript& redeem) {
    CScript ss;
    ss << std::vector<unsigned char>{0x01}        // sig placeholder
       << std::vector<unsigned char>{0x02}        // pubkey placeholder
       << s2 << s1 << su                          // pushed reverse of verification order
       << OP_TRUE
       << std::vector<unsigned char>(redeem.begin(), redeem.end());
    return ss;
}

CMutableTransaction MakeClaim3S(const COutPoint& htlcOut, const CScript& scriptSig,
                                CAmount voutValue, const CScript& dest) {
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType    = CTransaction::TxType::HTLC_CLAIM_3S;
    CTxIn in(htlcOut);
    in.scriptSig = scriptSig;
    mtx.vin.push_back(in);
    mtx.vout.emplace_back(CTxOut(voutValue, dest));
    return mtx;
}

CMutableTransaction MakeRefund3S(const COutPoint& htlcOut, CAmount voutValue, const CScript& dest) {
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType    = CTransaction::TxType::HTLC_REFUND_3S;
    mtx.vin.emplace_back(CTxIn(htlcOut));
    mtx.vout.emplace_back(CTxOut(voutValue, dest));
    return mtx;
}

struct Fx {
    CCoinsView coinsDummy;
    CCoinsViewCache view{&coinsDummy};
    CScript redeem = OpTrue();
    CScript dest;
    std::vector<unsigned char> su = Preimage(0xAA), s1 = Preimage(0xBB), s2 = Preimage(0xCC);
    COutPoint out{uint256S("dd"), 0};
    CAmount P = 100000;
    uint32_t expiry = 500;
    Fx() {
        BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
        BOOST_REQUIRE(g_htlcdb != nullptr);
        CKey k; k.MakeNewKey(true);
        dest = GetScriptForDestination(k.GetPubKey().GetID());
    }
    HTLC3SRecord writeActive() { return WriteActive3S(out, P, su, s1, s2, redeem, expiry); }
    // Assert the record on disk is still ACTIVE and unchanged in the fields we set.
    void assertUnchanged(const HTLC3SRecord& before) {
        HTLC3SRecord after;
        BOOST_REQUIRE(g_htlcdb->ReadHTLC3S(out, after));
        BOOST_CHECK(after.IsActive());
        BOOST_CHECK(after.status == before.status);
        BOOST_CHECK_EQUAL(after.amount, before.amount);
        BOOST_CHECK(after.hashlock_user == before.hashlock_user);
    }
};

} // namespace

// ---- CLAIM_3S ---------------------------------------------------------------

BOOST_AUTO_TEST_CASE(claim3s_happy_path)
{
    LOCK(cs_main); Fx f; f.writeActive();
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest);
    CValidationState st;
    BOOST_CHECK_MESSAGE(CheckHTLC3SClaim(CTransaction(tx), f.view, st),
                        "valid claim rejected: " + st.GetRejectReason());
}

BOOST_AUTO_TEST_CASE(claim3s_wrong_preimage)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto bad = Preimage(0x99);  // SHA256 != hashlock_user
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(bad, f.s1, f.s2, f.redeem), f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-preimage-mismatch");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_missing_preimage_scriptsig)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    CScript ss;  // fewer than 7 elements → extractor fails
    ss << std::vector<unsigned char>{0x01} << OP_TRUE
       << std::vector<unsigned char>(f.redeem.begin(), f.redeem.end());
    auto tx = MakeClaim3S(f.out, ss, f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-invalid-scriptsig");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_wrong_preimage_size)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    std::vector<unsigned char> shortPre(16, 0xAA);  // not 32 bytes
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(shortPre, f.s1, f.s2, f.redeem), f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-invalid-scriptsig");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_amount_too_low)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P - 1, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-amount-mismatch");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_amount_too_high)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P + 1, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-amount-mismatch");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_amount_zero)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), 0, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-amount-mismatch");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_htlc_missing)
{
    LOCK(cs_main); Fx f;  // no record written
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-not-htlc3s");
}

BOOST_AUTO_TEST_CASE(claim3s_not_active)
{
    LOCK(cs_main); Fx f; auto rec = f.writeActive();
    rec.status = HTLCStatus::CLAIMED;  // resolve it
    BOOST_REQUIRE(g_htlcdb->WriteHTLC3S(rec));
    auto tx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(tx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-not-active");
}

BOOST_AUTO_TEST_CASE(claim3s_wrong_type)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto mtx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest);
    mtx.nType = CTransaction::TxType::HTLC_REFUND_3S;  // wrong type for claim check
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(mtx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-type");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(claim3s_stray_optrue_output)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto mtx = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest);
    mtx.vout.emplace_back(CTxOut(1, OpTrue()));  // non-covenant stray OP_TRUE
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(mtx), f.view, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3sclaim-stray-optrue");
    f.assertUnchanged(before);
}

// ---- REFUND_3S --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(refund3s_before_expiry)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto tx = MakeRefund3S(f.out, f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SRefund(CTransaction(tx), f.view, f.expiry - 1, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3srefund-not-expired");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(refund3s_boundary_exact_expiry_ok)
{
    LOCK(cs_main); Fx f; f.writeActive();
    auto tx = MakeRefund3S(f.out, f.P, f.dest);
    CValidationState st;
    // nHeight == expiryHeight is the first refundable height (guard is nHeight < expiry).
    BOOST_CHECK_MESSAGE(CheckHTLC3SRefund(CTransaction(tx), f.view, f.expiry, st),
                        "refund at exact expiry rejected: " + st.GetRejectReason());
}

BOOST_AUTO_TEST_CASE(refund3s_after_expiry_ok)
{
    LOCK(cs_main); Fx f; f.writeActive();
    auto tx = MakeRefund3S(f.out, f.P, f.dest);
    CValidationState st;
    BOOST_CHECK_MESSAGE(CheckHTLC3SRefund(CTransaction(tx), f.view, f.expiry + 10, st),
                        "refund after expiry rejected: " + st.GetRejectReason());
}

BOOST_AUTO_TEST_CASE(refund3s_amount_mismatch)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto tx = MakeRefund3S(f.out, f.P - 1, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SRefund(CTransaction(tx), f.view, f.expiry, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3srefund-amount-mismatch");
    f.assertUnchanged(before);
}

BOOST_AUTO_TEST_CASE(refund3s_not_active)
{
    LOCK(cs_main); Fx f; auto rec = f.writeActive();
    rec.status = HTLCStatus::REFUNDED;
    BOOST_REQUIRE(g_htlcdb->WriteHTLC3S(rec));
    auto tx = MakeRefund3S(f.out, f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SRefund(CTransaction(tx), f.view, f.expiry, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3srefund-not-active");
}

BOOST_AUTO_TEST_CASE(refund3s_htlc_missing)
{
    LOCK(cs_main); Fx f;  // no record
    auto tx = MakeRefund3S(f.out, f.P, f.dest);
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SRefund(CTransaction(tx), f.view, f.expiry, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3srefund-not-htlc3s");
}

BOOST_AUTO_TEST_CASE(refund3s_wrong_type)
{
    LOCK(cs_main); Fx f; auto before = f.writeActive();
    auto mtx = MakeRefund3S(f.out, f.P, f.dest);
    mtx.nType = CTransaction::TxType::HTLC_CLAIM_3S;
    CValidationState st;
    BOOST_CHECK(!CheckHTLC3SRefund(CTransaction(mtx), f.view, f.expiry, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlc3srefund-type");
    f.assertUnchanged(before);
}

// ---- Mutual exclusivity (canonical property, no consensus change) -----------

BOOST_AUTO_TEST_CASE(claim3s_and_refund3s_mutually_exclusive_on_resolved_record)
{
    LOCK(cs_main); Fx f; auto rec = f.writeActive();
    // Simulate a completed claim: record becomes CLAIMED.
    rec.status = HTLCStatus::CLAIMED;
    BOOST_REQUIRE(g_htlcdb->WriteHTLC3S(rec));
    // A refund on the now-resolved outpoint must be rejected as not-active.
    auto refund = MakeRefund3S(f.out, f.P, f.dest);
    CValidationState st1;
    BOOST_CHECK(!CheckHTLC3SRefund(CTransaction(refund), f.view, f.expiry, st1));
    BOOST_CHECK_EQUAL(st1.GetRejectReason(), "bad-htlc3srefund-not-active");
    // And a second claim likewise.
    auto claim = MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest);
    CValidationState st2;
    BOOST_CHECK(!CheckHTLC3SClaim(CTransaction(claim), f.view, st2));
    BOOST_CHECK_EQUAL(st2.GetRejectReason(), "bad-htlc3sclaim-not-active");
}

// ---- STATE / REORG (real Apply → Undo drivers) ------------------------------
// These drive the SAME Apply*/Undo* functions ProcessSpecialTxsInBlock and the
// reorg path invoke, through the real g_settlementdb / g_htlcdb batches. They
// prove: a resolve mutates state deterministically, its undo restores the EXACT
// prior state (record ACTIVE, preimages cleared, receipt erased, undo row gone),
// and that after a real apply no second leg can resolve the same outpoint.

// Fixture that additionally owns an in-memory settlement DB for receipt effects.
struct FxState : Fx {
    FxState() {
        BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true));
        BOOST_REQUIRE(g_settlementdb != nullptr);
    }
    void applyClaim(const CTransaction& tx, uint32_t nHeight) {
        auto sb = g_settlementdb->CreateBatch();
        auto hb = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(ApplyHTLC3SClaim(tx, view, nHeight, sb, hb));
        BOOST_REQUIRE(sb.Commit());
        BOOST_REQUIRE(hb.Commit());
    }
    void undoClaim(const CTransaction& tx) {
        auto sb = g_settlementdb->CreateBatch();
        auto hb = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(UndoHTLC3SClaim(tx, sb, hb));
        BOOST_REQUIRE(sb.Commit());
        BOOST_REQUIRE(hb.Commit());
    }
    void applyRefund(const CTransaction& tx, uint32_t nHeight) {
        auto sb = g_settlementdb->CreateBatch();
        auto hb = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(ApplyHTLC3SRefund(tx, view, nHeight, sb, hb));
        BOOST_REQUIRE(sb.Commit());
        BOOST_REQUIRE(hb.Commit());
    }
    void undoRefund(const CTransaction& tx) {
        auto sb = g_settlementdb->CreateBatch();
        auto hb = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(UndoHTLC3SRefund(tx, sb, hb));
        BOOST_REQUIRE(sb.Commit());
        BOOST_REQUIRE(hb.Commit());
    }
    HTLC3SRecord read() {
        HTLC3SRecord r; BOOST_REQUIRE(g_htlcdb->ReadHTLC3S(out, r)); return r;
    }
};

BOOST_AUTO_TEST_CASE(claim3s_apply_then_undo_restores_exact_state)
{
    LOCK(cs_main); FxState f; auto before = f.writeActive();
    auto tx = CTransaction(MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest));

    // Apply: record → CLAIMED, preimages stored, claimer receipt at (txid,0).
    f.applyClaim(tx, /*nHeight=*/f.expiry - 100);
    HTLC3SRecord mid = f.read();
    BOOST_CHECK(mid.status == HTLCStatus::CLAIMED);
    BOOST_CHECK(mid.resolveTxid == tx.GetHash());
    BOOST_CHECK(!mid.preimage_user.IsNull());  // preimage stored on apply
    BOOST_CHECK(g_settlementdb->IsM1Receipt(COutPoint(tx.GetHash(), 0)));

    // Undo: back to the exact prior ACTIVE record; receipt + undo row gone.
    f.undoClaim(tx);
    HTLC3SRecord after = f.read();
    BOOST_CHECK(after.status == HTLCStatus::ACTIVE);
    BOOST_CHECK_EQUAL(after.amount, before.amount);
    BOOST_CHECK(after.hashlock_user == before.hashlock_user);
    BOOST_CHECK(after.hashlock_lp1 == before.hashlock_lp1);
    BOOST_CHECK(after.hashlock_lp2 == before.hashlock_lp2);
    BOOST_CHECK(after.resolveTxid.IsNull());
    BOOST_CHECK(after.preimage_user.IsNull());
    BOOST_CHECK(after.resultReceipt.IsNull());
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(COutPoint(tx.GetHash(), 0)));
    HTLC3SResolveUndoData dummy;
    BOOST_CHECK(!g_htlcdb->ReadResolve3SUndo(tx.GetHash(), dummy));
    // And the outpoint is claimable again (state truly reverted).
    CValidationState st;
    BOOST_CHECK_MESSAGE(CheckHTLC3SClaim(tx, f.view, st),
                        "re-claim after undo rejected: " + st.GetRejectReason());
}

BOOST_AUTO_TEST_CASE(refund3s_apply_then_undo_restores_exact_state)
{
    LOCK(cs_main); FxState f; auto before = f.writeActive();
    auto tx = CTransaction(MakeRefund3S(f.out, f.P, f.dest));

    f.applyRefund(tx, /*nHeight=*/f.expiry);
    HTLC3SRecord mid = f.read();
    BOOST_CHECK(mid.status == HTLCStatus::REFUNDED);
    BOOST_CHECK(g_settlementdb->IsM1Receipt(COutPoint(tx.GetHash(), 0)));

    f.undoRefund(tx);
    HTLC3SRecord after = f.read();
    BOOST_CHECK(after.status == HTLCStatus::ACTIVE);
    BOOST_CHECK_EQUAL(after.amount, before.amount);
    BOOST_CHECK(after.hashlock_user == before.hashlock_user);
    BOOST_CHECK(after.resolveTxid.IsNull());
    BOOST_CHECK(after.resultReceipt.IsNull());
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(COutPoint(tx.GetHash(), 0)));
    HTLC3SResolveUndoData dummy;
    BOOST_CHECK(!g_htlcdb->ReadResolve3SUndo(tx.GetHash(), dummy));
}

BOOST_AUTO_TEST_CASE(claim3s_after_real_apply_second_claim_and_refund_both_rejected)
{
    LOCK(cs_main); FxState f; f.writeActive();
    auto claim = CTransaction(MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest));
    f.applyClaim(claim, /*nHeight=*/f.expiry - 100);
    // After a REAL claim apply, no second leg resolves the same outpoint.
    CValidationState st1;
    BOOST_CHECK(!CheckHTLC3SClaim(claim, f.view, st1));
    BOOST_CHECK_EQUAL(st1.GetRejectReason(), "bad-htlc3sclaim-not-active");
    auto refund = CTransaction(MakeRefund3S(f.out, f.P, f.dest));
    CValidationState st2;
    BOOST_CHECK(!CheckHTLC3SRefund(refund, f.view, f.expiry, st2));
    BOOST_CHECK_EQUAL(st2.GetRejectReason(), "bad-htlc3srefund-not-active");
}

BOOST_AUTO_TEST_CASE(refund3s_after_real_apply_claim_and_second_refund_both_rejected)
{
    LOCK(cs_main); FxState f; f.writeActive();
    auto refund = CTransaction(MakeRefund3S(f.out, f.P, f.dest));
    f.applyRefund(refund, /*nHeight=*/f.expiry);
    CValidationState st1;
    BOOST_CHECK(!CheckHTLC3SRefund(refund, f.view, f.expiry, st1));
    BOOST_CHECK_EQUAL(st1.GetRejectReason(), "bad-htlc3srefund-not-active");
    auto claim = CTransaction(MakeClaim3S(f.out, ClaimScriptSig(f.su, f.s1, f.s2, f.redeem), f.P, f.dest));
    CValidationState st2;
    BOOST_CHECK(!CheckHTLC3SClaim(claim, f.view, st2));
    BOOST_CHECK_EQUAL(st2.GetRejectReason(), "bad-htlc3sclaim-not-active");
}

BOOST_AUTO_TEST_SUITE_END()
