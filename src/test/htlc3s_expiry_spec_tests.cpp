// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ============================================================================
// F-HTLC-2 — pivot expiry-order rules (ADR-HTLC3S-EXPIRY-CONSTRAINT,
// ACCEPTED FOR PUBLIC-TESTNET GENESIS, USER GO 2026-07-21).
//
//   R1 (create):    htlc3ExpiryHeight >= expiryHeight + HTLC3S_MIN_LIFETIME
//                   -> "bad-htlccreate-expiry-order"
//   R2 (claim):     htlc3ExpiryHeight >= nHeight + HTLC3S_MIN_LIFETIME
//                   -> "bad-htlcclaim-child-underlife"
//   Companion:      expiryHeight > nHeight at creation
//                   -> "bad-htlccreate-expired-at-creation"
//   HTLC3S_MIN_LIFETIME = 2 (structural floor: detect 1 + include 1).
//   All arithmetic in int64 (payload heights are attacker-controlled uint32).
//
// Red-first protocol: this suite is REGISTERED and was proven RED against the
// pre-fix consensus (the rules did not exist), then turns green with the fix.
// No test is disabled or weakened.
// ============================================================================

#include "amount.h"
#include "coins.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/conditional.h"
#include "script/script.h"
#include "script/standard.h"
#include "state/settlement.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"
#include "htlc/htlc.h"
#include "htlc/htlcdb.h"
#include "masternode/specialtx_validation.h"   // CheckSpecialTx (real dispatch)
#include "streams.h"
#include "validation.h"                        // cs_main
#include "version.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(htlc3s_expiry_spec_tests, BasicTestingSetup)

namespace {

// The consensus floor under test. Kept as a local literal so the suite
// compiled (and ran RED) against the pre-fix tree; the cross-check test
// below pins it to the consensus constant once the fix lands.
constexpr int64_t SPEC_MIN_LIFETIME = 2;

CScript OpTrue() { CScript s; s << OP_TRUE; return s; }

CKeyID NewKeyID() {
    CKey k; k.MakeNewKey(true);
    return k.GetPubKey().GetID();
}

struct Fx {
    CCoinsView coinsDummy;
    CCoinsViewCache view{&coinsDummy};
    CAmount P = 100000;
    COutPoint receiptOut{uint256S("aa"), 0};
    Fx() {
        BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
        BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true));
        BOOST_REQUIRE(g_htlcdb != nullptr && g_settlementdb != nullptr);
        M1Receipt r;
        r.outpoint = receiptOut;
        r.amount = P;
        r.nCreateHeight = 1;
        auto sb = g_settlementdb->CreateBatch();
        sb.WriteReceipt(r);
        BOOST_REQUIRE(sb.Commit());
        BOOST_REQUIRE(g_settlementdb->IsM1Receipt(receiptOut));
    }
};

HTLCCreatePayload MakeCovenantPayload(uint32_t parentExpiry, uint32_t childExpiry) {
    HTLCCreatePayload p;
    p.nVersion = HTLC_CREATE_PAYLOAD_VERSION_CTV;
    p.hashlock = uint256S("11");
    p.expiryHeight = parentExpiry;
    p.claimKeyID = NewKeyID();
    p.refundKeyID = NewKeyID();
    p.templateCommitment = uint256S("22");   // non-null => HasCovenant()
    p.htlc3ExpiryHeight = childExpiry;
    p.htlc3ClaimKeyID = NewKeyID();
    p.htlc3RefundKeyID = NewKeyID();
    return p;
}

HTLCCreatePayload MakePlainPayload(uint32_t parentExpiry) {
    HTLCCreatePayload p;
    p.nVersion = HTLC_CREATE_PAYLOAD_VERSION;   // v1: no covenant fields
    p.hashlock = uint256S("11");
    p.expiryHeight = parentExpiry;
    p.claimKeyID = NewKeyID();
    p.refundKeyID = NewKeyID();
    return p;
}

CMutableTransaction MakeCreateTx(const COutPoint& receiptOut, CAmount amount,
                                 const HTLCCreatePayload& payload) {
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CREATE_M1;
    mtx.vin.emplace_back(CTxIn(receiptOut));
    CScript redeem = OpTrue();
    mtx.vout.emplace_back(CTxOut(amount, GetScriptForDestination(CScriptID(redeem))));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());
    return mtx;
}

bool RunCheckCreate(Fx& f, const HTLCCreatePayload& payload, uint32_t nHeight,
                    std::string& reason) {
    auto tx = CTransaction(MakeCreateTx(f.receiptOut, f.P, payload));
    CValidationState st;
    bool ok = CheckHTLCCreate(tx, f.view, st, /*fCheckUTXO=*/false, nHeight);
    reason = st.GetRejectReason();
    return ok;
}

// Claim-side fixture: an ACTIVE covenant HTLC with a REAL preimage and the
// canonical covenant claim shape (vout[0]=amount-fee, vout[1]=OP_TRUE fee),
// driven through CheckSpecialTx — the exact mempool/ConnectBlock dispatch —
// so the run is signature-stable across the fix.
struct ClaimFx : Fx {
    CKey key;
    CKeyID keyID;
    std::vector<unsigned char> secret = std::vector<unsigned char>(32, 0x7A);
    uint256 hashlock;
    COutPoint htlcOut{uint256S("bb"), 0};
    CScript redeem;
    CAmount fee = CTV_FIXED_FEE;

    ClaimFx() {
        key.MakeNewKey(true);
        keyID = key.GetPubKey().GetID();
        CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());
    }

    void writeCovenantParent(uint32_t parentExpiry, uint32_t childExpiry) {
        redeem = CreateConditionalWithCovenantScript(hashlock, parentExpiry, keyID,
                                                     keyID, uint256S("22"));
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

    CTransaction makeClaim() {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::HTLC_CLAIM;
        CTxIn in(htlcOut);
        in.scriptSig = CreateConditionalSpendA(std::vector<unsigned char>(72, 0x30),
                                               key.GetPubKey(), secret, redeem);
        mtx.vin.push_back(in);
        mtx.vout.emplace_back(CTxOut(P - fee, GetScriptForDestination(CScriptID(OpTrue()))));
        mtx.vout.emplace_back(CTxOut(fee, OpTrue()));
        return CTransaction(mtx);
    }

    // Drive the REAL dispatch at chain height nHeight (idxPrev = nHeight - 1).
    bool runClaimAt(uint32_t nHeight, std::string& reason) {
        CBlockIndex idxPrev;
        idxPrev.nHeight = (int)nHeight - 1;
        CValidationState st;
        bool ok = CheckSpecialTx(makeClaim(), &idxPrev, &view, st);
        reason = st.GetRejectReason();
        return ok;
    }
};

} // namespace

// ---- Companion: no born-expired parent (any HTLC_CREATE_M1) -----------------

BOOST_AUTO_TEST_CASE(create_rejects_parent_expiring_now)
{
    LOCK(cs_main); Fx f; std::string reason;
    bool ok = RunCheckCreate(f, MakeCovenantPayload(/*parent=*/100, /*child=*/200), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "parent expiring at current height must be rejected");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expired-at-creation");
}

BOOST_AUTO_TEST_CASE(create_rejects_parent_expired_in_past)
{
    LOCK(cs_main); Fx f; std::string reason;
    bool ok = RunCheckCreate(f, MakeCovenantPayload(/*parent=*/50, /*child=*/200), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "parent expired in the past must be rejected");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expired-at-creation");
}

BOOST_AUTO_TEST_CASE(create_noncovenant_rejects_born_expired)
{
    LOCK(cs_main); Fx f; std::string reason;
    bool ok = RunCheckCreate(f, MakePlainPayload(/*parent=*/50), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "non-covenant born-expired parent must be rejected");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expired-at-creation");
}

BOOST_AUTO_TEST_CASE(create_noncovenant_valid_expiry_accepted)
{
    LOCK(cs_main); Fx f; std::string reason;
    BOOST_CHECK_MESSAGE(RunCheckCreate(f, MakePlainPayload(500), /*h=*/100, reason),
                        "valid non-covenant create rejected: " + reason);
}

// ---- R1: child must outlive the parent by HTLC3S_MIN_LIFETIME ---------------

// The pre-fix production builder default (settlement_wallet.cpp): equality.
BOOST_AUTO_TEST_CASE(create_rejects_child_equal_parent_builder_legacy_default)
{
    LOCK(cs_main); Fx f; std::string reason;
    bool ok = RunCheckCreate(f, MakeCovenantPayload(500, 500), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "equal expiries (legacy builder default) must be rejected");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expiry-order");
}

BOOST_AUTO_TEST_CASE(create_rejects_child_one_block_after_parent)
{
    LOCK(cs_main); Fx f; std::string reason;
    bool ok = RunCheckCreate(f, MakeCovenantPayload(500, 501), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "one-block margin must be rejected (< HTLC3S_MIN_LIFETIME)");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expiry-order");
}

BOOST_AUTO_TEST_CASE(create_accepts_child_at_exact_min_lifetime)
{
    LOCK(cs_main); Fx f; std::string reason;
    BOOST_CHECK_MESSAGE(
        RunCheckCreate(f, MakeCovenantPayload(500, 500 + SPEC_MIN_LIFETIME), /*h=*/100, reason),
        "exact-margin child expiry rejected: " + reason);
}

BOOST_AUTO_TEST_CASE(create_accepts_child_above_min_lifetime)
{
    LOCK(cs_main); Fx f; std::string reason;
    BOOST_CHECK_MESSAGE(RunCheckCreate(f, MakeCovenantPayload(500, 800), /*h=*/100, reason),
                        "wide-margin child expiry rejected: " + reason);
}

// ---- Overflow / uint32 extremes (int64 arithmetic mandatory) ----------------

// parent + HTLC3S_MIN_LIFETIME wraps in uint32: a naive 32-bit compare would
// accept a tiny child. The int64 rule must reject (no uint32 child can satisfy
// the floor) — this IS the explicit overflow rejection.
BOOST_AUTO_TEST_CASE(create_rejects_overflow_parent_plus_lifetime_wraps)
{
    LOCK(cs_main); Fx f; std::string reason;
    bool ok = RunCheckCreate(f, MakeCovenantPayload(0xFFFFFFFEu, 5), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "wrapped child expiry must be rejected (int64 compare)");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expiry-order");
}

BOOST_AUTO_TEST_CASE(create_rejects_parent_at_uint32_max)
{
    LOCK(cs_main); Fx f; std::string reason;
    // Even the largest representable child cannot satisfy parent + lifetime.
    bool ok = RunCheckCreate(f, MakeCovenantPayload(0xFFFFFFFFu, 0xFFFFFFFFu), /*h=*/100, reason);
    BOOST_CHECK_MESSAGE(!ok, "uint32-max parent must be rejected (floor unsatisfiable)");
    BOOST_CHECK_EQUAL(reason, "bad-htlccreate-expiry-order");
}

// A uint32-max CHILD with a sane parent satisfies R1. Accepted by consensus —
// the voluntary lock-forever risk is a documented wallet-policy matter (ADR:
// no consensus max bound in this pass).
BOOST_AUTO_TEST_CASE(create_accepts_child_at_uint32_max)
{
    LOCK(cs_main); Fx f; std::string reason;
    BOOST_CHECK_MESSAGE(RunCheckCreate(f, MakeCovenantPayload(500, 0xFFFFFFFFu), /*h=*/100, reason),
                        "uint32-max child with sane parent rejected: " + reason);
}

// ---- R2: the child born by a claim must live >= HTLC3S_MIN_LIFETIME --------

BOOST_AUTO_TEST_CASE(claim_rejects_child_underlife)
{
    LOCK(cs_main); ClaimFx f; std::string reason;
    const uint32_t H = 300;
    f.writeCovenantParent(/*parentExpiry=*/500, /*childExpiry=*/H + 1);  // < H + 2
    bool ok = f.runClaimAt(H, reason);
    BOOST_CHECK_MESSAGE(!ok, "claim birthing an under-life child must be rejected");
    BOOST_CHECK_EQUAL(reason, "bad-htlcclaim-child-underlife");
}

BOOST_AUTO_TEST_CASE(claim_accepts_child_at_exact_min_lifetime)
{
    LOCK(cs_main); ClaimFx f; std::string reason;
    const uint32_t H = 300;
    f.writeCovenantParent(/*parentExpiry=*/500, /*childExpiry=*/H + SPEC_MIN_LIFETIME);
    BOOST_CHECK_MESSAGE(f.runClaimAt(H, reason),
                        "claim at exact child min-lifetime rejected: " + reason);
}

// ---- Full pivot path with a healthy margin ---------------------------------

BOOST_AUTO_TEST_CASE(full_pivot_path_with_margin)
{
    LOCK(cs_main); ClaimFx f; std::string reason;
    const uint32_t createH = 100, parentExpiry = 500, childExpiry = 510, claimH = 200;

    // Create passes the new rules...
    BOOST_CHECK_MESSAGE(
        RunCheckCreate(f, MakeCovenantPayload(parentExpiry, childExpiry), createH, reason),
        "margined covenant create rejected: " + reason);

    // ...and the claim both validates through the real dispatch and births a
    // child with at least the minimum lifetime, via the real Apply driver.
    f.writeCovenantParent(parentExpiry, childExpiry);
    BOOST_CHECK_MESSAGE(f.runClaimAt(claimH, reason),
                        "margined covenant claim rejected: " + reason);
    CTransaction claimTx = f.makeClaim();
    {
        auto sb = g_settlementdb->CreateBatch();
        auto hb = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(ApplyHTLCClaim(claimTx, f.view, claimH, sb, hb));
        BOOST_REQUIRE(sb.Commit());
        BOOST_REQUIRE(hb.Commit());
    }
    HTLCRecord child;
    BOOST_REQUIRE(g_htlcdb->ReadHTLC(COutPoint(claimTx.GetHash(), 0), child));
    BOOST_CHECK(child.IsActive());
    BOOST_CHECK_EQUAL(child.expiryHeight, childExpiry);
    BOOST_CHECK((int64_t)child.expiryHeight >= (int64_t)child.createHeight + SPEC_MIN_LIFETIME);
}

// ---- Added with the fix (need the new CheckHTLCClaim signature) -------------

// GO case "overflow currentHeight + 2": nHeight + HTLC3S_MIN_LIFETIME would
// wrap in uint32 at an extreme height; the int64 rule must still reject the
// under-life child. Direct call — exercises the fixed function's arithmetic.
BOOST_AUTO_TEST_CASE(claim_direct_int64_no_wrap_at_extreme_height)
{
    LOCK(cs_main); ClaimFx f;
    f.writeCovenantParent(/*parentExpiry=*/0xFFFFFFFFu, /*childExpiry=*/5);
    CValidationState st;
    BOOST_CHECK(!CheckHTLCClaim(f.makeClaim(), f.view, /*nHeight=*/0xFFFFFFFEu, st));
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-child-underlife");
}

// Pin the suite's local literal to the consensus constant so they can never
// silently diverge.
BOOST_AUTO_TEST_CASE(spec_constant_matches_consensus)
{
    BOOST_CHECK_EQUAL(SPEC_MIN_LIFETIME, (int64_t)HTLC3S_MIN_LIFETIME);
}

BOOST_AUTO_TEST_SUITE_END()
