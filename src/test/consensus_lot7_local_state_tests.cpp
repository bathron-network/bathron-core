// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ═══════════════════════════════════════════════════════════════════════════════
// LOT 7 (L6-F16) — a node-LOCAL derived-DB state must never produce block invalidity
// or a peer ban; a genuine consensus violation against the parent's state must.
// ═══════════════════════════════════════════════════════════════════════════════
//
// L6-F16: CheckUnlock / CheckTransfer / the six CheckHTLC* / A7 read the DERIVED,
// node-local settlement and HTLC databases and, on a miss, returned state.DoS(100)
// -> persisted BLOCK_FAILED_VALID + a peer ban. A node with an empty or behind DB
// therefore rejected valid TX_UNLOCK blocks and banned the peers that served them,
// while a synced node accepted them — divergence caused purely by local storage.
//
// PHASE 1 proved (measured) that in normal operation ReadBestBlock() of both DBs
// equals pindexPrev at read time. PHASE 2 gates on that:
//   - marker == parent  -> the DB IS the canonical parent state: present/absent is
//     authoritative, and the real consensus check stands (a genuinely invalid tx is
//     still DoS'd);
//   - marker missing / behind / different -> LOCAL fault: fatal+reindex on the block
//     path, plain non-persisting Error on mempool. Never DoS, never a ban.
//
// The gate is CheckLocalStateConsistency; the vault half is answered from the
// canonical coins view (IsVaultScript), not the DB (arch A).

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "htlc/htlcdb.h"
#include "masternode/specialtx_validation.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "state/settlement.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"
#include "test/test_bathron.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

//! A minimal chain of synthetic block indexes with real phashBlock pointers, plus the
//! two derived DBs in memory. Every helper keeps the DB markers at the CHOSEN parent
//! so the gate's "DB == parent" precondition is under the test's control.
struct Lot7Setup : public TestingSetup {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> idx;
    CCoinsView backing;
    CCoinsViewCache view{&backing};

    Lot7Setup() : idx(6)
    {
        BOOST_REQUIRE(InitSettlementDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));
        BOOST_REQUIRE(InitHtlcDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));
        ResetConsensusDBFatalForTests();
        hashes.reserve(6);
        for (int h = 0; h < 6; ++h) {
            hashes.push_back(ArithToUint256(arith_uint256(0x7070000 + h)));
            idx[h].nHeight = 1000 + h;
            idx[h].phashBlock = &hashes[h];
            idx[h].pprev = (h == 0) ? nullptr : &idx[h - 1];
        }
        SyncMarkersTo(&idx[4]);   // both DBs current at idx[4] by default
    }
    ~Lot7Setup() { ResetConsensusDBFatalForTests(); }

    CBlockIndex* parent() { return &idx[4]; }

    void SyncMarkersTo(const CBlockIndex* p)
    {
        g_settlementdb->WriteBestBlock(p->GetBlockHash());
        g_htlcdb->WriteBestBlock(p->GetBlockHash());
    }

    //! A TX_UNLOCK spending a receipt (present in the DB) and a vault. The vault input's
    //! coin is added to the coins view as OP_TRUE so arch A classifies it canonically.
    CTransaction MakeUnlock()
    {
        // Seed a receipt + a vault the tx will consume.
        const COutPoint rcptOP(ArithToUint256(arith_uint256(0xA1)), 0);
        const COutPoint vaultOP(ArithToUint256(arith_uint256(0xB1)), 0);
        M1Receipt r; r.outpoint = rcptOP; r.amount = 1000; r.nCreateHeight = 1001;
        g_settlementdb->WriteReceipt(r);
        VaultEntry v; v.outpoint = vaultOP; v.amount = 1000; v.nLockHeight = 1001;
        g_settlementdb->WriteVault(v);
        // Coins view: receipt as P2PKH-ish, vault as OP_TRUE.
        Coin cv; cv.out.nValue = 1000; cv.out.scriptPubKey = CScript() << OP_TRUE; cv.nHeight = 1001;
        view.AddCoin(vaultOP, std::move(cv), false);
        Coin cr; cr.out.nValue = 1000; cr.out.scriptPubKey = CScript() << OP_DUP; cr.nHeight = 1001;
        view.AddCoin(rcptOP, std::move(cr), false);

        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_UNLOCK;
        mtx.vin.emplace_back(rcptOP);
        mtx.vin.emplace_back(vaultOP);
        mtx.vout.emplace_back(1000, CScript() << OP_DUP);
        return CTransaction(mtx);
    }
};

//! Reject reason produced by the LOT 7 gate for a settlement-behind DB.
const std::string kSettlementBehind = "local-state-behind-settlement";

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot7_local_state, Lot7Setup)

// ───────────────────────────────────────────────────────────────────────────────
// PROOF 1 — DBs consistent -> the real verdict stands (no interference)
// ───────────────────────────────────────────────────────────────────────────────

// With the markers at the parent, the gate is transparent: a well-formed special tx
// reaches its business check exactly as before.
BOOST_AUTO_TEST_CASE(consistent_db_lets_the_real_check_run)
{
    LOCK(cs_main);
    SyncMarkersTo(parent());
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    // We do not assert accept/reject of the business rule here (that is settlement_tests'
    // job); we assert the gate did NOT interpose a local-state error.
    CheckSpecialTx(unlock, parent(), &view, st, /*fBlockConnect=*/true);
    BOOST_CHECK_MESSAGE(st.GetRejectReason() != kSettlementBehind,
                        "a consistent DB must not raise local-state-behind");
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(), "a consistent DB must not fire the fatal latch");
}

// ───────────────────────────────────────────────────────────────────────────────
// PROOF 2 & 3 — empty / behind DB: local fault only, never invalidity or ban
// ───────────────────────────────────────────────────────────────────────────────

// MEMPOOL path, DB behind (marker at an older block): state.Error, NOT DoS, no ban,
// no fatal latch. fBlockConnect=false models AcceptToMemoryPool.
BOOST_AUTO_TEST_CASE(behind_db_on_mempool_is_local_error_never_dos)
{
    LOCK(cs_main);
    SyncMarkersTo(&idx[2]);        // settlement marker is two blocks behind the parent
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    const bool ok = CheckSpecialTx(unlock, parent(), &view, st, /*fBlockConnect=*/false);
    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(st.IsError(), "behind DB on mempool must be MODE_ERROR");
    BOOST_CHECK_MESSAGE(!st.IsInvalid(), "behind DB must NEVER be consensus invalidity");
    int dos = 0; st.IsInvalid(dos);
    BOOST_CHECK_MESSAGE(dos == 0, "behind DB must score no DoS / no ban");
    BOOST_CHECK_EQUAL(st.GetRejectReason(), kSettlementBehind);
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(), "mempool path must not fire the fatal latch");
}

// EMPTY DB (no marker at all) on mempool: same — local error, not invalidity.
BOOST_AUTO_TEST_CASE(empty_db_on_mempool_is_local_error)
{
    LOCK(cs_main);
    BOOST_REQUIRE(InitSettlementDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));  // wipe -> no marker
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(unlock, parent(), &view, st, /*fBlockConnect=*/false));
    BOOST_CHECK(st.IsError());
    BOOST_CHECK(!st.IsInvalid());
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(), "an empty DB is NOT a silent exemption, but on "
                        "mempool it is a local error, not a fatal");
}

// BLOCK-CONNECT path, DB behind: the LOT 1 fatal latch fires (node halts, -reindex),
// state is a NON-invalid Error, and StartShutdown is requested exactly once.
BOOST_AUTO_TEST_CASE(behind_db_on_block_connect_is_fatal_not_invalid)
{
    LOCK(cs_main);
    SyncMarkersTo(&idx[2]);
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    const bool ok = CheckSpecialTx(unlock, parent(), &view, st, /*fBlockConnect=*/true);
    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(), "block-connect + behind DB must fire the fatal latch");
    BOOST_CHECK_MESSAGE(st.IsError(), "the fatal latch sets a NON-invalid Error");
    BOOST_CHECK_MESSAGE(!st.IsInvalid(), "a storage fault is NEVER block invalidity");
    // The latch requests a clean shutdown -> -reindex, exactly once. Assert and consume it.
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 1);
    test_shutdown::Reset();
}

// ───────────────────────────────────────────────────────────────────────────────
// PROOF 4 — marker correct but record absent: DETERMINISTIC consensus rejection
// ───────────────────────────────────────────────────────────────────────────────

// When the marker IS the parent, an absent record is AUTHORITATIVE: the operation that
// requires it is genuinely invalid, and the node must DoS (this is real consensus, and
// two synced nodes agree). Here a NORMAL tx spends a coin the DB does not know as a
// receipt while the coins view marks the spent input as an M1 receipt is not possible;
// instead we exercise the converse: the vault protection with a consistent DB rejects a
// non-UNLOCK spend of a vault with a normal DoS, not a local error.
BOOST_AUTO_TEST_CASE(consistent_db_vault_misuse_is_a_real_dos)
{
    LOCK(cs_main);
    SyncMarkersTo(parent());
    // A vault coin (OP_TRUE) spent by a NON-unlock type must be rejected by the REAL
    // rule, as a DoS — not swallowed as a local state error.
    const COutPoint vaultOP(ArithToUint256(arith_uint256(0xB2)), 0);
    VaultEntry v; v.outpoint = vaultOP; v.amount = 500; v.nLockHeight = 1001;
    g_settlementdb->WriteVault(v);
    Coin cv; cv.out.nValue = 500; cv.out.scriptPubKey = CScript() << OP_TRUE; cv.nHeight = 1001;
    view.AddCoin(vaultOP, std::move(cv), false);

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;   // NOT unlock
    mtx.vin.emplace_back(vaultOP);
    mtx.vout.emplace_back(500, CScript() << OP_DUP);
    CTransaction tx(mtx);

    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(tx, parent(), &view, st, /*fBlockConnect=*/true));
    int dos = 0;
    BOOST_CHECK_MESSAGE(st.IsInvalid(dos) && dos == 100,
                        "vault misuse under a consistent DB is a REAL consensus DoS, not a local error");
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-vault-protected");
    BOOST_CHECK(!IsConsensusDBFatal());
}

// ───────────────────────────────────────────────────────────────────────────────
// PROOF 5 — coins view / vault DB disagreement -> local fault, not invalid tx (arch A)
// ───────────────────────────────────────────────────────────────────────────────

// DB says vault, coins view says NOT a vault (corrupt DB), marker == parent. Arch A:
// the canonical coins view wins; the disagreement is a LOCAL fault -> fatal on connect.
BOOST_AUTO_TEST_CASE(vault_db_vs_coinsview_disagreement_is_local_fault)
{
    LOCK(cs_main);
    SyncMarkersTo(parent());
    const COutPoint op(ArithToUint256(arith_uint256(0xB3)), 0);
    // DB: vault. Coins view: NOT OP_TRUE (a plain P2PKH-ish script) -> disagreement.
    VaultEntry v; v.outpoint = op; v.amount = 700; v.nLockHeight = 1001;
    g_settlementdb->WriteVault(v);
    Coin c; c.out.nValue = 700; c.out.scriptPubKey = CScript() << OP_DUP << OP_HASH160; c.nHeight = 1001;
    view.AddCoin(op, std::move(c), false);

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;
    mtx.vin.emplace_back(op);
    mtx.vout.emplace_back(700, CScript() << OP_DUP);
    CTransaction tx(mtx);

    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(tx, parent(), &view, st, /*fBlockConnect=*/true));
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(),
                        "coins-view/DB vault disagreement on connect is a corrupt-DB local fault");
    BOOST_CHECK(!st.IsInvalid());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 1);
    test_shutdown::Reset();
}

// ───────────────────────────────────────────────────────────────────────────────
// SEPARATELY: settlement correct / HTLC behind, and the converse
// ───────────────────────────────────────────────────────────────────────────────

// An HTLC-type tx requires BOTH DBs. Settlement current, HTLC behind -> local fault on
// the HTLC DB specifically.
BOOST_AUTO_TEST_CASE(settlement_ok_htlc_behind_is_local_fault_on_htlc)
{
    LOCK(cs_main);
    g_settlementdb->WriteBestBlock(parent()->GetBlockHash());
    g_htlcdb->WriteBestBlock(idx[1].GetBlockHash());     // HTLC DB behind

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CLAIM;
    mtx.vin.emplace_back(COutPoint(ArithToUint256(arith_uint256(0xC1)), 0));
    mtx.vout.emplace_back(100, CScript() << OP_DUP);
    CTransaction tx(mtx);

    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(tx, parent(), &view, st, /*fBlockConnect=*/false));
    BOOST_CHECK(st.IsError() && !st.IsInvalid());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "local-state-behind-htlc");
}

// Settlement behind / HTLC current: the settlement DB is checked first, so an HTLC tx
// with settlement behind reports the settlement fault.
BOOST_AUTO_TEST_CASE(settlement_behind_htlc_ok_reports_settlement)
{
    LOCK(cs_main);
    g_settlementdb->WriteBestBlock(idx[1].GetBlockHash());  // settlement behind
    g_htlcdb->WriteBestBlock(parent()->GetBlockHash());

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CLAIM;
    mtx.vin.emplace_back(COutPoint(ArithToUint256(arith_uint256(0xC2)), 0));
    mtx.vout.emplace_back(100, CScript() << OP_DUP);
    CTransaction tx(mtx);

    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(tx, parent(), &view, st, /*fBlockConnect=*/false));
    BOOST_CHECK(st.IsError() && !st.IsInvalid());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), kSettlementBehind);
}

// ───────────────────────────────────────────────────────────────────────────────
// LATERAL PARENT after a rollback to the fork: a DB at the ORIGINAL tip is "behind"
// relative to the side-branch parent -> local fault, never a wrong verdict.
// ───────────────────────────────────────────────────────────────────────────────

// idx[4] is the (former) tip; idx[3] a side parent. If the DB marker is at idx[4] but
// we validate a child of idx[3] (a different branch's parent), the marker != parent,
// so the gate refuses locally rather than reading idx[4]'s records as if they were
// idx[3]'s state.
BOOST_AUTO_TEST_CASE(lateral_parent_with_tip_marker_is_local_fault)
{
    LOCK(cs_main);
    SyncMarkersTo(&idx[4]);                 // DB at the former tip
    CBlockIndex* sideParent = &idx[3];      // validate against a DIFFERENT parent
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(unlock, sideParent, &view, st, /*fBlockConnect=*/false));
    BOOST_CHECK(st.IsError() && !st.IsInvalid());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), kSettlementBehind);
}

// After the DB is re-synced to the side parent, the same tx no longer trips the gate.
BOOST_AUTO_TEST_CASE(after_resync_to_side_parent_gate_is_transparent)
{
    LOCK(cs_main);
    CBlockIndex* sideParent = &idx[3];
    SyncMarkersTo(sideParent);
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    CheckSpecialTx(unlock, sideParent, &view, st, /*fBlockConnect=*/false);
    BOOST_CHECK_MESSAGE(st.GetRejectReason() != kSettlementBehind,
                        "once the DB is at the side parent, the gate is transparent");
}

// ───────────────────────────────────────────────────────────────────────────────
// GENESIS BOUNDARY — regression for the CRITICAL the process lab + independent
// review both caught: gate B fatal-latched block 1 of every fresh chain because the
// derived-DB best-block MARKER is only written by a block's own commit, so at the
// genesis parent it is legitimately ABSENT. The genesis parent (height 0) must be
// transparent; beyond genesis, an absent marker is still a fault.
// ───────────────────────────────────────────────────────────────────────────────

// Block 1 (parent = genesis, height 0) on a fresh node with NO marker: gate B must be
// transparent and must NOT fire the fatal latch, even on the block-connect path.
BOOST_AUTO_TEST_CASE(genesis_parent_fresh_db_is_transparent_not_fatal)
{
    LOCK(cs_main);
    BOOST_REQUIRE(InitSettlementDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));  // fresh, no marker
    BOOST_REQUIRE(InitHtlcDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));
    ResetConsensusDBFatalForTests();
    uint256 genHash = ArithToUint256(arith_uint256(0x6E0));
    CBlockIndex gen; gen.nHeight = 0; gen.phashBlock = &genHash; gen.pprev = nullptr;
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    CheckSpecialTx(unlock, &gen, &view, st, /*fBlockConnect=*/true);
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(),
        "block-1 validation (genesis parent, fresh marker-less DB) must NOT fatal-latch");
    BOOST_CHECK_MESSAGE(st.GetRejectReason() != kSettlementBehind,
        "genesis parent must not raise local-state-behind");
}

// The genesis exemption is genesis-ONLY: an absent marker under a parent BEYOND genesis
// (height > 0) is a wiped/torn DB and must still fire the fatal latch on connect.
BOOST_AUTO_TEST_CASE(absent_marker_beyond_genesis_still_fatal)
{
    LOCK(cs_main);
    BOOST_REQUIRE(InitSettlementDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));  // fresh, no marker
    BOOST_REQUIRE(InitHtlcDB(1 << 16, /*fMemory=*/true, /*fWipe=*/true));
    ResetConsensusDBFatalForTests();
    CTransaction unlock = MakeUnlock();
    CValidationState st;
    CheckSpecialTx(unlock, parent(), &view, st, /*fBlockConnect=*/true);   // parent() is height 1004
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(),
        "an empty marker under a non-genesis parent is a wiped DB -> fatal");
    BOOST_CHECK(!st.IsInvalid());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 1);
    test_shutdown::Reset();
}

// ───────────────────────────────────────────────────────────────────────────────
// ARCH A (MEDIUM, independent review) — an OP_TRUE coin that the vault DB does NOT
// know is a vault must be protected by SCRIPT (deterministic DoS on a non-UNLOCK
// spend), NOT halt the node. This is the empty/behind-DB direction the LOT targets,
// and it also removes the false-halt on a bare-OP_TRUE output. The opposite
// direction (DB=vault, coin not OP_TRUE) stays a fatal local fault — see
// vault_db_vs_coinsview_disagreement_is_local_fault above.
// ───────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(optrue_coin_absent_from_vault_db_is_protected_by_script_not_fatal)
{
    LOCK(cs_main);
    SyncMarkersTo(parent());
    const COutPoint op(ArithToUint256(arith_uint256(0xB4)), 0);
    // Coins view: OP_TRUE (a vault by script). DB: NO vault entry for it (behind/empty).
    Coin c; c.out.nValue = 900; c.out.scriptPubKey = CScript() << OP_TRUE; c.nHeight = 1001;
    view.AddCoin(op, std::move(c), false);
    // A NON-unlock spend of the OP_TRUE coin.
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;   // NOT unlock
    mtx.vin.emplace_back(op);
    mtx.vout.emplace_back(900, CScript() << OP_DUP);
    CTransaction tx(mtx);

    CValidationState st;
    BOOST_CHECK(!CheckSpecialTx(tx, parent(), &view, st, /*fBlockConnect=*/true));
    int dos = 0;
    BOOST_CHECK_MESSAGE(st.IsInvalid(dos) && dos == 100,
        "an OP_TRUE coin is vault-protected by SCRIPT: a non-UNLOCK spend is a real DoS");
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-vault-protected");
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(),
        "classification by script must NEVER fatal on an OP_TRUE coin the DB lacks");
}

BOOST_AUTO_TEST_SUITE_END()
