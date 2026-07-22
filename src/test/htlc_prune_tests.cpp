// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the htlcdb GC of RESOLVED HTLC records (fix for the unbounded
// htlcdb-growth DoS — audit finding #1). Exercises CHtlcDB::PruneResolvedAtHeight:
//   - a resolved record + its hashlock index + create/resolve undo are all erased,
//     and the schedule entry is consumed (a second prune is a no-op);
//   - a record that is still ACTIVE (a resolution reorged away leaves a stale
//     schedule entry) is DEFENSIVELY kept, only the stale schedule entry is cleaned;
//   - the HTLC3S variant erases record + all 3 hashlock indices + undos.

#include "htlc/htlc.h"
#include "htlc/htlcdb.h"
#include "uint256.h"

#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(htlc_prune_tests, BasicTestingSetup)

namespace {

uint256 U(uint8_t b)
{
    uint256 h;
    h.begin()[0] = b;
    h.begin()[1] = 0xC7; // avoid all-zero collisions
    return h;
}

HTLCRecord MakeResolvedHTLC(const COutPoint& op, const uint256& hashlock,
                            const uint256& resolveTxid, HTLCStatus status)
{
    HTLCRecord rec;
    rec.htlcOutpoint = op;
    rec.hashlock = hashlock;
    rec.amount = 1000;
    rec.createHeight = 10;
    rec.expiryHeight = 20;
    rec.status = status;
    rec.resolveTxid = resolveTxid;
    return rec;
}

HTLC3SRecord MakeResolved3S(const COutPoint& op, const uint256& hu, const uint256& hl1,
                            const uint256& hl2, const uint256& resolveTxid, HTLCStatus status)
{
    HTLC3SRecord rec;
    rec.htlcOutpoint = op;
    rec.hashlock_user = hu;
    rec.hashlock_lp1 = hl1;
    rec.hashlock_lp2 = hl2;
    rec.amount = 1000;
    rec.createHeight = 10;
    rec.expiryHeight = 20;
    rec.status = status;
    rec.resolveTxid = resolveTxid;
    return rec;
}

} // namespace

// A resolved HTLC scheduled at height R is fully GC'd when PruneResolvedAtHeight(R) runs.
BOOST_AUTO_TEST_CASE(prune_erases_resolved_record)
{
    BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    const uint32_t R = 500;
    const COutPoint op(U(1), 0);          // create txid == op.hash == U(1)
    const uint256 hashlock = U(2);
    const uint256 resolveTxid = U(3);

    HTLCRecord rec = MakeResolvedHTLC(op, hashlock, resolveTxid, HTLCStatus::CLAIMED);
    BOOST_REQUIRE(g_htlcdb->WriteHTLC(rec));
    BOOST_REQUIRE(g_htlcdb->WriteHashlockIndex(hashlock, op));
    HTLCResolveUndoData rud; rud.htlcRecord = rec;
    BOOST_REQUIRE(g_htlcdb->WriteResolveUndo(resolveTxid, rud));
    HTLCCreateUndoData cud; cud.originalAmount = 1000;
    BOOST_REQUIRE(g_htlcdb->WriteCreateUndo(op.hash, cud));
    { auto b = g_htlcdb->CreateBatch(); b.WritePruneSchedule(R, op, /*is3S=*/false); BOOST_REQUIRE(b.Commit()); }

    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 1u);
    BOOST_CHECK(g_htlcdb->IsHTLC(op));

    { auto pb = g_htlcdb->CreateBatch(); g_htlcdb->PruneResolvedAtHeight(R, pb); BOOST_REQUIRE(pb.Commit()); }

    // Record + every satellite entry gone.
    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 0u);
    BOOST_CHECK(!g_htlcdb->IsHTLC(op));
    HTLCResolveUndoData rud2; BOOST_CHECK(!g_htlcdb->ReadResolveUndo(resolveTxid, rud2));
    HTLCCreateUndoData cud2; BOOST_CHECK(!g_htlcdb->ReadCreateUndo(op.hash, cud2));
    std::vector<COutPoint> outs; BOOST_CHECK(!g_htlcdb->GetByHashlock(hashlock, outs));

    // Schedule entry consumed → a second prune at R is a clean no-op.
    { auto pb2 = g_htlcdb->CreateBatch(); g_htlcdb->PruneResolvedAtHeight(R, pb2); BOOST_REQUIRE(pb2.Commit()); }
    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 0u);
}

// Defensive: a stale schedule entry (resolution reorged away → record back to
// ACTIVE) must NOT erase the still-live record; only the stale entry is cleaned.
BOOST_AUTO_TEST_CASE(prune_keeps_active_record)
{
    BOOST_REQUIRE(InitHtlcDB(1 << 20, true, true));
    const uint32_t R = 500;
    const COutPoint op(U(4), 0);
    const uint256 hashlock = U(5);

    HTLCRecord rec = MakeResolvedHTLC(op, hashlock, uint256(), HTLCStatus::ACTIVE);
    BOOST_REQUIRE(g_htlcdb->WriteHTLC(rec));
    BOOST_REQUIRE(g_htlcdb->WriteHashlockIndex(hashlock, op));
    { auto b = g_htlcdb->CreateBatch(); b.WritePruneSchedule(R, op, false); BOOST_REQUIRE(b.Commit()); }

    { auto pb = g_htlcdb->CreateBatch(); g_htlcdb->PruneResolvedAtHeight(R, pb); BOOST_REQUIRE(pb.Commit()); }

    // Active record survives; its hashlock index survives.
    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 1u);
    BOOST_CHECK(g_htlcdb->IsHTLC(op));
    std::vector<COutPoint> outs; BOOST_CHECK(g_htlcdb->GetByHashlock(hashlock, outs));

    // The stale schedule entry was cleaned → re-prune still keeps the active record.
    { auto pb2 = g_htlcdb->CreateBatch(); g_htlcdb->PruneResolvedAtHeight(R, pb2); BOOST_REQUIRE(pb2.Commit()); }
    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 1u);
}

// HTLC3S variant: resolved 3S record + all 3 hashlock indices + undos are GC'd.
BOOST_AUTO_TEST_CASE(prune_erases_resolved_3s_record)
{
    BOOST_REQUIRE(InitHtlcDB(1 << 20, true, true));
    const uint32_t R = 777;
    const COutPoint op(U(6), 0);
    const uint256 hu = U(7), hl1 = U(8), hl2 = U(9), resolveTxid = U(10);

    HTLC3SRecord rec = MakeResolved3S(op, hu, hl1, hl2, resolveTxid, HTLCStatus::REFUNDED);
    BOOST_REQUIRE(g_htlcdb->WriteHTLC3S(rec));
    BOOST_REQUIRE(g_htlcdb->WriteHashlock3SUserIndex(hu, op));
    BOOST_REQUIRE(g_htlcdb->WriteHashlock3SLp1Index(hl1, op));
    BOOST_REQUIRE(g_htlcdb->WriteHashlock3SLp2Index(hl2, op));
    HTLC3SResolveUndoData rud; rud.htlcRecord = rec;
    BOOST_REQUIRE(g_htlcdb->WriteResolve3SUndo(resolveTxid, rud));
    HTLC3SCreateUndoData cud; cud.originalAmount = 1000;
    BOOST_REQUIRE(g_htlcdb->WriteCreate3SUndo(op.hash, cud));
    { auto b = g_htlcdb->CreateBatch(); b.WritePruneSchedule(R, op, /*is3S=*/true); BOOST_REQUIRE(b.Commit()); }

    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 1u);

    { auto pb = g_htlcdb->CreateBatch(); g_htlcdb->PruneResolvedAtHeight(R, pb); BOOST_REQUIRE(pb.Commit()); }

    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 0u);
    BOOST_CHECK(!g_htlcdb->IsHTLC3S(op));
    std::vector<COutPoint> ou, o1, o2;
    BOOST_CHECK(!g_htlcdb->GetByHashlock3SUser(hu, ou));
    BOOST_CHECK(!g_htlcdb->GetByHashlock3SLp1(hl1, o1));
    BOOST_CHECK(!g_htlcdb->GetByHashlock3SLp2(hl2, o2));
    HTLC3SResolveUndoData rud2; BOOST_CHECK(!g_htlcdb->ReadResolve3SUndo(resolveTxid, rud2));
    HTLC3SCreateUndoData cud2; BOOST_CHECK(!g_htlcdb->ReadCreate3SUndo(op.hash, cud2));
}

// Only the target height is pruned: a record scheduled at a LATER height survives.
BOOST_AUTO_TEST_CASE(prune_only_target_height)
{
    BOOST_REQUIRE(InitHtlcDB(1 << 20, true, true));
    const COutPoint opA(U(11), 0), opB(U(12), 0);
    HTLCRecord a = MakeResolvedHTLC(opA, U(13), U(14), HTLCStatus::CLAIMED);
    HTLCRecord b = MakeResolvedHTLC(opB, U(15), U(16), HTLCStatus::CLAIMED);
    BOOST_REQUIRE(g_htlcdb->WriteHTLC(a));
    BOOST_REQUIRE(g_htlcdb->WriteHTLC(b));
    { auto bt = g_htlcdb->CreateBatch();
      bt.WritePruneSchedule(100, opA, false);
      bt.WritePruneSchedule(200, opB, false);
      BOOST_REQUIRE(bt.Commit()); }

    { auto pb = g_htlcdb->CreateBatch(); g_htlcdb->PruneResolvedAtHeight(100, pb); BOOST_REQUIRE(pb.Commit()); }

    // Only opA (scheduled@100) pruned; opB (scheduled@200) survives.
    BOOST_CHECK(!g_htlcdb->IsHTLC(opA));
    BOOST_CHECK(g_htlcdb->IsHTLC(opB));
    BOOST_CHECK_EQUAL(g_htlcdb->CountRecords(), 1u);
}

BOOST_AUTO_TEST_SUITE_END()
