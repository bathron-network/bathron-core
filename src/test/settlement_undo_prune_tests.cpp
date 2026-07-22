// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the GC of TX_UNLOCK/TX_TRANSFER_M1 undo data (audit finding #6 —
// unbounded settlement undo growth). Exercises CSettlementDB::PruneUndoAtHeight:
// undo records scheduled at a height are erased when pruned; only the target height
// is affected; a stale schedule entry (undo already gone) is a clean no-op.

#include "state/settlement.h"
#include "state/settlementdb.h"
#include "uint256.h"

#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(settlement_undo_prune_tests, BasicTestingSetup)

namespace {
uint256 U(uint8_t b) { uint256 h; h.begin()[0] = b; h.begin()[1] = 0x5E; return h; }
}

BOOST_AUTO_TEST_CASE(prune_erases_scheduled_undo)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    const uint32_t R = 500;
    const uint256 unlockTx = U(1), transferTx = U(2);

    UnlockUndoData uu; uu.m0Released = 1000; uu.netM1Burned = 1000;
    BOOST_REQUIRE(g_settlementdb->WriteUnlockUndo(unlockTx, uu));
    TransferUndoData tu; tu.numM1Outputs = 2;
    BOOST_REQUIRE(g_settlementdb->WriteTransferUndo(transferTx, tu));
    { auto b = g_settlementdb->CreateBatch();
      b.WriteUndoPruneSchedule(R, unlockTx, /*undoType=*/0);
      b.WriteUndoPruneSchedule(R, transferTx, /*undoType=*/1);
      BOOST_REQUIRE(b.Commit()); }

    UnlockUndoData tmp; BOOST_CHECK(g_settlementdb->ReadUnlockUndo(unlockTx, tmp));
    TransferUndoData tmp2; BOOST_CHECK(g_settlementdb->ReadTransferUndo(transferTx, tmp2));

    { auto pb = g_settlementdb->CreateBatch(); g_settlementdb->PruneUndoAtHeight(R, pb); BOOST_REQUIRE(pb.Commit()); }

    // Both undo records gone.
    BOOST_CHECK(!g_settlementdb->ReadUnlockUndo(unlockTx, tmp));
    BOOST_CHECK(!g_settlementdb->ReadTransferUndo(transferTx, tmp2));
    // Schedule consumed → a second prune at R is a clean no-op.
    { auto pb2 = g_settlementdb->CreateBatch(); g_settlementdb->PruneUndoAtHeight(R, pb2); BOOST_REQUIRE(pb2.Commit()); }
    BOOST_CHECK(!g_settlementdb->ReadUnlockUndo(unlockTx, tmp));
}

BOOST_AUTO_TEST_CASE(prune_only_target_height)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true, true));
    const uint256 txA = U(3), txB = U(4);
    UnlockUndoData uu; uu.m0Released = 1;
    BOOST_REQUIRE(g_settlementdb->WriteUnlockUndo(txA, uu));
    BOOST_REQUIRE(g_settlementdb->WriteUnlockUndo(txB, uu));
    { auto b = g_settlementdb->CreateBatch();
      b.WriteUndoPruneSchedule(100, txA, 0);
      b.WriteUndoPruneSchedule(200, txB, 0);
      BOOST_REQUIRE(b.Commit()); }

    { auto pb = g_settlementdb->CreateBatch(); g_settlementdb->PruneUndoAtHeight(100, pb); BOOST_REQUIRE(pb.Commit()); }

    UnlockUndoData tmp;
    BOOST_CHECK(!g_settlementdb->ReadUnlockUndo(txA, tmp)); // scheduled@100 pruned
    BOOST_CHECK(g_settlementdb->ReadUnlockUndo(txB, tmp));  // scheduled@200 survives
}

// Stale schedule entry (undo already erased on reorg-disconnect) prunes cleanly.
BOOST_AUTO_TEST_CASE(prune_stale_schedule_is_noop)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true, true));
    const uint32_t R = 500;
    const uint256 txid = U(5);
    // Schedule with NO corresponding undo record (simulates reorged-away tx).
    { auto b = g_settlementdb->CreateBatch(); b.WriteUndoPruneSchedule(R, txid, 0); BOOST_REQUIRE(b.Commit()); }
    { auto pb = g_settlementdb->CreateBatch(); g_settlementdb->PruneUndoAtHeight(R, pb); BOOST_REQUIRE(pb.Commit()); }
    UnlockUndoData tmp;
    BOOST_CHECK(!g_settlementdb->ReadUnlockUndo(txid, tmp)); // still absent, no crash
}

BOOST_AUTO_TEST_SUITE_END()
