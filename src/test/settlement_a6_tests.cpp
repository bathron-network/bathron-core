// Copyright (c) 2025-2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * A6 Invariant Unit Tests
 *
 * Ref: doc/blueprints/done/BP30-SETTLEMENT.md
 *
 * A6 Invariant: M0_vaulted == M1_supply
 *
 * Tests:
 *   1. add_no_overflow_basic - AddNoOverflow detects overflow
 *   2. a6_valid_state - CheckA6P1 validates A6
 *   3. a6_after_lock - A6 holds after LOCK
 *   4. a6_after_unlock - A6 holds after UNLOCK
 */

#include "state/settlement.h"
#include "state/settlementdb.h"
#include "state/settlement_logic.h"
#include "amount.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(settlement_a6_tests, BasicTestingSetup)

// =============================================================================
// Test 1: AddNoOverflow - Overflow detection with __int128
// =============================================================================
BOOST_AUTO_TEST_CASE(add_no_overflow_basic)
{
    CAmount result = 0;

    // Normal addition
    BOOST_CHECK(AddNoOverflow(100 * COIN, 200 * COIN, result));
    BOOST_CHECK_EQUAL(result, 300 * COIN);

    // Zero addition
    BOOST_CHECK(AddNoOverflow(0, 0, result));
    BOOST_CHECK_EQUAL(result, 0);

    // Max safe sum
    CAmount half_max = std::numeric_limits<int64_t>::max() / 2;
    BOOST_CHECK(AddNoOverflow(half_max, half_max, result));
    BOOST_CHECK_EQUAL(result, half_max * 2);
}

BOOST_AUTO_TEST_CASE(add_no_overflow_overflow_detection)
{
    CAmount result = 0;

    // Overflow: INT64_MAX + 1
    CAmount max_val = std::numeric_limits<int64_t>::max();
    BOOST_CHECK(!AddNoOverflow(max_val, 1, result));

    // Overflow: INT64_MAX + INT64_MAX
    BOOST_CHECK(!AddNoOverflow(max_val, max_val, result));

    // Large but not overflowing
    CAmount safe_large = max_val / 2;
    BOOST_CHECK(AddNoOverflow(safe_large, safe_large, result));
}

BOOST_AUTO_TEST_CASE(add_no_overflow_negative)
{
    CAmount result = 0;

    // Negative underflow: INT64_MIN + negative
    CAmount min_val = std::numeric_limits<int64_t>::min();
    BOOST_CHECK(!AddNoOverflow(min_val, -1, result));

    // Normal negative addition
    BOOST_CHECK(AddNoOverflow(-100 * COIN, -200 * COIN, result));
    BOOST_CHECK_EQUAL(result, -300 * COIN);

    // Mixed positive/negative
    BOOST_CHECK(AddNoOverflow(100 * COIN, -50 * COIN, result));
    BOOST_CHECK_EQUAL(result, 50 * COIN);
}

// =============================================================================
// Test 2: CheckA6P1 - Basic A6 invariant validation
// =============================================================================
BOOST_AUTO_TEST_CASE(a6_valid_state)
{
    // A6: M0_vaulted == M1_supply
    SettlementState state;
    state.M0_vaulted = 1000 * COIN;
    state.M1_supply = 1000 * COIN;

    CValidationState validationState;
    BOOST_CHECK(CheckA6P1(state, validationState));
    BOOST_CHECK(validationState.IsValid());
}

BOOST_AUTO_TEST_CASE(a6_broken_detection)
{
    // M0_vaulted != M1_supply
    SettlementState state;
    state.M0_vaulted = 1000 * COIN;
    state.M1_supply = 900 * COIN;  // 900 != 1000

    CValidationState validationState;
    BOOST_CHECK(!CheckA6P1(state, validationState));
    BOOST_CHECK(validationState.GetRejectReason().find("settlement-a6-broken") != std::string::npos);
}

// =============================================================================
// Test 3: A6 after LOCK operation
// =============================================================================
BOOST_AUTO_TEST_CASE(a6_after_lock)
{
    // Simulate LOCK: M0_vaulted += P, M1_supply += P
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;

    // Initial state: A6 should hold (0 == 0)
    CValidationState validationState;
    BOOST_CHECK(CheckA6P1(state, validationState));

    // Apply LOCK (P = 500 COIN)
    CAmount P = 500 * COIN;
    state.M0_vaulted += P;
    state.M1_supply += P;

    // After LOCK: A6 should still hold (500 == 500)
    CValidationState postLockState;
    BOOST_CHECK(CheckA6P1(state, postLockState));
}

// =============================================================================
// Test 4: A6 after UNLOCK operation
// =============================================================================
BOOST_AUTO_TEST_CASE(a6_after_unlock)
{
    // Start with locked state
    SettlementState state;
    state.M0_vaulted = 1000 * COIN;
    state.M1_supply = 1000 * COIN;

    // Initial: A6 holds (1000 == 1000)
    CValidationState validationState;
    BOOST_CHECK(CheckA6P1(state, validationState));

    // Apply UNLOCK (burn 500 M1, release 500 M0)
    CAmount U = 500 * COIN;
    state.M0_vaulted -= U;
    state.M1_supply -= U;

    // After UNLOCK: A6 should still hold (500 == 500)
    CValidationState postUnlockState;
    BOOST_CHECK(CheckA6P1(state, postUnlockState));
}

// =============================================================================
// Test 5: A6 reorg scenario (undo then redo)
// =============================================================================
BOOST_AUTO_TEST_CASE(a6_reorg_cycle)
{
    // Initial state
    SettlementState state;
    state.M0_vaulted = 500 * COIN;
    state.M1_supply = 500 * COIN;

    // Save snapshot for "undo"
    SettlementState snapshot = state;

    // Apply LOCK (P = 200)
    CAmount P = 200 * COIN;
    state.M0_vaulted += P;
    state.M1_supply += P;

    CValidationState afterLock;
    BOOST_CHECK(CheckA6P1(state, afterLock));
    BOOST_CHECK_EQUAL(state.M0_vaulted, 700 * COIN);

    // Simulate reorg: UNDO the LOCK
    state = snapshot;

    CValidationState afterUndo;
    BOOST_CHECK(CheckA6P1(state, afterUndo));
    BOOST_CHECK_EQUAL(state.M0_vaulted, 500 * COIN);

    // Re-apply LOCK
    state.M0_vaulted += P;
    state.M1_supply += P;

    CValidationState afterRedo;
    BOOST_CHECK(CheckA6P1(state, afterRedo));
    BOOST_CHECK_EQUAL(state.M0_vaulted, 700 * COIN);
}

// =============================================================================
// Test 6: Edge case - all zeros
// =============================================================================
BOOST_AUTO_TEST_CASE(a6_all_zeros)
{
    // Edge case: all zeros
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;

    // A6: 0 == 0
    CValidationState validationState;
    BOOST_CHECK(CheckA6P1(state, validationState));
}

// =============================================================================
// Test 7: Large values (near MAX_MONEY)
// =============================================================================
BOOST_AUTO_TEST_CASE(a6_large_values)
{
    // MAX_MONEY = 21M * COIN = 2.1e15 satoshi
    // Test with values near MAX_MONEY

    SettlementState state;
    state.M0_vaulted = 20000000 * COIN;  // 20M
    state.M1_supply = 20000000 * COIN;   // 20M

    // A6: 20M == 20M
    CValidationState validationState;
    BOOST_CHECK(CheckA6P1(state, validationState));
}

// =============================================================================
// B10: A6 held across a reorg, driven by the REAL Apply/Undo functions.
//
// The a6_reorg_cycle above only does scalar arithmetic on SettlementState and
// never touches the DB or the Apply/Undo wiring, so it proves nothing about a
// real disconnect. These cases run ApplyLock/UndoLock and ApplyUnlock/UndoUnlock
// against an in-memory g_settlementdb (Apply -> Undo -> re-Apply = a reorg at
// the settlement-logic layer) and assert BOTH CheckA6P1 (scalar A6) AND
// SumAllVaultUTXOs()==M0_vaulted (vault-UTXO conservation — the shape that the
// historical fee-shadowing / "second vault backing leaked on reorg" bugs broke,
// which a scalar check alone would miss) at every step.
// =============================================================================

namespace {

CScript OpTrue()
{
    CScript s; s << OP_TRUE; return s;
}

CMutableTransaction MockLock(CAmount P, const CScript& vault, const CScript& receipt)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_LOCK;
    mtx.vin.emplace_back(CTxIn(COutPoint(uint256S("11"), 0)));
    mtx.vout.emplace_back(CTxOut(P, vault));       // vout[0] vault (A11 order)
    mtx.vout.emplace_back(CTxOut(P, receipt));     // vout[1] receipt
    return mtx;
}

CMutableTransaction MockUnlock(const COutPoint& receipt, const COutPoint& vault,
                               CAmount amt, const CScript& dest)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;
    mtx.vin.emplace_back(CTxIn(receipt));          // vin[0] receipt
    mtx.vin.emplace_back(CTxIn(vault));            // vin[1] vault
    mtx.vout.emplace_back(CTxOut(amt, dest));
    return mtx;
}

CAmount SumVaults()
{
    CAmount total = 0;
    g_settlementdb->ForEachVault([&total](const VaultEntry& v){ total += v.amount; return true; });
    return total;
}

void SeedPair(CAmount P, uint32_t lockHeight, COutPoint& vaultOut, COutPoint& receiptOut)
{
    static int ctr = 0; ++ctr;
    uint256 txid; txid.SetHex(strprintf("a6b10cafe%055d", ctr));
    vaultOut = COutPoint(txid, 0);
    receiptOut = COutPoint(txid, 1);
    VaultEntry v; v.outpoint = vaultOut; v.amount = P; v.nLockHeight = lockHeight;
    BOOST_REQUIRE(g_settlementdb->WriteVault(v));
    M1Receipt r; r.outpoint = receiptOut; r.amount = P; r.nCreateHeight = lockHeight;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(r));
}

} // namespace

// =============================================================================
// B4: A7 supply cap (M0_total_supply in [0, 21M]) via the extracted CheckA7
// circuit breaker. Reaching the inline check through ProcessSpecialTxsInBlock
// needs the full block-connect path + a valid near-cap mint; the check is a
// pure predicate on M0_total_supply, so it is extracted (CheckA7) and tested
// directly. nMaxMoneyOut = 21,000,000 * COIN sats.
// =============================================================================
BOOST_AUTO_TEST_CASE(a7_supply_cap_boundary)
{
    const CAmount cap = 21000000LL * COIN;    // must equal consensus.nMaxMoneyOut
    SettlementState state;
    CValidationState vs;

    // At the cap exactly: accepted.
    state.M0_total_supply = cap;
    BOOST_CHECK(CheckA7(state, cap, vs));

    // Well below the cap: accepted.
    state.M0_total_supply = 24195000LL;       // ~current live testnet M0
    BOOST_CHECK(CheckA7(state, cap, vs));

    // Zero: accepted (genesis).
    state.M0_total_supply = 0;
    BOOST_CHECK(CheckA7(state, cap, vs));
}

BOOST_AUTO_TEST_CASE(a7_supply_cap_exceeded_rejected)
{
    const CAmount cap = 21000000LL * COIN;
    SettlementState state;
    CValidationState vs;

    // One satoshi over the cap: rejected (inflation beyond the BTC supply).
    state.M0_total_supply = cap + 1;
    BOOST_CHECK(!CheckA7(state, cap, vs));
    BOOST_CHECK_EQUAL(vs.GetRejectReason(), "settlement-a7-cap");
}

BOOST_AUTO_TEST_CASE(a7_supply_negative_rejected)
{
    const CAmount cap = 21000000LL * COIN;
    SettlementState state;
    CValidationState vs;

    // Negative total (an overflow in accounting) is rejected by the same guard.
    state.M0_total_supply = -1;
    BOOST_CHECK(!CheckA7(state, cap, vs));
    BOOST_CHECK_EQUAL(vs.GetRejectReason(), "settlement-a7-cap");
}

// The consensus wiring must feed CheckA7 the real nMaxMoneyOut. Pin that the
// mainnet cap is exactly 21M * COIN so a mint that would push M0 past the BTC
// supply is rejected.
BOOST_AUTO_TEST_CASE(a7_cap_equals_21M_btc)
{
    BOOST_CHECK_EQUAL(Params().GetConsensus().nMaxMoneyOut, 21000000LL * COIN);
}

BOOST_AUTO_TEST_CASE(a6_reorg_lock_undo_via_real_drivers)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true));
    const CAmount P = 100 * COIN;
    CKey key; key.MakeNewKey(true);
    CTransaction tx(MockLock(P, OpTrue(), GetScriptForDestination(key.GetPubKey().GetID())));

    SettlementState state; state.M0_vaulted = 0; state.M1_supply = 0; state.nHeight = 1000;
    CCoinsView dummy; CCoinsViewCache view(&dummy);
    CValidationState vs;

    // Connect the block: ApplyLock.
    { auto b = g_settlementdb->CreateBatch(); BOOST_REQUIRE(ApplyLock(tx, view, state, 1001, b)); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK(CheckA6P1(state, vs));
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK_EQUAL(SumVaults(), P);              // vault UTXO backs the receipt

    // Disconnect (reorg): UndoLock -> back to genesis, A6 + no leaked vault.
    { auto b = g_settlementdb->CreateBatch(); BOOST_REQUIRE(UndoLock(tx, state, b)); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK(CheckA6P1(state, vs));
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK_EQUAL(SumVaults(), 0);

    // Reconnect (alternate branch re-applies the same lock): A6 holds again.
    { auto b = g_settlementdb->CreateBatch(); BOOST_REQUIRE(ApplyLock(tx, view, state, 1001, b)); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK(CheckA6P1(state, vs));
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(SumVaults(), P);
}

BOOST_AUTO_TEST_CASE(a6_reorg_unlock_undo_via_real_drivers)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true));
    const CAmount P = 150 * COIN;
    CKey key; key.MakeNewKey(true);
    CScript dest = GetScriptForDestination(key.GetPubKey().GetID());
    COutPoint vaultOut, receiptOut;
    SeedPair(P, 1000, vaultOut, receiptOut);

    SettlementState state; state.M0_vaulted = P; state.M1_supply = P; state.nHeight = 1000;
    CTransaction tx(MockUnlock(receiptOut, vaultOut, P, dest));
    CCoinsView dummy; CCoinsViewCache view(&dummy);
    CValidationState vs;
    BOOST_CHECK(CheckA6P1(state, vs));
    BOOST_CHECK_EQUAL(SumVaults(), P);

    // Connect: ApplyUnlock releases the vault -> 0/0, no vault UTXO left.
    UnlockUndoData undo;
    { auto b = g_settlementdb->CreateBatch(); BOOST_REQUIRE(ApplyUnlock(tx, view, state, b, undo)); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK(CheckA6P1(state, vs));
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK_EQUAL(SumVaults(), 0);

    // Disconnect (reorg): UndoUnlock restores the vault + receipt -> P/P, and
    // exactly one vault UTXO worth P (guards the "second vault backing leaked
    // on reorg" class of bugs that CheckA6P1 alone cannot see).
    { auto b = g_settlementdb->CreateBatch(); BOOST_REQUIRE(UndoUnlock(tx, undo, state, b)); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK(CheckA6P1(state, vs));
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK_EQUAL(SumVaults(), P);              // no leaked/duplicated vault
}

BOOST_AUTO_TEST_SUITE_END()
