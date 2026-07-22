// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Property/fuzz harness for the money invariants A5/A6/A7 (test-plan B11).
 *
 * Fixed-seed deterministic PRNG (reproducible in CI — no time/rand): drives a
 * long random sequence of the REAL settlement drivers and asserts the invariants
 * hold at EVERY step, exploring interleavings that the fixed unit tests never
 * reach.
 *
 *   1. A6 + vault-UTXO conservation: thousands of random LOCK / full-UNLOCK ops
 *      through ApplyLock/ApplyUnlock against an in-memory g_settlementdb. After
 *      each op: CheckA6P1, state matches an independent model, the vault+receipt
 *      UTXOs are written (IsVault after LOCK) / erased (!IsVault && !IsM1Receipt
 *      after UNLOCK), and sum(all vault UTXOs) == M0_vaulted (no leak/duplicate),
 *      and CheckA7 holds.
 *   2. A5 + A7 supply accounting: random per-block mint amounts; A5 (M0_total(N)
 *      == M0_total(N-1) + burns) must hold, A7 (<= 21M cap) must hold, and an
 *      out-of-conservation or over-cap step must be rejected.
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
#include <tuple>
#include <vector>

namespace {

// Deterministic xorshift64 — same sequence on every platform / CI run.
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9e3779b97f4a7c15ULL) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    uint64_t below(uint64_t n) { return next() % n; }
};

CScript OpTrue() { CScript s; s << OP_TRUE; return s; }

uint256 TxidFromCounter(int ctr)
{
    // MUST be valid hex and unique per ctr: %064x, not a mnemonic prefix. (A
    // prior 'fu11%060d' contained 'u', which SetHex stops on, collapsing every
    // txid to the same value -> outpoint collisions.)
    uint256 h; h.SetHex(strprintf("%064x", (unsigned int)ctr)); return h;
}

CAmount SumVaults()
{
    CAmount total = 0;
    g_settlementdb->ForEachVault([&total](const VaultEntry& v){ total += v.amount; return true; });
    return total;
}

CMutableTransaction MockLock(const uint256& txid, CAmount P, const CScript& receipt)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_LOCK;
    // The lock's own funding input (unused by ApplyLock); make it unique per tx.
    mtx.vin.emplace_back(CTxIn(COutPoint(txid, 9)));
    mtx.vout.emplace_back(CTxOut(P, OpTrue()));    // vout[0] vault (A11 order)
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(settlement_fuzz_tests, BasicTestingSetup)

// Property 1: over a long random LOCK/UNLOCK sequence driven by the real Apply
// functions, A6 and vault-UTXO conservation hold at every single step.
BOOST_AUTO_TEST_CASE(fuzz_lock_unlock_conservation)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    const CAmount cap = Params().GetConsensus().nMaxMoneyOut;
    CKey key; key.MakeNewKey(true);
    const CScript dest = GetScriptForDestination(key.GetPubKey().GetID());

    Rng rng(0xBA7480011ULL);                        // fixed seed = reproducible
    SettlementState state;                          // 0/0/0
    std::vector<std::tuple<COutPoint, COutPoint, CAmount>> pool;   // (receipt, vault, P)
    CAmount modelVaulted = 0, modelM1 = 0;
    int ctr = 0;
    uint32_t height = 1000;
    const int N = 2000;
    const char* lastOp = "none"; CAmount lastP = 0;

    for (int i = 0; i < N; ++i) {
        CValidationState vs;
        CCoinsView cd; CCoinsViewCache view(&cd);

        // Bias slightly toward LOCK, and always LOCK when the pool is empty, so
        // the sequence keeps moving. Amounts kept small so the running total
        // never approaches the 21M cap (A7 is fuzzed separately below).
        bool doLock = pool.empty() || rng.below(3) != 0;
        if (doLock) {
            CAmount P = 1 + (CAmount)rng.below(1'000'000);
            // The counter only makes each tx's input (hence its hash) unique;
            // ApplyLock stores the vault/receipt at tx.GetHash():0/:1, so track
            // the REAL hash, not the counter value.
            CTransaction tx(MockLock(TxidFromCounter(ctr++), P, dest));
            const uint256 h = tx.GetHash();
            auto b = g_settlementdb->CreateBatch();
            BOOST_REQUIRE_MESSAGE(ApplyLock(tx, view, state, height++, b),
                                  "ApplyLock failed at i=" << i);
            BOOST_REQUIRE(b.Commit());
            pool.emplace_back(COutPoint(h, 1), COutPoint(h, 0), P);
            modelVaulted += P; modelM1 += P;
            lastOp = "LOCK"; lastP = P;
            BOOST_REQUIRE_MESSAGE(g_settlementdb->IsVault(COutPoint(h, 0)),
                                  "vault not persisted at i=" << i);
        } else {
            size_t j = (size_t)rng.below(pool.size());
            COutPoint r, v; CAmount P;
            std::tie(r, v, P) = pool[j];
            CTransaction tx(MockUnlock(r, v, P, dest));   // full unlock, no fee
            UnlockUndoData undo;
            auto b = g_settlementdb->CreateBatch();
            BOOST_REQUIRE_MESSAGE(ApplyUnlock(tx, view, state, b, undo),
                                  "ApplyUnlock failed at i=" << i);
            BOOST_REQUIRE(b.Commit());
            pool[j] = pool.back(); pool.pop_back();
            modelVaulted -= P; modelM1 -= P;
            lastOp = "UNLOCK"; lastP = P;
            // The spent vault + receipt UTXOs are gone (consensus point-gets —
            // the path ApplyUnlock/CheckUnlock actually use).
            BOOST_REQUIRE_MESSAGE(!g_settlementdb->IsVault(v) && !g_settlementdb->IsM1Receipt(r),
                                  "vault/receipt not erased at i=" << i);
        }

        // Invariants after EVERY operation.
        BOOST_REQUIRE_MESSAGE(CheckA6P1(state, vs), "A6 broke at i=" << i);
        BOOST_REQUIRE_MESSAGE(state.M0_vaulted == modelVaulted,
                              "M0_vaulted drift at i=" << i);
        BOOST_REQUIRE_MESSAGE(state.M1_supply == modelM1, "M1_supply drift at i=" << i);
        BOOST_REQUIRE(CheckA7(state, cap, vs));
        // Vault-UTXO conservation: the sum of all vault UTXOs equals M0_vaulted
        // (no vault leaks or duplicates). With unique outpoints ForEachVault and
        // the point-gets above agree.
        BOOST_REQUIRE_MESSAGE(SumVaults() == state.M0_vaulted,
                              "vault-UTXO leak at i=" << i << " (sum=" << SumVaults()
                              << " state=" << state.M0_vaulted << ") after " << lastOp
                              << " P=" << lastP);
    }

    // Drain the pool: unlock everything, must return to genesis (0/0, no vaults).
    for (const auto& e : pool) {
        CValidationState vs; CCoinsView cd; CCoinsViewCache view(&cd);
        COutPoint r, v; CAmount P; std::tie(r, v, P) = e;
        CTransaction tx(MockUnlock(r, v, P, dest));
        UnlockUndoData undo;
        auto b = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyUnlock(tx, view, state, b, undo));
        BOOST_REQUIRE(b.Commit());
    }
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK_EQUAL(SumVaults(), 0);              // every vault UTXO reclaimed
}

// Property 2: random per-block mint amounts. A5 conservation and the A7 cap hold
// for well-formed steps; a broken-conservation or over-cap step is rejected.
BOOST_AUTO_TEST_CASE(fuzz_supply_a5_a7)
{
    const CAmount cap = Params().GetConsensus().nMaxMoneyOut;
    Rng rng(0xA5A7C0DEULL);
    SettlementState prev;                           // M0_total_supply = 0

    for (int i = 0; i < 5000; ++i) {
        CValidationState vs;
        // A burn small enough that the cumulative total stays under the cap.
        CAmount burns = (CAmount)rng.below(1'000'000'000ULL);
        if (prev.M0_total_supply > cap - burns) burns = 0;   // stay bounded

        SettlementState cur = prev;
        cur.burnclaims_block = burns;
        cur.M0_total_supply = prev.M0_total_supply + burns;

        BOOST_REQUIRE_MESSAGE(CheckA5(cur, prev, vs), "A5 broke at i=" << i);
        BOOST_REQUIRE_MESSAGE(CheckA7(cur, cap, vs), "A7 broke at i=" << i);
        prev = cur;
    }

    // A broken-conservation step (M0_total != prev + burns) is rejected by A5.
    {
        CValidationState vs;
        SettlementState bad = prev;
        bad.burnclaims_block = 100;
        bad.M0_total_supply = prev.M0_total_supply + 100 + 1;   // off by one
        BOOST_CHECK(!CheckA5(bad, prev, vs));
    }
    // An over-cap step is rejected by A7.
    {
        CValidationState vs;
        SettlementState over = prev;
        over.M0_total_supply = cap + 1;
        BOOST_CHECK(!CheckA7(over, cap, vs));
        BOOST_CHECK_EQUAL(vs.GetRejectReason(), "settlement-a7-cap");
    }
}

BOOST_AUTO_TEST_SUITE_END()
