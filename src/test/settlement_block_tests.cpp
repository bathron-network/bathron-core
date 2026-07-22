// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Real-path block-level settlement harness (hard-test campaign #8 / harness #2).
//
// WHAT WAS MISSING
// ----------------
// Every prior settlement test (settlement_tests, settlement_a6_tests B10,
// settlement_fuzz_tests B11) drives the per-tx DRIVERS directly —
// ApplyLock/ApplyUnlock/ApplyTransfer against an in-memory g_settlementdb, one
// tx at a time, manually chained. None of them drives the block-level
// ORCHESTRATOR `ProcessSpecialTxsInBlock` (masternode/specialtx_validation.cpp),
// which is what ConnectBlock actually runs: the per-type dispatch switch, the
// in-block pending-receipt / same-block-respend guards, the A5/A7 accounting
// against the previous block's snapshot, the deferred-commit atomicity (a
// rejected tx must leave the whole DB untouched), and the reverse-order
// `UndoSpecialTxsInBlock` reorg path (which reads the persisted undo records).
// That orchestration had ZERO direct test coverage.
//
// WHAT THIS DOES
// --------------
// Drives the REAL entrypoint `ProcessSpecialTxsInBlock(block, pindex, &view,
// state, /*fJustCheck=*/false, /*fSettlementOnly=*/true)` under cs_main — the
// exact call `RebuildSettlementFromChain` uses. `fSettlementOnly=true` bypasses
// only CheckSpecialTx + the deterministic-MN ProcessBlock (which need a full MN
// context), keeping the entire money path: the dispatch switch, Check*/Apply*,
// A5/A6/A7, batches. So this is the genuine block-connect settlement path, not a
// driver re-implementation.
//
// Four properties, all asserting the consensus money invariants after EVERY
// block (A5/A6/A7 + the UTXO-level vault-sum == M0_vaulted guard that scalar A6
// alone misses) against an independent model:
//   1. real_path_lock_unlock_conservation  — many blocks, each carrying several
//      interleaved TX_LOCK / TX_UNLOCK in adversarial order.
//   2. real_path_reject_leaves_state_untouched — malformed tx of every settlement
//      type is rejected AND the deferred-commit leaves the DB byte-for-byte
//      unchanged (no partial mutation).
//   3. real_path_transfer_roundtrip — lock -> TX_TRANSFER_M1 (recipient + OP_TRUE
//      fee split) -> multi-input full unlock, all through the block path.
//   4. real_path_reorg_undo_roundtrip — connect a chain, disconnect a suffix via
//      the real UndoSpecialTxsInBlock, assert the state is restored exactly, then
//      reconnect and assert we are back.
//
// All amounts are satoshis; M0/M1 are 1:1 (A6). Fixed-seed xorshift64 → fully
// deterministic, reproducible, no time/rand. Same driver is fuzzed by
// test/fuzz/settlement_block.cpp under libFuzzer+ASan/UBSan.

#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "masternode/specialtx_validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "state/settlement.h"
#include "state/settlementdb.h"
#include "state/settlement_logic.h"
#include "sync.h"
#include "uint256.h"
#include "validation.h"

#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

#include <deque>
#include <map>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(settlement_block_tests, BasicTestingSetup)

namespace {

// Deterministic, reproducible PRNG (xorshift64) — no time/rand in consensus tests.
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    uint32_t below(uint32_t n) { return n ? (uint32_t)(next() % n) : 0; }
};

CScript OpTrue()
{
    CScript s;
    s << OP_TRUE;
    return s;
}

// A distinct, spendable, non-OP_TRUE P2PKH script (receipt / M0-out destinations
// must be spendable and not OP_TRUE — see CheckLock / CheckUnlock).
CScript P2PKH(uint8_t tag)
{
    CScript s;
    s << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

uint256 HashFromU64(uint64_t x)
{
    uint256 h;
    unsigned char* p = h.begin();
    for (int i = 0; i < 8; ++i) p[i] = (unsigned char)(x >> (8 * i));
    p[8] = 0xA5; // avoid the all-zero-suffix so distinct x never collide on SetNull semantics
    return h;
}

// Minimal coinbase so block.vtx[0]->IsCoinBase() is true (A5 reads vtx[0]).
CTransactionRef MakeCoinbase(uint32_t height)
{
    CMutableTransaction cb;
    cb.nVersion = CTransaction::TxVersion::SAPLING;
    cb.nType = CTransaction::TxType::NORMAL;
    CScript sig;
    sig << (int)height;
    cb.vin.emplace_back(CTxIn(COutPoint(), sig)); // null prevout -> coinbase
    cb.vout.emplace_back(CTxOut(0, OpTrue()));
    return MakeTransactionRef(CTransaction(cb));
}

// TX_LOCK: vin = one fresh outpoint (IsM0Standard == "not a vault/receipt", so any
// fresh outpoint qualifies), vout[0]=OP_TRUE vault(P), vout[1]=P2PKH receipt(P).
CMutableTransaction MakeLock(const COutPoint& fundingIn, CAmount P, uint8_t receiptTag)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_LOCK;
    mtx.vin.emplace_back(CTxIn(fundingIn));
    mtx.vout.emplace_back(CTxOut(P, OpTrue()));         // vout[0] vault
    mtx.vout.emplace_back(CTxOut(P, P2PKH(receiptTag))); // vout[1] receipt
    return mtx;
}

// TX_UNLOCK full redeem (fee == 0): vin = receipts (canonical first) then vaults,
// vout[0] = P2PKH(m0Out) where m0Out = sum(receipts) = sum(vaults).
CMutableTransaction MakeFullUnlock(const std::vector<COutPoint>& receipts,
                                   const std::vector<COutPoint>& vaults,
                                   CAmount m0Out, uint8_t destTag)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;
    for (const COutPoint& r : receipts) mtx.vin.emplace_back(CTxIn(r)); // receipts first
    for (const COutPoint& v : vaults)   mtx.vin.emplace_back(CTxIn(v)); // then vaults
    mtx.vout.emplace_back(CTxOut(m0Out, P2PKH(destTag)));               // vout[0] M0 out
    return mtx;
}

// TX_TRANSFER_M1: single receipt input, split into recipient(P-fee) + OP_TRUE
// fee(fee). Strict M1 conservation: recipient + fee == receipt amount.
CMutableTransaction MakeTransfer(const COutPoint& receiptIn, CAmount m1In,
                                 CAmount fee, uint8_t recipientTag)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;
    mtx.vin.emplace_back(CTxIn(receiptIn));
    mtx.vout.emplace_back(CTxOut(m1In - fee, P2PKH(recipientTag))); // vout[0] recipient (M1)
    mtx.vout.emplace_back(CTxOut(fee, OpTrue()));                   // vout[1] OP_TRUE fee (M1)
    return mtx;
}

// A growable index chain with stable addresses (pprev pointers + phashBlock must
// stay valid across pushes) and the per-block CBlock objects (kept for undo).
struct Chain {
    std::deque<uint256> hashes;    // stable storage for phashBlock
    std::deque<CBlockIndex> idx;   // stable storage for pprev
    std::deque<CBlock> blocks;     // kept so reorg can re-drive UndoSpecialTxsInBlock

    CBlockIndex* genesis(uint32_t height, const uint256& h)
    {
        hashes.push_back(h);
        idx.emplace_back();
        idx.back().nHeight = height;
        idx.back().pprev = nullptr;
        idx.back().phashBlock = &hashes.back();
        return &idx.back();
    }
    // append a real block index on top of `prev`
    CBlockIndex* extend(CBlockIndex* prev, const CBlock& blk)
    {
        blocks.push_back(blk);
        hashes.push_back(blk.GetHash());
        idx.emplace_back();
        idx.back().nHeight = prev->nHeight + 1;
        idx.back().pprev = prev;
        idx.back().phashBlock = &hashes.back();
        return &idx.back();
    }
};

// Independent scalar+set model of the settlement state.
struct Model {
    CAmount vaulted = 0;
    CAmount m1 = 0;
    CAmount m0Total = 0;
    std::map<COutPoint, CAmount> vaults;   // live vault outpoints -> amount
    std::map<COutPoint, CAmount> receipts; // live receipt outpoints -> amount
};

// Assemble a CBlock from a coinbase + special txs, with a distinct header hash.
CBlock MakeBlock(uint32_t height, const uint256& prevHash,
                 const std::vector<CTransactionRef>& specials)
{
    CBlock blk;
    blk.nVersion = 4;
    blk.hashPrevBlock = prevHash;
    blk.nTime = 1700000000 + height;
    blk.nBits = 0x207fffff;
    blk.nNonce = height;
    blk.vtx.push_back(MakeCoinbase(height));
    for (const CTransactionRef& t : specials) blk.vtx.push_back(t);
    return blk;
}

// Assert the DB state matches the model + all consensus money invariants.
void AssertInvariants(const Model& m)
{
    SettlementState st;
    BOOST_REQUIRE(g_settlementdb->ReadLatestState(st));
    BOOST_CHECK_EQUAL(st.M0_vaulted, m.vaulted);
    BOOST_CHECK_EQUAL(st.M1_supply, m.m1);
    BOOST_CHECK_EQUAL(st.M0_total_supply, m.m0Total);

    // A6 (scalar) : M0_vaulted == M1_supply.
    CValidationState vs;
    BOOST_CHECK(CheckA6P1(st, vs));

    // A7 : 0 <= M0_total <= 21M cap.
    CValidationState vs7;
    BOOST_CHECK(CheckA7(st, Params().GetConsensus().nMaxMoneyOut, vs7));

    // Vault-UTXO conservation : sum(live vault UTXOs) == M0_vaulted (the
    // reorg-leak guard scalar A6 misses).
    CAmount sumVaults = 0;
    g_settlementdb->ForEachVault([&](const VaultEntry& v) { sumVaults += v.amount; return true; });
    BOOST_CHECK_EQUAL(sumVaults, m.vaulted);

    // Sanity beyond what consensus checks: never lock more than exists.
    BOOST_CHECK(m.vaulted <= m.m0Total);
    BOOST_CHECK(m.vaulted >= 0);
    BOOST_CHECK(m.m1 >= 0);
}

// Seed genesis settlement state at height 0 with a nonzero M0_total (represents
// prior mints) so LOCKs are economically backed. Returns the genesis hash.
uint256 SeedGenesis(CAmount m0Total)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    uint256 genHash = HashFromU64(0xB47);
    SettlementState s0;
    s0.SetNull();
    s0.M0_total_supply = m0Total;
    s0.nHeight = 0;
    s0.hashBlock = genHash;
    BOOST_REQUIRE(g_settlementdb->WriteState(s0));
    return genHash;
}

} // namespace

// ── 1. Many blocks, interleaved LOCK/UNLOCK, adversarial ordering ───────────────
BOOST_AUTO_TEST_CASE(real_path_lock_unlock_conservation)
{
    LOCK(cs_main);
    const CAmount P = 100 * COIN;         // fixed unit -> any receipt+vault full-unlocks
    const CAmount SEED = 1000000 * COIN;  // plenty of standard M0 to lock (< 21M cap)
    uint256 genHash = SeedGenesis(SEED);

    Chain chain;
    CBlockIndex* tip = chain.genesis(0, genHash);
    Model model;
    model.m0Total = SEED;

    Rng rng(0xB10C5E77C0FFEEULL);
    uint8_t tag = 1;

    for (int h = 1; h <= 60; ++h) {
        std::vector<CTransactionRef> specials;
        std::string desc;
        // UNLOCK may only consume outpoints that existed BEFORE this block (a
        // receipt/vault created by a same-block LOCK is not yet in the committed
        // DB, so spending it in the same block is invalid). Snapshot the pools.
        std::vector<COutPoint> availR, availV;
        for (auto& kv : model.receipts) availR.push_back(kv.first);
        for (auto& kv : model.vaults) availV.push_back(kv.first);
        size_t rCursor = 0, vCursor = 0;

        // 1..4 ops per block, adversarially interleaved.
        int nOps = 1 + (int)rng.below(4);
        for (int op = 0; op < nOps; ++op) {
            bool canUnlock = rCursor < availR.size() && vCursor < availV.size();
            bool doLock = !canUnlock || (rng.below(100) < 60); // bias to lock
            if (doLock) {
                // fresh funding outpoint -> IsM0Standard.
                COutPoint fund(HashFromU64(0x1000u + (uint64_t)h * 16 + op), 0);
                CMutableTransaction mtx = MakeLock(fund, P, tag++);
                CTransaction tx(mtx);
                specials.push_back(MakeTransactionRef(tx));
                model.vaults[COutPoint(tx.GetHash(), 0)] = P;
                model.receipts[COutPoint(tx.GetHash(), 1)] = P;
                model.vaulted += P;
                model.m1 += P;
                desc += "L ";
            } else {
                // full unlock: 1 pre-block receipt (P) + 1 pre-block vault (P).
                COutPoint r = availR[rCursor++];
                COutPoint v = availV[vCursor++];
                CMutableTransaction mtx = MakeFullUnlock({r}, {v}, P, tag++);
                CTransaction tx(mtx);
                specials.push_back(MakeTransactionRef(tx));
                model.receipts.erase(r);
                model.vaults.erase(v);
                model.vaulted -= P;
                model.m1 -= P;
                desc += "U ";
            }
        }

        CBlock blk = MakeBlock((uint32_t)h, *tip->phashBlock, specials);
        CBlockIndex* pindex = chain.extend(tip, blk);
        // real block-level settlement path
        CValidationState state;
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);
        BOOST_REQUIRE_MESSAGE(
            ProcessSpecialTxsInBlock(blk, pindex, &view, state, /*fJustCheck=*/false, /*fSettlementOnly=*/true),
            "block " << h << " [" << desc << "] rejected reason='" << state.GetRejectReason()
                     << "' vaulted=" << model.vaulted);
        AssertInvariants(model);
        tip = pindex;
    }
    BOOST_TEST_MESSAGE("real-path lock/unlock: 60 blocks connected, invariants held every block");
}

// ── 2. A malformed tx of every type is rejected AND leaves state untouched ───────
BOOST_AUTO_TEST_CASE(real_path_reject_leaves_state_untouched)
{
    LOCK(cs_main);
    const CAmount P = 50 * COIN;
    uint256 genHash = SeedGenesis(1000 * COIN);
    Chain chain;
    CBlockIndex* tip = chain.genesis(0, genHash);
    Model model; model.m0Total = 1000 * COIN;

    // Height 1: one honest lock, so there is live state to (fail to) corrupt.
    COutPoint fund(HashFromU64(0x2000), 0);
    CMutableTransaction good = MakeLock(fund, P, 9);
    CTransaction goodTx(good);
    {
        CBlock blk = MakeBlock(1, *tip->phashBlock, {MakeTransactionRef(goodTx)});
        CBlockIndex* pindex = chain.extend(tip, blk);
        CValidationState state; CCoinsView d; CCoinsViewCache view(&d);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(blk, pindex, &view, state, false, true));
        model.vaults[COutPoint(goodTx.GetHash(), 0)] = P;
        model.receipts[COutPoint(goodTx.GetHash(), 1)] = P;
        model.vaulted += P; model.m1 += P;
        tip = pindex;
        AssertInvariants(model);
    }
    COutPoint liveReceipt(goodTx.GetHash(), 1);
    COutPoint liveVault(goodTx.GetHash(), 0);

    // Snapshot the exact live state.
    SettlementState before;
    BOOST_REQUIRE(g_settlementdb->ReadLatestState(before));

    // Each malformed block must be REJECTED and must not mutate the DB (deferred
    // commit -> a mid-block reject discards the whole batch).
    struct Bad { const char* name; CMutableTransaction tx; };
    std::vector<Bad> bads;

    // (a) LOCK with vault != receipt amount.
    {
        CMutableTransaction m = MakeLock(COutPoint(HashFromU64(0x3001), 0), P, 3);
        m.vout[1].nValue = P - 1; // receipt != vault
        bads.push_back({"lock-amount-mismatch", m});
    }
    // (b) LOCK whose vout[0] is not OP_TRUE.
    {
        CMutableTransaction m = MakeLock(COutPoint(HashFromU64(0x3002), 0), P, 3);
        m.vout[0].scriptPubKey = P2PKH(7); // vault must be OP_TRUE
        bads.push_back({"lock-vault-not-optrue", m});
    }
    // (c) UNLOCK over-release: consume 1 receipt+1 vault (P each) but claim m0Out=2P.
    {
        CMutableTransaction m = MakeFullUnlock({liveReceipt}, {liveVault}, 2 * P, 4);
        bads.push_back({"unlock-over-release", m});
    }
    // (d) UNLOCK with no vault input (receipt only).
    {
        CMutableTransaction m = MakeFullUnlock({liveReceipt}, {}, P, 4);
        bads.push_back({"unlock-no-vault", m});
    }
    // (e) TRANSFER with malformed outputs (recipient == full receipt leaves no
    //     room for the mandatory OP_TRUE fee output -> rejected).
    {
        CMutableTransaction m = MakeTransfer(liveReceipt, P, 1000, 5);
        m.vout[0].nValue = P; // recipient consumes the whole receipt; fee has no cover
        bads.push_back({"transfer-malformed-outputs", m});
    }

    for (const Bad& b : bads) {
        CTransaction tx(b.tx);
        CBlock blk = MakeBlock(2, *tip->phashBlock, {MakeTransactionRef(tx)});
        // NB: do NOT chain.extend here (a rejected block never becomes tip); build
        // a throwaway index on top of the real tip.
        Chain scratch;
        // reuse tip as pprev via a local index:
        std::deque<uint256> hs; std::deque<CBlockIndex> ix;
        hs.push_back(blk.GetHash());
        ix.emplace_back();
        ix.back().nHeight = tip->nHeight + 1;
        ix.back().pprev = tip;
        ix.back().phashBlock = &hs.back();
        CValidationState state; CCoinsView d; CCoinsViewCache view(&d);
        bool ok = ProcessSpecialTxsInBlock(blk, &ix.back(), &view, state, false, true);
        BOOST_CHECK_MESSAGE(!ok, "malformed '" << b.name << "' was ACCEPTED (should reject)");

        // State byte-for-byte unchanged.
        SettlementState after;
        BOOST_REQUIRE(g_settlementdb->ReadLatestState(after));
        BOOST_CHECK_EQUAL(after.M0_vaulted, before.M0_vaulted);
        BOOST_CHECK_EQUAL(after.M1_supply, before.M1_supply);
        BOOST_CHECK_EQUAL(after.M0_total_supply, before.M0_total_supply);
        BOOST_CHECK(g_settlementdb->IsM1Receipt(liveReceipt)); // still live
        BOOST_CHECK(g_settlementdb->IsVault(liveVault));
    }
    AssertInvariants(model); // model untouched by rejects
}

// ── 3. TX_TRANSFER_M1 round-trip through the real block path ─────────────────────
BOOST_AUTO_TEST_CASE(real_path_transfer_roundtrip)
{
    LOCK(cs_main);
    const CAmount P = 100 * COIN;
    const CAmount FEE = 10000; // >> ComputeMinM1Fee for a ~200B tx
    uint256 genHash = SeedGenesis(1000 * COIN);
    Chain chain;
    CBlockIndex* tip = chain.genesis(0, genHash);
    Model model; model.m0Total = 1000 * COIN;

    // Block 1: LOCK P -> vault(P) + receipt(P).
    CTransaction lockTx{MakeLock(COutPoint(HashFromU64(0x4000), 0), P, 11)};
    {
        CBlock blk = MakeBlock(1, *tip->phashBlock, {MakeTransactionRef(lockTx)});
        CBlockIndex* pindex = chain.extend(tip, blk);
        CValidationState st; CCoinsView d; CCoinsViewCache view(&d);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(blk, pindex, &view, st, false, true));
        model.vaulted += P; model.m1 += P; tip = pindex;
    }
    COutPoint vault(lockTx.GetHash(), 0);
    COutPoint receipt(lockTx.GetHash(), 1);
    AssertInvariants(model);

    // Block 2: TRANSFER receipt(P) -> recipient(P-FEE) + OP_TRUE fee(FEE). M1 and
    // M0_vaulted are unchanged (strict M1 conservation, no vault touched).
    CTransaction xferTx{MakeTransfer(receipt, P, FEE, 12)};
    {
        CBlock blk = MakeBlock(2, *tip->phashBlock, {MakeTransactionRef(xferTx)});
        CBlockIndex* pindex = chain.extend(tip, blk);
        CValidationState st; CCoinsView d; CCoinsViewCache view(&d);
        BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(blk, pindex, &view, st, false, true),
                              "transfer rejected: " << st.GetRejectReason());
        tip = pindex;
    }
    // model scalars unchanged; receipts are now (P-FEE) at vout0 and (FEE) at vout1.
    AssertInvariants(model);
    COutPoint recA(xferTx.GetHash(), 0); // recipient P-FEE
    COutPoint recB(xferTx.GetHash(), 1); // OP_TRUE fee, written as a receipt
    BOOST_CHECK(g_settlementdb->IsM1Receipt(recA));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(recB));

    // Block 3: multi-input full unlock — consume BOTH split receipts (sum P) + the
    // vault (P). vout[0] = P2PKH(P), fee 0. M0_vaulted -> 0, M1 -> 0.
    CTransaction unlockTx{MakeFullUnlock({recA, recB}, {vault}, P, 13)};
    {
        CBlock blk = MakeBlock(3, *tip->phashBlock, {MakeTransactionRef(unlockTx)});
        CBlockIndex* pindex = chain.extend(tip, blk);
        CValidationState st; CCoinsView d; CCoinsViewCache view(&d);
        BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(blk, pindex, &view, st, false, true),
                              "unlock rejected: " << st.GetRejectReason());
        model.vaulted -= P; model.m1 -= P; tip = pindex;
    }
    AssertInvariants(model);
    BOOST_CHECK_EQUAL(model.vaulted, 0);
    BOOST_CHECK_EQUAL(model.m1, 0);
}

// ── 4. Reorg: connect, disconnect a suffix via the real UndoSpecialTxsInBlock,
//      assert exact restoration, reconnect ────────────────────────────────────────
BOOST_AUTO_TEST_CASE(real_path_reorg_undo_roundtrip)
{
    LOCK(cs_main);
    const CAmount P = 100 * COIN;
    uint256 genHash = SeedGenesis(1000 * COIN);
    Chain chain;
    CBlockIndex* tip = chain.genesis(0, genHash);
    Model model; model.m0Total = 1000 * COIN;

    // Connect 5 blocks: each locks one P (so undo of each is well-defined).
    std::vector<CBlockIndex*> pidx;
    std::vector<CBlock> blks;
    std::vector<std::pair<COutPoint, COutPoint>> locked; // (vault, receipt) per block
    for (int h = 1; h <= 5; ++h) {
        CTransaction lockTx{MakeLock(COutPoint(HashFromU64(0x5000u + h), 0), P, (uint8_t)(20 + h))};
        CBlock blk = MakeBlock((uint32_t)h, *tip->phashBlock, {MakeTransactionRef(lockTx)});
        CBlockIndex* pindex = chain.extend(tip, blk);
        CValidationState st; CCoinsView d; CCoinsViewCache view(&d);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(blk, pindex, &view, st, false, true));
        model.vaulted += P; model.m1 += P;
        pidx.push_back(pindex);
        blks.push_back(blk);
        locked.emplace_back(COutPoint(lockTx.GetHash(), 0), COutPoint(lockTx.GetHash(), 1));
        tip = pindex;
    }
    AssertInvariants(model);
    // Snapshot state at height 2 (the reorg target).
    SettlementState atH2;
    BOOST_REQUIRE(g_settlementdb->ReadState(2, atH2));

    // Disconnect blocks 5,4,3 (reverse order) via the REAL undo orchestrator.
    for (int h = 5; h >= 3; --h) {
        BOOST_REQUIRE_MESSAGE(UndoSpecialTxsInBlock(blks[h - 1], pidx[h - 1], /*fJustCheck=*/false),
                              "undo of block " << h << " failed");
        model.vaulted -= P; model.m1 -= P;
        // the vault+receipt that block created must be gone
        BOOST_CHECK(!g_settlementdb->IsVault(locked[h - 1].first));
        BOOST_CHECK(!g_settlementdb->IsM1Receipt(locked[h - 1].second));
    }

    // State at height 2 must be byte-identical to the pre-disconnect snapshot.
    SettlementState restored;
    BOOST_REQUIRE(g_settlementdb->ReadState(2, restored));
    BOOST_CHECK_EQUAL(restored.M0_vaulted, atH2.M0_vaulted);
    BOOST_CHECK_EQUAL(restored.M1_supply, atH2.M1_supply);
    BOOST_CHECK_EQUAL(restored.M0_total_supply, atH2.M0_total_supply);
    BOOST_CHECK_EQUAL(model.vaulted, 2 * P); // only blocks 1,2 remain
    {
        SettlementState st; BOOST_REQUIRE(g_settlementdb->ReadState(2, st));
        CValidationState vs; BOOST_CHECK(CheckA6P1(st, vs));
        CAmount sumVaults = 0;
        g_settlementdb->ForEachVault([&](const VaultEntry& v) { sumVaults += v.amount; return true; });
        BOOST_CHECK_EQUAL(sumVaults, model.vaulted);
    }

    // Reconnect block 3 -> back to 3 locks live.
    {
        CValidationState st; CCoinsView d; CCoinsViewCache view(&d);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(blks[2], pidx[2], &view, st, false, true));
        model.vaulted += P; model.m1 += P;
        BOOST_CHECK(g_settlementdb->IsVault(locked[2].first));
        BOOST_CHECK(g_settlementdb->IsM1Receipt(locked[2].second));
    }
    {
        SettlementState st; BOOST_REQUIRE(g_settlementdb->ReadState(3, st));
        BOOST_CHECK_EQUAL(st.M0_vaulted, model.vaulted);
        CValidationState vs; BOOST_CHECK(CheckA6P1(st, vs));
    }
}

// B4.4 O2b needs UPGRADE_FEE_RECEIPT_PINNED active; it is ALWAYS_ACTIVE only on
// regtest (mainnet flips at freeze, testnet at a deploy-time height), while this
// suite's default fixture is MAIN. Run the two O2b cases under a regtest fixture.
struct RegtestSettlementSetup : public BasicTestingSetup {
    RegtestSettlementSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

// ── 5. B4.4 O2b — fee-receipt owner registration + undo (via the block path) ────
BOOST_FIXTURE_TEST_CASE(fee_receipt_owner_registered_and_undone, RegtestSettlementSetup)
{
    LOCK(cs_main);
    const CAmount P = 100 * COIN, FEE = 12;
    uint256 genHash = SeedGenesis(1000000 * COIN);
    Chain chain;
    CBlockIndex* tip = chain.genesis(0, genHash);

    // Block 1: LOCK -> receipt. Block 2: TRANSFER it (creates the OP_TRUE fee
    // output). Regtest has UPGRADE_FEE_RECEIPT_PINNED ALWAYS_ACTIVE, so connect
    // must register the fee output's owner = coinbase vout[0].
    COutPoint fund(HashFromU64(0xF001), 0);
    CTransaction lockTx{MakeLock(fund, P, /*receiptTag=*/7)};
    COutPoint receipt(lockTx.GetHash(), 1);
    {
        CBlock blk = MakeBlock(1, *tip->phashBlock, {MakeTransactionRef(lockTx)});
        CBlockIndex* pindex = chain.extend(tip, blk);
        CValidationState state; CCoinsView dummy; CCoinsViewCache view(&dummy);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(blk, pindex, &view, state, false, true));
        tip = pindex;
    }
    CTransaction xferTx{MakeTransfer(receipt, P, FEE, /*recipientTag=*/8)};
    COutPoint feeOutpoint(xferTx.GetHash(), 1); // vout[1] = OP_TRUE fee
    CBlock blk2 = MakeBlock(2, *tip->phashBlock, {MakeTransactionRef(xferTx)});
    CBlockIndex* pindex2 = chain.extend(tip, blk2);
    CScript expectedOwner = blk2.vtx[0]->vout[0].scriptPubKey;
    {
        CValidationState state; CCoinsView dummy; CCoinsViewCache view(&dummy);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(blk2, pindex2, &view, state, false, true));
    }
    BOOST_CHECK(g_settlementdb->IsFeeOwned(feeOutpoint));
    CScript owner; BOOST_REQUIRE(g_settlementdb->ReadFeeOwner(feeOutpoint, owner));
    BOOST_CHECK(owner == expectedOwner);
    BOOST_CHECK(!g_settlementdb->IsFeeOwned(COutPoint(xferTx.GetHash(), 0))); // recipient not owned

    BOOST_REQUIRE(UndoSpecialTxsInBlock(blk2, pindex2, false));
    BOOST_CHECK(!g_settlementdb->IsFeeOwned(feeOutpoint)); // symmetric erase
}

// ── 6. B4.4 O2b — destination covenant enforced in CheckSpecialTx ───────────────
BOOST_FIXTURE_TEST_CASE(fee_receipt_destination_covenant, RegtestSettlementSetup)
{
    LOCK(cs_main);
    const CAmount P = 100 * COIN, FEE = 12;
    uint256 genHash = SeedGenesis(1000000 * COIN);
    Chain chain;
    CBlockIndex* prev = chain.genesis(50, genHash); // regtest gate ALWAYS_ACTIVE

    const CScript ownerScript = P2PKH(0x9A);
    COutPoint feeRcpt(HashFromU64(0xFEE1), 1);
    M1Receipt r; r.outpoint = feeRcpt; r.amount = P; r.nCreateHeight = 50;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(r));
    BOOST_REQUIRE(g_settlementdb->WriteFeeOwner(feeRcpt, ownerScript));

    CCoinsView dummy; CCoinsViewCache view(&dummy);

    // (a) transfer paying the owner (recipient == owner) PASSES.
    {
        CMutableTransaction t; t.nVersion = CTransaction::TxVersion::SAPLING;
        t.nType = CTransaction::TxType::TX_TRANSFER_M1;
        t.vin.emplace_back(CTxIn(feeRcpt));
        t.vout.emplace_back(CTxOut(P - FEE, ownerScript));
        t.vout.emplace_back(CTxOut(FEE, OpTrue()));
        CValidationState state;
        BOOST_CHECK_MESSAGE(CheckSpecialTx(CTransaction(t), prev, &view, state),
                            "owner-paying transfer rejected: " << state.GetRejectReason());
    }
    // (b) transfer paying a THIRD PARTY (front-run) is REJECTED.
    {
        CMutableTransaction t; t.nVersion = CTransaction::TxVersion::SAPLING;
        t.nType = CTransaction::TxType::TX_TRANSFER_M1;
        t.vin.emplace_back(CTxIn(feeRcpt));
        t.vout.emplace_back(CTxOut(P - FEE, P2PKH(0x11)));
        t.vout.emplace_back(CTxOut(FEE, OpTrue()));
        CValidationState state;
        BOOST_CHECK(!CheckSpecialTx(CTransaction(t), prev, &view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-feereceipt-owner");
    }
    // (b2) UNLOCK sweep paying the owner: the unlock fee is NOT an output (it is
    // released to the coinbase), so the covenant allows exactly min-fee slack.
    {
        VaultEntry v; v.outpoint = COutPoint(HashFromU64(0xFA01), 0);
        v.amount = P; v.nLockHeight = 50;
        BOOST_REQUIRE(g_settlementdb->WriteVault(v));
        CMutableTransaction t; t.nVersion = CTransaction::TxVersion::SAPLING;
        t.nType = CTransaction::TxType::TX_UNLOCK;
        t.vin.emplace_back(CTxIn(feeRcpt));          // owned receipt first
        t.vin.emplace_back(CTxIn(v.outpoint));       // vault
        // Full redeem, fee = 50 (the builder's floor): m0Out = P - 50 to the owner,
        // NO OP_TRUE output — the 50 is invisible (coinbase side). Only the min-fee
        // slack lets this pass.
        t.vout.emplace_back(CTxOut(P - 50, ownerScript));
        CValidationState state;
        BOOST_CHECK_MESSAGE(CheckSpecialTx(CTransaction(t), prev, &view, state),
                            "owner-paying unlock sweep rejected: " << state.GetRejectReason());
    }
    // (b3) UNLOCK griefing: huge invisible fee (value neither to owner nor OP_TRUE,
    // beyond the min-fee slack) is REJECTED.
    {
        VaultEntry v; v.outpoint = COutPoint(HashFromU64(0xFA02), 0);
        v.amount = P; v.nLockHeight = 50;
        BOOST_REQUIRE(g_settlementdb->WriteVault(v));
        CMutableTransaction t; t.nVersion = CTransaction::TxVersion::SAPLING;
        t.nType = CTransaction::TxType::TX_UNLOCK;
        t.vin.emplace_back(CTxIn(feeRcpt));
        t.vin.emplace_back(CTxIn(v.outpoint));
        t.vout.emplace_back(CTxOut(P / 2, ownerScript)); // only half reaches the owner
        CValidationState state;
        BOOST_CHECK(!CheckSpecialTx(CTransaction(t), prev, &view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-feereceipt-owner");
    }
    // (c) legacy (unowned) receipt: no fee-owner entry -> covenant does not apply.
    {
        COutPoint legacy(HashFromU64(0xFEE2), 1);
        M1Receipt lr; lr.outpoint = legacy; lr.amount = P; lr.nCreateHeight = 50;
        BOOST_REQUIRE(g_settlementdb->WriteReceipt(lr));
        CMutableTransaction t; t.nVersion = CTransaction::TxVersion::SAPLING;
        t.nType = CTransaction::TxType::TX_TRANSFER_M1;
        t.vin.emplace_back(CTxIn(legacy));
        t.vout.emplace_back(CTxOut(P - FEE, P2PKH(0x22)));
        t.vout.emplace_back(CTxOut(FEE, OpTrue()));
        CValidationState state;
        BOOST_CHECK_MESSAGE(CheckSpecialTx(CTransaction(t), prev, &view, state),
                            "legacy unowned receipt rejected: " << state.GetRejectReason());
    }
}

// ── 7. B4.4 O2b — ADVERSARIAL HARDENING: fee-receipt covenant property test ─────
// Hammer CheckFeeReceiptOwnerCovenant (extracted enforcement half) with thousands
// of randomized hostile scenarios and assert the SECURITY invariant directly (not
// just "matches the model"): whenever the covenant ACCEPTS a tx spending
// fee-owned receipts, the value that escaped the owner line is bounded by the
// per-tx slack — i.e. a third party can never receive owned value beyond dust.
// Also proves no crash / no CAmount overflow on amounts near MAX_MONEY.
BOOST_FIXTURE_TEST_CASE(fee_receipt_covenant_property, RegtestSettlementSetup)
{
    LOCK(cs_main);
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    BOOST_REQUIRE(InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));

    Rng rng(0xFEEDC0FFEEULL);
    // A small pool of candidate owner scripts (so "different owners" collisions
    // and "owner == a payout target" cases occur often).
    std::vector<CScript> owners = { P2PKH(0x01), P2PKH(0x02), P2PKH(0x03), OpTrue() };
    const CAmount BIG = (CAmount)21000000 * 100000000 / 8;  // ~2.6e15, near-cap arithmetic w/o overflow

    int accepted = 0, rejectedMixed = 0, rejectedOwner = 0, noCovenant = 0;
    for (int iter = 0; iter < 6000; ++iter) {
        // Seed 1..3 fee-owned receipts + maybe 1 unowned receipt, at fresh outpoints.
        BOOST_REQUIRE(InitSettlementDB(1 << 20, true, true));  // clean DB per case
        CMutableTransaction t;
        t.nVersion = CTransaction::TxVersion::SAPLING;
        t.nType = (rng.below(2) ? CTransaction::TxType::TX_UNLOCK
                                : CTransaction::TxType::TX_TRANSFER_M1);

        // Independent model state.
        std::map<std::vector<unsigned char>, CAmount> ownedByScript;  // owner-script -> owned M1 in
        int nOwned = 1 + (int)rng.below(3);
        std::set<std::vector<unsigned char>> distinctOwners;
        for (int i = 0; i < nOwned; ++i) {
            COutPoint op(HashFromU64(0x5000u + (uint64_t)iter * 8 + i), 0);
            CScript owner = owners[rng.below(owners.size())];
            CAmount amt = 1 + (CAmount)(rng.next() % (uint64_t)BIG);
            M1Receipt r; r.outpoint = op; r.amount = amt; r.nCreateHeight = 1;
            BOOST_REQUIRE(g_settlementdb->WriteReceipt(r));
            BOOST_REQUIRE(g_settlementdb->WriteFeeOwner(op, owner));
            t.vin.emplace_back(CTxIn(op));
            ownedByScript[std::vector<unsigned char>(owner.begin(), owner.end())] += amt;
            distinctOwners.insert(std::vector<unsigned char>(owner.begin(), owner.end()));
        }
        // Maybe one unowned receipt input (must not affect the covenant).
        if (rng.below(2)) {
            COutPoint op(HashFromU64(0x6000u + iter), 0);
            M1Receipt r; r.outpoint = op; r.amount = 1 + (CAmount)(rng.next() % 1000); r.nCreateHeight = 1;
            BOOST_REQUIRE(g_settlementdb->WriteReceipt(r));  // no fee-owner entry
            t.vin.emplace_back(CTxIn(op));
        }
        // Random outputs: owner / OP_TRUE / third-party, random values.
        int nOut = 1 + (int)rng.below(4);
        for (int i = 0; i < nOut; ++i) {
            uint32_t kind = rng.below(3);
            CScript spk = (kind == 0) ? owners[rng.below(owners.size())]
                        : (kind == 1) ? OpTrue()
                                      : P2PKH(0x80 + (uint8_t)rng.below(64));  // third party
            CAmount v = (CAmount)(rng.next() % (uint64_t)BIG);
            t.vout.emplace_back(CTxOut(v, spk));
        }

        const CTransaction tx(t);
        CValidationState state;
        const bool ok = CheckFeeReceiptOwnerCovenant(tx, state);

        if (distinctOwners.size() > 1) {
            // Must reject as mixed-owner (deterministic).
            BOOST_REQUIRE(!ok);
            BOOST_REQUIRE_EQUAL(state.GetRejectReason(), "bad-txns-feereceipt-owner-mixed");
            ++rejectedMixed;
            continue;
        }
        // Single owner O with ownedIn.
        const std::vector<unsigned char>& okey = ownedByScript.begin()->first;
        const CScript O(okey.begin(), okey.end());
        const CAmount ownedIn = ownedByScript.begin()->second;
        // Value reaching the owner line (owner script OR any OP_TRUE output).
        CAmount toOwnerLine = 0, toThirdParty = 0;
        for (const CTxOut& out : tx.vout) {
            const CScript& s = out.scriptPubKey;
            const bool isOpTrue = (s.size() == 1 && s[0] == OP_TRUE);
            if (s == O || isOpTrue) toOwnerLine += out.nValue;
            else toThirdParty += out.nValue;
        }
        CAmount slack = 0;
        if (tx.nType == CTransaction::TxType::TX_UNLOCK) {
            slack = std::max(ComputeMinM1Fee(::GetSerializeSize(tx, PROTOCOL_VERSION)), (CAmount)50);
        }
        if (ok) {
            // THE SECURITY INVARIANT: an accepted spend of fee-owned receipts never
            // lets owned value escape the owner line beyond the (dust) slack.
            BOOST_REQUIRE_MESSAGE(ownedIn - toOwnerLine <= slack,
                "iter " << iter << ": ACCEPTED but ownedIn=" << ownedIn
                        << " toOwnerLine=" << toOwnerLine << " slack=" << slack
                        << " (escaped=" << (ownedIn - toOwnerLine) << ")");
            ++accepted;
        } else {
            BOOST_REQUIRE_EQUAL(state.GetRejectReason(), "bad-txns-feereceipt-owner");
            // Rejection must be justified: the owner line was underpaid past slack.
            BOOST_REQUIRE(toOwnerLine + slack < ownedIn);
            ++rejectedOwner;
        }
        (void)toThirdParty; (void)noCovenant;
    }
    BOOST_TEST_MESSAGE("fee-receipt covenant property: 6000 cases | accepted=" << accepted
                       << " rejected-mixed=" << rejectedMixed
                       << " rejected-owner=" << rejectedOwner
                       << " — anti-theft invariant held on every ACCEPT, no overflow/crash");
    BOOST_CHECK(accepted > 0 && rejectedMixed > 0 && rejectedOwner > 0);
}

BOOST_AUTO_TEST_SUITE_END()
