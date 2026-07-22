// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * BTC Headers reorg round-trip tests (BP-BTCHEADERS-REORG / audit R5).
 *
 * Exercises the consensus connect/disconnect machinery that healed the
 * 2026-06-26 prod wedge, with an in-memory btcheadersdb so the reorg-undo
 * path is regression-tested rather than only validated once on the network:
 *
 *   1. reorg round-trip  : connect branch A, connect a heavier branch B that
 *                          overwrites + extends, assert tip moved to B, then
 *                          disconnect B and assert the tip/height-index/chainwork
 *                          are restored to A *exactly*.
 *   2. pure-append undo  : connect A, append at the tip (no overwrite), disconnect,
 *                          assert back to A (undo with empty `replaced`).
 *   3. R5 hard-error     : disconnecting a post-activation tx with NO undo record
 *                          must hard-error (return false) instead of silently
 *                          running the V1 truncate, and must leave the DB untouched.
 *   4. V1 truncate       : a genuinely pre-activation block still truncates on
 *                          disconnect (legacy append-only path).
 *
 * Process/Disconnect do not verify the publisher signature or PoW (that is
 * CheckBtcHeadersTx, run earlier), so the txs here carry an empty signature.
 */

#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "burnclaim/burnclaim.h"
#include "burnclaim/burnclaimdb.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "test/test_bathron.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

// TESTNET — UPGRADE_BTCHEADERS_REORG is ALWAYS_ACTIVE, so any height exercises V2.
static const int H_V2_A = 200000;
static const int H_V2_B = 200001;       // next block

namespace {

BtcBlockHeader MakeHeader(const uint256& prev, uint32_t nonce, uint32_t nTime)
{
    BtcBlockHeader h;
    h.nVersion = 4;
    h.hashPrevBlock = prev;
    // Non-null, distinct merkle root (IsNull() keys on the merkle root).
    h.hashMerkleRoot = ArithToUint256(arith_uint256(nonce) + 1);
    h.nTime = nTime;
    h.nBits = 0x1d00ffff;                // valid compact target -> GetBlockProof > 0
    h.nNonce = nonce;
    return h;
}

CTransactionRef MakeHeadersTx(uint32_t startHeight, const std::vector<BtcBlockHeader>& headers)
{
    BtcHeadersPayload p;
    p.nVersion = BtcHeadersPayload::CURRENT_VERSION;
    p.publisherProTxHash = uint256();    // unused by Process/Disconnect
    p.startHeight = startHeight;
    p.count = static_cast<uint16_t>(headers.size());
    p.headers = headers;
    // p.sig left empty: signature is checked in CheckBtcHeadersTx, not here.

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;
    SetTxPayload(mtx, p);
    return MakeTransactionRef(std::move(mtx));
}

bool Connect(const CTransactionRef& tx, int height)
{
    auto batch = g_btcheadersdb->CreateBatch();
    if (!ProcessBtcHeadersTxInBlock(*tx, batch, height)) return false;
    return batch.Commit();
}

// Fixture: in-memory headers DB + a minimal SPV instance (GetBlockProof only).
struct BtcHeadersReorgSetup : public BasicTestingSetup {
    BtcHeadersReorgSetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
    }
    ~BtcHeadersReorgSetup()
    {
        g_btcheadersdb.reset();
        g_btc_spv.reset();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(btcheaders_reorg_tests, BtcHeadersReorgSetup)

// ---------------------------------------------------------------------------
// 1. Reorg round-trip: connect A (h1..h3), connect heavier B (h2'..h4',
//    overwriting heights 2-3 and extending to 4), then disconnect B and verify
//    the active chain, height index and per-height chainwork are restored to A.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(reorg_roundtrip_restores_branch_a_exactly)
{
    const uint256 genesis = ArithToUint256(arith_uint256(1));
    BtcBlockHeader h1 = MakeHeader(genesis,        1, 1000);
    BtcBlockHeader h2 = MakeHeader(h1.GetHash(),   2, 1001);
    BtcBlockHeader h3 = MakeHeader(h2.GetHash(),   3, 1002);
    auto txA = MakeHeadersTx(1, {h1, h2, h3});

    BtcBlockHeader h2b = MakeHeader(h1.GetHash(),  12, 2001);
    BtcBlockHeader h3b = MakeHeader(h2b.GetHash(), 13, 2002);
    BtcBlockHeader h4b = MakeHeader(h3b.GetHash(), 14, 2003);
    auto txB = MakeHeadersTx(2, {h2b, h3b, h4b});

    // --- connect A ---
    BOOST_REQUIRE(Connect(txA, H_V2_A));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 3u);
    {
        uint32_t th; uint256 hash;
        BOOST_REQUIRE(g_btcheadersdb->GetTip(th, hash));
        BOOST_CHECK(hash == h3.GetHash());
    }
    // Capture A's state at the heights B will overwrite.
    arith_uint256 workA2, workA3;
    BOOST_REQUIRE(g_btcheadersdb->GetOrComputeChainWork(2, workA2));
    BOOST_REQUIRE(g_btcheadersdb->GetOrComputeChainWork(3, workA3));

    // --- connect heavier B (reorg) ---
    BOOST_REQUIRE(Connect(txB, H_V2_B));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 4u);
    {
        uint32_t th; uint256 hash;
        BOOST_REQUIRE(g_btcheadersdb->GetTip(th, hash));
        BOOST_CHECK(hash == h4b.GetHash());
        uint256 at2;
        BOOST_REQUIRE(g_btcheadersdb->GetHashAtHeight(2, at2));
        BOOST_CHECK(at2 == h2b.GetHash());      // height 2 now points at B
    }

    // --- disconnect B: must restore A exactly ---
    {
        auto batch = g_btcheadersdb->CreateBatch();
        BOOST_REQUIRE(DisconnectBtcHeadersTx(*txB, batch, H_V2_B));
        BOOST_REQUIRE(batch.Commit());
    }
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 3u);
    {
        uint32_t th; uint256 hash;
        BOOST_REQUIRE(g_btcheadersdb->GetTip(th, hash));
        BOOST_CHECK(hash == h3.GetHash());
    }
    // Height index restored to A.
    uint256 at2, at3, at4;
    BOOST_REQUIRE(g_btcheadersdb->GetHashAtHeight(2, at2));
    BOOST_REQUIRE(g_btcheadersdb->GetHashAtHeight(3, at3));
    BOOST_CHECK(at2 == h2.GetHash());
    BOOST_CHECK(at3 == h3.GetHash());
    BOOST_CHECK(!g_btcheadersdb->GetHashAtHeight(4, at4));   // B's extension dropped
    // Per-height chainwork restored to A.
    arith_uint256 w2, w3;
    BOOST_REQUIRE(g_btcheadersdb->GetOrComputeChainWork(2, w2));
    BOOST_REQUIRE(g_btcheadersdb->GetOrComputeChainWork(3, w3));
    BOOST_CHECK(w2 == workA2);
    BOOST_CHECK(w3 == workA3);
    // The original header bytes survive (append-only 'H' store) and are reachable.
    BtcBlockHeader got2;
    BOOST_REQUIRE(g_btcheadersdb->GetHeaderByHeight(2, got2));
    BOOST_CHECK(got2.GetHash() == h2.GetHash());
    // Undo record consumed.
    BOOST_CHECK(!g_btcheadersdb->HasReorgUndo(txB->GetHash()));
}

// ---------------------------------------------------------------------------
// 2. Pure append at the tip (no overwrite) then disconnect: undo carries an
//    empty `replaced` set; disconnect must erase only the new heights.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(pure_append_undo_restores_tip)
{
    const uint256 genesis = ArithToUint256(arith_uint256(1));
    BtcBlockHeader h1 = MakeHeader(genesis,      1, 1000);
    BtcBlockHeader h2 = MakeHeader(h1.GetHash(), 2, 1001);
    auto txA = MakeHeadersTx(1, {h1, h2});

    BtcBlockHeader h3 = MakeHeader(h2.GetHash(), 3, 1002);
    BtcBlockHeader h4 = MakeHeader(h3.GetHash(), 4, 1003);
    auto txAppend = MakeHeadersTx(3, {h3, h4});

    BOOST_REQUIRE(Connect(txA, H_V2_A));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 2u);

    BOOST_REQUIRE(Connect(txAppend, H_V2_B));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 4u);

    {
        auto batch = g_btcheadersdb->CreateBatch();
        BOOST_REQUIRE(DisconnectBtcHeadersTx(*txAppend, batch, H_V2_B));
        BOOST_REQUIRE(batch.Commit());
    }
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 2u);
    uint32_t th; uint256 hash;
    BOOST_REQUIRE(g_btcheadersdb->GetTip(th, hash));
    BOOST_CHECK(hash == h2.GetHash());
    uint256 at3, at4;
    BOOST_CHECK(!g_btcheadersdb->GetHashAtHeight(3, at3));
    BOOST_CHECK(!g_btcheadersdb->GetHashAtHeight(4, at4));
}

// ---------------------------------------------------------------------------
// 3. R5: a post-activation disconnect with no reorg-undo record must hard-error
//    (not silently truncate), and must not mutate the DB.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(disconnect_missing_undo_post_activation_hard_errors)
{
    const uint256 genesis = ArithToUint256(arith_uint256(1));
    BtcBlockHeader h1 = MakeHeader(genesis,      1, 1000);
    BtcBlockHeader h2 = MakeHeader(h1.GetHash(), 2, 1001);
    BtcBlockHeader h3 = MakeHeader(h2.GetHash(), 3, 1002);
    auto txA = MakeHeadersTx(1, {h1, h2, h3});
    BOOST_REQUIRE(Connect(txA, H_V2_A));
    const uint32_t tipBefore = g_btcheadersdb->GetTipHeight();
    uint256 hashBefore = g_btcheadersdb->GetTipHash();

    // A header-tx that was never connected -> no undo record under its txid.
    BtcBlockHeader hx = MakeHeader(h1.GetHash(), 99, 9000);
    auto txNever = MakeHeadersTx(2, {hx});
    BOOST_REQUIRE(!g_btcheadersdb->HasReorgUndo(txNever->GetHash()));

    {
        auto batch = g_btcheadersdb->CreateBatch();
        // Hard-error: post-activation height + missing undo.
        BOOST_CHECK(!DisconnectBtcHeadersTx(*txNever, batch, H_V2_A));
        // Deliberately not committed (the caller aborts the block on error).
    }
    // DB untouched.
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), tipBefore);
    BOOST_CHECK(g_btcheadersdb->GetTipHash() == hashBefore);
}

// (The pre-activation V1 truncate test was removed: every network now activates
// UPGRADE_BTCHEADERS_REORG ALWAYS_ACTIVE, so the V1 path is unreachable.)

// ---------------------------------------------------------------------------
// spv-headers-0: multiple TX_BTC_HEADERS chunks in ONE block (one batch, single
// Commit) must accumulate chainwork across the chunk boundary. Before the fix,
// the second chunk re-read the stale committed DB for its parent work and
// restarted from zero, so the stored tip-work was undercounted and per-height
// chainwork was non-monotonic across the boundary.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(multi_chunk_one_batch_accumulates_chainwork)
{
    const uint256 genesis = ArithToUint256(arith_uint256(1));
    BtcBlockHeader h1 = MakeHeader(genesis,      1, 1000);
    BtcBlockHeader h2 = MakeHeader(h1.GetHash(), 2, 1001);
    BtcBlockHeader h3 = MakeHeader(h2.GetHash(), 3, 1002);
    auto tx1 = MakeHeadersTx(1, {h1, h2, h3});

    BtcBlockHeader h4 = MakeHeader(h3.GetHash(), 4, 1003);
    BtcBlockHeader h5 = MakeHeader(h4.GetHash(), 5, 1004);
    BtcBlockHeader h6 = MakeHeader(h5.GetHash(), 6, 1005);
    auto tx2 = MakeHeadersTx(4, {h4, h5, h6});

    // Both chunks into ONE batch, committed once (the genesis multi-chunk shape).
    auto batch = g_btcheadersdb->CreateBatch();
    BOOST_REQUIRE(ProcessBtcHeadersTxInBlock(*tx1, batch, H_V2_A));
    BOOST_REQUIRE(ProcessBtcHeadersTxInBlock(*tx2, batch, H_V2_A));
    BOOST_REQUIRE(batch.Commit());

    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 6u);

    // Tip work must equal the sum of all six block proofs (not just chunk 2's).
    arith_uint256 expected = 0;
    for (const auto& h : {h1, h2, h3, h4, h5, h6}) {
        expected += g_btc_spv->GetBlockProof(h);
    }
    arith_uint256 tipWork;
    BOOST_REQUIRE(g_btcheadersdb->GetTipWork(tipWork));
    BOOST_CHECK(tipWork == expected);

    // Per-height chainwork is monotonic across the chunk boundary (h3 -> h4).
    arith_uint256 w3, w4;
    BOOST_REQUIRE(g_btcheadersdb->GetOrComputeChainWork(3, w3));
    BOOST_REQUIRE(g_btcheadersdb->GetOrComputeChainWork(4, w4));
    BOOST_CHECK(w4 > w3);
    BOOST_CHECK(w4 == w3 + g_btc_spv->GetBlockProof(h4));
}

// spv-headers-1: a continuation chunk in the same genesis block whose header[0]
// does NOT build on the previous chunk's tip must be rejected at connect time.
BOOST_AUTO_TEST_CASE(multi_chunk_broken_continuity_rejected)
{
    const uint256 genesis = ArithToUint256(arith_uint256(1));
    BtcBlockHeader h1 = MakeHeader(genesis,      1, 1000);
    BtcBlockHeader h2 = MakeHeader(h1.GetHash(), 2, 1001);
    BtcBlockHeader h3 = MakeHeader(h2.GetHash(), 3, 1002);
    auto tx1 = MakeHeadersTx(1, {h1, h2, h3});

    // Chunk 2 starts at height 4 but header[0] builds on an unrelated hash, not h3.
    BtcBlockHeader bad4 = MakeHeader(ArithToUint256(arith_uint256(999)), 99, 2000);
    BtcBlockHeader bad5 = MakeHeader(bad4.GetHash(),                    100, 2001);
    auto tx2 = MakeHeadersTx(4, {bad4, bad5});

    auto batch = g_btcheadersdb->CreateBatch();
    BOOST_REQUIRE(ProcessBtcHeadersTxInBlock(*tx1, batch, H_V2_A));
    // Refused: header[0].hashPrevBlock != pending tip (h3).
    BOOST_CHECK(!ProcessBtcHeadersTxInBlock(*tx2, batch, H_V2_A));
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// Burn-claim reorg-safety: IsBtcBurnStillValidConsensus (audit R2/R4, item #9).
//
// The consensus guard that decides whether a recorded burn may still be minted.
// It reads ONLY the consensus btcheadersdb (never the local btcspv, per R3/R4)
// and enforces K = GetRequiredConfirmations() (= K_CONFIRMATIONS_TESTNET = 6,
// the value just reverted from 100). These pin the exact reorg/confirmation
// boundaries so a future change can't silently re-open the BC-07/M1K-05 split.
// ===========================================================================

namespace {

// Write a contiguous active header chain at heights [1..n] and set the tip.
// Returns the per-height hashes (index i -> height i+1).
std::vector<uint256> SeedChain(uint32_t n)
{
    std::vector<uint256> hashes;
    auto batch = g_btcheadersdb->CreateBatch();
    uint256 prev = ArithToUint256(arith_uint256(0xBEEF));
    for (uint32_t h = 1; h <= n; ++h) {
        BtcBlockHeader hdr = MakeHeader(prev, h, 1000 + h);
        batch.WriteHeader(h, hdr);
        prev = hdr.GetHash();
        hashes.push_back(prev);
    }
    batch.WriteTip(n, hashes.back());
    BOOST_REQUIRE(batch.Commit());
    return hashes;
}

BurnClaimRecord MakeRecord(uint32_t btcHeight, const uint256& btcBlockHash)
{
    BurnClaimRecord r;
    r.btcTxid = ArithToUint256(arith_uint256(btcHeight) + 0x1000);
    r.btcBlockHash = btcBlockHash;
    r.btcHeight = btcHeight;
    r.burnedSats = 100000;
    r.bathronDest = uint160();
    r.claimHeight = 0;
    r.finalHeight = 0;
    r.status = BurnClaimStatus::PENDING;
    return r;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(burnclaim_reorg_consensus_tests, BtcHeadersReorgSetup)

// K_CONFIRMATIONS_TESTNET is 6 (reverted from 100): a burn exactly K-deep is
// valid, K-1 deep is not. This test is the guard on that revert.
BOOST_AUTO_TEST_CASE(burn_valid_at_exactly_k_confirmations)
{
    BOOST_REQUIRE_EQUAL(GetRequiredConfirmations(), 6u);
    auto hashes = SeedChain(10);                       // tip = height 10
    // height 5 => conf = 10 - 5 + 1 = 6 == K -> valid
    BOOST_CHECK(IsBtcBurnStillValidConsensus(MakeRecord(5, hashes[4])));
    // height 6 => conf = 5 < K -> rejected
    BOOST_CHECK(!IsBtcBurnStillValidConsensus(MakeRecord(6, hashes[5])));
}

// A burn whose recorded block hash no longer matches the active chain at that
// height (i.e. reorged out) must be rejected — the core R2/R4 protection.
BOOST_AUTO_TEST_CASE(burn_rejected_when_block_reorged_out)
{
    auto hashes = SeedChain(10);
    // Deep enough (height 3 => conf 8 >= 6) but wrong hash at that height.
    uint256 wrong = ArithToUint256(arith_uint256(0xDEAD));
    BOOST_CHECK(!IsBtcBurnStillValidConsensus(MakeRecord(3, wrong)));
    // Sanity: the correct hash at the same height IS accepted.
    BOOST_CHECK(IsBtcBurnStillValidConsensus(MakeRecord(3, hashes[2])));
}

// A burn referencing a height absent from the consensus DB is rejected (never
// falls back to the local btcspv).
BOOST_AUTO_TEST_CASE(burn_rejected_when_height_absent)
{
    auto hashes = SeedChain(10);
    uint256 any = ArithToUint256(arith_uint256(0xF00D));
    BOOST_CHECK(!IsBtcBurnStillValidConsensus(MakeRecord(11, any)));   // above tip
    BOOST_CHECK(!IsBtcBurnStillValidConsensus(MakeRecord(99, any)));   // far above
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// CheckBtcHeadersTx: a BTC-headers reorg may not fork at/below a FINALIZED
// (minted) burn anchor (audit R2, item #9). This is the publication-side half
// of R2 — the guard that makes K-confirmation finality real: once a burn is
// minted, the network refuses to reorg its BTC anchor away (would orphan M0,
// break A4). Asserted as an A/B on the *same* reorg tx: present vs absent FINAL
// burn, so only the R2 guard differs.
//
// REGTEST so UPGRADE_BTCHEADERS_REORG is ALWAYS_ACTIVE while the validated
// height (1) is still <= nDMMBootstrapHeight (2): that makes the reorg path
// active AND skips the MN/signature checks (bootstrap), letting the test reach
// the guard without a registered masternode or a signed payload.
// ===========================================================================

namespace {

struct BtcHeadersCheckSetup : public BasicTestingSetup {
    BtcHeadersCheckSetup() : BasicTestingSetup(CBaseChainParams::REGTEST)
    {
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
        g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, true, true);
    }
    ~BtcHeadersCheckSetup()
    {
        g_btcheadersdb.reset();
        g_btc_spv.reset();
        g_burnclaimdb.reset();
    }
};

// Seed an active header chain at heights [1..n] via the real connect path so
// per-height chainwork is populated (the reorg work-check reads it). Returns
// the active hashes (index i -> height i+1).
std::vector<uint256> SeedActiveChainViaConnect(uint32_t n)
{
    std::vector<BtcBlockHeader> hdrs;
    std::vector<uint256> hashes;
    uint256 prev = ArithToUint256(arith_uint256(0xA11CE));
    for (uint32_t h = 1; h <= n; ++h) {
        BtcBlockHeader hd = MakeHeader(prev, 1000 + h, 5000 + h);
        hdrs.push_back(hd);
        prev = hd.GetHash();
        hashes.push_back(prev);
    }
    auto tx = MakeHeadersTx(1, hdrs);
    auto batch = g_btcheadersdb->CreateBatch();
    BOOST_REQUIRE(ProcessBtcHeadersTxInBlock(*tx, batch, 1));   // regtest -> V2 path
    BOOST_REQUIRE(batch.Commit());
    return hashes;
}

// A shorter, lighter branch forking from height 3 (parent = active hash@3),
// i.e. startHeight 4 — below where the FINAL burn anchor sits in test A.
CTransactionRef MakeReorgTxFromHeight4(const std::vector<uint256>& active)
{
    BtcBlockHeader r4 = MakeHeader(active[2], 7004, 9004);   // prev = active hash@3
    BtcBlockHeader r5 = MakeHeader(r4.GetHash(), 7005, 9005);
    return MakeHeadersTx(4, {r4, r5});
}

} // namespace

// ===========================================================================
// R6: M0BTC supply must accumulate across multiple Increment/Decrement calls
// within ONE batch. ConnectMintM0BTC mints every claim of a multi-claim
// TX_MINT_M0BTC in a single batch (burnclaim.cpp ConnectMintM0BTC loop), so a
// per-call re-read of the committed total dropped all but the last write.
// These would fail before the in-batch-delta fix (e.g. report 400 not 3900).
// ===========================================================================
BOOST_FIXTURE_TEST_SUITE(burnclaim_supply_batch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(multi_claim_mint_accumulates_supply)
{
    CBurnClaimDB db(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    BOOST_CHECK_EQUAL(db.GetM0BTCSupply(), 0u);
    {
        auto b = db.CreateBatch();
        b.IncrementM0BTCSupply(1000);
        b.IncrementM0BTCSupply(2500);
        b.IncrementM0BTCSupply(400);
        BOOST_REQUIRE(b.Commit());
    }
    BOOST_CHECK_EQUAL(db.GetM0BTCSupply(), 3900u);   // pre-fix: 400 (last write wins)
}

BOOST_AUTO_TEST_CASE(multi_claim_disconnect_decrements_supply)
{
    CBurnClaimDB db(1 << 20, true, true);
    { auto b = db.CreateBatch(); b.IncrementM0BTCSupply(5000); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK_EQUAL(db.GetM0BTCSupply(), 5000u);
    {
        auto b = db.CreateBatch();
        b.DecrementM0BTCSupply(1000);
        b.DecrementM0BTCSupply(1500);
        BOOST_REQUIRE(b.Commit());
    }
    BOOST_CHECK_EQUAL(db.GetM0BTCSupply(), 2500u);   // pre-fix: 3500
}

// Mixed within a batch composes, and the total is floored at 0.
BOOST_AUTO_TEST_CASE(in_batch_delta_floors_at_zero)
{
    CBurnClaimDB db(1 << 20, true, true);
    {
        auto b = db.CreateBatch();
        b.IncrementM0BTCSupply(1000);
        b.DecrementM0BTCSupply(3000);
        BOOST_REQUIRE(b.Commit());
    }
    BOOST_CHECK_EQUAL(db.GetM0BTCSupply(), 0u);       // 0 + 1000 - 3000 -> floored
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// R8 / SPV-audit defense-in-depth: at most one TX_BTC_HEADERS per block. The
// guard lives in CheckBlock (validation.cpp, "bad-block-multiple-btcheaders");
// it had no coverage. Built as a bare block (coinbase + N header txs) checked
// with POW/merkle/sig off so the structural count is reached directly.
// ===========================================================================
namespace {

CTransactionRef MakeCoinbase()
{
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();              // IsCoinBase: 1 input, null prevout
    cb.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    cb.vout.resize(1);
    cb.vout[0].nValue = 0;
    cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return MakeTransactionRef(std::move(cb));
}

// Build a TX_BTC_HEADERS with an explicit publisher: non-null = "published" (MN),
// null = genesis/bootstrap seed tx (R8-exempt).
CTransactionRef MakeHeaderTxPub(uint32_t startHeight, const BtcBlockHeader& h, bool published)
{
    BtcHeadersPayload p;
    p.nVersion = BtcHeadersPayload::CURRENT_VERSION;
    p.publisherProTxHash = published ? ArithToUint256(arith_uint256(0xABCDEF)) : uint256();
    p.startHeight = startHeight;
    p.count = 1;
    p.headers = {h};
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;
    SetTxPayload(mtx, p);
    return MakeTransactionRef(std::move(mtx));
}

CBlock MakeBlockWithHeaderTxs(int nHeaderTxs, bool published)
{
    CBlock block;
    block.vtx.push_back(MakeCoinbase());
    const uint256 prev = ArithToUint256(arith_uint256(0x5151));
    for (int i = 0; i < nHeaderTxs; ++i) {
        BtcBlockHeader h = MakeHeader(prev, 3000 + i, 8000 + i);
        block.vtx.push_back(MakeHeaderTxPub(500 + i, h, published));   // distinct txs
    }
    return block;
}

} // namespace

// ===========================================================================
// P1 mempool replacement (multi-publisher robustness, audit P1 hardening):
// BtcHeadersCandidateReplaces — a candidate may evict the single-slot mempool
// incumbent only if it reaches a STRICTLY higher resulting tip. Pure function,
// so tested directly. Every candidate is assumed already CheckBtcHeadersTx-valid.
// ===========================================================================
// ===========================================================================
// Genesis checkpoint header integrity (hardening #1): the hardcoded full header
// of the SPV genesis checkpoint MUST hash to the checkpoint hash — it is the
// difficulty anchor for the first seeded BTC header. A wrong literal aborts the
// node at init (self-check in CBtcSPV::Init); this pins the values so a typo is
// caught in CI too. (The signet header literals were previously mistranscribed.)
// ===========================================================================
BOOST_AUTO_TEST_SUITE(btcspv_genesis_header_tests)

BOOST_AUTO_TEST_CASE(signet_genesis_header_hashes_to_checkpoint)
{
    BtcBlockHeader h;
    BOOST_REQUIRE(GetBtcSignetGenesisHeader(h));
    BOOST_CHECK_EQUAL(h.GetHash().GetHex(),
        "0000000732c0c78558a50be0774d99188f65ee374e10ff9816deaf42df9f7780");
}

BOOST_AUTO_TEST_CASE(mainnet_genesis_header_hashes_to_checkpoint)
{
    BtcBlockHeader h;
    BOOST_REQUIRE(GetBtcMainnetGenesisHeader(h));
    BOOST_CHECK_EQUAL(h.GetHash().GetHex(),
        "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(btcheaders_p1_replacement_tests)

BOOST_AUTO_TEST_CASE(more_headers_same_start_replaces)
{
    // start 100: incumbent reaches 149, candidate reaches 159 -> replaces.
    BOOST_CHECK(BtcHeadersCandidateReplaces(100, 60, 100, 50));
}

BOOST_AUTO_TEST_CASE(fewer_headers_same_start_does_not_replace)
{
    BOOST_CHECK(!BtcHeadersCandidateReplaces(100, 40, 100, 50));
}

BOOST_AUTO_TEST_CASE(equal_tip_does_not_replace)
{
    // Same resulting tip (149) -> no replacement, no txid-grind churn.
    BOOST_CHECK(!BtcHeadersCandidateReplaces(100, 50, 100, 50));
    // Different start/count but identical resulting tip (149) -> still no replace.
    BOOST_CHECK(!BtcHeadersCandidateReplaces(120, 30, 100, 50));
}

BOOST_AUTO_TEST_CASE(higher_tip_with_fewer_headers_replaces)
{
    // Candidate has fewer headers (45 < 50) but starts higher and reaches a
    // strictly higher tip (154 > 149): raw-count logic would wrongly reject it;
    // tip-based logic correctly prefers it.
    BOOST_CHECK(BtcHeadersCandidateReplaces(110, 45, 100, 50));
}

BOOST_AUTO_TEST_CASE(reorg_publication_reaching_higher_tip_replaces)
{
    // A reorg publication starting BELOW the incumbent's start but extending
    // further (fork at 90, 65 headers -> tip 154) beats incumbent tip 149.
    BOOST_CHECK(BtcHeadersCandidateReplaces(90, 65, 100, 50));
    // Same reorg start but not reaching higher (fork at 90, 60 -> tip 149) ties.
    BOOST_CHECK(!BtcHeadersCandidateReplaces(90, 60, 100, 50));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(btcheaders_block_guard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_published_btcheaders_txs_in_block_rejected)
{
    CBlock block = MakeBlockWithHeaderTxs(2, /*published=*/true);
    LOCK(cs_main);
    CValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, /*POW=*/false, /*merkle=*/false, /*sig=*/false));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-block-multiple-btcheaders");
}

BOOST_AUTO_TEST_CASE(one_published_btcheaders_tx_passes_the_guard)
{
    CBlock block = MakeBlockWithHeaderTxs(1, /*published=*/true);
    LOCK(cs_main);
    CValidationState state;
    CheckBlock(block, state, false, false, false);
    BOOST_CHECK(state.GetRejectReason() != "bad-block-multiple-btcheaders");
}

// The genesis seed splits the BTC header history into MANY null-publisher
// TX_BTC_HEADERS in block 1 — these are exempt from the per-block cap.
BOOST_AUTO_TEST_CASE(many_genesis_btcheaders_txs_allowed)
{
    CBlock block = MakeBlockWithHeaderTxs(5, /*published=*/false);
    LOCK(cs_main);
    CValidationState state;
    CheckBlock(block, state, false, false, false);
    BOOST_CHECK(state.GetRejectReason() != "bad-block-multiple-btcheaders");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(btcheaders_check_finalized_burn_tests, BtcHeadersCheckSetup)

// With a FINAL burn anchored at height 5, a reorg forking at height 4 (<= 5)
// is rejected with the dedicated R2 code.
BOOST_AUTO_TEST_CASE(reorg_below_finalized_burn_rejected)
{
    auto active = SeedActiveChainViaConnect(10);

    BurnClaimRecord fin = MakeRecord(5, active[4]);      // anchor = active hash@5
    fin.status = BurnClaimStatus::FINAL;
    fin.finalHeight = 1;
    BOOST_REQUIRE(g_burnclaimdb->StoreBurnClaim(fin));
    BOOST_REQUIRE_EQUAL(GetHighestFinalizedBtcHeight(), 5u);

    auto reorgTx = MakeReorgTxFromHeight4(active);
    CBlockIndex idx;
    idx.nHeight = 1;
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*reorgTx, &idx, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-reorg-below-finalized-burn");
}

// A9 (F5 checkpoint floor): with an SPV checkpoint pinned at height 5, a reorg
// forking at height 4 (startHeight 4 <= 5) is rejected — no SPV reorg may rewrite
// BTC history at/below a pinned checkpoint, so every burn anchored there stays
// backed. This is the sibling of the finalized-burn floor above and the literal
// "btc checkpoint" half of invariant A9.
BOOST_AUTO_TEST_CASE(reorg_below_checkpoint_rejected)
{
    auto active = SeedActiveChainViaConnect(10);
    g_btc_spv->AddCheckpointForTest(5, active[4]);      // pin SPV checkpoint @ height 5
    BOOST_REQUIRE_EQUAL(g_btc_spv->HighestCheckpointHeight(), 5u);

    auto reorgTx = MakeReorgTxFromHeight4(active);        // startHeight 4 <= 5
    CBlockIndex idx;
    idx.nHeight = 1;
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*reorgTx, &idx, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-reorg-below-checkpoint");
}

// Control: with the checkpoint pinned BELOW the fork (@ height 3), the floor is
// inert (4 > 3) and validation proceeds past it (here failing the heavier-work
// check) — proving the rejection above is the checkpoint guard, not the fixture.
BOOST_AUTO_TEST_CASE(reorg_above_checkpoint_passes_the_floor)
{
    auto active = SeedActiveChainViaConnect(10);
    g_btc_spv->AddCheckpointForTest(3, active[2]);      // pin SPV checkpoint @ height 3

    auto reorgTx = MakeReorgTxFromHeight4(active);        // startHeight 4 > 3
    CBlockIndex idx;
    idx.nHeight = 1;
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*reorgTx, &idx, state));
    BOOST_CHECK(state.GetRejectReason() != "bad-btcheaders-reorg-below-checkpoint");
}

// Same reorg tx, but with no FINAL burn: the R2 guard is inert (finalFloor == 0)
// and validation proceeds past it (here failing the heavier-branch work check),
// proving the rejection above is the FINAL-burn guard and not an artefact.
BOOST_AUTO_TEST_CASE(reorg_passes_finalized_guard_when_no_final_burn)
{
    auto active = SeedActiveChainViaConnect(10);
    BOOST_REQUIRE_EQUAL(GetHighestFinalizedBtcHeight(), 0u);

    auto reorgTx = MakeReorgTxFromHeight4(active);
    CBlockIndex idx;
    idx.nHeight = 1;
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*reorgTx, &idx, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-not-heavier");
}

// #3: a TX_BTC_HEADERS re-stating headers already on the active chain (full
// match) is rejected as a duplicate (would clobber the undo / move the tip back).
BOOST_AUTO_TEST_CASE(duplicate_btcheaders_rejected)
{
    std::vector<BtcBlockHeader> hdrs;
    uint256 prev = ArithToUint256(arith_uint256(0xD00D));
    for (uint32_t hh = 1; hh <= 6; ++hh) {
        BtcBlockHeader hd = MakeHeader(prev, 2000 + hh, 6000 + hh);
        hdrs.push_back(hd); prev = hd.GetHash();
    }
    auto tx = MakeHeadersTx(1, hdrs);
    { auto b = g_btcheadersdb->CreateBatch();
      BOOST_REQUIRE(ProcessBtcHeadersTxInBlock(*tx, b, 1)); BOOST_REQUIRE(b.Commit()); }

    CBlockIndex idx; idx.nHeight = 1;
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*tx, &idx, state));          // re-submit the same tx
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-duplicate");
}

// #5: a tx whose headers[0] matches the active chain but whose tail DIFFERS is
// NOT treated as a replay — it must run R3' (here failing the heavier check),
// proving the old headers[0]-only shortcut no longer lets a tail overwrite skip work.
BOOST_AUTO_TEST_CASE(partial_match_runs_reorg_path_not_skipped)
{
    std::vector<BtcBlockHeader> hdrs;
    uint256 prev = ArithToUint256(arith_uint256(0xC0DE));
    for (uint32_t hh = 1; hh <= 6; ++hh) {
        BtcBlockHeader hd = MakeHeader(prev, 2000 + hh, 6000 + hh);
        hdrs.push_back(hd); prev = hd.GetHash();
    }
    auto tx = MakeHeadersTx(1, hdrs);
    { auto b = g_btcheadersdb->CreateBatch();
      BOOST_REQUIRE(ProcessBtcHeadersTxInBlock(*tx, b, 1)); BOOST_REQUIRE(b.Commit()); }

    BtcBlockHeader h3 = hdrs[2];                                   // == active@3
    BtcBlockHeader h4b = MakeHeader(h3.GetHash(), 9001, 9001);     // differs from active@4
    auto reorgTx = MakeHeadersTx(3, {h3, h4b});

    CBlockIndex idx; idx.nHeight = 1;
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*reorgTx, &idx, state));
    BOOST_CHECK(state.GetRejectReason() != "bad-btcheaders-duplicate");   // not a replay
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-not-heavier"); // reached R3'
}

// cross-cutting-3: the burnclaim DB writes its best block on every connected
// block, so a startup best-block mismatch is a genuine inconsistency and must
// require a rebuild (previously it only logged a warning and started anyway).
BOOST_AUTO_TEST_CASE(burnclaim_db_mismatch_requires_rebuild)
{
    const uint256 tip   = ArithToUint256(arith_uint256(0xC0FFEE));
    const uint256 other = ArithToUint256(arith_uint256(0xBADBAD));

    // Empty DB: consistent, no rebuild.
    bool rebuild = true;
    BOOST_CHECK(CheckBurnClaimDBConsistency(tip, rebuild));
    BOOST_CHECK(!rebuild);

    // DB best block == chain tip: consistent.
    g_burnclaimdb->WriteBestBlock(tip);
    rebuild = true;
    BOOST_CHECK(CheckBurnClaimDBConsistency(tip, rebuild));
    BOOST_CHECK(!rebuild);

    // DB best block != chain tip: inconsistent -> must require rebuild.
    g_burnclaimdb->WriteBestBlock(other);
    rebuild = false;
    BOOST_CHECK(!CheckBurnClaimDBConsistency(tip, rebuild));
    BOOST_CHECK(rebuild);
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// A9 — canonical-chain (halving-boundary) checkpoints. VerifyCanonicalChain
// (BP12) is the code-level home of the documented invariant
// `A9: btc_supply(checkpoint) == expected_supply`: at each halving height the
// SPV header MUST match a hardcoded hash, so BATHRON only ever tracks THE
// Bitcoin chain (with the real supply schedule), never a fork. Enforced in the
// SPV header-accept path (INVALID_CHECKPOINT on mismatch). This is a pure free
// function over the static per-network tables — no fixture / DB needed.
// (Note: the code names these tables "A7" (BP12); that name is overloaded with
// the settlement 21M-cap A7 — the DOC invariant is A9. See doc reconciliation.)
// ===========================================================================
BOOST_FIXTURE_TEST_SUITE(a9_canonical_chain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matching_hash_at_checkpoint_passes)
{
    const auto& cps = GetA7SignetCheckpoints();
    BOOST_REQUIRE(!cps.empty());
    // The exact hardcoded hash at the exact checkpoint height is accepted.
    BOOST_CHECK(VerifyCanonicalChain(cps[0].height, cps[0].expectedHash, /*testnet=*/true));
}

BOOST_AUTO_TEST_CASE(wrong_hash_at_checkpoint_rejected)
{
    const auto& cps = GetA7SignetCheckpoints();
    BOOST_REQUIRE(!cps.empty());
    // A DIFFERENT chain (fork) at the checkpoint height is rejected — this is the
    // "only THE Bitcoin chain" guarantee that A9 encodes.
    const uint256 forged = ArithToUint256(arith_uint256(0xDEADBEEF));
    BOOST_CHECK(forged != cps[0].expectedHash);
    BOOST_CHECK(!VerifyCanonicalChain(cps[0].height, forged, /*testnet=*/true));
}

BOOST_AUTO_TEST_CASE(non_checkpoint_height_is_unconstrained)
{
    const auto& cps = GetA7SignetCheckpoints();
    BOOST_REQUIRE(!cps.empty());
    // Off a checkpoint height, ANY hash passes (checkpoints bind only at their
    // exact heights, never retroactively — matches the header comment).
    const uint256 any = ArithToUint256(arith_uint256(0x1234));
    BOOST_CHECK(VerifyCanonicalChain(cps[0].height + 1, any, /*testnet=*/true));
    BOOST_CHECK(VerifyCanonicalChain(cps[0].height - 1, any, /*testnet=*/true));
}

BOOST_AUTO_TEST_CASE(mainnet_halving_anchors_bind)
{
    const auto& cps = GetA7MainnetCheckpoints();
    BOOST_REQUIRE(!cps.empty());
    // Mainnet pins the four halving boundaries (210k/420k/630k/840k). Each binds:
    // correct hash passes, a forged one at the same height is rejected.
    const uint256 forged = ArithToUint256(arith_uint256(0xB16B00B5));
    for (const auto& cp : cps) {
        BOOST_CHECK(VerifyCanonicalChain(cp.height, cp.expectedHash, /*testnet=*/false));
        BOOST_CHECK(!VerifyCanonicalChain(cp.height, forged, /*testnet=*/false));
    }
}

BOOST_AUTO_TEST_SUITE_END()
