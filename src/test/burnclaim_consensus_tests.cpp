// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * CheckBurnClaim + CheckMintM0BTC consensus tests (test-plan B1/B2).
 *
 * These two functions ARE the M0-creation surface that guards invariant A5
 * (all M0 comes from SPV-verified BTC burns). Before this file they had no
 * real unit coverage — burnclaim_spv_tests.cpp only asserted constants, and
 * CheckMintM0BTC had no test at all. Here we drive both against in-memory
 * consensus DBs (btcheadersdb + btcspv + burnclaimdb) with a real raw BTC
 * burn tx, its txid as the single-tx merkle root, and exercise the happy path
 * plus every reject code.
 *
 * Fixture pattern (in-memory DBs) mirrors btcheaders_reorg_tests.cpp.
 */

#include "burnclaim/burnclaim.h"
#include "burnclaim/burnclaimdb.h"
#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_bathron.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

namespace {

// BCS-4 canonical burn script hash: SHA256(OP_FALSE). ParseBurnOutputs only
// accepts a P2WSH output paying exactly this hash.
const char* BURN_HASH_HEX =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

void PutLE(std::vector<uint8_t>& v, uint64_t x, int bytes)
{
    for (int i = 0; i < bytes; ++i) v.push_back((uint8_t)((x >> (8 * i)) & 0xff));
}

// v01 OP_RETURN metadata payload: "BATHRON" | 0x01 | network | dest20.
std::vector<uint8_t> MetaV1(uint8_t network, uint8_t destByte)
{
    std::vector<uint8_t> p = {'B', 'A', 'T', 'H', 'R', 'O', 'N', 0x01, network};
    p.insert(p.end(), 20, destByte);
    return p;
}

// Serialize a minimal, well-formed non-witness BTC burn tx: 1 dummy input,
// vout[0] = OP_RETURN(meta), vout[1] = P2WSH burn(sats). Returns raw bytes; the
// txid is HASH256 of exactly these bytes (no witness).
std::vector<uint8_t> MakeRawBurnTx(const std::vector<uint8_t>& meta, int64_t sats)
{
    std::vector<uint8_t> tx;
    PutLE(tx, 2, 4);                                   // version
    tx.push_back(0x01);                                // vin count
    tx.insert(tx.end(), 32, 0x11);                     // prevout hash
    PutLE(tx, 0, 4);                                   // prevout n
    tx.push_back(0x00);                                // scriptSig len
    PutLE(tx, 0xffffffff, 4);                          // sequence
    tx.push_back(0x02);                                // vout count
    // vout[0] OP_RETURN meta
    PutLE(tx, 0, 8);                                   // value 0
    tx.push_back((uint8_t)(2 + meta.size()));          // scriptLen
    tx.push_back(0x6a);                                // OP_RETURN
    tx.push_back((uint8_t)meta.size());                // push len
    tx.insert(tx.end(), meta.begin(), meta.end());
    // vout[1] P2WSH burn
    PutLE(tx, (uint64_t)sats, 8);                      // value
    tx.push_back(0x22);                                // scriptLen = 34
    tx.push_back(0x00); tx.push_back(0x20);            // OP_0 PUSH32
    std::vector<uint8_t> bh = ParseHex(BURN_HASH_HEX);
    tx.insert(tx.end(), bh.begin(), bh.end());
    PutLE(tx, 0, 4);                                   // locktime
    return tx;
}

uint256 TxidOf(const std::vector<uint8_t>& rawTx)
{
    BtcParsedTx parsed;
    BOOST_REQUIRE(ParseBtcTransaction(rawTx, parsed));
    return ComputeBtcTxid(parsed);
}

// Write an active header at `height` whose merkle root == `merkleRoot`, so a
// single-tx block's txid==merkleRoot verifies with an empty proof. Returns the
// header hash (== payload.btcBlockHash).
uint256 SeedHeader(uint32_t height, const uint256& merkleRoot)
{
    BtcBlockHeader hdr;
    hdr.nVersion = 4;
    hdr.hashPrevBlock = ArithToUint256(arith_uint256(0xBEEF) + height);
    hdr.hashMerkleRoot = merkleRoot;
    hdr.nTime = 1000 + height;
    hdr.nBits = 0x1d00ffff;
    hdr.nNonce = height;
    uint256 hash = hdr.GetHash();
    auto batch = g_btcheadersdb->CreateBatch();
    batch.WriteHeader(height, hdr);
    batch.WriteTip(height, hash);
    BOOST_REQUIRE(batch.Commit());
    return hash;
}

// A fully valid v01 claim payload against a freshly-seeded header. burnHeight is
// where the header is active; nHeight is the (unused-by-CheckBurnClaim) BATHRON
// height parameter.
BurnClaimPayload MakeValidPayload(int64_t sats, uint8_t network, uint32_t burnHeight)
{
    BurnClaimPayload p;
    p.btcTxBytes = MakeRawBurnTx(MetaV1(network, 0xAB), sats);
    uint256 txid = TxidOf(p.btcTxBytes);
    p.btcBlockHash = SeedHeader(burnHeight, txid);   // merkle root = txid (single tx)
    p.btcBlockHeight = burnHeight;
    p.merkleProof = {};                              // single-tx block
    p.txIndex = 0;
    return p;
}

std::string Reject(CValidationState& s) { return s.GetRejectReason(); }

} // namespace

// =============================================================================
// B1 — CheckBurnClaim
// =============================================================================

struct BurnClaimSetup : public BasicTestingSetup {
    BurnClaimSetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
        g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, true, true);
    }
    ~BurnClaimSetup()
    {
        g_btcheadersdb.reset();
        g_btc_spv.reset();
        g_burnclaimdb.reset();
    }
};

BOOST_FIXTURE_TEST_SUITE(check_burnclaim_consensus_tests, BurnClaimSetup)

BOOST_AUTO_TEST_CASE(valid_claim_accepted)
{
    BurnClaimPayload p = MakeValidPayload(100000, 0x01, 300000);
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckBurnClaim(p, state, 400000), Reject(state));
}

BOOST_AUTO_TEST_CASE(parse_failed_rejected)
{
    BurnClaimPayload p = MakeValidPayload(100000, 0x01, 300000);
    p.btcTxBytes = {0x00, 0x01, 0x02};                 // garbage, not a BTC tx
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-parse-failed");
}

BOOST_AUTO_TEST_CASE(header_missing_rejected)
{
    // Build a valid tx but point at a block hash that was never written.
    BurnClaimPayload p;
    p.btcTxBytes = MakeRawBurnTx(MetaV1(0x01, 0xAB), 100000);
    p.btcBlockHash = ArithToUint256(arith_uint256(0xDEAD));   // absent
    p.btcBlockHeight = 300000;
    p.merkleProof = {};
    p.txIndex = 0;
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burnclaim-btc-header-missing");
}

BOOST_AUTO_TEST_CASE(block_not_best_rejected)
{
    // Header exists at 300000 but the claim states a different height, so
    // GetHashAtHeight(claimedHeight) != btcBlockHash (reorg-demotion guard).
    BurnClaimPayload p = MakeValidPayload(100000, 0x01, 300000);
    p.btcBlockHeight = 300001;                          // wrong height for this hash
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-block-not-best");
}

BOOST_AUTO_TEST_CASE(merkle_invalid_rejected)
{
    // Seed the header with a merkle root that is NOT the tx's txid.
    BurnClaimPayload p;
    p.btcTxBytes = MakeRawBurnTx(MetaV1(0x01, 0xAB), 100000);
    uint256 wrongRoot = ArithToUint256(arith_uint256(0xC0FFEE));
    p.btcBlockHash = SeedHeader(300000, wrongRoot);
    p.btcBlockHeight = 300000;
    p.merkleProof = {};
    p.txIndex = 0;
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-merkle-invalid");
}

BOOST_AUTO_TEST_CASE(duplicate_rejected)
{
    BurnClaimPayload p = MakeValidPayload(100000, 0x01, 300000);
    uint256 txid = TxidOf(p.btcTxBytes);
    // Pre-store a FINAL claim with the same btc txid -> anti-replay trips
    // (FINAL is immutable and always blocks; PENDING would need a matching
    // active header to block, tested implicitly by the valid path).
    BurnClaimRecord rec;
    rec.btcTxid = txid;
    rec.status = BurnClaimStatus::FINAL;
    auto batch = g_burnclaimdb->CreateBatch();
    batch.StoreBurnClaim(rec);
    BOOST_REQUIRE(batch.Commit());
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-duplicate");
}

BOOST_AUTO_TEST_CASE(format_invalid_rejected)
{
    // A tx with the BATHRON OP_RETURN but NO P2WSH burn output (wrong burn hash).
    std::vector<uint8_t> tx;
    PutLE(tx, 2, 4); tx.push_back(0x01);
    tx.insert(tx.end(), 32, 0x11); PutLE(tx, 0, 4); tx.push_back(0x00); PutLE(tx, 0xffffffff, 4);
    tx.push_back(0x02);
    std::vector<uint8_t> meta = MetaV1(0x01, 0xAB);
    PutLE(tx, 0, 8); tx.push_back((uint8_t)(2 + meta.size()));
    tx.push_back(0x6a); tx.push_back((uint8_t)meta.size());
    tx.insert(tx.end(), meta.begin(), meta.end());
    // burn output pays a P2WSH to the WRONG hash (all 0xAA)
    PutLE(tx, 100000, 8); tx.push_back(0x22); tx.push_back(0x00); tx.push_back(0x20);
    tx.insert(tx.end(), 32, 0xAA);
    PutLE(tx, 0, 4);

    BurnClaimPayload p;
    p.btcTxBytes = tx;
    uint256 txid = TxidOf(p.btcTxBytes);
    p.btcBlockHash = SeedHeader(300000, txid);
    p.btcBlockHeight = 300000;
    p.merkleProof = {};
    p.txIndex = 0;
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-format-invalid");
}

BOOST_AUTO_TEST_CASE(dust_rejected)
{
    // Below MIN_BURN_SATS (1000) but a well-formed burn.
    BurnClaimPayload p = MakeValidPayload(500, 0x01, 300000);
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-amount-dust");
}

BOOST_AUTO_TEST_CASE(network_mismatch_rejected)
{
    // Mainnet network byte (0x00) on a testnet chain.
    BurnClaimPayload p = MakeValidPayload(100000, 0x00, 300000);
    CValidationState state;
    BOOST_CHECK(!CheckBurnClaim(p, state, 400000));
    BOOST_CHECK_EQUAL(Reject(state), "burn-claim-network-mismatch");
}

BOOST_AUTO_TEST_SUITE_END()

// =============================================================================
// B2 — CheckMintM0BTC (strict equality: dest, value, order, K, state)
// =============================================================================

namespace {

// Seed an active header chain [1..n] (WriteHeader+WriteTip), return the hashes.
std::vector<uint256> SeedChainLocal(uint32_t n)
{
    std::vector<uint256> hashes;
    auto batch = g_btcheadersdb->CreateBatch();
    uint256 prev = ArithToUint256(arith_uint256(0xBEEF));
    for (uint32_t h = 1; h <= n; ++h) {
        BtcBlockHeader hdr;
        hdr.nVersion = 4;
        hdr.hashPrevBlock = prev;
        hdr.hashMerkleRoot = ArithToUint256(arith_uint256(h) + 1);
        hdr.nTime = 1000 + h;
        hdr.nBits = 0x1d00ffff;
        hdr.nNonce = h;
        uint256 hash = hdr.GetHash();
        batch.WriteHeader(h, hdr);
        prev = hash;
        hashes.push_back(hash);
    }
    batch.WriteTip(n, hashes.back());
    BOOST_REQUIRE(batch.Commit());
    return hashes;
}

// A PENDING claim record deep enough to be K-confirmations valid on a 10-block
// seeded chain (btcHeight 5 -> 6 confs == K_CONFIRMATIONS testnet).
BurnClaimRecord StoredClaim(const uint256& txid, const uint256& btcBlockHash,
                            uint32_t btcHeight, uint64_t sats, uint8_t destType,
                            uint32_t claimHeight)
{
    BurnClaimRecord r;
    r.btcTxid = txid;
    r.btcBlockHash = btcBlockHash;
    r.btcHeight = btcHeight;
    r.burnedSats = sats;
    std::fill(r.bathronDest.begin(), r.bathronDest.end(), 0x42);
    r.destType = destType;
    r.claimHeight = claimHeight;
    r.finalHeight = 0;
    r.status = BurnClaimStatus::PENDING;
    auto batch = g_burnclaimdb->CreateBatch();
    batch.StoreBurnClaim(r);
    BOOST_REQUIRE(batch.Commit());
    return r;
}

// Build a TX_MINT_M0BTC whose payload references `txids` (already sorted) and
// whose vout[i] pays the mint dest/value of `records[i]`. Overridable to inject
// faults.
CTransactionRef MakeMintTx(const std::vector<uint256>& txids,
                           const std::vector<BurnClaimRecord>& records,
                           bool emptyVin = true)
{
    MintPayload p;
    p.nVersion = MINT_PAYLOAD_VERSION;
    p.btcTxids = txids;

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;
    if (!emptyVin) {
        mtx.vin.emplace_back();
    }
    for (const auto& r : records) {
        mtx.vout.emplace_back((CAmount)r.burnedSats, GetMintDestScript(r));
    }
    SetTxPayload(mtx, p);
    return MakeTransactionRef(std::move(mtx));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(check_mint_m0btc_tests, BurnClaimSetup)

BOOST_AUTO_TEST_CASE(valid_mint_accepted)
{
    auto hashes = SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));
    BurnClaimRecord r = StoredClaim(txid, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    auto tx = MakeMintTx({txid}, {r});
    CValidationState state;
    // claimHeight 0 + K(20) = 20; blockHeight 21 > 20 -> valid
    BOOST_CHECK_MESSAGE(CheckMintM0BTC(*tx, state, 21), Reject(state));
}

BOOST_AUTO_TEST_CASE(has_inputs_rejected)
{
    auto hashes = SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));
    BurnClaimRecord r = StoredClaim(txid, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    auto tx = MakeMintTx({txid}, {r}, /*emptyVin=*/false);
    CValidationState state;
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 21));
    BOOST_CHECK_EQUAL(Reject(state), "mint-has-inputs");
}

BOOST_AUTO_TEST_CASE(output_count_mismatch_rejected)
{
    auto hashes = SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));
    BurnClaimRecord r = StoredClaim(txid, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    // payload lists 1 txid but the tx carries 2 outputs.
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;
    mtx.vout.emplace_back((CAmount)r.burnedSats, GetMintDestScript(r));
    mtx.vout.emplace_back((CAmount)r.burnedSats, GetMintDestScript(r));
    MintPayload p; p.btcTxids = {txid};
    SetTxPayload(mtx, p);
    auto tx = MakeTransactionRef(std::move(mtx));
    CValidationState state;
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 21));
    BOOST_CHECK_EQUAL(Reject(state), "mint-output-count");
}

BOOST_AUTO_TEST_CASE(unknown_claim_rejected)
{
    SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));   // never stored
    BurnClaimRecord r;
    r.btcTxid = txid; r.burnedSats = 100000; r.destType = BURN_DEST_P2PKH;
    std::fill(r.bathronDest.begin(), r.bathronDest.end(), 0x42);
    auto tx = MakeMintTx({txid}, {r});
    CValidationState state;
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 21));
    BOOST_CHECK_EQUAL(Reject(state), "mint-unknown-claim");
}

BOOST_AUTO_TEST_CASE(too_early_off_by_one_rejected)
{
    auto hashes = SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));
    BurnClaimRecord r = StoredClaim(txid, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    auto tx = MakeMintTx({txid}, {r});
    CValidationState state;
    // blockHeight 20 == claimHeight(0)+K(20) -> NOT strictly greater -> too early
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 20));
    BOOST_CHECK_EQUAL(Reject(state), "mint-claim-too-early");
}

BOOST_AUTO_TEST_CASE(dest_mismatch_rejected)
{
    auto hashes = SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));
    // Stored as P2PKH, but the mint tx pays the P2SH form (producer/validator
    // divergence on destination wrapping).
    BurnClaimRecord r = StoredClaim(txid, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    BurnClaimRecord asP2sh = r; asP2sh.destType = BURN_DEST_P2SH;
    auto tx = MakeMintTx({txid}, {asP2sh});
    CValidationState state;
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 21));
    BOOST_CHECK_EQUAL(Reject(state), "mint-dest-mismatch");
}

BOOST_AUTO_TEST_CASE(amount_mismatch_rejected)
{
    auto hashes = SeedChainLocal(10);
    uint256 txid = ArithToUint256(arith_uint256(0xABCD));
    BurnClaimRecord r = StoredClaim(txid, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    // Mint one satoshi more than burned (breaks 1:1 -> would inflate M0).
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;
    mtx.vout.emplace_back((CAmount)r.burnedSats + 1, GetMintDestScript(r));
    MintPayload p; p.btcTxids = {txid};
    SetTxPayload(mtx, p);
    auto tx = MakeTransactionRef(std::move(mtx));
    CValidationState state;
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 21));
    BOOST_CHECK_EQUAL(Reject(state), "mint-amount-mismatch");
}

BOOST_AUTO_TEST_CASE(out_of_order_rejected)
{
    auto hashes = SeedChainLocal(10);
    // Two claims fed in DESCENDING uint256 order. Canonical ordering is enforced
    // FIRST by MintPayload::IsTriviallyValid ("mint-payload-invalid"), so the
    // later std::is_sorted "mint-not-sorted" branch is defense-in-depth (never
    // reached here). Either way, an out-of-order mint is rejected — the property
    // we care about (determinism of the mint set).
    // uint256 operator< is byte-order, not numeric, so derive lo/hi from it.
    uint256 a = ArithToUint256(arith_uint256(0xAAAA));
    uint256 b = ArithToUint256(arith_uint256(0xBBBB));
    uint256 lo = std::min(a, b), hi = std::max(a, b);
    BurnClaimRecord rHi = StoredClaim(hi, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    BurnClaimRecord rLo = StoredClaim(lo, hashes[4], 5, 100000, BURN_DEST_P2PKH, 0);
    auto tx = MakeMintTx({hi, lo}, {rHi, rLo});         // descending -> rejected
    CValidationState state;
    BOOST_CHECK(!CheckMintM0BTC(*tx, state, 21));
    BOOST_CHECK_EQUAL(Reject(state), "mint-payload-invalid");
}

BOOST_AUTO_TEST_SUITE_END()

// =============================================================================
// B4.6 — CheckNoDuplicateBurnClaimsInBlock (block-level dedup + BP10 cap)
// =============================================================================

namespace {

CTransactionRef MakeClaimTx(const BurnClaimPayload& p)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BURN_CLAIM;
    SetTxPayload(mtx, p);
    return MakeTransactionRef(std::move(mtx));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(burnclaim_block_dedup_tests, BurnClaimSetup)

BOOST_AUTO_TEST_CASE(distinct_claims_pass)
{
    // Two different burns (different sats -> different raw tx -> different BTC
    // txid) + a NORMAL tx in between: no duplicate, guard passes.
    std::vector<CTransactionRef> vtx;
    vtx.push_back(MakeClaimTx(MakeValidPayload(100000, 0x01, 100)));
    vtx.push_back(MakeTransactionRef(CMutableTransaction{}));  // NORMAL, ignored
    vtx.push_back(MakeClaimTx(MakeValidPayload(200000, 0x01, 101)));
    CValidationState state;
    BOOST_CHECK(CheckNoDuplicateBurnClaimsInBlock(vtx, state));
}

BOOST_AUTO_TEST_CASE(duplicate_claim_rejected)
{
    // Same embedded BTC burn in two DIFFERENT wrapper txs (txIndex differs, so
    // the BATHRON txids differ — the block-duplicate check would not catch it).
    // Dedup keys on the computed BTC txid, independent of proof validity.
    BurnClaimPayload p1 = MakeValidPayload(100000, 0x01, 100);
    BurnClaimPayload p2 = p1;
    p2.txIndex = 1;
    std::vector<CTransactionRef> vtx{MakeClaimTx(p1), MakeClaimTx(p2)};
    BOOST_REQUIRE(vtx[0]->GetHash() != vtx[1]->GetHash());
    CValidationState state;
    BOOST_CHECK(!CheckNoDuplicateBurnClaimsInBlock(vtx, state));
    BOOST_CHECK_EQUAL(Reject(state), "bad-burnclaim-duplicate-in-block");
}

BOOST_AUTO_TEST_CASE(undecodable_claim_skipped)
{
    // A claim with garbage payload is NOT this guard's job (CheckSpecialTx
    // rejects it with the precise reason) — the guard skips it and still
    // dedupes the decodable ones.
    CMutableTransaction bad;
    bad.nVersion = CTransaction::TxVersion::SAPLING;
    bad.nType = CTransaction::TxType::TX_BURN_CLAIM;
    bad.extraPayload = std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef};
    std::vector<CTransactionRef> vtx;
    vtx.push_back(MakeTransactionRef(std::move(bad)));
    vtx.push_back(MakeClaimTx(MakeValidPayload(100000, 0x01, 100)));
    CValidationState state;
    BOOST_CHECK(CheckNoDuplicateBurnClaimsInBlock(vtx, state));
}

BOOST_AUTO_TEST_CASE(claim_cap_enforced)
{
    // MAX_BURN_CLAIMS_PER_BLOCK (BP10, =50) was declared but never wired.
    // 50 distinct claims pass; the 51st rejects the block.
    std::vector<CTransactionRef> vtx;
    for (size_t i = 0; i < MAX_BURN_CLAIMS_PER_BLOCK; ++i) {
        vtx.push_back(MakeClaimTx(MakeValidPayload(100000 + (int64_t)i, 0x01, 100 + i)));
    }
    CValidationState okState;
    BOOST_CHECK(CheckNoDuplicateBurnClaimsInBlock(vtx, okState));

    vtx.push_back(MakeClaimTx(MakeValidPayload(999999, 0x01, 999)));
    CValidationState state;
    BOOST_CHECK(!CheckNoDuplicateBurnClaimsInBlock(vtx, state));
    BOOST_CHECK_EQUAL(Reject(state), "bad-burnclaim-too-many");
}

BOOST_AUTO_TEST_SUITE_END()
