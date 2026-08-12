// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// PHASE 2.6 — TESTNET4 (BIP-94) ADAPTER TESTS ON REAL HEADER VECTORS
// =============================================================================
//
// Every "real" vector below is a genuine Bitcoin Testnet4 header
// (src/test/data/btc_testnet4_headers.h — provenance in that file: fetched
// from mempool.space/testnet4, byte-identical cross-check against a locally
// synced Bitcoin Core v28.1, checkpoints confirmed on mempool.emzy.de).
//
// The embedded range around the pinned checkpoint 145152 (= 72*2016) happens
// to exercise, ON REAL DATA: the mandated 20-minute min-difficulty exception
// (gap 1201 s), the min-difficulty walk-back terminating on the boundary
// block's real nBits (145156, with a NEGATIVE 6375 s timestamp gap), and the
// BIP-94 first-block retarget reproducing 145152's exact nBits 0x190274df.
//
// Where a rule cannot be isolated with real vectors (any mutation of a real
// header breaks its PoW first), the rule is pinned through the PURE engine
// (ExpectedNextBits / CheckTimewarp) — same code the store and consensus R6
// run — with clearly-labeled synthetic inputs.
//
// Scope note (ADDENDUM PHASE 2.6): no Bitcoin transaction is created or
// broadcast anywhere in this suite. REAL TESTNET4 BURN E2E = PENDING PHASE 3;
// the synthetic-burn harness controls live in burnclaim tests and are labeled
// as harness controls, never as real burns.

#include "btcspv/btcspv.h"
#include "chainparams.h"
#include "fs.h"
#include "hash.h"
#include "streams.h"
#include "test/data/btc_testnet4_headers.h"
#include "test/test_bathron.h"
#include "utilstrencodings.h"
#include "util/system.h"
#include "uint256.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <vector>

namespace {

BtcBlockHeader ParseHeaderHex(const std::string& hex)
{
    std::vector<unsigned char> raw = ParseHex(hex);
    assert(raw.size() == 80);
    CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
    BtcBlockHeader h;
    ss >> h;
    return h;
}

//! height -> real header, for every embedded vector.
const std::map<uint32_t, BtcBlockHeader>& RealHeaders()
{
    static std::map<uint32_t, BtcBlockHeader> m;
    if (m.empty()) {
        for (size_t i = 0; i < TESTNET4_HEADERS_COUNT; i++) {
            m[TESTNET4_HEADERS[i].height] = ParseHeaderHex(TESTNET4_HEADERS[i].hex);
        }
    }
    return m;
}

//! Ancestor accessor over the real-vector map (for the pure engine).
std::function<bool(uint32_t, BtcBlockHeader&)> MapAccessor()
{
    return [](uint32_t h, BtcBlockHeader& out) {
        const auto& m = RealHeaders();
        auto it = m.find(h);
        if (it == m.end()) return false;
        out = it->second;
        return true;
    };
}

constexpr uint32_t MINDIFF = 0x1d00ffff;

struct Testnet4SpvSetup : public BasicTestingSetup {
    Testnet4SpvSetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        // Per-case on-disk datadir (same hygiene as P0AtomicitySetup): without
        // this, GetDataDir() is the process-cached path and the LevelDB store
        // leaks across test cases.
        SetDataDir("t4case");
        ClearDatadirCache();
        g_btc_spv = std::make_unique<CBtcSPV>();
        BOOST_REQUIRE(g_btc_spv->Init((GetDataDir() / "btcspv-t4").string(),
                                      BtcSourceNet::BITCOIN_TESTNET4));
    }
    ~Testnet4SpvSetup() { g_btc_spv.reset(); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(btcspv_testnet4_tests, Testnet4SpvSetup)

// -----------------------------------------------------------------------------
// D.1 — genesis and checkpoints are the exact real objects.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(genesis_and_checkpoint_vectors_are_exact)
{
    const auto& m = RealHeaders();

    // BIP-94 genesis: hash, merkle root, nTime, nBits, nNonce — from the spec.
    const BtcBlockHeader& g = m.at(0);
    BOOST_CHECK_EQUAL(g.GetHash().GetHex(),
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043");
    BOOST_CHECK(g.GetHash() == GetBtcTestnet4Params().genesisHash);
    BOOST_CHECK_EQUAL(g.hashMerkleRoot.GetHex(),
        "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e");
    BOOST_CHECK_EQUAL(g.nTime, 1714777860U);
    BOOST_CHECK_EQUAL(g.nBits, MINDIFF);
    BOOST_CHECK_EQUAL(g.nNonce, 393743547U);

    // The pinned SPV genesis checkpoint IS the real 145152 header, bit for bit.
    BtcBlockHeader pin;
    BOOST_REQUIRE(GetBtcTestnet4GenesisHeader(pin));
    const BtcBlockHeader& real = m.at(145152);
    BOOST_CHECK(pin.GetHash() == real.GetHash());
    BOOST_CHECK_EQUAL(pin.nBits, real.nBits);
    BOOST_CHECK_EQUAL(pin.nTime, real.nTime);

    // Every SPV checkpoint hash matches the real chain.
    for (const auto& cp : GetBtcTestnet4Checkpoints()) {
        auto it = m.find(cp.height);
        if (it != m.end()) {
            BOOST_CHECK(cp.hash == it->second.GetHash());
        }
    }

    // Every embedded vector self-verifies its PoW encoding (real headers are
    // mined): hash <= target for all 74 vectors.
    for (const auto& kv : m) {
        arith_uint256 target;
        target.SetCompact(kv.second.nBits);
        BOOST_CHECK_MESSAGE(UintToArith256(kv.second.GetHash()) <= target,
                            "vector at height " << kv.first << " fails its own PoW");
    }
}

// -----------------------------------------------------------------------------
// D.2 — consecutive REAL headers sync from the pin through the full store
// validation (PoW, MTP, min-difficulty schedule, walk-back, timewarp guard).
// The range 145153..145160 includes mandated min-diff blocks (gap 1201 s),
// and 145156: a NEGATIVE timestamp gap with a real-difficulty walk-back to
// the boundary block's nBits.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_consecutive_headers_sync_from_the_pin)
{
    const auto& m = RealHeaders();
    std::vector<BtcBlockHeader> batch;
    for (uint32_t h = 145153; h <= 145160; h++) batch.push_back(m.at(h));

    const arith_uint256 workBefore = g_btc_spv->GetTipChainWork();
    CBtcSPV::BatchResult res = g_btc_spv->AddHeaders(batch);
    BOOST_CHECK_EQUAL(res.accepted, 8U);
    BOOST_CHECK_MESSAGE(res.rejected == 0,
                        "first reject: " << res.firstRejectReason
                        << " hash=" << res.firstRejectHash.GetHex());
    BOOST_CHECK_EQUAL(g_btc_spv->GetTipHeight(), 145160U);
    BOOST_CHECK(g_btc_spv->GetTipHash() == m.at(145160).GetHash());
    BOOST_CHECK(g_btc_spv->GetTipChainWork() > workBefore);
    BOOST_CHECK(g_btc_spv->IsInBestChain(m.at(145156).GetHash()));
}

// -----------------------------------------------------------------------------
// D.13/D.14 — restart: the store reloads its tip from disk (the node-restart
// path; BATHRON-side disconnect/reconnect and -reindex undo live in
// btcheaders_reorg_tests on the consensus DB).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(store_survives_restart_with_real_headers)
{
    const auto& m = RealHeaders();
    std::vector<BtcBlockHeader> batch;
    for (uint32_t h = 145153; h <= 145156; h++) batch.push_back(m.at(h));
    BOOST_REQUIRE_EQUAL(g_btc_spv->AddHeaders(batch).accepted, 4U);
    BOOST_REQUIRE_EQUAL(g_btc_spv->GetTipHeight(), 145156U);
    const uint256 tip = g_btc_spv->GetTipHash();

    // Restart: fresh instance over the same datadir.
    g_btc_spv->Shutdown();
    g_btc_spv = std::make_unique<CBtcSPV>();
    BOOST_REQUIRE(g_btc_spv->Init((GetDataDir() / "btcspv-t4").string(),
                                  BtcSourceNet::BITCOIN_TESTNET4));
    BOOST_CHECK_EQUAL(g_btc_spv->GetTipHeight(), 145156U);
    BOOST_CHECK(g_btc_spv->GetTipHash() == tip);
    // And it keeps extending with real data after the restart.
    BOOST_CHECK(g_btc_spv->AddHeader(m.at(145157)) == BtcHeaderStatus::VALID);
}

// -----------------------------------------------------------------------------
// D.3 — broken hashPrevBlock chains are refused.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(prevhash_break_is_rejected)
{
    const auto& m = RealHeaders();
    // 145154 without 145153: unknown parent -> ORPHAN, tip unmoved.
    BOOST_CHECK(g_btc_spv->AddHeader(m.at(145154)) == BtcHeaderStatus::ORPHAN);
    BOOST_CHECK_EQUAL(g_btc_spv->GetTipHeight(), 145152U);

    // A real header whose prev-link is REWRITTEN to skip its parent: the hash
    // commits to hashPrevBlock, so the tampered header no longer meets its own
    // PoW — ancestry is sealed by the mining itself.
    BtcBlockHeader tampered = m.at(145154);
    tampered.hashPrevBlock = m.at(145152).GetHash();
    BOOST_CHECK(g_btc_spv->AddHeader(tampered) == BtcHeaderStatus::INVALID_POW);
}

// -----------------------------------------------------------------------------
// D.4 — invalid PoW is refused (real header, nonce off by one).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(invalid_pow_is_rejected)
{
    BtcBlockHeader bad = RealHeaders().at(145153);
    bad.nNonce += 1;
    BOOST_CHECK(g_btc_spv->AddHeader(bad) == BtcHeaderStatus::INVALID_POW);
    BOOST_CHECK_EQUAL(g_btc_spv->GetTipHeight(), 145152U);
}

// -----------------------------------------------------------------------------
// D.5/D.6 — the difficulty schedule on REAL data, through the same pure
// engine the store and consensus R6 execute:
//   * gap > 1200 s  => nBits MUST be powLimit (min-difficulty is mandatory,
//     not optional: Core enforces exact equality with GetNextWorkRequired);
//   * otherwise     => walk-back to the last non-min-difficulty block of the
//     period (here: the boundary block 145152, nBits 0x190274df) — including
//     across a NEGATIVE timestamp gap (145156).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(min_difficulty_schedule_matches_real_chain)
{
    const auto& m = RealHeaders();
    auto acc = MapAccessor();

    for (uint32_t h = 145153; h <= 145160; h++) {
        const BtcBlockHeader& parent = m.at(h - 1);
        const BtcBlockHeader& cur = m.at(h);
        uint32_t expected = g_btc_spv->ExpectedNextBits(h, parent, cur.nTime, acc);
        BOOST_CHECK_MESSAGE(expected == cur.nBits,
            "height " << h << ": engine says 0x" << std::hex << expected
                      << ", real chain has 0x" << cur.nBits);
        // And a WRONG nBits at the same height is not the expected one:
        // carrying real difficulty where min-diff is mandated (or vice versa)
        // is bad-diffbits.
        uint32_t wrong = (cur.nBits == MINDIFF) ? m.at(145152).nBits : MINDIFF;
        BOOST_CHECK(expected != wrong);
    }

    // Boundary of the 20-minute rule (review L-7a): the exception fires on
    // STRICTLY MORE than 2*600 s. At exactly 1200 s the schedule is the
    // walk-back, not powLimit — a '>' -> '>=' mutation dies here.
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145153, m.at(145152), m.at(145152).nTime + 1200, acc),
        m.at(145152).nBits);
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145153, m.at(145152), m.at(145152).nTime + 1201, acc),
        MINDIFF);

    // Spot-check the two regimes explicitly:
    // 145153: gap 1201 s > 1200 s => powLimit mandated.
    BOOST_CHECK_EQUAL(m.at(145153).nTime - m.at(145152).nTime, 1201U);
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145153, m.at(145152), m.at(145153).nTime, acc), MINDIFF);
    // 145156: negative gap => walk-back over 3 min-diff blocks to the
    // boundary's real difficulty.
    BOOST_CHECK((int64_t)m.at(145156).nTime - (int64_t)m.at(145155).nTime < 0);
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145156, m.at(145155), m.at(145156).nTime, acc),
        m.at(145152).nBits);
}

// -----------------------------------------------------------------------------
// D.7 — the BIP-94 retarget at the real boundary 145152 reproduces the real
// nBits 0x190274df exactly from the real period-first (143136) and period-last
// (145151) headers.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bip94_retarget_reproduces_real_boundary_nbits)
{
    const auto& m = RealHeaders();
    auto acc = MapAccessor();

    const uint32_t expected =
        g_btc_spv->ExpectedNextBits(145152, m.at(145151), m.at(145152).nTime, acc);
    BOOST_CHECK_EQUAL(expected, m.at(145152).nBits);
    BOOST_CHECK_EQUAL(expected, 0x190274dfU);

    // Ancestor unavailable => the engine reports "unverifiable" (0), it never
    // guesses: rerun with an accessor that hides the period-first header.
    auto blind = [](uint32_t, BtcBlockHeader&) { return false; };
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145152, m.at(145151), m.at(145152).nTime, blind), 0U);
}

// -----------------------------------------------------------------------------
// D.8a — BIP-94 timewarp bound on real data + rule isolation. (Real boundary
// satisfies it; the mutated header violates it by exactly one second past the
// 600 s allowance; off-boundary heights are exempt; and the bound is a
// Testnet4/BIP-94 rule — mainnet params don't enforce it.)
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bip94_timewarp_bound)
{
    const auto& m = RealHeaders();
    const BtcBlockHeader& parent = m.at(145151);
    BtcBlockHeader boundary = m.at(145152);

    BOOST_CHECK(g_btc_spv->CheckTimewarp(145152, boundary, parent));

    // Violation: first block of the period earlier than parent - 600 s.
    boundary.nTime = parent.nTime - 601;
    BOOST_CHECK(!g_btc_spv->CheckTimewarp(145152, boundary, parent));
    // Exactly at the bound: allowed (rule is nTime >= prev - 600).
    boundary.nTime = parent.nTime - 600;
    BOOST_CHECK(g_btc_spv->CheckTimewarp(145152, boundary, parent));
    // Off-boundary: rule does not apply.
    boundary.nTime = parent.nTime - 601;
    BOOST_CHECK(g_btc_spv->CheckTimewarp(145153, boundary, parent));
}

// -----------------------------------------------------------------------------
// D.8b — the BIP-94 retarget base is the FIRST block of the closing period.
// At the real 145152 boundary first and last happen to carry the same nBits,
// so this discriminator uses the BLOCK-STORM configuration the rule was
// designed for (SYNTHETIC INPUTS, clearly labeled): last block of the period
// is min-difficulty. Legacy (pre-BIP-94) retarget from the last block would
// start from powLimit and stay pinned there; the BIP-94 base keeps the real
// difficulty.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bip94_first_block_base_discriminates_block_storm)
{
    const auto& m = RealHeaders();

    // SYNTHETIC harness inputs (not real chain data): period-first at real
    // difficulty, period-last min-difficulty, plausible timestamps.
    BtcBlockHeader first = m.at(143136);          // real difficulty 0x190228f4
    BtcBlockHeader last;
    last.SetNull();
    last.hashMerkleRoot = uint256S("01");         // non-null
    last.nTime = first.nTime + 14 * 24 * 3600;    // exactly on-target timespan
    last.nBits = MINDIFF;                         // block-storm: min-diff last

    auto acc = [&first](uint32_t h, BtcBlockHeader& out) {
        if (h == 143136) { out = first; return true; }
        return false;
    };
    const uint32_t got = g_btc_spv->ExpectedNextBits(145152, last, last.nTime + 600, acc);

    // BIP-94: base = first.nBits, on-target timespan => nBits carried over.
    BOOST_CHECK_EQUAL(got, first.nBits);
    // The legacy base would have yielded powLimit (min-diff carried into the
    // next period — the very block-storm bug BIP-94 fixes).
    BOOST_CHECK(got != MINDIFF);
}

// -----------------------------------------------------------------------------
// D.9 — chain selection by cumulative work: on real data every extension
// increases tip chainwork monotonically, and each header's own work follows
// its nBits (a min-diff block contributes ~2^32, the boundary block ~2^49).
// (Fork-vs-fork selection and reorg undo machinery: btcheaders_reorg_tests.)
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(chainwork_accumulates_by_real_nbits)
{
    const auto& m = RealHeaders();
    const arith_uint256 wMin = g_btc_spv->GetBlockProof(m.at(145153));  // min-diff
    const arith_uint256 wReal = g_btc_spv->GetBlockProof(m.at(145152)); // boundary
    BOOST_CHECK(wReal > wMin * 1000);   // ~2^17 apart in practice

    arith_uint256 prev = g_btc_spv->GetTipChainWork();
    for (uint32_t h = 145153; h <= 145156; h++) {
        BOOST_REQUIRE(g_btc_spv->AddHeader(m.at(h)) == BtcHeaderStatus::VALID);
        arith_uint256 now = g_btc_spv->GetTipChainWork();
        BOOST_CHECK(now == prev + g_btc_spv->GetBlockProof(m.at(h)));
        prev = now;
    }
}

// -----------------------------------------------------------------------------
// D.6b — the ×¼..×4 timespan clamp (inactive at the real 145152 boundary,
// whose actual timespan sits inside the bounds — so it gets its own SYNTHETIC
// harness case; same pure engine, clearly-labeled inputs).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(retarget_clamp_bounds_adjustment)
{
    const auto& m = RealHeaders();
    const int64_t timespan = 14 * 24 * 3600;

    BtcBlockHeader first = m.at(143136);   // real difficulty base
    BtcBlockHeader last;
    last.SetNull();
    last.hashMerkleRoot = uint256S("01");
    last.nBits = first.nBits;
    auto acc = [&first](uint32_t h, BtcBlockHeader& out) {
        if (h == 143136) { out = first; return true; }
        return false;
    };

    arith_uint256 base;
    base.SetCompact(first.nBits);

    // Absurdly fast period (timespan/100): clamped to ×¼ (difficulty up 4x max).
    last.nTime = first.nTime + (uint32_t)(timespan / 100);
    arith_uint256 quarter = base / 4;
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145152, last, last.nTime + 600, acc),
        quarter.GetCompact());

    // Absurdly slow period (timespan*100): clamped to ×4 (difficulty down 4x max).
    last.nTime = first.nTime + (uint32_t)(timespan * 100);
    arith_uint256 quadruple = base * 4;
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145152, last, last.nTime + 600, acc),
        quadruple.GetCompact());

    // powLimit cap (review L-7b): a slow period whose base is ALREADY at
    // powLimit must emit exactly powLimit, never above it.
    BtcBlockHeader easyFirst = first;
    easyFirst.nBits = 0x1d00ffff;   // min-difficulty-era base
    auto accEasy = [&easyFirst](uint32_t h, BtcBlockHeader& out) {
        if (h == 143136) { out = easyFirst; return true; }
        return false;
    };
    last.nBits = easyFirst.nBits;
    BOOST_CHECK_EQUAL(
        g_btc_spv->ExpectedNextBits(145152, last, last.nTime + 600, accEasy),
        0x1d00ffffU);
}

// -----------------------------------------------------------------------------
// M-3 (review) — the SPV store is tagged with its committed source network: a
// store built for another Bitcoin network is REFUSED at init instead of
// silently serving its stale tip (the signet-era-datadir liveness trap).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(store_from_another_source_network_is_refused)
{
    // The fixture's store was built as BITCOIN_TESTNET4. Re-opening the SAME
    // datadir committed to BITCOIN_MAINNET must fail...
    g_btc_spv->Shutdown();
    auto spv = std::make_unique<CBtcSPV>();
    BOOST_CHECK(!spv->Init((GetDataDir() / "btcspv-t4").string(),
                           BtcSourceNet::BITCOIN_MAINNET));
    // ...while re-opening under the committed network keeps working.
    auto spv2 = std::make_unique<CBtcSPV>();
    BOOST_CHECK(spv2->Init((GetDataDir() / "btcspv-t4").string(),
                           BtcSourceNet::BITCOIN_TESTNET4));
    BOOST_CHECK_EQUAL(spv2->GetTipHeight(), 145152U);
    spv2->Shutdown();
}

// -----------------------------------------------------------------------------
// D.5b — STRICTNESS at the store level: a header whose PoW is genuinely valid
// but whose nBits departs from the schedule is REJECTED (invalid-retarget),
// not logged. Real vectors cannot isolate this (mutating a real header breaks
// its PoW first, and mining at Testnet4 min-difficulty costs 2^32 hashes), so
// this uses EXPLICIT HARNESS PARAMS (InitForTest, trivial powLimit) — the
// schedule logic under test is the same engine, and the signet-era advisory
// path this guards against is exactly what PHASE 2.6 removed.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(harness_store_rejects_wrong_nbits_strictly)
{
    // HARNESS network params — NOT a Bitcoin network (magic 0xB47C0000).
    BtcNetworkParams hp;
    hp.magic = 0xB47C0000;
    hp.genesisHash.SetNull();
    hp.defaultPort = 0;
    hp.powLimit = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    hp.nPowTargetSpacing = 600;
    hp.nPowTargetTimespan = 14 * 24 * 3600;
    hp.fPowAllowMinDifficultyBlocks = true;
    hp.enforceBIP94 = true;
    hp.genesisCheckpointHeight = 145152;    // keep the boundary geometry

    // Pin: a trivially-minable "checkpoint" at the boundary height.
    BtcBlockHeader pin;
    pin.SetNull();
    pin.nVersion = 4;
    pin.hashMerkleRoot = uint256S("aa");
    pin.nTime = 1700000000;
    pin.nBits = hp.powLimit.GetCompact();
    pin.nNonce = 0;

    std::vector<BtcCheckpoint> cps{{145152, pin.GetHash(), arith_uint256(1)}};
    auto spv = std::make_unique<CBtcSPV>();
    BOOST_REQUIRE(spv->InitForTest((GetDataDir() / "btcspv-harness").string(), hp, cps, &pin));

    // Mine a trivially-cheap valid child (expected ~2 hashes at this powLimit).
    auto mine = [&hp](BtcBlockHeader& h) {
        arith_uint256 target;
        target.SetCompact(h.nBits);
        for (uint32_t n = 0; n < 100000; n++) {
            h.nNonce = n;
            if (UintToArith256(h.GetHash()) <= target) return true;
        }
        return false;
    };

    BtcBlockHeader good;
    good.SetNull();
    good.nVersion = 4;
    good.hashPrevBlock = pin.GetHash();
    good.hashMerkleRoot = uint256S("bb");
    good.nTime = pin.nTime + 600;           // not late: nBits must equal parent's
    good.nBits = pin.nBits;
    BOOST_REQUIRE(mine(good));
    BOOST_CHECK(spv->AddHeader(good) == BtcHeaderStatus::VALID);

    // Same construction, VALID PoW, but nBits off-schedule (harder than
    // required — off-boundary and not late, so nBits MUST equal the parent's).
    BtcBlockHeader wrong;
    wrong.SetNull();
    wrong.nVersion = 4;
    wrong.hashPrevBlock = good.GetHash();
    wrong.hashMerkleRoot = uint256S("cc");
    wrong.nTime = good.nTime + 600;
    {
        arith_uint256 harder = hp.powLimit >> 1;
        wrong.nBits = harder.GetCompact();
    }
    BOOST_REQUIRE(mine(wrong));             // PoW itself is genuinely valid...
    // ...and the store still refuses it: strict, never advisory.
    BOOST_CHECK(spv->AddHeader(wrong) == BtcHeaderStatus::INVALID_RETARGET);
    BOOST_CHECK_EQUAL(spv->GetTipHash().GetHex(), good.GetHash().GetHex());

    // MTP floor: a valid-PoW, schedule-correct header whose nTime does not
    // exceed the median-time-past is refused.
    BtcBlockHeader stale;
    stale.SetNull();
    stale.nVersion = 4;
    stale.hashPrevBlock = good.GetHash();
    stale.hashMerkleRoot = uint256S("dd");
    stale.nTime = good.nTime;               // == MTP of {pin, good} -> too old
    stale.nBits = good.nBits;
    BOOST_REQUIRE(mine(stale));
    BOOST_CHECK(spv->AddHeader(stale) == BtcHeaderStatus::INVALID_TIMESTAMP_MTP);

    spv->Shutdown();
}

BOOST_AUTO_TEST_SUITE_END()
