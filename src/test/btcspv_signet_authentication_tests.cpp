// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// PHASE 2.6 — BITCOIN SOURCE AUTHENTICATION CONTROLS (post-signet-refusal)
// =============================================================================
//
// History: this file was the PHASE 2.5 audit harness that MEASURED signet's
// forgeability (a CPU-mined ~2^27-hash header with an attacker-chosen merkle
// root passed every shipped check in ~31 s — "SIGNET IS NOT A MONETARY
// SOURCE", doc/BITCOIN-SOURCE-AUTHENTICATION-AUDIT.md). PHASE 2.6 acted on
// that verdict: the Bitcoin source of the BATHRON measurement network is now
// Testnet4 (BIP-94) and every signet parameter was REMOVED from the tree.
//
// What remains here are the CONTROLS that keep it that way:
//   1. the validated object is still an 80-byte header (no BIP-325 field),
//   2. genuine signet headers are REFUSED by the Testnet4-committed SPV,
//   3. no signet parameter set is reachable: the source enum has exactly
//      {BITCOIN_MAINNET, BITCOIN_TESTNET4}, and Testnet4 carries the FULL
//      mainnet-strength powLimit (~2^224), not signet's forgeable ~2^233,
//   4. a chosen-merkle-root header that is not actually mined is rejected.

#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "chainparams.h"
#include "fs.h"
#include "hash.h"
#include "streams.h"
#include "test/test_bathron.h"
#include "util/system.h"
#include "uint256.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

//! Serialize a BTC header the way the network does (80 bytes).
std::vector<uint8_t> SerializeHeader(const BtcBlockHeader& h)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << h;
    return std::vector<uint8_t>(ss.begin(), ss.end());
}

//! Expected hashes to mine one header at `nBits` (= 2^256 / (target+1)).
double ExpectedHashesLog2(uint32_t nBits)
{
    arith_uint256 target;
    target.SetCompact(nBits);
    // log2(2^256 / target) = 256 - log2(target); bit length is exact enough here.
    return 256.0 - (double)target.bits();
}

//! REAL Bitcoin Signet block 286000 — kept as a STATIC ADVERSARIAL VECTOR only
//! (it was the removed signet SPV pin). Verified: hashes to
//! 0000000732c0c78558a50be0774d99188f65ee374e10ff9816deaf42df9f7780.
BtcBlockHeader RealSignetHeader286000()
{
    BtcBlockHeader h;
    h.nVersion = 0x20000000;
    h.hashPrevBlock = uint256S("00000009dbc0a60881fe55e6439cf024b5c66be84d5618e7a50e3531a762dbb4");
    h.hashMerkleRoot = uint256S("74311cdb2b23e38c7b8a3c913794df3b83b5c58d12eee67d5aab37abfb40d4f3");
    h.nTime = 1767768593;
    h.nBits = 0x1d1420d7;
    h.nNonce = 192496662;
    return h;
}

struct SourceAuthSetup : public BasicTestingSetup {
    SourceAuthSetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        // Per-case on-disk datadir (same hygiene as P0AtomicitySetup).
        SetDataDir("srcauthcase");
        ClearDatadirCache();
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
        // The consensus-committed source of the BATHRON measurement network.
        BOOST_REQUIRE_MESSAGE(
            g_btc_spv->Init((GetDataDir() / "btcspv-audit").string(), BtcSourceNet::BITCOIN_TESTNET4),
            "could not initialise the SPV client with Testnet4 parameters");
    }
    ~SourceAuthSetup()
    {
        g_btcheadersdb.reset();
        g_btc_spv.reset();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(btcspv_signet_authentication_tests, SourceAuthSetup)

// -----------------------------------------------------------------------------
// 1. MECHANICAL (unchanged from the audit): the published/validated object is
//    80 bytes. There is no field for a coinbase, witness commitment or BIP-325
//    solution — which is exactly WHY signet could never be authenticated and
//    was refused as a monetary source.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(the_validated_object_is_an_80_byte_header)
{
    BtcBlockHeader pin;
    BOOST_REQUIRE(GetBtcTestnet4GenesisHeader(pin));
    BOOST_CHECK_EQUAL(SerializeHeader(pin).size(), 80U);
    BOOST_CHECK_EQUAL(pin.GetHash().GetHex(),
        "00000000000000014694285ac2a2980339778e6b73d2199a65a5f62f2df44d2d");

    BtcHeadersPayload pl;
    pl.headers.push_back(pin);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << pl.headers;
    // 1 header + compact-size count == 81 bytes: no room for, and no field
    // for, a coinbase, a witness commitment or a signet solution.
    BOOST_CHECK_EQUAL(ss.size(), 81U);
}

// -----------------------------------------------------------------------------
// 2. CONTROL (PHASE-D #15): a GENUINE signet header — the very block that used
//    to be the shipped signet pin — is REFUSED by the Testnet4-committed SPV.
//    Its compact target (0x1d1420d7 ≈ 2^228) exceeds Testnet4's powLimit
//    (0xffff·2^208 ≈ 2^224), so it dies in CheckProofOfWork before ancestry
//    is even considered.
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_signet_headers_are_refused_on_the_testnet4_source)
{
    BtcBlockHeader signet = RealSignetHeader286000();
    // The vector is genuine (this control is about the network, not the data).
    BOOST_REQUIRE_EQUAL(signet.GetHash().GetHex(),
        "0000000732c0c78558a50be0774d99188f65ee374e10ff9816deaf42df9f7780");

    // Refused by the per-header PoW predicate (target above Testnet4 powLimit).
    BOOST_CHECK(!g_btc_spv->CheckProofOfWork(signet));

    // And refused end-to-end by the store.
    BtcHeaderStatus st = g_btc_spv->AddHeader(signet);
    BOOST_CHECK(st != BtcHeaderStatus::VALID);
    BOOST_CHECK(st != BtcHeaderStatus::DUPLICATE);
}

// -----------------------------------------------------------------------------
// 3. CONTROL (PHASE-D #16): no signet parameter set is reachable. The source
//    enum has exactly two members, and the Testnet4 params carry the FULL
//    mainnet-strength powLimit — one forged header now costs >= 2^32 expected
//    hashes even at min-difficulty (vs the ~2^27 measured on signet in the
//    PHASE 2.5 audit), and real periods sit far higher (the pinned 145152
//    nBits implies ~2^49).
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(no_signet_parameters_are_reachable)
{
    // Enum surface: exactly mainnet and testnet4.
    BOOST_CHECK_EQUAL(BtcSourceNetToString(BtcSourceNet::BITCOIN_MAINNET), "mainnet");
    BOOST_CHECK_EQUAL(BtcSourceNetToString(BtcSourceNet::BITCOIN_TESTNET4), "testnet4");

    const BtcNetworkParams& t4 = GetBtcTestnet4Params();
    const BtcNetworkParams& mn = GetBtcMainnetParams();
    // Same powLimit as mainnet — NOT signet's 0x00000377ae… (~2^233).
    BOOST_CHECK(t4.powLimit == mn.powLimit);
    BOOST_CHECK_EQUAL(t4.powLimit.GetCompact(), 0x1d00ffffU);
    // Not the signet network identity.
    BOOST_CHECK(t4.magic != 0x0A03CF40U);
    BOOST_CHECK(t4.genesisHash !=
        uint256S("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"));
    // BIP-94 schedule committed.
    BOOST_CHECK(t4.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK(t4.enforceBIP94);
    BOOST_CHECK_EQUAL(t4.DifficultyAdjustmentInterval(), 2016);

    // Forge-cost floor: min-difficulty on Testnet4 is ~2^32 expected hashes.
    BOOST_CHECK(ExpectedHashesLog2(0x1d00ffff) >= 31.0);
    // The real pinned difficulty is far above the floor.
    BtcBlockHeader pin;
    BOOST_REQUIRE(GetBtcTestnet4GenesisHeader(pin));
    BOOST_CHECK(ExpectedHashesLog2(pin.nBits) > 45.0);

    // The BATHRON testnet chain params commit to the Testnet4 source.
    BOOST_CHECK(Params().GetConsensus().btcSourceNet == BtcSourceNet::BITCOIN_TESTNET4);
}

// -----------------------------------------------------------------------------
// 4. PHASE-D #11: a header carrying an ATTACKER-CHOSEN merkle root on the real
//    Testnet4 parent, but not actually mined, is rejected. (On signet the
//    equivalent forgery WAS mined in ~31 s of CPU and accepted — that is the
//    difference the source switch buys.)
// -----------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(chosen_merkle_root_without_real_mining_is_rejected)
{
    BtcBlockHeader parent;
    BOOST_REQUIRE(GetBtcTestnet4GenesisHeader(parent));

    BtcBlockHeader forged;
    forged.nVersion = 0x20000000;
    forged.hashPrevBlock = parent.GetHash();
    forged.hashMerkleRoot = uint256S("00000000000000000000000000000000000000000000000000000000deadbeef");
    forged.nTime = parent.nTime + 600;
    forged.nBits = parent.nBits;    // difficulty-correct (non-boundary: nBits == parent)
    forged.nNonce = 0;              // ...but NOT mined

    // PoW is the authentication, and it fails.
    BOOST_CHECK(!g_btc_spv->CheckProofOfWork(forged));
    BOOST_CHECK(g_btc_spv->AddHeader(forged) == BtcHeaderStatus::INVALID_POW);

    // Sanity: the same header ALSO fails if it tries the min-difficulty escape
    // with the wrong nBits (a late block MUST carry powLimit exactly under the
    // 20-minute rule; carrying it unmined still dies in PoW).
    forged.nTime = parent.nTime + 1201;
    BOOST_CHECK(g_btc_spv->AddHeader(forged) != BtcHeaderStatus::VALID);
}

BOOST_AUTO_TEST_SUITE_END()
