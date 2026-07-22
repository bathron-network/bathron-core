// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * A2 — BCS v02 mint-to-scripthash (doc/PREMAINNET-CONSENSUS-ADDITIONS.md §2)
 *
 * v01: OP_RETURN "BATHRON" | 01 | NET | DEST20            → mint P2PKH
 * v02: OP_RETURN "BATHRON" | 02 | NET | TYPE | DEST20     → TYPE 00 P2PKH,
 *                                                            TYPE 01 P2SH
 * Covers: v01 regression, v02 both types, unknown type/version rejected,
 * length/version coherence, and GetMintDestScript form selection (the shared
 * producer/validator helper).
 */

#include "test/test_bathron.h"

#include "burnclaim/burnclaim.h"
#include "script/script.h"
#include "script/standard.h"
#include "utilstrencodings.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bcs_v02_tests, BasicTestingSetup)

namespace {

// BCS-4 burn script hash: SHA256(OP_FALSE)
const char* BURN_HASH_HEX =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

BtcTxOut MakeBurnOutput(int64_t sats)
{
    BtcTxOut out;
    out.nValue = sats;
    out.scriptPubKey = {0x00, 0x20};  // OP_0 PUSH32
    std::vector<uint8_t> h = ParseHex(BURN_HASH_HEX);
    out.scriptPubKey.insert(out.scriptPubKey.end(), h.begin(), h.end());
    return out;
}

BtcTxOut MakeMetadataOutput(const std::vector<uint8_t>& payload)
{
    BtcTxOut out;
    out.nValue = 0;
    out.scriptPubKey = {0x6a, (uint8_t)payload.size()};  // OP_RETURN PUSH<n>
    out.scriptPubKey.insert(out.scriptPubKey.end(), payload.begin(),
                            payload.end());
    return out;
}

std::vector<uint8_t> MetaV1(uint8_t network, uint8_t destByte)
{
    std::vector<uint8_t> p = {'B', 'A', 'T', 'H', 'R', 'O', 'N', 0x01, network};
    p.insert(p.end(), 20, destByte);
    return p;
}

std::vector<uint8_t> MetaV2(uint8_t network, uint8_t destType, uint8_t destByte)
{
    std::vector<uint8_t> p = {'B', 'A', 'T', 'H', 'R', 'O', 'N', 0x02, network,
                              destType};
    p.insert(p.end(), 20, destByte);
    return p;
}

BtcParsedTx MakeBurnTx(const std::vector<uint8_t>& metaPayload, int64_t sats)
{
    BtcParsedTx tx;
    tx.nVersion = 2;
    tx.vout.push_back(MakeMetadataOutput(metaPayload));
    tx.vout.push_back(MakeBurnOutput(sats));
    return tx;
}

} // namespace

// =============================================================================
// v01 regression — unchanged semantics
// =============================================================================

BOOST_AUTO_TEST_CASE(v01_parses_as_p2pkh)
{
    BtcParsedTx tx = MakeBurnTx(MetaV1(0x01, 0xAB), 100000);
    BurnInfo info;
    BOOST_REQUIRE(ParseBurnOutputs(tx, info));
    BOOST_CHECK_EQUAL(info.version, 1);
    BOOST_CHECK_EQUAL(info.destType, BURN_DEST_P2PKH);
    BOOST_CHECK_EQUAL(info.burnedSats, 100000U);
    BOOST_CHECK_EQUAL(info.bathronDest.begin()[0], 0xAB);
    BOOST_CHECK_EQUAL(info.bathronDest.begin()[19], 0xAB);
}

BOOST_AUTO_TEST_CASE(v01_wrong_length_rejected)
{
    // v01 payload with 21-byte dest (30 total) must NOT pass as v01
    std::vector<uint8_t> p = MetaV1(0x01, 0xAB);
    p.push_back(0xAB);
    BtcParsedTx tx = MakeBurnTx(p, 100000);
    BurnInfo info;
    BOOST_CHECK(!ParseBurnOutputs(tx, info));
}

// =============================================================================
// v02 — explicit destination type
// =============================================================================

BOOST_AUTO_TEST_CASE(v02_p2pkh_parses)
{
    BtcParsedTx tx = MakeBurnTx(MetaV2(0x01, BURN_DEST_P2PKH, 0xCD), 250000);
    BurnInfo info;
    BOOST_REQUIRE(ParseBurnOutputs(tx, info));
    BOOST_CHECK_EQUAL(info.version, 2);
    BOOST_CHECK_EQUAL(info.destType, BURN_DEST_P2PKH);
    BOOST_CHECK_EQUAL(info.bathronDest.begin()[0], 0xCD);
}

BOOST_AUTO_TEST_CASE(v02_p2sh_parses)
{
    BtcParsedTx tx = MakeBurnTx(MetaV2(0x01, BURN_DEST_P2SH, 0xEF), 250000);
    BurnInfo info;
    BOOST_REQUIRE(ParseBurnOutputs(tx, info));
    BOOST_CHECK_EQUAL(info.version, 2);
    BOOST_CHECK_EQUAL(info.destType, BURN_DEST_P2SH);
    BOOST_CHECK_EQUAL(info.bathronDest.begin()[0], 0xEF);
    BOOST_CHECK_EQUAL(info.burnedSats, 250000U);
}

BOOST_AUTO_TEST_CASE(v02_unknown_dest_type_rejected)
{
    BtcParsedTx tx = MakeBurnTx(MetaV2(0x01, 0x02, 0xEF), 250000);
    BurnInfo info;
    BOOST_CHECK(!ParseBurnOutputs(tx, info));
}

BOOST_AUTO_TEST_CASE(v02_wrong_length_rejected)
{
    // v02 with only 19 dest bytes (29 total — v01 length, v02 version byte)
    std::vector<uint8_t> p = {'B', 'A', 'T', 'H', 'R', 'O', 'N', 0x02, 0x01,
                              BURN_DEST_P2SH};
    p.insert(p.end(), 19, 0xEF);
    BtcParsedTx tx = MakeBurnTx(p, 250000);
    BurnInfo info;
    BOOST_CHECK(!ParseBurnOutputs(tx, info));
}

BOOST_AUTO_TEST_CASE(unknown_version_rejected)
{
    // version byte 3, 30-byte shape
    std::vector<uint8_t> p = {'B', 'A', 'T', 'H', 'R', 'O', 'N', 0x03, 0x01,
                              0x00};
    p.insert(p.end(), 20, 0x11);
    BtcParsedTx tx = MakeBurnTx(p, 250000);
    BurnInfo info;
    BOOST_CHECK(!ParseBurnOutputs(tx, info));
}

// =============================================================================
// GetMintDestScript — the shared producer/validator destination form
// =============================================================================

BOOST_AUTO_TEST_CASE(mint_dest_script_forms)
{
    BurnClaimRecord rec;
    std::fill(rec.bathronDest.begin(), rec.bathronDest.end(), 0x42);

    rec.destType = BURN_DEST_P2PKH;
    CScript p2pkh = GetMintDestScript(rec);
    txnouttype whichType;
    std::vector<std::vector<unsigned char>> sols;
    BOOST_REQUIRE(Solver(p2pkh, whichType, sols));
    BOOST_CHECK_EQUAL(whichType, TX_PUBKEYHASH);

    rec.destType = BURN_DEST_P2SH;
    CScript p2sh = GetMintDestScript(rec);
    BOOST_REQUIRE(Solver(p2sh, whichType, sols));
    BOOST_CHECK_EQUAL(whichType, TX_SCRIPTHASH);

    // Same hash160, different wrapping — never the same script
    BOOST_CHECK(p2pkh != p2sh);
}

BOOST_AUTO_TEST_SUITE_END()
