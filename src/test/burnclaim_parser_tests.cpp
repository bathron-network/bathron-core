// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Regression test for the unbounded-allocation DoS in the hand-rolled BTC-tx
// parser (burnclaim.cpp). A crafted SegWit tx with a huge per-input witness
// item count fed scriptWitness.resize(witnessCount) with no bound -> multi-GB
// eager allocation -> bad_alloc/OOM, reachable by any peer via TX_BURN_CLAIM.
// The fix bounds witnessCount (>10000 -> reject) before resize, mirroring the
// vin/vout/script-length caps. Pre-fix this test OOM/crashes; post-fix
// ParseBtcTransaction returns false immediately.

#include "test/test_bathron.h"

#include "burnclaim/burnclaim.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(burnclaim_parser_tests, BasicTestingSetup)

namespace {
void put_u32le(std::vector<uint8_t>& v, uint32_t x)
{
    v.push_back(x & 0xff); v.push_back((x >> 8) & 0xff);
    v.push_back((x >> 16) & 0xff); v.push_back((x >> 24) & 0xff);
}
} // namespace

// Crafted SegWit tx claiming witnessCount = 2^64-1. The fix must reject this
// (>10000) before resize(). Using the max value keeps this a SAFE regression
// guard: if the bound were removed, resize() throws std::length_error
// immediately (count > vector::max_size) rather than OOM-killing the runner —
// while a real attacker would instead pick ~2^33 to force a multi-GB alloc.
BOOST_AUTO_TEST_CASE(huge_witness_count_is_rejected_not_oom)
{
    std::vector<uint8_t> tx;
    put_u32le(tx, 1);                 // version
    tx.push_back(0x00);               // SegWit marker
    tx.push_back(0x01);               // SegWit flag -> hasWitness
    tx.push_back(0x01);               // vinCount = 1
    tx.insert(tx.end(), 32, 0x00);    // prevout hash
    put_u32le(tx, 0);                 // prevout index
    tx.push_back(0x00);               // scriptSig length = 0
    put_u32le(tx, 0xffffffff);        // sequence
    tx.push_back(0x01);               // voutCount = 1
    tx.insert(tx.end(), 8, 0x00);     // value = 0
    tx.push_back(0x00);               // scriptPubKey length = 0
    // witness for vin[0]: CompactSize 0xff + 8-byte LE count = 2^64-1.
    tx.push_back(0xff);
    tx.insert(tx.end(), 8, 0xff);     // witnessCount = 0xffffffffffffffff
    put_u32le(tx, 0);                 // locktime (unreached after the fix)

    BtcParsedTx parsed;
    // Must return false (bounded) — and must NOT attempt a huge allocation.
    BOOST_CHECK(!ParseBtcTransaction(tx, parsed));
}

// A well-formed minimal legacy (non-witness) tx must still parse, so the bound
// does not break valid transactions.
BOOST_AUTO_TEST_CASE(minimal_legacy_tx_still_parses)
{
    std::vector<uint8_t> tx;
    put_u32le(tx, 1);                 // version
    tx.push_back(0x01);               // vinCount = 1
    tx.insert(tx.end(), 32, 0x00);    // prevout hash
    put_u32le(tx, 0);                 // prevout index
    tx.push_back(0x00);               // scriptSig length = 0
    put_u32le(tx, 0xffffffff);        // sequence
    tx.push_back(0x01);               // voutCount = 1
    put_u32le(tx, 1); put_u32le(tx, 0); // value = 1 (8 bytes LE)
    tx.push_back(0x00);               // scriptPubKey length = 0
    put_u32le(tx, 0);                 // locktime

    BtcParsedTx parsed;
    BOOST_CHECK(ParseBtcTransaction(tx, parsed));
    BOOST_CHECK_EQUAL(parsed.vin.size(), 1U);
    BOOST_CHECK_EQUAL(parsed.vout.size(), 1U);
    BOOST_CHECK(!parsed.hasWitness);
}

BOOST_AUTO_TEST_SUITE_END()
