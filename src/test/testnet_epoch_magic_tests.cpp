// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Epoch-4 separation guard for the measurement network (2026-08-05).
//
// The superseded testnet5 fleet stays live (rollback window) on epoch 3, the
// SAME default P2P port. The only things separating the two networks on the
// wire are the magic bytes and the pinned genesis, so both are locked here:
// an epoch regression, a magic collision or a genesis drift must fail this
// suite (and the static_asserts next to the magic derivation) before it can
// reach a binary.

#include "chainparams.h"
#include "protocol.h"
#include "version.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <memory>

BOOST_FIXTURE_TEST_SUITE(testnet_epoch_magic_tests, BasicTestingSetup)

namespace
{
const unsigned char OLD_EPOCH3_MAGIC[CMessageHeader::MESSAGE_START_SIZE] = {0xfa, 0xbf, 0xb5, 0xdd};
const unsigned char NEW_EPOCH4_MAGIC[CMessageHeader::MESSAGE_START_SIZE] = {0xfa, 0xbf, 0xb5, 0xde};
} // namespace

BOOST_AUTO_TEST_CASE(testnet_magic_is_epoch4_and_disjoint_from_every_known_network)
{
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    const auto regtest = CreateChainParams(CBaseChainParams::REGTEST);

    BOOST_CHECK_EQUAL(TESTNET_EPOCH, 4);
    BOOST_CHECK(memcmp(testnet->MessageStart(), NEW_EPOCH4_MAGIC, CMessageHeader::MESSAGE_START_SIZE) == 0);

    // The superseded live network (epoch 3) and its predecessor (epoch 2) share
    // this port: their magics must never be ours again.
    BOOST_CHECK(memcmp(testnet->MessageStart(), OLD_EPOCH3_MAGIC, CMessageHeader::MESSAGE_START_SIZE) != 0);
    const unsigned char epoch2Magic[CMessageHeader::MESSAGE_START_SIZE] = {0xfa, 0xbf, 0xb5, 0xdc};
    BOOST_CHECK(memcmp(testnet->MessageStart(), epoch2Magic, CMessageHeader::MESSAGE_START_SIZE) != 0);

    // And it is not any other BATHRON network's magic either.
    BOOST_CHECK(memcmp(testnet->MessageStart(), mainnet->MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0);
    BOOST_CHECK(memcmp(testnet->MessageStart(), regtest->MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0);
    BOOST_CHECK(memcmp(mainnet->MessageStart(), regtest->MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0);
}

BOOST_AUTO_TEST_CASE(old_epoch3_message_is_rejected_by_the_new_network)
{
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);

    // A well-formed header stamped with the superseded network's magic must not
    // validate against the measurement network's expected message start...
    CMessageHeader oldHdr(OLD_EPOCH3_MAGIC, "ping", 8);
    BOOST_CHECK(!oldHdr.IsValid(testnet->MessageStart()));

    // ...while the identical header under the epoch-4 magic does, so the
    // rejection above is attributable to the magic alone.
    CMessageHeader newHdr(testnet->MessageStart(), "ping", 8);
    BOOST_CHECK(newHdr.IsValid(testnet->MessageStart()));
}

BOOST_AUTO_TEST_CASE(measurement_genesis_is_unchanged_by_the_epoch_bump)
{
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);

    // The epoch feeds the P2P envelope only: the pinned measurement genesis
    // (and so the chain identity) must be byte-identical to the ae3e36ec value.
    BOOST_CHECK_EQUAL(testnet->GetConsensus().hashGenesisBlock.GetHex(),
                      "691b0a7e8cb0e7ee159ef7a4fa10d9c6ddb2d5282e5bac7447846459ff54c730");
    BOOST_CHECK_EQUAL(testnet->GenesisBlock().GetHash().GetHex(),
                      "691b0a7e8cb0e7ee159ef7a4fa10d9c6ddb2d5282e5bac7447846459ff54c730");
    BOOST_CHECK_EQUAL(testnet->GenesisBlock().hashMerkleRoot.GetHex(),
                      "ca0cc3b20bfbb4d84ba56aa760bcb85bbd6637973a12ce24c69d0d2ad79c445a");
}

BOOST_AUTO_TEST_SUITE_END()
