// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * CheckBtcHeadersTx publisher-signature (R2) + MN-membership (R1) — test-plan B3.
 *
 * TX_BTC_HEADERS is how BTC state enters consensus (btcheadersdb, which backs
 * burn-claim SPV and OP_BTCSTATEVERIFY). Only a REGISTERED masternode operator
 * may publish it, proven by an ECDSA signature over the payload hash with the
 * publisher's operator key. btcheaders_reorg_tests deliberately uses EMPTY
 * signatures (it drives Process/Disconnect), so R1/R2 — the gate on WHO may
 * write BTC state — had no coverage until now.
 *
 * g_btcheadersdb / g_btc_spv are left NULL so the R3-R6/cooldown context block
 * (gated on pindexPrev && g_btcheadersdb) is skipped and a payload passing R1/R2
 * returns cleanly. Signatures are DER ECDSA (operator key .Sign / pubkey.Verify).
 */

#include "arith_uint256.h"
#include "btcheaders/btcheaders.h"
#include "chain.h"
#include "consensus/validation.h"
#include "key.h"
#include "primitives/transaction.h"
#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include <boost/test/unit_test.hpp>

namespace {

BtcBlockHeader DummyHeader(uint32_t nonce)
{
    BtcBlockHeader h;
    h.nVersion = 4;
    h.hashPrevBlock = ArithToUint256(arith_uint256(0xA11CE) + nonce);
    h.hashMerkleRoot = ArithToUint256(arith_uint256(nonce) + 1);
    h.nTime = 1000 + nonce;
    h.nBits = 0x1d00ffff;
    h.nNonce = nonce;
    return h;
}

// Build a TX_BTC_HEADERS payload for `publisher`, optionally signed by `signer`.
BtcHeadersPayload MakePayload(const uint256& publisher, uint32_t startHeight)
{
    BtcHeadersPayload p;
    p.nVersion = BTCHEADERS_VERSION;
    p.publisherProTxHash = publisher;
    p.startHeight = startHeight;
    p.headers = {DummyHeader(startHeight)};
    p.count = 1;
    return p;
}

CTransactionRef ToTx(const BtcHeadersPayload& p)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;
    SetTxPayload(mtx, p);
    return MakeTransactionRef(std::move(mtx));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(btcheaders_sig_tests, MultiMNFinalitySetup)

// A registered operator, signing with its own key, is accepted. This is the
// first live check that the R2 signature path actually accepts a real sig.
BOOST_AUTO_TEST_CASE(valid_operator_publish_accepted)
{
    const uint256 proTx = operators[0].mns[0].proTxHash;
    BtcHeadersPayload p = MakePayload(proTx, 300000);
    BOOST_REQUIRE(operators[0].key.Sign(p.GetSignatureHash(), p.sig));

    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckBtcHeadersTx(*ToTx(p), TipIndex(), state),
                        state.GetRejectReason());
}

// R1: publisher not in the MN list -> rejected.
BOOST_AUTO_TEST_CASE(unknown_mn_rejected)
{
    const uint256 fake = ArithToUint256(arith_uint256(0xDEAD));
    BtcHeadersPayload p = MakePayload(fake, 300000);
    p.sig = std::vector<unsigned char>(72, 0x30);   // non-empty, structurally junk
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*ToTx(p), TipIndex(), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-unknown-mn");
}

// R2: known publisher but a garbage signature -> rejected.
BOOST_AUTO_TEST_CASE(bad_signature_rejected)
{
    const uint256 proTx = operators[0].mns[0].proTxHash;
    BtcHeadersPayload p = MakePayload(proTx, 300000);
    p.sig = std::vector<unsigned char>(72, 0x30);
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*ToTx(p), TipIndex(), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-sig");
}

// R2 anti-spoof (the security case): publish AS operator 0 but sign with
// operator 1's key -> the key must match the publisher, so rejected.
BOOST_AUTO_TEST_CASE(cross_operator_spoof_rejected)
{
    const uint256 proTx0 = operators[0].mns[0].proTxHash;
    BtcHeadersPayload p = MakePayload(proTx0, 300000);
    BOOST_REQUIRE(operators[1].key.Sign(p.GetSignatureHash(), p.sig));   // wrong key
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*ToTx(p), TipIndex(), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-sig");
}

// The signature covers the header/height fields: mutate startHeight after
// signing -> hash changes -> rejected (malleability guard). count stays == 1.
BOOST_AUTO_TEST_CASE(tampered_payload_rejected)
{
    const uint256 proTx = operators[0].mns[0].proTxHash;
    BtcHeadersPayload p = MakePayload(proTx, 300000);
    BOOST_REQUIRE(operators[0].key.Sign(p.GetSignatureHash(), p.sig));
    p.startHeight = 300001;                          // covered field, sig now stale
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*ToTx(p), TipIndex(), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-sig");
}

// Non-bootstrap block with an empty signature is caught before R1.
BOOST_AUTO_TEST_CASE(empty_sig_rejected)
{
    const uint256 proTx = operators[0].mns[0].proTxHash;
    BtcHeadersPayload p = MakePayload(proTx, 300000);   // sig left empty
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*ToTx(p), TipIndex(), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-empty-sig");
}

// Null publisher (non-bootstrap) -> rejected.
BOOST_AUTO_TEST_CASE(null_publisher_rejected)
{
    BtcHeadersPayload p = MakePayload(uint256(), 300000);
    p.sig = std::vector<unsigned char>(72, 0x30);
    CValidationState state;
    BOOST_CHECK(!CheckBtcHeadersTx(*ToTx(p), TipIndex(), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-btcheaders-null-publisher");
}

// Bootstrap exemption (proves it): at height <= nDMMBootstrapHeight the MN/sig
// checks are skipped, so an unsigned, null-publisher payload is accepted (the
// cold-start path where no MNs exist yet).
BOOST_AUTO_TEST_CASE(bootstrap_allows_unsigned)
{
    CBlockIndex bootstrapPrev;
    bootstrapPrev.nHeight = 100;                     // 101 <= 250 (testnet bootstrap)
    BtcHeadersPayload p = MakePayload(uint256(), 100);   // null publisher, empty sig
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckBtcHeadersTx(*ToTx(p), &bootstrapPrev, state),
                        state.GetRejectReason());
}

BOOST_AUTO_TEST_SUITE_END()
