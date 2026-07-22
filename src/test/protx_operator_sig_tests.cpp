// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Regression for commit af76a55 (test-plan B9).
 *
 * Operator ProUpServ/ProUpReg payloads are signed over the payload hash with a
 * COMPACT (65-byte recoverable) ECDSA signature and MUST be verified with
 * CHashSigner::VerifyHash (recover pubkey, compare key-id) — NOT CPubKey::Verify
 * (which expects a DER signature). The bug verified operator hash-sigs with
 * CPubKey::Verify, so EVERY ProUpServ/ProUpReg operator tx was rejected
 * "bad-protx-sig" and a PoSe-banned MN could never revive.
 *
 * The buggy line (CheckHashSig CPubKey overload) is a static template only
 * reachable through CheckProUpServTx/CheckProUpRegTx (which need a populated
 * deterministicMNManager + a CBlockIndex = a regtest chain, disproportionate).
 * Instead we pin the exact INVARIANT the fix encodes, on a real payload hash
 * with a real operator key: the compact verifier accepts an operator sig, the
 * DER verifier does not, a wrong key is rejected cleanly, and the signature
 * covers the payload (tamper-evident).
 */

#include "consensus/validation.h"
#include "hash.h"
#include "key.h"
#include "masternode/providertx.h"
#include "messagesigner.h"
#include "pubkey.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(protx_operator_sig_tests, BasicTestingSetup)

namespace {

ProUpServPL MakeProUpServ()
{
    ProUpServPL pl;
    pl.nVersion = ProUpServPL::CURRENT_VERSION;  // v2 = ECDSA
    pl.proTxHash = uint256S("beef");
    pl.inputsHash = uint256S("f00d");
    // addr left default — covered by the hash regardless.
    return pl;
}

} // namespace

// The exact thing af76a55 restored: an operator compact-signs the payload hash,
// and CHashSigner::VerifyHash accepts it.
BOOST_AUTO_TEST_CASE(compact_operator_sig_verifies)
{
    CKey op; op.MakeNewKey(true);
    ProUpServPL pl = MakeProUpServ();
    uint256 hash = ::SerializeHash(pl);           // SER_GETHASH excludes vchSig

    BOOST_REQUIRE(CHashSigner::SignHash(hash, op, pl.vchSig));
    BOOST_CHECK_EQUAL(pl.vchSig.size(), 65U);     // compact recoverable sig

    std::string err;
    BOOST_CHECK_MESSAGE(CHashSigner::VerifyHash(hash, op.GetPubKey(), pl.vchSig, err), err);
}

// WHY the bug existed: the compact sig is NOT DER-verifiable, so the pre-fix
// CPubKey::Verify path rejected every operator sig.
BOOST_AUTO_TEST_CASE(compact_sig_is_not_der_verifiable)
{
    CKey op; op.MakeNewKey(true);
    uint256 hash = uint256S("abc123");
    std::vector<unsigned char> compact;
    BOOST_REQUIRE(CHashSigner::SignHash(hash, op, compact));

    // The literal pre-fix call. It must FAIL — that was the on-chain breakage.
    BOOST_CHECK(!op.GetPubKey().Verify(hash, compact));
}

// A DER signature fed to the compact verifier is rejected — the inverse guard.
BOOST_AUTO_TEST_CASE(der_sig_rejected_by_compact_verifier)
{
    CKey op; op.MakeNewKey(true);
    uint256 hash = uint256S("abc123");
    std::vector<unsigned char> der;
    BOOST_REQUIRE(op.Sign(hash, der));            // DER signature (not compact)

    std::string err;
    BOOST_CHECK(!CHashSigner::VerifyHash(hash, op.GetPubKey(), der, err));
    BOOST_CHECK_EQUAL(err, "Error recovering public key.");
}

// A sig from a different operator key must not verify against the expected key.
BOOST_AUTO_TEST_CASE(wrong_operator_key_rejected)
{
    CKey op; op.MakeNewKey(true);
    CKey other; other.MakeNewKey(true);
    ProUpServPL pl = MakeProUpServ();
    uint256 hash = ::SerializeHash(pl);
    BOOST_REQUIRE(CHashSigner::SignHash(hash, op, pl.vchSig));

    std::string err;
    BOOST_CHECK(!CHashSigner::VerifyHash(hash, other.GetPubKey(), pl.vchSig, err));
    BOOST_CHECK(err.rfind("Keys don't match", 0) == 0);
}

// The signature covers the payload: mutating a covered field invalidates it
// (replay/tamper guard). vchSig is excluded from the hash (SER_GETHASH), so
// populating it does not change the hash.
BOOST_AUTO_TEST_CASE(sig_covers_payload_fields)
{
    CKey op; op.MakeNewKey(true);
    ProUpServPL pl = MakeProUpServ();
    uint256 hash0 = ::SerializeHash(pl);
    BOOST_REQUIRE(CHashSigner::SignHash(hash0, op, pl.vchSig));
    // Hash is stable after signing (vchSig not covered).
    BOOST_CHECK(::SerializeHash(pl) == hash0);

    // Tamper a covered field -> new hash -> old sig no longer verifies.
    pl.inputsHash = uint256S("deadbeef");
    uint256 hash1 = ::SerializeHash(pl);
    BOOST_CHECK(hash1 != hash0);
    std::string err;
    BOOST_CHECK(!CHashSigner::VerifyHash(hash1, op.GetPubKey(), pl.vchSig, err));
}

// Same compact/DER contract for the ProUpReg operator-signed payload (the other
// af76a55 call site).
BOOST_AUTO_TEST_CASE(proupreg_operator_sig_verifies)
{
    CKey op; op.MakeNewKey(true);
    ProUpRegPL pl;
    pl.nVersion = ProUpRegPL::CURRENT_VERSION;    // v3 = +VRF
    pl.proTxHash = uint256S("beef");
    pl.pubKeyOperator = op.GetPubKey();
    CKey vrf; vrf.MakeNewKey(true);
    pl.pubKeyVRF = vrf.GetPubKey();
    pl.inputsHash = uint256S("f00d");

    uint256 hash = ::SerializeHash(pl);
    BOOST_REQUIRE(CHashSigner::SignHash(hash, op, pl.vchSig));
    std::string err;
    BOOST_CHECK_MESSAGE(CHashSigner::VerifyHash(hash, op.GetPubKey(), pl.vchSig, err), err);
    BOOST_CHECK(!op.GetPubKey().Verify(hash, pl.vchSig));   // still not DER
}

BOOST_AUTO_TEST_SUITE_END()
