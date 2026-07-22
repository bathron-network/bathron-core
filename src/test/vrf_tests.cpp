// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for the ECVRF-secp256k1 (SHA256_TAI, suite 0xFE, draft-irtf-cfrg-vrf-05)
// C++ wrapper. Validated against the OFFICIAL cross-implementation test vectors
// shared by aergo/koinos/witnet — this byte-identical agreement across three
// independent implementations is the substitute for the (nonexistent) RFC 9381
// secp256k1 test vectors (see vrf-sortition-roadmap.md §11.2).

#include "vrf.h"

#include "key.h"
#include "pubkey.h"
#include "test/test_bathron.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(vrf_tests, BasicTestingSetup)

namespace {
const std::vector<unsigned char> kSampleMsg = {'s', 'a', 'm', 'p', 'l', 'e'};
}

// Official PROVE vector: sk c9afa9d8..., msg "sample" → exact 81-byte proof.
// Determinism: a second prove of the same (sk, msg) yields the identical proof.
BOOST_AUTO_TEST_CASE(official_prove_vector_is_deterministic)
{
    const std::vector<unsigned char> sk = ParseHex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    const std::vector<unsigned char> expectedProof = ParseHex(
        "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08"
        "748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf"
        "66ebf5abe6fadb01b5efb37c0a0ec9");

    vrf::Proof proof{};
    BOOST_REQUIRE(vrf::Prove(proof, sk.data(), kSampleMsg));
    BOOST_CHECK_EQUAL_COLLECTIONS(proof.begin(), proof.end(),
                                  expectedProof.begin(), expectedProof.end());

    vrf::Proof proof2{};
    BOOST_REQUIRE(vrf::Prove(proof2, sk.data(), kSampleMsg));
    BOOST_CHECK(proof == proof2);
}

// Official VERIFY vector: known (pk, proof, msg) → known 32-byte output, and
// proof_to_hash on the verified proof returns the same output.
BOOST_AUTO_TEST_CASE(official_verify_vector)
{
    const std::vector<unsigned char> pk = ParseHex("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
    const std::vector<unsigned char> proofVec = ParseHex(
        "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08"
        "14faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4"
        "b2c31b5ef6997a585a9f1a72517b6f");
    const std::vector<unsigned char> expectedOut = ParseHex("612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81");

    BOOST_REQUIRE_EQUAL(proofVec.size(), vrf::PROOF_SIZE);
    vrf::Proof proof{};
    std::copy(proofVec.begin(), proofVec.end(), proof.begin());

    vrf::Output out{};
    BOOST_REQUIRE(vrf::Verify(out, proof, pk.data(), kSampleMsg));
    BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(),
                                  expectedOut.begin(), expectedOut.end());

    vrf::Output out2{};
    BOOST_REQUIRE(vrf::ProofToHash(out2, proof));
    BOOST_CHECK(out == out2);
}

// A single flipped bit anywhere in the proof must make verification fail.
BOOST_AUTO_TEST_CASE(tampered_proof_is_rejected)
{
    const std::vector<unsigned char> pk = ParseHex("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
    const std::vector<unsigned char> proofVec = ParseHex(
        "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08"
        "14faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4"
        "b2c31b5ef6997a585a9f1a72517b6f");

    vrf::Proof proof{};
    std::copy(proofVec.begin(), proofVec.end(), proof.begin());
    proof[40] ^= 0x01;

    vrf::Output out{};
    BOOST_CHECK(!vrf::Verify(out, proof, pk.data(), kSampleMsg));
}

// audit F1: malformed proofs whose scalars are out of range (zero, or s == group order)
// must be REJECTED CLEANLY. vrf_verify now checks every ecmult return, so it never reads
// an uninitialised point (was undefined behaviour upstream). Both must return false.
BOOST_AUTO_TEST_CASE(malformed_out_of_range_scalar_proof_is_rejected)
{
    const std::vector<unsigned char> pk = ParseHex("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
    const std::vector<unsigned char> proofVec = ParseHex(
        "031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08"
        "14faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4"
        "b2c31b5ef6997a585a9f1a72517b6f");

    // (a) zero the c (pi[33:49]) and s (pi[49:81]) fields → zero scalars → clean reject.
    vrf::Proof zero{};
    std::copy(proofVec.begin(), proofVec.end(), zero.begin());
    for (size_t i = 33; i < vrf::PROOF_SIZE; ++i) zero[i] = 0;
    vrf::Output o1{};
    BOOST_CHECK(!vrf::Verify(o1, zero, pk.data(), kSampleMsg));

    // (b) set s := n (the secp256k1 group order) → overflow on parse → clean reject.
    vrf::Proof overflow{};
    std::copy(proofVec.begin(), proofVec.end(), overflow.begin());
    const std::vector<unsigned char> order = ParseHex(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    std::copy(order.begin(), order.end(), overflow.begin() + 49);  // s field = n
    vrf::Output o2{};
    BOOST_CHECK(!vrf::Verify(o2, overflow, pk.data(), kSampleMsg));
}

// End-to-end through BATHRON's own key derivation: prove with a CKey, verify
// against the CPubKey it yields, and check output consistency.
BOOST_AUTO_TEST_CASE(prove_verify_roundtrip_with_ckey)
{
    const std::vector<unsigned char> skBytes = ParseHex("0000000000000000000000000000000000000000000000000000000000000001");
    CKey key;
    key.Set(skBytes.begin(), skBytes.end(), /*fCompressedIn=*/true);
    BOOST_REQUIRE(key.IsValid());
    CPubKey pub = key.GetPubKey();
    BOOST_REQUIRE(pub.IsCompressed());
    BOOST_REQUIRE_EQUAL(pub.size(), vrf::PUBKEY_SIZE);

    const std::vector<unsigned char> seed = ParseHex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");

    vrf::Proof proof{};
    BOOST_REQUIRE(vrf::Prove(proof, skBytes.data(), seed));

    vrf::Output out{};
    BOOST_REQUIRE(vrf::Verify(out, proof, pub.begin(), seed));

    // Wrong message must not verify.
    const std::vector<unsigned char> otherSeed = ParseHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    vrf::Output out2{};
    BOOST_CHECK(!vrf::Verify(out2, proof, pub.begin(), otherSeed));
}

// Operator-derived VRF key (étape 3.1b): distinct from the operator key, deterministic,
// compressed, and usable end-to-end (Prove with derived secret, Verify with derived pubkey).
BOOST_AUTO_TEST_CASE(derive_vrf_key_from_operator)
{
    CKey op;
    op.MakeNewKey(/*fCompressed=*/true);

    CKey vrfKey;
    BOOST_REQUIRE(vrf::DeriveKeyFromOperator(op, vrfKey));
    BOOST_REQUIRE(vrfKey.IsValid());

    // Distinct scalar from the operator key (no key reuse across primitives).
    BOOST_CHECK(vrfKey.GetPubKey() != op.GetPubKey());

    // Compressed → 33-byte pubkey, exactly the pubKeyVRF carried in ProRegTx v3.
    const CPubKey vrfPub = vrfKey.GetPubKey();
    BOOST_CHECK(vrfPub.IsCompressed());
    BOOST_REQUIRE_EQUAL(vrfPub.size(), vrf::PUBKEY_SIZE);

    // Deterministic: same operator key → identical VRF key (registrar pubkey ==
    // signer's runtime key). Different operator key → different VRF key.
    CKey vrfKey2;
    BOOST_REQUIRE(vrf::DeriveKeyFromOperator(op, vrfKey2));
    BOOST_CHECK(vrfKey2.GetPubKey() == vrfPub);

    CKey op2;
    op2.MakeNewKey(true);
    CKey vrfOther;
    BOOST_REQUIRE(vrf::DeriveKeyFromOperator(op2, vrfOther));
    BOOST_CHECK(vrfOther.GetPubKey() != vrfPub);

    // End-to-end: the derived keypair proves and verifies over a seed.
    const std::vector<unsigned char> seed = ParseHex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
    const std::vector<unsigned char> sk(vrfKey.begin(), vrfKey.end());
    vrf::Proof proof{};
    BOOST_REQUIRE(vrf::Prove(proof, sk.data(), seed));
    vrf::Output out{};
    BOOST_CHECK(vrf::Verify(out, proof, vrfPub.begin(), seed));

    // An invalid operator key derives nothing.
    CKey invalid;
    BOOST_CHECK(!vrf::DeriveKeyFromOperator(invalid, vrfKey2));
}

BOOST_AUTO_TEST_SUITE_END()
