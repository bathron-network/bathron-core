// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_VRF_H
#define BATHRON_VRF_H

#include <array>
#include <cstddef>
#include <vector>

class CKey;

/**
 * Thin, deterministic C++ wrapper over the vendored ECVRF-secp256k1 module
 * (ciphersuite SECP256K1_SHA256_TAI, suite octet 0xFE, draft-irtf-cfrg-vrf-05;
 * RFC 9381 defines no secp256k1 suite). Hash-to-curve = try-and-increment,
 * nonce = RFC 6979 → prove is deterministic, required for consensus.
 *
 * This is the primitive the finality-committee sortition (state/quorum.h) builds
 * on — consensus-critical: the sole finality path (proof carried in CHuSignature).
 */
namespace vrf {

static constexpr size_t SECKEY_SIZE = 32;
static constexpr size_t PUBKEY_SIZE = 33;  // compressed
static constexpr size_t PROOF_SIZE  = 81;  // gamma(33) || c(16) || s(32)
static constexpr size_t OUTPUT_SIZE = 32;  // beta

using Proof  = std::array<unsigned char, PROOF_SIZE>;
using Output = std::array<unsigned char, OUTPUT_SIZE>;

/** Deterministic VRF prove. `msg` is the VRF input (the public seed). Returns
 *  false on failure (e.g. invalid secret key). */
bool Prove(Proof& proofOut, const unsigned char seckey[SECKEY_SIZE], const std::vector<unsigned char>& msg);

/** Verify `proof` against a 33-byte compressed `pubkey` and `msg`. On success
 *  fills `outputOut` (the 32-byte VRF output) and returns true. */
bool Verify(Output& outputOut, const Proof& proof, const unsigned char pubkey[PUBKEY_SIZE], const std::vector<unsigned char>& msg);

/** Recover the VRF output from a proof WITHOUT verifying it. Only use on a proof
 *  that was already verified or produced locally. */
bool ProofToHash(Output& outputOut, const Proof& proof);

/**
 * Derive the dedicated VRF key from the operator's ECDSA key (VRF roadmap étape 3.1b).
 *
 * The VRF secret is a domain-separated hash of the operator secret — a DISTINCT
 * secp256k1 scalar, never used for ECDSA, so this satisfies the "dedicated VRF key"
 * decision (§11.1) while the operator still manages a SINGLE secret (its operator key).
 * Deterministic: the registrar's published pubKeyVRF and the signer's runtime proofs
 * derive byte-identically from the same operator key. The derived key is compressed,
 * so its public key is the 33-byte `pubKeyVRF` carried in ProRegTx v3.
 *
 * @return false if `operatorKey` is invalid, or (astronomically unlikely) no valid
 *         scalar is found within the bounded retry count.
 */
bool DeriveKeyFromOperator(const CKey& operatorKey, CKey& vrfKeyOut);

} // namespace vrf

#endif // BATHRON_VRF_H
