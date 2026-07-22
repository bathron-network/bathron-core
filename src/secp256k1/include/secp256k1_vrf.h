#ifndef SECP256K1_VRF_H
#define SECP256K1_VRF_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ECVRF over secp256k1, ciphersuite SECP256K1_SHA256_TAI (suite octet 0xFE,
 * IETF draft-irtf-cfrg-vrf-05; RFC 9381 defines no secp256k1 suite). Vendored
 * from koinos/secp256k1-vrf @ d3e16a7d (MIT), itself derived from
 * aergoio/secp256k1-vrf. Hash-to-curve = try-and-increment; nonce = RFC 6979.
 * Proof is 81 bytes (gamma||c||s), output/beta is 32 bytes. */

/** Generate a VRF output and proof from a secret key and a message.
 *  Returns: 1 on success, 0 on failure.
 *  Out:    proof:   pointer to a 81-byte array to be filled by the function.
 *  In:     seckey:  pointer to a 32-byte private key.
 *          pubkey:  pointer to an initialized secp256k1_pubkey.
 *          msg:     pointer to the input message.
 *          msglen:  length of msg in bytes.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_vrf_prove(
    unsigned char proof[81],
    const unsigned char *seckey,
    secp256k1_pubkey* pubkey,
    const void *msg,
    const unsigned int msglen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verify a VRF proof and recover its output.
 *  Returns: 1 on success, 0 on failure.
 *  Out:    output:  pointer to a 32-byte array to be filled by the function.
 *  In:     proof:   pointer to a 81-byte array containing the proof.
 *          pk:      pointer to a 33-byte compressed public key.
 *          msg:     pointer to the input message.
 *          msglen:  length of msg in bytes.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_vrf_verify(
    unsigned char output[32],
    const unsigned char proof[81],
    const unsigned char pk[33],
    const void *msg, const unsigned int msglen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Recover the VRF output from a proof.
 *  Returns: 1 on success, 0 on failure.
 *  Out:    output:  pointer to a 32-byte array to be filled by the function.
 *  In:     proof:   pointer to a 81-byte array containing the proof.
 *
 *  ATTENTION: DO NOT USE without prior verification of the proof, unless the
 *             proof was just generated locally via secp256k1_vrf_prove().
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_vrf_proof_to_hash(
    unsigned char output[32],
    const unsigned char proof[81]
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_VRF_H */
