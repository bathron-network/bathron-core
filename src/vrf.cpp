// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vrf.h"

#include "hash.h"
#include "key.h"
#include "support/cleanse.h"
#include "uint256.h"

#include <secp256k1.h>
#include <secp256k1_vrf.h>

#include <string>

namespace {
// A single SIGN context, created once. It is needed only to derive the public
// key inside Prove(); secp256k1_vrf_prove/verify/proof_to_hash take no context.
secp256k1_context* GetVrfContext()
{
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    return ctx;
}
} // namespace

namespace vrf {

bool Prove(Proof& proofOut, const unsigned char seckey[SECKEY_SIZE], const std::vector<unsigned char>& msg)
{
    secp256k1_context* ctx = GetVrfContext();
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, seckey)) {
        return false;
    }
    return secp256k1_vrf_prove(proofOut.data(), seckey, &pub,
                               msg.data(), static_cast<unsigned int>(msg.size())) == 1;
}

bool Verify(Output& outputOut, const Proof& proof, const unsigned char pubkey[PUBKEY_SIZE], const std::vector<unsigned char>& msg)
{
    return secp256k1_vrf_verify(outputOut.data(), proof.data(), pubkey,
                                msg.data(), static_cast<unsigned int>(msg.size())) == 1;
}

bool ProofToHash(Output& outputOut, const Proof& proof)
{
    return secp256k1_vrf_proof_to_hash(outputOut.data(), proof.data()) == 1;
}

bool DeriveKeyFromOperator(const CKey& operatorKey, CKey& vrfKeyOut)
{
    if (!operatorKey.IsValid()) {
        return false;
    }
    // vrf_sk = SHA256(domain || operator_sk || counter), retrying on the vanishingly
    // rare out-of-range scalar. Counter starts at 0 → fully deterministic.
    for (uint32_t counter = 0; counter < 256; ++counter) {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("BATHRON-VRF-derive-v1");
        ss.write(reinterpret_cast<const char*>(operatorKey.begin()),
                 static_cast<size_t>(operatorKey.size()));
        ss << counter;
        uint256 h = ss.GetHash();
        vrfKeyOut.Set(h.begin(), h.end(), /*fCompressed=*/true);
        const bool ok = vrfKeyOut.IsValid();
        // audit F3: h holds the derived VRF SECRET — wipe the stack copy (non-elidable)
        // before returning/looping; the secret now lives only in vrfKeyOut (secure alloc).
        memory_cleanse(h.begin(), h.size());
        if (ok) {
            return true;
        }
    }
    return false;
}

} // namespace vrf
