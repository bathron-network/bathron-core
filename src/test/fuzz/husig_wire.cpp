// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the HUSIG finality-signature WIRE chokepoint (hard-test #7).
//
// This is the third and last of the "attacker bytes meet consensus money"
// chokepoints named in HARDTEST-CAMPAIGN.md — the other two (the script
// interpreter and the ConnectBlock settlement path) are fuzzed by script_eval
// and settlement_block. The HUSIG path is reached by an UNAUTHENTICATED remote
// peer: net_processing does `vRecv >> sig` into an hu::CHuSignature and hands it
// to ProcessHuSignature -> ValidateSignatureFromContext, which runs
//   (1) the wire deserialization of CHuSignature,
//   (2) CPubKey::RecoverCompact() over the attacker's ECDSA signature bytes, and
//   (3) vrf::Verify() over the attacker's 81-byte ECVRF proof
// — the exact site where the VRF audit found finding F1 (unchecked ecmult -> UB
// on a malformed proof, since fixed). ValidateSignatureFromContext is private, so
// we fuzz those three attacker-controlled crypto entries directly; the rest of
// the function is map lookups on the (hostile) proTxHash, which cannot crash.
//
// Property under libFuzzer + ASan/UBSan: no crash / OOM / UB on ANY input.
//
//   ./configure --enable-fuzz --without-gui --disable-bench CC=clang CXX=clang++
//   make -C src test/fuzz/husig_wire \
//     CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1" \
//     LDFLAGS="-fsanitize=fuzzer,address,undefined"
//   ./src/test/fuzz/husig_wire corpus/

#include "hash.h"
#include "pubkey.h"
#include "state/finality.h"
#include "streams.h"
#include "test/fuzz/fuzz.h"
#include "uint256.h"
#include "vrf.h"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace {
// A valid compressed secp256k1 public key (the generator point G). Used as the
// VRF public key so vrf::Verify() actually runs its curve math on the attacker's
// proof rather than bailing on an invalid key.
const unsigned char VRF_PUB[vrf::PUBKEY_SIZE] = {
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
};
} // namespace

void test_one_input(std::vector<uint8_t> buffer)
{
    // (1) The exact wire parse: `vRecv >> sig`. Hostile bytes -> CHuSignature.
    {
        CDataStream ss(buffer, SER_NETWORK, PROTOCOL_VERSION);
        try {
            hu::CHuSignature sig;
            ss >> sig;
            // Touch every field the handler reads (ProcessHuSignature basic checks).
            (void)sig.blockHash.IsNull();
            (void)sig.proTxHash.IsNull();
            (void)sig.vchSig.size();
            (void)sig.vchVrfProof.size();
        } catch (const std::exception&) {
            // Truncated / oversized vectors throw — expected, must not crash.
        }
    }
    if (buffer.empty()) return;

    // The message digest the signature is checked against: SHA256("HUSIG"||blockHash).
    CHashWriter h(SER_GETHASH, 0);
    h << std::string("HUSIG");
    h << uint256();  // fixed blockHash — the sig bytes are what we fuzz
    const uint256 msgHash = h.GetHash();

    // (2) ECDSA recovery on the attacker's signature bytes. RecoverCompact needs
    // exactly 65 bytes; build one from the buffer so we reach the recovery internals
    // (recovery-id / r / s edge cases) rather than the size early-out.
    {
        std::vector<unsigned char> sig65(65, 0);
        for (size_t i = 0; i < 65 && i < buffer.size(); ++i) sig65[i] = buffer[i];
        CPubKey rec;
        (void)rec.RecoverCompact(msgHash, sig65);
    }

    // (3) ECVRF verify on the attacker's 81-byte proof (the F1 UB site). First 81
    // bytes (zero-padded) as the proof; up to 64 bytes as the seed message.
    {
        vrf::Proof proof{};
        for (size_t i = 0; i < vrf::PROOF_SIZE && i < buffer.size(); ++i) proof[i] = buffer[i];
        std::vector<unsigned char> msg(buffer.begin(),
                                       buffer.begin() + std::min<size_t>(buffer.size(), 64));
        vrf::Output out;
        (void)vrf::Verify(out, proof, VRF_PUB, msg);
    }
}
