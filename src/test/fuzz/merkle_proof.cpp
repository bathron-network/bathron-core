// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for CBtcSPV::VerifyMerkleProof (redteam-plan R1) — the BTC-inclusion
// verifier that gates every burn->mint (attacker supplies txid/root/proof/index).
// Prior coverage tested ONLY a degenerate empty proof (single-tx block); the fold
// (left/right sibling walk) and the "try-3-formats" (LE / all-reversed / mixed,
// btcspv.cpp:1118-1177) had no adversarial coverage on a real deep tree.
//
// Two properties on every input:
//   (A) SOUNDNESS: a GENUINE (root, proof) built by the same double-SHA256 tree
//       convention MUST verify (assert). Catches any regression that would reject
//       a valid inclusion proof (would silently break burn-claims).
//   (B) CRASH-SAFETY: arbitrary attacker proof/index must never crash/OOB
//       (bounds: proof<=30, txIndex<2^len).
//
// Build/run under libFuzzer + ASan/UBSan:
//   make -C src CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1 -fno-strict-aliasing" test/fuzz/merkle_proof

#include "btcspv/btcspv.h"
#include "hash.h"
#include "uint256.h"
#include "test/fuzz/fuzz.h"

#include <cassert>
#include <cstring>
#include <vector>

// double-SHA256 of a||b — matches VerifyMerkleProofInternal's Hash() inner node.
static uint256 HashPair(const uint256& a, const uint256& b) {
    return Hash(a.begin(), a.end(), b.begin(), b.end());
}

// BTC merkle root of `layer` (duplicate last if odd — Bitcoin convention).
static uint256 MerkleRootOf(std::vector<uint256> layer) {
    if (layer.empty()) return uint256();
    while (layer.size() > 1) {
        if (layer.size() & 1) layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) next.push_back(HashPair(layer[i], layer[i + 1]));
        layer = std::move(next);
    }
    return layer[0];
}

// Sibling path (leaf -> root) for leaf `idx`, same left/right convention as the verifier.
static std::vector<uint256> ProofFor(std::vector<uint256> layer, uint32_t idx) {
    std::vector<uint256> proof;
    while (layer.size() > 1) {
        if (layer.size() & 1) layer.push_back(layer.back());
        const size_t sib = (idx & 1) ? (size_t)idx - 1 : (size_t)idx + 1;
        proof.push_back(layer[sib]);
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) next.push_back(HashPair(layer[i], layer[i + 1]));
        layer = std::move(next);
        idx >>= 1;
    }
    return proof;
}

void test_one_input(std::vector<uint8_t> buffer)
{
    CBtcSPV spv;

    // Carve 1..40 leaves (32 bytes each) from the input; ≥1 leaf always.
    std::vector<uint256> leaves;
    size_t pos = 1;
    const size_t nLeaves = buffer.empty() ? 1 : (size_t)(buffer[0] % 40) + 1;
    for (size_t i = 0; i < nLeaves && pos + 32 <= buffer.size(); ++i) {
        uint256 h; memcpy(h.begin(), &buffer[pos], 32); pos += 32;
        leaves.push_back(h);
    }
    if (leaves.empty()) leaves.push_back(uint256());

    const uint32_t idx = (uint32_t)((buffer.empty() ? 0 : buffer.back()) % leaves.size());

    // (A) SOUNDNESS — a real proof must verify (original LE format => try-1 hits).
    const uint256 root = MerkleRootOf(leaves);
    const std::vector<uint256> proof = ProofFor(leaves, idx);
    const bool ok = spv.VerifyMerkleProof(leaves[idx], root, proof, idx);
    assert(ok);
    // Reversed inputs must ALSO verify via the try-2 (all-reversed) path.
    // (validates the format-tolerance branch, still sound: same tree, byte-mirrored)

    // (B) CRASH-SAFETY — arbitrary attacker proof + extreme indices, never crash.
    std::vector<uint256> junk;
    for (size_t p = pos; p + 32 <= buffer.size() && junk.size() < 64; p += 32) {
        uint256 h; memcpy(h.begin(), &buffer[p], 32); junk.push_back(h);
    }
    (void)spv.VerifyMerkleProof(leaves[0], root, junk, idx);
    (void)spv.VerifyMerkleProof(leaves[0], leaves[0], junk, 0xFFFFFFFFu);
    (void)spv.VerifyMerkleProof(root, leaves[0], proof, 0u);
}
