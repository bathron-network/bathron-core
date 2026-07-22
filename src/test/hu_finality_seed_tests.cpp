// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for the finality-committee SEED derivation (anti double-lever).
//
// hu::GetHuFinalitySeedHash(pindex, k) must return the hash of the ancestor at
// height (H - k), purely from chain structure (deterministic, no runtime finality
// check), clamping to genesis when H < k. This is étape 1 of the VRF-sortition
// roadmap: it decouples the finality-committee seed (hash(H-k)) from the DMM
// production seed (hash(H-1)), so a single block producer no longer controls both.

#include "test/test_bathron.h"

#include "arith_uint256.h"
#include "chain.h"
#include "state/quorum.h"
#include "uint256.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(hu_finality_seed_tests, BasicTestingSetup)

namespace {
// Build a linked CBlockIndex chain of `length` blocks. Each block's hash encodes
// its height (hash == ArithToUint256(height)) so assertions read trivially.
struct TestChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks;

    explicit TestChain(int length) : hashes(length), blocks(length)
    {
        for (int i = 0; i < length; i++) {
            hashes[i] = ArithToUint256(i);
            blocks[i].nHeight = i;
            blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
            blocks[i].phashBlock = &hashes[i];
            blocks[i].BuildSkip();  // required: GetAncestor follows pskip
        }
    }

    const CBlockIndex* at(int height) const { return &blocks[height]; }
};

uint256 HashOfHeight(int height) { return ArithToUint256(height); }
} // namespace

// Normal case: seed of block H = hash(H - k), for a range of heights and offsets.
BOOST_AUTO_TEST_CASE(seed_is_hash_of_ancestor_at_offset)
{
    TestChain chain(200);

    for (int k : {1, 3, 6, 12}) {
        for (int H : {50, 100, 150, 199}) {
            uint256 seed = hu::GetHuFinalitySeedHash(chain.at(H), k);
            BOOST_CHECK_MESSAGE(seed == HashOfHeight(H - k),
                "H=" << H << " k=" << k << " expected hash(H-k)");
        }
    }
}

// k=1 must reproduce the legacy seed (hash of the immediate parent, H-1).
BOOST_AUTO_TEST_CASE(offset_one_matches_legacy_pprev_seed)
{
    TestChain chain(50);
    const CBlockIndex* pindex = chain.at(40);
    uint256 seed = hu::GetHuFinalitySeedHash(pindex, 1);
    BOOST_CHECK(seed == pindex->pprev->GetBlockHash());
    BOOST_CHECK(seed == HashOfHeight(39));
}

// Bootstrap: when H - k < 0, the height clamps to 0 → genesis hash. Also exactly
// at H == k the ancestor is the genesis block (height 0).
BOOST_AUTO_TEST_CASE(bootstrap_clamps_to_genesis)
{
    TestChain chain(20);
    const uint256 genesis = HashOfHeight(0);

    // H < k  → clamp to genesis
    BOOST_CHECK(hu::GetHuFinalitySeedHash(chain.at(3), 6) == genesis);
    BOOST_CHECK(hu::GetHuFinalitySeedHash(chain.at(0), 6) == genesis);
    BOOST_CHECK(hu::GetHuFinalitySeedHash(chain.at(5), 6) == genesis);

    // H == k  → exactly genesis (height 0), no clamp needed
    BOOST_CHECK(hu::GetHuFinalitySeedHash(chain.at(6), 6) == genesis);

    // H == k + 1 → height 1, first non-genesis seed
    BOOST_CHECK(hu::GetHuFinalitySeedHash(chain.at(7), 6) == HashOfHeight(1));
}

// Determinism: two independent computations on equivalent chains agree, and the
// result depends only on (H, k) — not on the tip or any external state.
BOOST_AUTO_TEST_CASE(seed_is_deterministic)
{
    TestChain a(120);
    TestChain b(120);
    for (int H : {30, 64, 119}) {
        BOOST_CHECK(hu::GetHuFinalitySeedHash(a.at(H), 6) ==
                    hu::GetHuFinalitySeedHash(b.at(H), 6));
    }
}

// Null pindex → null hash (defensive contract).
BOOST_AUTO_TEST_CASE(null_pindex_returns_null)
{
    BOOST_CHECK(hu::GetHuFinalitySeedHash(nullptr, 6) == uint256());
}

BOOST_AUTO_TEST_SUITE_END()
