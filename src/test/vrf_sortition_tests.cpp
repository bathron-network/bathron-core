// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for the VRF sortition primitive (roadmap étape 3.2): IsVrfSelected (pure
// 1-op-1-vote decision) and IsOperatorVrfSelected (verify a proof + decide). Not
// yet wired into signaling — these test the primitive in isolation.

#include "state/quorum.h"
#include "vrf.h"

#include "arith_uint256.h"
#include "chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "streams.h"
#include "sync.h"
#include "test/util/mn_finality_setup.h"
#include "uint256.h"
#include "validation.h"
#include "version.h"

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace hu;

BOOST_FIXTURE_TEST_SUITE(vrf_sortition_tests, BasicTestingSetup)

// Bounds and edge cases of the pure decision function.
BOOST_AUTO_TEST_CASE(sortition_bounds_and_edges)
{
    vrf::Output zero{};            // smallest possible output
    vrf::Output maxo;
    maxo.fill(0xff);               // largest possible output

    // p = E/N = 1/4: output 0 is under the threshold, output max is over it.
    BOOST_CHECK(IsVrfSelected(zero, /*E=*/1, /*N=*/4));
    BOOST_CHECK(!IsVrfSelected(maxo, /*E=*/1, /*N=*/4));

    // E >= N → everyone is selected, regardless of output.
    BOOST_CHECK(IsVrfSelected(maxo, /*E=*/4, /*N=*/4));
    BOOST_CHECK(IsVrfSelected(maxo, /*E=*/5, /*N=*/4));

    // Degenerate inputs → never selected.
    BOOST_CHECK(!IsVrfSelected(zero, /*E=*/0, /*N=*/4));
    BOOST_CHECK(!IsVrfSelected(zero, /*E=*/2, /*N=*/0));
    BOOST_CHECK(!IsVrfSelected(zero, /*E=*/-1, /*N=*/4));

    // Deterministic: identical inputs → identical result.
    BOOST_CHECK_EQUAL(IsVrfSelected(zero, 1, 4), IsVrfSelected(zero, 1, 4));
    BOOST_CHECK_EQUAL(IsVrfSelected(maxo, 1, 4), IsVrfSelected(maxo, 1, 4));
}

// Over many uniform outputs the selected fraction tracks p = E/N.
BOOST_AUTO_TEST_CASE(sortition_calibrates_to_p)
{
    const int E = 1, N = 2;  // p = 0.5
    const int M = 4000;
    int selected = 0;
    for (int i = 0; i < M; ++i) {
        vrf::Output o;
        GetRandBytes(o.data(), static_cast<int>(o.size()));
        if (IsVrfSelected(o, E, N)) ++selected;
    }
    const double frac = static_cast<double>(selected) / M;
    BOOST_CHECK_GT(frac, 0.45);
    BOOST_CHECK_LT(frac, 0.55);
}

// ceil(2/3·E) derivation, with the legacy-equivalence anchors (E = old committee size).
BOOST_AUTO_TEST_CASE(vrf_finality_threshold_ceil_two_thirds)
{
    // Reproduces today's fixed thresholds exactly when E equals the old quorum size.
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(12), 8);  // historical anchor (old fixed 8/12)
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(3), 2);   // N=3 -> 2
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(1), 1);   // N=1 -> 1

    // ceil(2E/3) across residues mod 3.
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(2), 2);   // ceil(4/3)=2
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(4), 3);   // ceil(8/3)=3
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(6), 4);   // exactly 4
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(9), 6);   // exactly 6
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(30), 20); // a larger open-network E

    // Degenerate E → 0 (can never finalize), never negative.
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(0), 0);
    BOOST_CHECK_EQUAL(HuVrfFinalityThreshold(-5), 0);

    // Strictly a super-majority: threshold is always > E/2 for E >= 1.
    for (int E = 1; E <= 64; ++E) {
        BOOST_CHECK_GT(2 * HuVrfFinalityThreshold(E), E);
    }
}

// HuActiveFinalityThreshold(consensus, N) = ceil(2/3 · min(E, N)) — the auto-scaling
// committee. One fixed E (the cap) covers a network from a handful of operators to
// thousands with NO retuning: below E the whole population votes; at/above E the
// committee is capped (VRF samples ~E) and the threshold stops growing.
BOOST_AUTO_TEST_CASE(active_finality_threshold_scales_with_min_E_N)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int E = consensus.nHuExpectedCommitteeSize;  // committee CAP (128)
    BOOST_REQUIRE_GT(E, 12);  // E is the large open-network cap, not a tiny committee

    // N <= E: effective committee = N, threshold = ceil(2/3·N) (tracks the network size).
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 3),  HuVrfFinalityThreshold(3));   // 2 (today's 3-operator fleet)
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 12), HuVrfFinalityThreshold(12));  // 8
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, E),  HuVrfFinalityThreshold(E));

    // N >= E: capped at E — threshold stays ceil(2/3·E), so 130 or 100000 operators need
    // no parameter change (the whole point: scale without retuning).
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, E + 1), HuVrfFinalityThreshold(E));
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 400),   HuVrfFinalityThreshold(E));
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 100000),HuVrfFinalityThreshold(E));

    // N <= 0 (block unresolved): conservative fallback to E (a high, never-0 threshold).
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 0),  HuVrfFinalityThreshold(E));
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, -5), HuVrfFinalityThreshold(E));
    BOOST_CHECK_GE(HuActiveFinalityThreshold(consensus, 0), 1);
}

struct SortitionSetup : public MultiMNFinalitySetup {
    SortitionSetup() : MultiMNFinalitySetup(/*numOperators=*/4, /*mnsPerOperator=*/1) {}
};

// End-to-end: a real proof over the block's finality seed → IsOperatorVrfSelected
// agrees with the independently-computed decision; tamper/wrong-key are rejected.
BOOST_FIXTURE_TEST_CASE(operator_vrf_selection_end_to_end, SortitionSetup)
{
    // Local CBlockIndex chain (hash encodes height) for the seed derivation.
    const int len = 30;
    std::vector<uint256> hashes(len);
    std::vector<CBlockIndex> blocks(len);
    for (int i = 0; i < len; ++i) {
        hashes[i] = ArithToUint256(i);
        blocks[i].nHeight = i;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].phashBlock = &hashes[i];
        blocks[i].BuildSkip();
    }
    const CBlockIndex* pindex = &blocks[20];

    // A dedicated VRF keypair (the operator's secret stays local).
    CKey vrfKey;
    vrfKey.MakeNewKey(/*fCompressed=*/true);
    const CPubKey vrfPub = vrfKey.GetPubKey();

    const Consensus::Params& consensus = Params().GetConsensus();
    const uint256 seed = GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
    const std::vector<unsigned char> msg(seed.begin(), seed.end());

    // Produce the proof, exactly as a signing node would.
    vrf::Proof proof{};
    const std::vector<unsigned char> sk(vrfKey.begin(), vrfKey.end());
    BOOST_REQUIRE(vrf::Prove(proof, sk.data(), msg));

    // Independently compute the expected decision.
    vrf::Output out{};
    BOOST_REQUIRE(vrf::Verify(out, proof, vrfPub.begin(), msg));
    const int N = static_cast<int>(operators.size());
    const bool expected = IsVrfSelected(out, consensus.nHuExpectedCommitteeSize, N);

    BOOST_CHECK_EQUAL(IsOperatorVrfSelected(mnList, pindex, vrfPub, proof), expected);

    // A tampered proof never selects (verification fails).
    vrf::Proof bad = proof;
    bad[10] ^= 0x01;
    BOOST_CHECK(!IsOperatorVrfSelected(mnList, pindex, vrfPub, bad));

    // A different public key never selects with this proof.
    CKey other;
    other.MakeNewKey(true);
    BOOST_CHECK(!IsOperatorVrfSelected(mnList, pindex, other.GetPubKey(), proof));

    // Null pindex → not selected.
    BOOST_CHECK(!IsOperatorVrfSelected(mnList, nullptr, vrfPub, proof));
}

// The 3.1b→3.3d→3.3e contract: the signer derives its VRF key FROM the operator key
// (vrf::DeriveKeyFromOperator), proves over the finality seed, and publishes the proof
// with the operator-derived pubKeyVRF. The verifier (IsOperatorVrfSelected — exactly
// what ValidateSignature calls under the gate) must accept it and agree with the
// independent decision. This closes the loop between key derivation, signing, and
// verification with a DERIVED (not freshly random) key.
BOOST_FIXTURE_TEST_CASE(derived_operator_key_vrf_end_to_end, SortitionSetup)
{
    const int len = 30;
    std::vector<uint256> hashes(len);
    std::vector<CBlockIndex> blocks(len);
    for (int i = 0; i < len; ++i) {
        hashes[i] = ArithToUint256(i);
        blocks[i].nHeight = i;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].phashBlock = &hashes[i];
        blocks[i].BuildSkip();
    }
    const CBlockIndex* pindex = &blocks[20];

    // Operator key → derived VRF key (what the registrar publishes AND the signer uses).
    CKey opKey;
    opKey.MakeNewKey(/*fCompressed=*/true);
    CKey vrfKey;
    BOOST_REQUIRE(vrf::DeriveKeyFromOperator(opKey, vrfKey));
    const CPubKey vrfPub = vrfKey.GetPubKey();  // == ProRegTx v3 pubKeyVRF (getvrfpubkey)

    const Consensus::Params& consensus = Params().GetConsensus();
    const uint256 seed = GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
    const std::vector<unsigned char> msg(seed.begin(), seed.end());

    // Signer proves with the DERIVED secret (as SignBlockWithMN path does).
    vrf::Proof proof{};
    const std::vector<unsigned char> sk(vrfKey.begin(), vrfKey.end());
    BOOST_REQUIRE(vrf::Prove(proof, sk.data(), msg));

    vrf::Output out{};
    BOOST_REQUIRE(vrf::Verify(out, proof, vrfPub.begin(), msg));
    const int N = static_cast<int>(operators.size());
    const bool expected = IsVrfSelected(out, consensus.nHuExpectedCommitteeSize, N);

    // Verifier accepts the derived-key proof and agrees with the decision.
    BOOST_CHECK_EQUAL(IsOperatorVrfSelected(mnList, pindex, vrfPub, proof), expected);

    // A proof from a key derived off a DIFFERENT operator key does not verify here.
    CKey opOther;
    opOther.MakeNewKey(true);
    CKey vrfOther;
    BOOST_REQUIRE(vrf::DeriveKeyFromOperator(opOther, vrfOther));
    BOOST_CHECK(!IsOperatorVrfSelected(mnList, pindex, vrfOther.GetPubKey(), proof));
}

// Multi-operator finality e2e: N=6 distinct operators (each operator-derived VRF key,
// pubKeyVRF in dmnState), all sign block H with a VRF proof over the seed. Composes the
// real pipeline — signer derive+prove (3.3d) → wire round-trip (3.3c) → verifier
// IsOperatorVrfSelected (3.3e core of ValidateSignature) → per-operator counting vs
// ceil(2/3·E) (3.3b). The finality decision must equal "VRF-selected operators >= threshold".
struct ManyOpSortitionSetup : public MultiMNFinalitySetup {
    ManyOpSortitionSetup() : MultiMNFinalitySetup(/*numOperators=*/6, /*mnsPerOperator=*/1) {}
};

BOOST_FIXTURE_TEST_CASE(multi_operator_vrf_finality_e2e, ManyOpSortitionSetup)
{
    // A local chain long enough to give many distinct seeds hash(H-k).
    const int len = 80;
    std::vector<uint256> hashes(len);
    std::vector<CBlockIndex> blocks(len);
    // Chain rooted at height 0 (so BuildSkip/GetAncestor — used by GetHuFinalitySeedHash
    // — stay within the synthetic chain), and registered in mapBlockIndex with the
    // operator list cached per block, so the per-block operator resolution
    // (GetUniqueOperatorCount → mapBlockIndex → GetListForBlock(pprev)) works on this
    // synthetic chain exactly as on a real one. V6_0 is ALWAYS_ACTIVE on testnet, so
    // GetListForBlock does not early-return empty at these low heights.
    for (int i = 0; i < len; ++i) {
        hashes[i] = ArithToUint256(0xE2E00000u + i);
        blocks[i].nHeight = i;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].phashBlock = &hashes[i];
        blocks[i].BuildSkip();
        LOCK(cs_main);
        mapBlockIndex[hashes[i]] = &blocks[i];
        deterministicMNManager->SetListForTesting(&blocks[i], mnList, /*asTip=*/false);
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const int E = consensus.nHuExpectedCommitteeSize;
    const int N = static_cast<int>(operators.size());
    // EFFECTIVE threshold = ceil(2/3·min(E,N)) — the auto-scaling committee. Here N<=E
    // (the realistic regime until the network reaches E operators), so the whole operator
    // set is the committee (IsOperatorVrfSelected short-circuits true at E>=N) and every
    // block reaches finality. The E<N sampling regime is covered by the pure tests
    // (sortition_bounds_and_edges / sortition_calibrates_to_p).
    const int threshold = HuActiveFinalityThreshold(consensus, N);

    // One wire round-trip check (3.3c) is enough — proof survives serialization.
    bool didWireCheck = false;

    int blocksTested = 0, blocksFinal = 0, totalSelected = 0;
    // Each height has its own seed → an independent draw over the SAME 6 operators.
    for (int h = 10; h < len; ++h) {
        const CBlockIndex* pindex = &blocks[h];
        const uint256 seed = GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
        const std::vector<unsigned char> msg(seed.begin(), seed.end());

        CFinalityManager finality(pindex->GetBlockHash(), pindex->nHeight);
        int selectedCount = 0;

        for (const auto& op : operators) {
            const auto& mn = op.mns.at(0);

            // Signer (3.3d): derive proof with the operator-derived VRF key.
            vrf::Proof proof{};
            const std::vector<unsigned char> sk(op.vrfKey.begin(), op.vrfKey.end());
            BOOST_REQUIRE(vrf::Prove(proof, sk.data(), msg));

            // Verifier (3.3e core, = ValidateSignature under the gate): membership by proof.
            const bool selected = IsOperatorVrfSelected(mnList, pindex, mn.vrfPubKey, proof);
            BOOST_CHECK_EQUAL(IsOperatorVrfSelected(mnList, pindex, mn.vrfPubKey, proof), selected);

            if (!didWireCheck) {
                // Wire round-trip (3.3c): the 81-byte proof survives serialization.
                CHuSignature sig;
                sig.blockHash = pindex->GetBlockHash();
                sig.proTxHash = mn.proTxHash;
                op.key.Sign(sig.blockHash, sig.vchSig);
                sig.vchVrfProof.assign(proof.begin(), proof.end());
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << sig;
                CHuSignature sig2;
                ss >> sig2;
                BOOST_CHECK(sig2.vchVrfProof == sig.vchVrfProof);
                BOOST_CHECK_EQUAL(sig2.vchVrfProof.size(), vrf::PROOF_SIZE);
                didWireCheck = true;
            }

            if (selected) {
                std::vector<unsigned char> ecdsa;
                op.key.Sign(pindex->GetBlockHash(), ecdsa);
                finality.mapSignatures[mn.proTxHash] = ecdsa;  // only selected count
                ++selectedCount;
            }
        }

        // INVARIANT (every block, every draw): finality iff selected >= ceil(2/3·E).
        BOOST_CHECK_EQUAL(finality.HasFinality(threshold), selectedCount >= threshold);
        BOOST_CHECK_EQUAL(static_cast<int>(finality.GetUniqueOperatorCount()), selectedCount);

        ++blocksTested;
        totalSelected += selectedCount;
        if (selectedCount >= threshold) ++blocksFinal;
    }

    // N <= E here, so the whole operator set is the committee and every block reaches
    // finality (selected == N >= ceil(2/3·N)). Assert finality was actually achieved on
    // the vast majority of blocks — the happy path is demonstrated end-to-end.
    BOOST_CHECK_GT(blocksFinal, blocksTested / 2);
    BOOST_TEST_MESSAGE("VRF finality reached on " << blocksFinal << "/" << blocksTested
                       << " blocks; mean selected = " << (double)totalSelected / blocksTested
                       << " (N=" << operators.size() << ", E=" << E << ", threshold=" << threshold << ")");

    // Drop the synthetic chain from the global index before `blocks` goes out of scope.
    {
        LOCK(cs_main);
        for (int i = 0; i < len; ++i) mapBlockIndex.erase(hashes[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
