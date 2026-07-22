// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Multi-MN HU-finality test fixture.
//
// The keystone for integration-testing operator-based quorum finality. It builds
// N operators (each a distinct ECDSA signing key) running mnsPerOperator
// masternodes, injects the resulting deterministic MN list into the global
// deterministicMNManager at a synthetic tip (via the test-only SetListForTesting
// seam), and exposes helpers to sign a block hash as any operator/MN. This lets
// tests exercise the real operator-resolution path (GetUniqueOperatorCount,
// quorum selection) without standing up a full multi-node regtest chain.
//
// In particular it can represent the live testnet topology (one operator running
// many MNs, e.g. Seed = 8 MN / 1 key), which is what the HU-finality findings
// (operator-vs-signature counting, network-threshold) turn on.

#ifndef BATHRON_TEST_UTIL_MN_FINALITY_SETUP_H
#define BATHRON_TEST_UTIL_MN_FINALITY_SETUP_H

#include "chain.h"
#include "key.h"
#include "masternode/deterministicmns.h"
#include "state/finality.h"
#include "test/test_bathron.h"
#include "uint256.h"

#include <vector>

//! A masternode identity for tests: its proTxHash, operator pubkey, and the
//! operator-derived VRF pubkey (== dmnState.pubKeyVRF, the v3 registration key).
struct TestMN {
    uint256 proTxHash;
    CPubKey operatorPubKey;
    CPubKey vrfPubKey;
};

//! One operator (a signing key + its derived VRF key) and the MNs it runs (all
//! share its operator key, hence one VRF identity per operator).
struct TestOperator {
    CKey key;
    CKey vrfKey;   //! vrf::DeriveKeyFromOperator(key) — set by BuildTestMNList.
    std::vector<TestMN> mns;
};

//! Build a deterministic MN list of `numOperators` operators, each running
//! `mnsPerOperator` MNs (unique internalId/proTxHash/collateral, non-null
//! confirmedHash so GetUniqueOperators counts them, not PoSe-banned). Fills
//! `outOperators` with the signing keys. Reusable across the unit fixture
//! (MultiMNFinalitySetup) and the chain-level fixture.
CDeterministicMNList BuildTestMNList(int numOperators, int mnsPerOperator,
                                     std::vector<TestOperator>& outOperators);

//! Builds `numOperators` operators, each running `mnsPerOperator` MNs, injects the
//! list into the global manager as the chain tip, and exposes per-operator signing.
struct MultiMNFinalitySetup : public TestnetSetup {
    explicit MultiMNFinalitySetup(int numOperators = 3, int mnsPerOperator = 1);
    ~MultiMNFinalitySetup();

    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;

    //! The synthetic tip index the injected list is keyed to (height in V6-active range).
    const CBlockIndex* TipIndex() const { return &m_tipIndex; }

    //! Sign `blockHash` as operators[opIdx] using its mnIdx-th MN identity.
    hu::CHuSignature SignAs(int opIdx, int mnIdx, const uint256& blockHash) const;

private:
    uint256 m_tipHash;
    CBlockIndex m_tipIndex;
};

#endif // BATHRON_TEST_UTIL_MN_FINALITY_SETUP_H
