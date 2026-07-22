// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/util/mn_finality_setup.h"

#include "arith_uint256.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "validation.h"
#include "vrf.h"

namespace {
//! Deterministic, distinct uint256 from a small counter (proTxHash / collateral).
uint256 CounterHash(uint32_t n)
{
    return ArithToUint256(arith_uint256(n));
}
} // namespace

CDeterministicMNList BuildTestMNList(int numOperators, int mnsPerOperator,
                                     std::vector<TestOperator>& outOperators)
{
    CDeterministicMNList list;
    outOperators.clear();

    uint32_t counter = 1;
    for (int op = 0; op < numOperators; ++op) {
        TestOperator to;
        to.key.MakeNewKey(/*fCompressed=*/true);
        const CPubKey opPub = to.key.GetPubKey();
        // Dedicated VRF key derived from the operator key (étape 3.1b), exactly as a
        // real node does. Its pubkey is the v3 pubKeyVRF stored in dmnState.
        vrf::DeriveKeyFromOperator(to.key, to.vrfKey);
        const CPubKey vrfPub = to.vrfKey.GetPubKey();

        for (int m = 0; m < mnsPerOperator; ++m) {
            const uint32_t id = counter++;            // unique per MN: proTxHash + internalId
            const uint256 proTxHash = CounterHash(id);

            // Build the DMN through the normal add path: collateral + owner key are
            // tracked as unique properties; the operator key is intentionally NOT
            // (the multi-MN model allows duplicate operator keys). internalId must
            // be unique or AddMN throws "duplicate masternode".
            auto state = std::make_shared<CDeterministicMNState>();
            CKey ownerKey;
            ownerKey.MakeNewKey(true);
            state->keyIDOwner = ownerKey.GetPubKey().GetID();
            state->pubKeyOperator = opPub;
            state->pubKeyVRF = vrfPub;   // v3 VRF sortition key (operator-derived)
            // Mark confirmed (non-null) so GetUniqueOperators (which skips
            // unconfirmed MNs) counts it; nPoSeBanHeight defaults to -1 (not banned).
            state->confirmedHash = CounterHash(0x20000000u + id);

            auto dmn = std::make_shared<CDeterministicMN>(uint64_t(id));
            dmn->proTxHash = proTxHash;
            dmn->collateralOutpoint = COutPoint(CounterHash(0x10000000u + id), 0);
            dmn->pdmnState = state;
            list.AddMN(dmn);

            to.mns.push_back(TestMN{proTxHash, opPub, vrfPub});
        }
        outOperators.push_back(std::move(to));
    }
    return list;
}

MultiMNFinalitySetup::MultiMNFinalitySetup(int numOperators, int mnsPerOperator)
{
    // Synthetic tip at a height where UPGRADE_V6_0 is active on testnet, so the
    // manager's GetListForBlock does not early-return an empty list.
    m_tipHash = CounterHash(0xFEED0001);
    m_tipIndex.nHeight = 5'000'000;
    m_tipIndex.phashBlock = &m_tipHash;

    mnList = BuildTestMNList(numOperators, mnsPerOperator, operators);
    deterministicMNManager->SetListForTesting(&m_tipIndex, mnList, /*asTip=*/true);

    // Register the synthetic tip in the block index so the per-block operator
    // resolution path (GetUniqueOperatorCount / HuFinalityOperatorCount →
    // mapBlockIndex.find(blockHash) → GetListForBlock(pprev)) resolves to this
    // injected list. Tests finalize TipIndex()->GetBlockHash(): with pprev null the
    // resolver uses the tip itself, and GetListForBlock keys mnListsCache by its hash.
    {
        LOCK(cs_main);
        mapBlockIndex[m_tipHash] = &m_tipIndex;
    }
}

MultiMNFinalitySetup::~MultiMNFinalitySetup()
{
    // Drop the dangling synthetic tip before this fixture's members are destroyed
    // (the manager is reset shortly after by ~TestingSetup, but be explicit).
    {
        LOCK(cs_main);
        mapBlockIndex.erase(m_tipHash);
    }
    if (deterministicMNManager) {
        deterministicMNManager->SetTipIndex(nullptr);
    }
}

hu::CHuSignature MultiMNFinalitySetup::SignAs(int opIdx, int mnIdx, const uint256& blockHash) const
{
    hu::CHuSignature sig;
    sig.blockHash = blockHash;
    sig.proTxHash = operators.at(opIdx).mns.at(mnIdx).proTxHash;
    operators.at(opIdx).key.Sign(blockHash, sig.vchSig);
    return sig;
}
