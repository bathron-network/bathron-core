// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/util/mn_finality_setup.h"

#include "arith_uint256.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "validation.h"
#include "vrf.h"

#include <cassert>

#include <boost/test/unit_test.hpp>

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
            // LOT 9 M3: a far-future lease so fixture operators are lease-valid at
            // any snapshot a test resolves (tests that need EXPIRED leases mutate
            // nLeaseExpiryHeight explicitly).
            state->nLeaseSequence = 0;
            state->nLeaseExpiryHeight = 2'000'000'000;

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

void SeedListOnChain(const CBlockIndex* pindex, const CDeterministicMNList& list)
{
    LOCK(cs_main);
    for (const CBlockIndex* bi = pindex; bi != nullptr; bi = bi->pprev) {
        deterministicMNManager->SetListForTesting(bi, list, /*asTip=*/(bi == pindex));
    }
}

bool SignBlockAsScheduledProducer(CBlock& block, const CBlockIndex* pindexPrev,
                                  const std::vector<TestOperator>& operators)
{
    CDeterministicMNCPtr leader;
    mn_consensus::DMMScheduleResult res;
    mn_consensus::ScheduleStatus status;
    {
        LOCK(cs_main);
        status = mn_consensus::ResolveScheduledProducer(pindexPrev, block.nTime, leader, res);
    }
    if (status != mn_consensus::ScheduleStatus::OK || !leader) {
        return false;   // no schedule here: the chain legitimately carries unsigned blocks
    }
    for (const auto& op : operators) {
        for (const auto& mn : op.mns) {
            if (mn.proTxHash == leader->proTxHash) {
                return op.key.Sign(block.GetHash(), block.vchBlockSig);
            }
        }
    }
    return false;
}

ScheduledChainSetup::ScheduledChainSetup(int numOperators, int mnsPerOperator)
    : TestChainSetup(/*blockCount=*/0)   // Params() is not selected yet in the ctor list
{
    // Mine the BOOTSTRAP window: unsigned, launcher-mined, no producer check —
    // exactly what generatebootstrap produces before any MN is online.
    const int bootstrapHeight = Params().GetConsensus().nDMMBootstrapHeight;
    for (int i = 0; i < bootstrapHeight; ++i) {
        CreateAndProcessBlock({}, coinbaseKey);
    }
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return chainActive.Height()), bootstrapHeight);

    // The tip is now the ANCHORED SNAPSHOT of the first epoch: seeding the list
    // here is what a real launch does — registrations land in the bootstrap window
    // and become the first epoch's operator set. Nothing already connected is
    // invalidated, because every block so far is below the activation height.
    mnList = BuildTestMNList(numOperators, mnsPerOperator, operators);
    SeedListOnChain(WITH_LOCK(cs_main, return chainActive.Tip()), mnList);
}

CBlockIndex* ScheduledChainSetup::MineScheduled(int n, CBlockIndex* customPrev,
                                                const CScript* payoutScript)
{
    CBlockIndex* prev = customPrev;
    CBlockIndex* last = nullptr;
    const CScript script = payoutScript ? *payoutScript
                                        : GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    for (int i = 0; i < n; ++i) {
        CBlockIndex* parent = prev ? prev : WITH_LOCK(cs_main, return chainActive.Tip());
        CBlock block = CreateBlock({}, script, /*fNoMempoolTx=*/true,
                                   /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                   /*customPrevBlock=*/parent);
        SignBlockAsScheduledProducer(block, parent, operators);
        lastSubmitAccepted = ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr);
        LOCK(cs_main);
        last = LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE_MESSAGE(last != nullptr, "scheduled block was not indexed");
        prev = last;
    }
    return last;
}

MultiMNFinalitySetup::MultiMNFinalitySetup(int numOperators, int mnsPerOperator)
{
    // Synthetic chain at heights where UPGRADE_V6_0 is active on testnet, so the
    // manager's GetListForBlock does not early-return an empty list.
    //
    // LOT 9 M3: the finality population is resolved from the EPOCH SNAPSHOT
    // (GetEpochFinalityOperators -> ResolveEpochOperatorSets), so a single
    // pprev-less index is no longer a valid model of a node: the snapshot ancestor
    // must exist and carry the list. The chain therefore spans one full epoch plus
    // the snapshot depth below the tip, and the list is injected at EVERY index.
    const Consensus::Params& consensus = Params().GetConsensus();
    const int span = consensus.nDMMScheduleEpochLength + consensus.nDMMSetSnapshotDepth + 2;
    const int tipHeight = 5'000'000;

    mnList = BuildTestMNList(numOperators, mnsPerOperator, operators);

    m_hashes.resize(span);
    m_chain.resize(span);
    {
        LOCK(cs_main);
        for (int i = 0; i < span; ++i) {
            // Hashes MUST differ across fixture instantiations: g_finalityCtx is a
            // global keyed by block hash with no per-case reset, so a 3-operator
            // context cached by an earlier case would otherwise be read back for a
            // 4-operator block (and it now carries N).
            m_hashes[i] = CounterHash(0xFEED0000u
                                      + (uint32_t)(numOperators * 0x100000)
                                      + (uint32_t)(mnsPerOperator * 0x10000)
                                      + (uint32_t)i);
            m_chain[i].nHeight = tipHeight - (span - 1) + i;
            m_chain[i].phashBlock = &m_hashes[i];
            m_chain[i].pprev = (i > 0) ? &m_chain[i - 1] : nullptr;
            deterministicMNManager->SetListForTesting(&m_chain[i], mnList,
                                                      /*asTip=*/(i == span - 1));
            mapBlockIndex[m_hashes[i]] = &m_chain[i];
        }
    }
    m_tipHash = m_hashes.back();
}

MultiMNFinalitySetup::~MultiMNFinalitySetup()
{
    // Drop the dangling synthetic indexes before this fixture's members are
    // destroyed (the manager is reset shortly after by ~TestingSetup, but be
    // explicit).
    {
        LOCK(cs_main);
        for (const uint256& h : m_hashes) mapBlockIndex.erase(h);
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

// ═════════════════════════════════════════════════════════════════════════════
// DMMScheduleChainSetup — LOT 9 M1+M2
// ═════════════════════════════════════════════════════════════════════════════

namespace {
//! Fixture geometry (LOT 9 M3.1): the child height is an exact EPOCH START of the
//! ANCHORED schedule — activation + K*epochLength, never a bare multiple of the
//! epoch length — so its snapshot and the whole ancestor walk are computed by the
//! production helpers and stay inside the synthetic chain whatever the params are.
constexpr int64_t DMM_FIXTURE_BASE_TIME = 1'900'000'000;

//! An epoch start near 5'000'000, derived (not hardcoded) from the live params.
int DMMFixtureChildHeight(const Consensus::Params& consensus)
{
    const int act = consensus.DMMScheduleActivationHeight();
    const int len = consensus.nDMMScheduleEpochLength;
    const int epochs = (5'000'000 - act) / len;      // K
    return act + epochs * len;                       // an exact epoch start
}
} // namespace

DMMScheduleChainSetup::DMMScheduleChainSetup(int numOperators, int mnsPerOperator,
                                             bool seedSnapshotList)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int childHeight = DMMFixtureChildHeight(consensus);
    // The chain reaches one FULL epoch below the child's snapshot, so tests may
    // also probe children INSIDE the fixture chain (their snapshot is one epoch
    // earlier) — needed by the getquorum display test.
    const int bottomHeight = childHeight - consensus.nDMMScheduleEpochLength
                                         - consensus.nDMMSetSnapshotDepth;
    const int parentHeight = childHeight - 1;
    const int n = parentHeight - bottomHeight + 1;

    mnList = BuildTestMNList(numOperators, mnsPerOperator, operators);

    m_chain.resize(n);
    m_hashes.resize(n);
    for (int i = 0; i < n; ++i) {
        m_hashes[i] = CounterHash(0xD1400000u + (uint32_t)i);
        m_chain[i].nHeight = bottomHeight + i;
        m_chain[i].phashBlock = &m_hashes[i];
        m_chain[i].nTime = (unsigned int)(DMM_FIXTURE_BASE_TIME + (int64_t)i * consensus.nTargetSpacing);
        m_chain[i].pprev = (i > 0) ? &m_chain[i - 1] : nullptr;
    }

    if (seedSnapshotList) {
        deterministicMNManager->SetListForTesting(SnapshotIndex(), mnList, /*asTip=*/false);
    }
}

CBlockIndex* DMMScheduleChainSetup::SnapshotIndex()
{
    // Derived by the PRODUCTION helper — never re-implemented here, so a change to
    // the anchored epoch math cannot silently desynchronise the fixture.
    const Consensus::Params& c = Params().GetConsensus();
    return IndexAt(mn_consensus::GetEpochSnapshotHeight(ChildHeight(),
                                                        c.DMMScheduleActivationHeight(),
                                                        c.nDMMScheduleEpochLength,
                                                        c.nDMMSetSnapshotDepth));
}

CBlockIndex* DMMScheduleChainSetup::IndexAt(int height)
{
    const int bottomHeight = m_chain.front().nHeight;
    assert(height >= bottomHeight && height <= m_chain.back().nHeight);
    return &m_chain[height - bottomHeight];
}

DMMScheduleChainSetup::~DMMScheduleChainSetup()
{
    if (m_tookChain) {
        LOCK(cs_main);
        chainActive.SetTip(m_savedTip);
    }
    if (deterministicMNManager) {
        deterministicMNManager->SetTipIndex(nullptr);
    }
}

int64_t DMMScheduleChainSetup::MinChildTime() const
{
    return (int64_t)m_chain.back().nTime + Params().GetConsensus().nTargetSpacing;
}

int64_t DMMScheduleChainSetup::ChildTimeAtSlot(int64_t s) const
{
    const Consensus::Params& consensus = Params().GetConsensus();
    assert(s >= 1);
    return MinChildTime() + consensus.nHuLeaderTimeoutSeconds
         + (s - 1) * consensus.nHuFallbackRecoverySeconds;
}

void DMMScheduleChainSetup::MakeChainActive()
{
    LOCK(cs_main);
    if (!m_tookChain) {
        m_savedTip = chainActive.Tip();
        m_tookChain = true;
    }
    chainActive.SetTip(Parent());
}

void DMMScheduleChainSetup::SeedListAt(const CBlockIndex* pindex)
{
    deterministicMNManager->SetListForTesting(pindex, mnList, /*asTip=*/false);
}

void DMMScheduleChainSetup::SignBlockAs(const uint256& proTxHash, CBlock& b) const
{
    for (const auto& op : operators) {
        for (const auto& mn : op.mns) {
            if (mn.proTxHash == proTxHash) {
                const bool ok = op.key.Sign(b.GetHash(), b.vchBlockSig);
                assert(ok);
                return;
            }
        }
    }
    assert(false && "SignBlockAs: proTxHash not in the fixture's operator set");
}
