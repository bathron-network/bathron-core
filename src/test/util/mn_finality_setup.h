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
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "primitives/block.h"
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

//! Inject `list` at `pindex` AND at every one of its ancestors. LOT 9 M3.1: a
//! block's operator population resolves through its EPOCH SNAPSHOT ancestor, not
//! through its parent, so seeding only the parent no longer models a real node —
//! the snapshot would resolve an empty list and N would collapse to 0.
void SeedListOnChain(const CBlockIndex* pindex, const CDeterministicMNList& list);

//! Sign `block` (extending `pindexPrev`) with the operator key of the SCHEDULED
//! producer, so a chain whose epoch snapshot holds operators can actually extend.
//! LOT 9 M3.1 made this necessary in every fixture that seeds a list: finality and
//! production now share one snapshot, so a seeded population means the producer
//! check is live and unsigned blocks are rejected. No-op when the schedule elects
//! nobody (empty snapshot) — those chains legitimately carry unsigned blocks.
//! Returns true iff the block was signed.
bool SignBlockAsScheduledProducer(CBlock& block, const CBlockIndex* pindexPrev,
                                  const std::vector<TestOperator>& operators);

//! LOT 9 M3.1 — a regtest chain that models a REAL launch, for fixtures that need
//! both a finality population and a chain that can extend and reorg.
//!
//! Geometry (regtest: activation = nDMMBootstrapHeight + 1 = 3):
//!   heights 1..2  BOOTSTRAP MODE — launcher-mined, unsigned, no producer check;
//!                 height 2 IS the anchored snapshot of the whole first epoch;
//!   heights 3..   SCHEDULED — the snapshot is seeded, so every block must be
//!                 signed by its scheduled producer, exactly as on a real node.
//!
//! The base TestChainSetup builds only the two bootstrap blocks; the MN list is
//! injected at the snapshot AFTER them, so no already-connected block is
//! retroactively invalidated (which is what seeding a snapshot under a pre-built
//! chain would do — and the reason these fixtures had to be reworked).
struct ScheduledChainSetup : public TestChainSetup {
    explicit ScheduledChainSetup(int numOperators = 1, int mnsPerOperator = 1);

    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;

    //! Mine `n` blocks signed by the scheduled producer, on the active tip (or on
    //! `customPrev` for a competing branch). Returns the last block's index.
    CBlockIndex* MineScheduled(int n, CBlockIndex* customPrev = nullptr,
                               const CScript* payoutScript = nullptr);

    //! Same, but returns ProcessNewBlock's verdict for the last block (some LOT 6
    //! cases assert on that verdict, since it propagates ActivateBestChain failure).
    bool lastSubmitAccepted{true};
};

//! Builds `numOperators` operators, each running `mnsPerOperator` MNs, injects the
//! list into the global manager as the chain tip, and exposes per-operator signing.
struct MultiMNFinalitySetup : public TestnetSetup {
    explicit MultiMNFinalitySetup(int numOperators = 3, int mnsPerOperator = 1);
    ~MultiMNFinalitySetup();

    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;

    //! The synthetic tip index the injected list is keyed to (height in V6-active
    //! range). Its ancestors exist and carry the same list, so the LOT 9 epoch
    //! snapshot resolves exactly as on a real node.
    const CBlockIndex* TipIndex() const { return &m_chain.back(); }

    //! Sign `blockHash` as operators[opIdx] using its mnIdx-th MN identity.
    hu::CHuSignature SignAs(int opIdx, int mnIdx, const uint256& blockHash) const;

private:
    uint256 m_tipHash;
    std::vector<uint256> m_hashes;     // stable storage backing phashBlock
    std::vector<CBlockIndex> m_chain;  // pre-sized: pprev pointers stay valid
};

//! LOT 9 M1+M2 — synthetic ancestor chain for the epoch-schedule engine.
//!
//! ResolveScheduledProducer resolves the epoch snapshot through
//! pindexPrev->GetAncestor(snapshotHeight), so wiring-level tests need a REAL
//! pprev-linked chain covering [snapshotHeight, parentHeight]. Geometry (with the
//! shipped nDMMScheduleEpochLength=60 / nDMMSetSnapshotDepth=30):
//!
//!   childHeight   = 5'000'040   (an exact epoch start, well past testnet bootstrap)
//!   epochStart    = 5'000'040
//!   snapshotHeight= 5'000'010   = the BOTTOM index of the chain
//!   parentHeight  = 5'000'039   = the TOP index (Parent())
//!
//! Block times step by nTargetSpacing so slot arithmetic is exact. By default the
//! operator list is seeded (SetListForTesting) at the SNAPSHOT index — exactly what
//! the resolver reads; pass seedSnapshotList=false to model missing local data.
//! The chain is NOT in chainActive unless MakeChainActive() is called (restored on
//! teardown), which is what separates DEFERRED from LOCAL_STATE_MISSING_FATAL.
struct DMMScheduleChainSetup : public TestnetSetup {
    explicit DMMScheduleChainSetup(int numOperators = 4, int mnsPerOperator = 1,
                                   bool seedSnapshotList = true);
    ~DMMScheduleChainSetup();

    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;

    CBlockIndex* Parent() { return &m_chain.back(); }
    //! The epoch-snapshot ancestor for ChildHeight() (epochStart - snapshotDepth).
    CBlockIndex* SnapshotIndex();
    //! Any index of the synthetic chain by height (asserts if outside it).
    CBlockIndex* IndexAt(int height);
    int ChildHeight() const { return m_chain.back().nHeight + 1; }
    //! Earliest schedulable child time: parent time + nTargetSpacing (rawSlot 0).
    int64_t MinChildTime() const;
    //! Child time sitting exactly at the start of fallback rawSlot `s` (s >= 1).
    int64_t ChildTimeAtSlot(int64_t s) const;

    //! Put the synthetic chain into chainActive (old tip restored on teardown).
    void MakeChainActive();

    //! Seed the injected list for `pindex` too (needed by paths that read the
    //! parent list directly, e.g. the getquorum display RPC).
    void SeedListAt(const CBlockIndex* pindex);

    //! Sign `b` with the operator key that owns `proTxHash` (must exist).
    void SignBlockAs(const uint256& proTxHash, CBlock& b) const;

private:
    std::vector<CBlockIndex> m_chain;   // bottom (snapshot) .. top (parent)
    std::vector<uint256> m_hashes;      // stable storage for phashBlock
    CBlockIndex* m_savedTip{nullptr};
    bool m_tookChain{false};
};

#endif // BATHRON_TEST_UTIL_MN_FINALITY_SETUP_H
