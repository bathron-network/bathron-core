// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Chain-level integration test for HU-finality reorg protection (finding
// hu-finality-4): InvalidateBlock must refuse to revert a block whose finality
// is recorded in the authoritative finality DB, even when the in-memory handler
// is empty — the post-restart / backend-divergence case.
//
// Built on a real mined REGTEST chain (TestChainSetup) + InitHuFinality, with an
// operator-resolved MN list injected at the tip (regtest quorum threshold = 1) so
// finality resolves operators. Finality is written to the DB only (not the
// in-memory handler) to model a node that restarted after finalizing.

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "masternode/deterministicmns.h"
#include "state/finality.h"
#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

using namespace hu;

namespace {

struct HuFinalityChainSetup : public TestChainSetup {
    std::vector<TestOperator> operators;

    HuFinalityChainSetup() : TestChainSetup(/*blockCount=*/10)
    {
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);

        // Inject an operator-resolved MN list so finality can resolve signers to
        // operators (regtest quorum threshold = 1). The per-block resolution counts
        // operators against GetListForBlock(block->pprev) (same population the VRF
        // selection uses), so seed the list for EVERY block in the active chain —
        // otherwise finalizing the tip would resolve against tip->pprev's (empty) list.
        LOCK(cs_main);
        CBlockIndex* tip = chainActive.Tip();
        CDeterministicMNList list = BuildTestMNList(/*numOperators=*/1, /*mnsPerOperator=*/1, operators);
        for (CBlockIndex* bi = tip; bi; bi = bi->pprev) {
            deterministicMNManager->SetListForTesting(bi, list, /*asTip=*/(bi == tip));
        }
    }

    ~HuFinalityChainSetup()
    {
        finalityHandler.reset();
        pFinalityDB.reset();
    }

    // Write a threshold finality record for pindex into the DB ONLY (the in-memory
    // handler stays empty, modelling a restarted node).
    void FinalizeInDB(const CBlockIndex* pindex)
    {
        CFinalityManager fm(pindex->GetBlockHash(), pindex->nHeight);
        CHuSignature s;
        s.blockHash = pindex->GetBlockHash();
        s.proTxHash = operators.at(0).mns.at(0).proTxHash;
        operators.at(0).key.Sign(s.blockHash, s.vchSig);
        fm.mapSignatures[s.proTxHash] = s.vchSig;
        pFinalityDB->WriteFinality(fm);
    }

    // Finalize pindex in the IN-MEMORY handler (drives mapHeightToBlock, which
    // HasConflictingFinality consults). regtest threshold = ceil(2/3*1) = 1, so a
    // single operator signature finalizes.
    void FinalizeInHandler(const CBlockIndex* pindex)
    {
        CHuSignature s;
        s.blockHash = pindex->GetBlockHash();
        s.proTxHash = operators.at(0).mns.at(0).proTxHash;
        operators.at(0).key.Sign(s.blockHash, s.vchSig);
        finalityHandler->AddSignature(s);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(hu_finality_reorg_tests, HuFinalityChainSetup)

// hu-finality-4: a DB-finalized tip cannot be invalidated even when the in-memory
// handler has no record of it.
BOOST_AUTO_TEST_CASE(invalidateblock_refused_when_db_finalized)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();
    BOOST_REQUIRE(tip != nullptr);

    FinalizeInDB(tip);

    // Preconditions: DB knows it is final; the in-memory handler does not.
    // IsBlockFinal now derives the active threshold from the record's height.
    BOOST_REQUIRE(pFinalityDB->IsBlockFinal(tip->GetBlockHash()));
    BOOST_REQUIRE(!finalityHandler->HasFinality(tip->nHeight, tip->GetBlockHash()));

    CValidationState state;
    const bool ok = InvalidateBlock(state, Params(), tip);

    // Must be refused, and the finalized tip must remain in the active chain.
    BOOST_CHECK(!ok);
    BOOST_CHECK(chainActive.Contains(tip));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "hu-finality-protected");
}

// Control: with no finality record, InvalidateBlock proceeds and disconnects the tip.
BOOST_AUTO_TEST_CASE(invalidateblock_allowed_when_not_finalized)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();
    BOOST_REQUIRE(tip != nullptr);

    CValidationState state;
    const bool ok = InvalidateBlock(state, Params(), tip);

    BOOST_CHECK(ok);
    BOOST_CHECK(!chainActive.Contains(tip));
}

// PARTITION SAFETY: once a block is finalized at height H, ANY conflicting block at H is
// rejected by HasConflictingFinality. This is the consensus rule that prevents two network
// partitions from each finalizing a DIFFERENT block at the same height — the safety backstop
// of the single-round 2/3 finality (quorum intersection rejects a conflicting finalization).
BOOST_AUTO_TEST_CASE(conflicting_finalization_rejected_partition_safety)
{
    LOCK(cs_main);
    CBlockIndex* a = chainActive[5];
    BOOST_REQUIRE(a != nullptr);
    const int H = a->nHeight;

    // Finalize block A at height H in the handler.
    FinalizeInHandler(a);
    BOOST_REQUIRE(finalityHandler->HasFinality(H, a->GetBlockHash()));

    // A different (conflicting) block hash at the SAME height (e.g. the block the other
    // partition would have finalized).
    uint256 bHash = a->GetBlockHash();
    *bHash.begin() ^= 0xff;  // flip a byte -> distinct hash
    BOOST_REQUIRE(bHash != a->GetBlockHash());

    // The conflicting block at the finalized height is rejected.
    BOOST_CHECK(finalityHandler->HasConflictingFinality(H, bHash));
    // The finalized block does not conflict with itself.
    BOOST_CHECK(!finalityHandler->HasConflictingFinality(H, a->GetBlockHash()));
    // Control: a height with no finalized block has no conflict.
    BOOST_CHECK(!finalityHandler->HasConflictingFinality(H + 1, bHash));
}

BOOST_AUTO_TEST_SUITE_END()
