// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ═══════════════════════════════════════════════════════════════════════════════
// LOT 6 — AUD-012 / L4-F1: the LOCAL finality view must never produce a
// persistent consensus status, and must never wedge the node.
// ═══════════════════════════════════════════════════════════════════════════════
//
// FINDING (AUD-012, canonical): "any `state.DoS` inside `ConnectBlock` reaches
// `InvalidBlockFound`, which **persists** `BLOCK_FAILED_VALID` — so a transient
// node-local reject poisons the block until `reconsiderblock`." The mirror hazard
// is the bare `return error(...)`: "the node retries and re-fails on every
// `ActivateBestChain`, stops advancing its tip indefinitely, marks nothing
// invalid". Both directions are hard divergence.
//
// L4-F1 recorded the required shape: evict the candidate from
// setBlockIndexCandidates for the CURRENT view without marking it invalid,
// re-admit it when the view changes, uniformly across the finality sites.
// L4-F5 recorded the prerequisite: g_activating_best_chain leaks on the
// ActivateBestChain failure path, which halts local production permanently.
//
// WHY A NAIVE state.Error IS FORBIDDEN (LOT 4 proved it CRITICAL): Error skips
// InvalidBlockFound, so nStatus stays 0; FindMostWorkChain evicts only on
// BLOCK_FAILED_MASK, so the refused block remains the best candidate forever.
//
// The cases below are ordered as the mission's cycle: refusal -> temporary
// eviction -> no persistent status -> re-admission -> restart/-reindex -> no spin,
// no production block.

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "masternode/deterministicmns.h"
#include "state/finality.h"
#include "state/quorum.h"
#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"
#include "validation.h"
#include "validationinterface.h"

#include <boost/test/unit_test.hpp>

using namespace hu;

namespace {

//! A real mined regtest chain with a REAL competing branch carrying MORE work, so
//! FindMostWorkChain genuinely prefers the fork and the selection filter is the only
//! thing that can stop the reorg. Finality is injected per-block on demand.
//! A real mined regtest chain plus a REAL competing branch carrying MORE work, so
//! FindMostWorkChain genuinely prefers the fork and the selection filter is the only
//! thing that can stop the reorg.
//!
//! MN-LIST INJECTION IS SURGICAL, AND THAT IS LOAD-BEARING. Finality resolves a
//! block's operator population through GetListForBlock(block->pprev), so finalizing
//! the tip needs a list at tip->pprev — and NOWHERE ELSE. Injecting more broadly
//! (the obvious first attempt) makes CheckBlockProducer's eligible-producer set
//! non-empty at the fork point, so every competing block is rejected `bad-mn-sig-empty`
//! by a REAL consensus rule and every case below becomes vacuous: the branch would
//! never be a candidate at all, and BLOCK_FAILED_VALID would be set by block
//! production rules rather than by finality. Keep the fork point list-free.
//! A real mined regtest chain, plus a competing branch built in TWO stages so the
//! refused candidate is one that was NEVER activated — which is the only shape where
//! the selection filter is the thing making the decision.
//!
//! Stage 1 (constructor): build F9,F10 on the fork point. They tie the original
//! branch on work, so the tie-break (first-seen, nSequenceId) keeps the ORIGINAL
//! chain active while F10 stays a candidate.
//! Stage 2 (ExtendCompetingBranch, called by each case AFTER finality is set):
//! append F11 at a height the local view does NOT hold finalized. The branch now
//! outweighs the original and would be activated — unless the local finality view
//! refuses it.
//!
//! WHY IT MUST BE SPLIT THIS WAY. AcceptBlockHeader (site S2) refuses to index any
//! header at a height already finalized to another hash, so the whole competing
//! branch cannot be introduced after the finality — an earlier version tried and
//! every case died with "competing block was not indexed". And a branch that is
//! ALREADY the active chain cannot be refused into abandonment: once a better tip
//! wins, PruneBlockIndexCandidates drops the losing tip from the candidate set, so
//! there is nothing left to switch back to (a second attempt asserted the node would
//! follow finality back and was simply wrong about Bitcoin's candidate lifecycle).
//! Only F11 — indexed, heavier, never activated — is refused by the filter itself.
//!
//! WHY MN-LIST INJECTION IS SURGICAL. A block's operator population resolves through
//! GetListForBlock(block->pprev), so finalizing X needs a list at X->pprev and
//! nowhere else. Injecting broadly makes CheckBlockProducer's eligible-producer set
//! non-empty at the fork point and every competing block is then rejected
//! `bad-mn-sig-empty` by a REAL production rule — the cases would go green while
//! proving nothing about finality.
struct Lot6ForkSetup : public ScheduledChainSetup {
    std::vector<CBlockIndex*> forkIndexes;   // competing branch, oldest first
    CBlockIndex* forkPoint{nullptr};
    CBlockIndex* originalTip{nullptr};

    // LOT 9 M3.1: the base builds the bootstrap window and seeds the anchored
    // snapshot; every block above the activation height is then mined SIGNED by
    // its scheduled producer, exactly as a real node does.
    Lot6ForkSetup() : ScheduledChainSetup(/*numOperators=*/1, /*mnsPerOperator=*/1)
    {
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
        MineScheduled(10);

        {
            LOCK(cs_main);
            originalTip = chainActive.Tip();
            BOOST_REQUIRE(originalTip && originalTip->pprev && originalTip->pprev->pprev);
            forkPoint = originalTip->pprev->pprev;
        }

        SubmitOnFork(2);   // F9, F10 — ties on work, does not take over
        BOOST_REQUIRE_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == originalTip,
                              "the tie-break must keep the original chain active at this stage");
    }

    ~Lot6ForkSetup()
    {
        finalityHandler.reset();
        pFinalityDB.reset();
    }

    //! Append `n` blocks to the competing branch and submit them.
    //! Returns ProcessNewBlock's verdict for the LAST submitted block. That verdict
    //! is the one that matters for the backstops: ProcessNewBlock runs its own
    //! ActivateBestChain and PROPAGATES its failure ("ActivateBestChain failed"), so
    //! this is where a backstop returning false becomes observable. Asserting on a
    //! LATER, separate ActivateBestChain call cannot see it — the filter refuses the
    //! candidate before the step by then, so the call succeeds and the mutant lives.
    bool lastSubmitAccepted{true};
    void SubmitOnFork(int n)
    {
        CBlockIndex* prev = forkIndexes.empty() ? forkPoint : forkIndexes.back();
        for (int i = 0; i < n; ++i) {
            CBlock block = CreateBlock({}, GetScriptForDestination(coinbaseKey.GetPubKey().GetID()),
                                       /*fNoMempoolTx=*/true, /*fTestBlockValidity=*/false,
                                       /*fIncludeQfc=*/true, /*customPrevBlock=*/prev);
            // LOT 9 M3.1: a seeded snapshot means the producer check is live.
            SignBlockAsScheduledProducer(block, prev, operators);
            lastSubmitAccepted = ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr);
            LOCK(cs_main);
            CBlockIndex* bi = LookupBlockIndex(block.GetHash());
            BOOST_REQUIRE_MESSAGE(bi != nullptr, "competing block was not indexed");
            forkIndexes.push_back(bi);
            prev = bi;
        }
    }

    //! Stage 2: one more block, at a height the local view does not hold finalized,
    //! making the competing branch strictly heavier. Returns its index.
    CBlockIndex* ExtendCompetingBranch()
    {
        SubmitOnFork(1);
        CBlockIndex* tipOfFork = forkIndexes.back();
        BOOST_REQUIRE_MESSAGE(tipOfFork->nChainWork > originalTip->nChainWork,
                              "the extended branch must outweigh the original, else nothing is refused");
        return tipOfFork;
    }

    //! Two SIBLING extensions of the competing branch: two distinct candidates, both
    //! heavier than the original tip, both refused by the same view. Needed because a
    //! single refused candidate cannot tell `while` from `if` in the filter loop.
    std::pair<CBlockIndex*, CBlockIndex*> ExtendCompetingBranchTwice()
    {
        CBlockIndex* base = forkIndexes.back();
        std::vector<CBlockIndex*> siblings;
        for (int i = 0; i < 2; ++i) {
            // Distinguish the siblings by paying a DIFFERENT script: same parent,
            // same height, different coinbase -> different block hash, and CreateBlock
            // solves each one for us (no direct SolveBlock, which is not exported).
            CKey k;
            k.MakeNewKey(true);
            CBlock block = CreateBlock({}, GetScriptForDestination(k.GetPubKey().GetID()),
                                       /*fNoMempoolTx=*/true, /*fTestBlockValidity=*/false,
                                       /*fIncludeQfc=*/true, /*customPrevBlock=*/base);
            SignBlockAsScheduledProducer(block, base, operators);   // LOT 9 M3.1
            ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr);
            LOCK(cs_main);
            CBlockIndex* bi = LookupBlockIndex(block.GetHash());
            BOOST_REQUIRE_MESSAGE(bi != nullptr, "sibling candidate was not indexed");
            siblings.push_back(bi);
        }
        BOOST_REQUIRE(siblings[0] != siblings[1]);
        return {siblings[0], siblings[1]};
    }

    //! Make `pindex` finalizable (seed the MN list at its parent, where its operator
    //! population resolves from) and finalize it in the in-memory handler.
    //! regtest threshold = ceil(2/3*min(E=1,N)) = 1.
    void FinalizeInHandler(const CBlockIndex* pindex)
    {
        AssertLockHeld(cs_main);
        // LOT 9 M3.1: the population resolves through the EPOCH SNAPSHOT ancestor,
        // so seeding the parent alone would leave N = 0. Seed the whole chain.
        if (pindex->pprev) {
            SeedListOnChain(pindex->pprev, mnList);
        }
        CHuSignature s;
        s.blockHash = pindex->GetBlockHash();
        s.proTxHash = operators.at(0).mns.at(0).proTxHash;
        operators.at(0).key.Sign(s.blockHash, s.vchSig);
        finalityHandler->AddSignature(s);
        BOOST_REQUIRE_MESSAGE(finalityHandler->HasFinality(pindex->nHeight, pindex->GetBlockHash()),
                              "finality did not actually register — the case would be vacuous");
    }

    //! HANDLER-FINAL, DB-NOT-FINAL. This is what it takes to reach the DisconnectTip
    //! backstop, and discovering why is the whole point of the phase counters:
    //! AddSignature PERSISTS to the DB as soon as the threshold is met
    //! (state/finality.cpp: `if (pFinalityDB) pFinalityDB->WriteFinality(finality)`),
    //! so a "handler-only" finalization is not handler-only at all — the DB-based
    //! reorg backstop fires FIRST and DisconnectTip is never reached. That is exactly
    //! why the r2 case named after DisconnectTip never touched it.
    //! There is no erase API, so the DB record is OVERWRITTEN with a sub-threshold
    //! (signature-less) one, which is a legitimate use of the public WriteFinality.
    void MakeHandlerFinalOnly(const CBlockIndex* pindex)
    {
        AssertLockHeld(cs_main);
        FinalizeInHandler(pindex);                       // handler + DB
        CFinalityManager blank(pindex->GetBlockHash(), pindex->nHeight);
        pFinalityDB->WriteFinality(blank);               // blank the DB record
        BOOST_REQUIRE_MESSAGE(finalityHandler->HasFinality(pindex->nHeight, pindex->GetBlockHash()),
                              "handler must still be final");
        BOOST_REQUIRE_MESSAGE(!pFinalityDB->IsBlockFinal(pindex->GetBlockHash()),
                              "the DB must NOT be final, else backstop 1 fires first");
    }

    //! Finalize in the DB only (models a node restarted after finalizing).
    void FinalizeInDB(const CBlockIndex* pindex)
    {
        AssertLockHeld(cs_main);
        // LOT 9 M3.1: the population resolves through the EPOCH SNAPSHOT ancestor,
        // so seeding the parent alone would leave N = 0. Seed the whole chain.
        if (pindex->pprev) {
            SeedListOnChain(pindex->pprev, mnList);
        }
        CFinalityManager fm(pindex->GetBlockHash(), pindex->nHeight);
        CHuSignature s;
        s.blockHash = pindex->GetBlockHash();
        s.proTxHash = operators.at(0).mns.at(0).proTxHash;
        operators.at(0).key.Sign(s.blockHash, s.vchSig);
        fm.mapSignatures[s.proTxHash] = s.vchSig;
        pFinalityDB->WriteFinality(fm);
        BOOST_REQUIRE(pFinalityDB->IsBlockFinal(pindex->GetBlockHash()));
    }

    //! Drop the local finality view — models -reindex (finalitydb wiped, LOT 1) and
    //! a restart whose in-memory handler starts empty.
    void ClearLocalFinalityView()
    {
        LOCK(cs_main);
        finalityHandler.reset();
        pFinalityDB.reset();
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
    }

    static bool CarriesFailedStatus(const CBlockIndex* pindex)
    {
        return (pindex->nStatus & BLOCK_FAILED_MASK) != 0;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot6_local_finality, Lot6ForkSetup)

// ───────────────────────────────────────────────────────────────────────────────
// PREREQUISITE (L4-F5) — g_activating_best_chain
// ───────────────────────────────────────────────────────────────────────────────
//
// Every exit of ActivateBestChain must return the counter to zero. Three exit
// classes were broken before LOT 6: the ActivateBestChainStep failure `return false`
// had NO decrement (leak -> activemasternode.cpp:550 refuses to produce forever),
// the no-blocks-connected early return did `store(false)` (a CLOBBER, not a
// decrement: it zeroes the counter even while a concurrent activation is in
// flight), and an exception from interruption_point() unwound past the decrement.

BOOST_AUTO_TEST_CASE(counter_zero_on_the_nothing_to_do_exit)
{
    BOOST_REQUIRE_EQUAL(g_activating_best_chain.load(), 0);
    CValidationState state;
    BOOST_CHECK(ActivateBestChain(state));            // already on the best chain
    BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
}

BOOST_AUTO_TEST_CASE(counter_zero_when_the_view_refuses_a_candidate)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    ExtendCompetingBranch();
    CValidationState state;
    ActivateBestChain(state);
    BOOST_CHECK_MESSAGE(g_activating_best_chain.load() == 0,
                        "L4-F5: a leaked counter means activemasternode never produces again");
}

// The counter IS the production gate. Repeated refusals must never let it drift.
BOOST_AUTO_TEST_CASE(production_gate_reopens_after_refusals)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    ExtendCompetingBranch();
    for (int i = 0; i < 4; ++i) {
        CValidationState state;
        ActivateBestChain(state);
        BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// THE CYCLE — late finality makes the ACTIVE branch a refused candidate
// ───────────────────────────────────────────────────────────────────────────────

// Steps 1-3. The node is on the competing branch. Finality for the ABANDONED branch
// arrives (gossip is asynchronous). The active branch now contains a block at a
// finalized height with a different hash, so the local view refuses it: the node
// must switch back WITHOUT marking anything invalid, and activation must succeed.
BOOST_AUTO_TEST_CASE(refused_candidate_is_not_activated_and_not_marked)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    CBlockIndex* forkTip = ExtendCompetingBranch();     // now strictly heavier

    CValidationState state;
    const bool ok = ActivateBestChain(state);

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(ok, "AUD-012: a local finality refusal must not fail activation");
    BOOST_CHECK_MESSAGE(chainActive.Tip() == originalTip,
                        "a heavier candidate refused by the local view must NOT be activated");
    for (const CBlockIndex* bi : forkIndexes) {
        BOOST_CHECK_MESSAGE(!CarriesFailedStatus(bi),
                            "AUD-012: no block refused by the LOCAL view may carry BLOCK_FAILED_VALID/CHILD");
    }
    BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
}

// Steps 2 and 5: the eviction is CALL-SCOPED. setBlockIndexCandidates is file-local
// to validation.cpp and deliberately NOT exported — adding a test-only accessor
// would mean adding production surface for a test — so membership is proven
// BEHAVIOURALLY, which is stronger: if the eviction had survived, the candidate
// could never be selected again, so activating it after the view stops refusing is
// possible only if it was re-inserted. (In debug builds CheckBlockIndex asserts the
// membership invariant directly; the RAII destructor restores the set before
// cs_main is released precisely so that assert keeps holding.)
BOOST_AUTO_TEST_CASE(eviction_does_not_survive_the_call)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    CBlockIndex* forkTip = ExtendCompetingBranch();

    for (int i = 0; i < 3; ++i) {          // several refused activations in a row
        CValidationState state;
        ActivateBestChain(state);
    }
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainActive.Tip()) == originalTip);

    ClearLocalFinalityView();              // the view stops refusing

    CValidationState state;
    ActivateBestChain(state);
    BOOST_CHECK_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == forkTip,
                        "candidate still selectable: the eviction did not survive the call");
}

// Step 5, and steps 6-7 together: after -reindex (finalitydb wiped, LOT 1) or a
// restart with an empty handler, the SAME candidate is activated with no operator
// action — no reconsiderblock, no manual repair. Re-admission here is not
// bookkeeping: every activation re-evaluates every candidate against the current
// view, so there is no "blocked set" to forget.
BOOST_AUTO_TEST_CASE(candidate_returns_once_the_view_no_longer_refuses)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    CBlockIndex* forkTip = ExtendCompetingBranch();

    CValidationState state1;
    ActivateBestChain(state1);
    BOOST_REQUIRE_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == originalTip,
                          "precondition: the branch was refused while the view held it back");

    ClearLocalFinalityView();

    CValidationState state2;
    BOOST_CHECK(ActivateBestChain(state2));
    BOOST_CHECK_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == forkTip,
                        "an empty finality view must re-admit the candidate automatically");
    BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
    LOCK(cs_main);
    BOOST_CHECK(!CarriesFailedStatus(forkTip));
}

// Step 7: no spin, no stall. Repeated activations under a standing refusal each
// return promptly, keep the chain stable, and never escalate to a persistent mark —
// the AUD-012 failure mode was "retries and re-fails on every ActivateBestChain,
// stops advancing its tip indefinitely".
BOOST_AUTO_TEST_CASE(repeated_activation_under_refusal_is_stable)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    CBlockIndex* forkTip = ExtendCompetingBranch();

    for (int i = 0; i < 5; ++i) {
        CValidationState state;
        BOOST_CHECK_MESSAGE(ActivateBestChain(state), "activation must keep succeeding under a standing refusal");
        BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
    }

    LOCK(cs_main);
    BOOST_CHECK(chainActive.Tip() == originalTip);
    BOOST_CHECK_MESSAGE(!CarriesFailedStatus(forkTip),
                        "repeated refusals must never escalate into a persistent mark");
}

// ───────────────────────────────────────────────────────────────────────────────
// TWO VIEWS, SAME BLOCKS
// ───────────────────────────────────────────────────────────────────────────────

// The mission's central requirement at the level a single-process test can reach:
// the SAME block index, driven under two DIFFERENT finality views, may legitimately
// end on two different chains — but neither view may stamp a persistent consensus
// status the other would not.
BOOST_AUTO_TEST_CASE(divergent_views_never_produce_divergent_consensus_status)
{
    // View A: finality for the original branch -> refuses the competing branch.
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    CBlockIndex* forkTip = ExtendCompetingBranch();
    CValidationState stateA;
    ActivateBestChain(stateA);
    const uint32_t forkStatusA = WITH_LOCK(cs_main, return forkTip->nStatus);
    const uint32_t origStatusA = WITH_LOCK(cs_main, return originalTip->nStatus);
    const CBlockIndex* chosenA = WITH_LOCK(cs_main, return chainActive.Tip());

    // View B: empty (the -reindex node). Same blocks, no finality.
    ClearLocalFinalityView();
    CValidationState stateB;
    ActivateBestChain(stateB);
    const uint32_t forkStatusB = WITH_LOCK(cs_main, return forkTip->nStatus);
    const uint32_t origStatusB = WITH_LOCK(cs_main, return originalTip->nStatus);
    const CBlockIndex* chosenB = WITH_LOCK(cs_main, return chainActive.Tip());

    // Different local chains: local policy doing its job, and explicitly allowed.
    BOOST_CHECK_MESSAGE(chosenA != chosenB,
                        "the two views should pick different chains, else this case proves nothing");
    BOOST_CHECK(chosenA == originalTip);
    BOOST_CHECK(chosenB == forkTip);

    // Identical consensus status: BLOCK_FAILED_MASK is what persists to disk and what
    // peers and future reorgs honour. Neither view may set it.
    BOOST_CHECK_MESSAGE((forkStatusA & BLOCK_FAILED_MASK) == 0 && (forkStatusB & BLOCK_FAILED_MASK) == 0,
                        "AUD-012: divergent local views must not stamp divergent consensus status");
    BOOST_CHECK_EQUAL(forkStatusA & BLOCK_FAILED_MASK, forkStatusB & BLOCK_FAILED_MASK);
    BOOST_CHECK_EQUAL(origStatusA & BLOCK_FAILED_MASK, origStatusB & BLOCK_FAILED_MASK);
    BOOST_CHECK_EQUAL(origStatusA & BLOCK_FAILED_MASK, 0u);
}

// ───────────────────────────────────────────────────────────────────────────────
// THE PREDICATE — above / at / below, and certificate states
// ───────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(reorg_above_at_and_below_the_finalized_block)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();          // fork tip
    CBlockIndex* mid = tip->pprev;
    CBlockIndex* deep = mid->pprev;
    BOOST_REQUIRE(deep != nullptr);

    // Nothing finalized: nothing refused.
    BOOST_CHECK(!LocalFinalityRefusesChain(tip, mid));
    BOOST_CHECK(!LocalFinalityRefusesChain(tip, deep));

    FinalizeInHandler(mid);

    // ABOVE: fork point == mid, so the disconnect span (mid, tip] excludes mid.
    BOOST_CHECK_MESSAGE(!LocalFinalityRefusesChain(tip, mid),
                        "a reorg above the finalized block disconnects nothing finalized");
    // AT: fork point one lower, the span now CONTAINS mid.
    BOOST_CHECK_MESSAGE(LocalFinalityRefusesChain(tip, deep),
                        "a reorg at the finalized block must be refused");
    // BELOW: deeper still, span still contains mid.
    BOOST_CHECK_MESSAGE(deep->pprev == nullptr || LocalFinalityRefusesChain(tip, deep->pprev),
                        "a reorg below the finalized block must be refused");
}

// Certificate states. NOTE ON REGTEST PARAMS: nHuExpectedCommitteeSize = 1, so the
// threshold is ceil(2/3*min(E,N)) = 1 for EVERY population — "incomplete" cannot be
// modelled by adding operators (a first version tried N=2 expecting threshold 2 and
// was simply wrong about the params). It is modelled by a record that exists and
// carries FEWER signatures than the threshold, i.e. zero.
BOOST_AUTO_TEST_CASE(certificate_absent_incomplete_valid_and_contradictory)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();

    BOOST_REQUIRE_EQUAL(HuActiveFinalityThreshold(Params().GetConsensus(), 1), 1);
    BOOST_REQUIRE_EQUAL(HuActiveFinalityThreshold(Params().GetConsensus(), 2), 1);

    // ABSENT.
    BOOST_CHECK(!BlockHasLocalFinality(tip));
    BOOST_CHECK(!LocalFinalityRefusesChain(tip, tip->pprev));

    // INCOMPLETE: a record with no signatures at all.
    {
        CFinalityManager fm(tip->GetBlockHash(), tip->nHeight);
        pFinalityDB->WriteFinality(fm);
    }
    BOOST_CHECK_MESSAGE(!BlockHasLocalFinality(tip),
                        "a signature-less record is not finality and must refuse nothing");
    BOOST_CHECK(!LocalFinalityRefusesChain(tip, tip->pprev));

    // VALID.
    FinalizeInDB(tip);
    BOOST_CHECK(BlockHasLocalFinality(tip));
    BOOST_CHECK(LocalFinalityRefusesChain(tip, tip->pprev));

    // CONTRADICTORY: a different hash at a finalized height.
    FinalizeInHandler(tip);
    BOOST_CHECK_MESSAGE(finalityHandler->HasConflictingFinality(tip->nHeight, tip->pprev->GetBlockHash()),
                        "another hash at a finalized height must be reported as conflicting");
    BOOST_CHECK_MESSAGE(!finalityHandler->HasConflictingFinality(tip->nHeight, tip->GetBlockHash()),
                        "the finalized block itself must never be reported as conflicting");
}

// The filter must be at least as broad as EVERY downstream backstop, or it admits a
// candidate a backstop then refuses on every retry — a spin. DisconnectTip reads the
// in-memory handler; WouldViolateHuFinality reads the DB. Pin the union.
BOOST_AUTO_TEST_CASE(predicate_is_the_union_of_handler_and_db)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();

    FinalizeInDB(tip);                                  // DB only, handler empty
    BOOST_REQUIRE(!finalityHandler->HasFinality(tip->nHeight, tip->GetBlockHash()));
    BOOST_REQUIRE(pFinalityDB->IsBlockFinal(tip->GetBlockHash()));
    BOOST_CHECK_MESSAGE(BlockHasLocalFinality(tip),
                        "DB-only finality must refuse: WouldViolateHuFinality (a backstop) reads the DB");
    BOOST_CHECK(LocalFinalityRefusesChain(tip, tip->pprev));
}

// ───────────────────────────────────────────────────────────────────────────────
// THE SITES — every local-finality refusal is an Error, never an Invalid
// ───────────────────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(invalidateblock_refusal_is_an_error_not_an_invalid)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();
    FinalizeInHandler(tip);

    CValidationState state;
    const bool ok = InvalidateBlock(state, Params(), tip);

    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(state.IsError(), "AUD-012: a local finality refusal must be MODE_ERROR");
    BOOST_CHECK_MESSAGE(!state.IsInvalid(),
                        "MODE_INVALID reaches InvalidBlockFound and persists BLOCK_FAILED_VALID");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "hu-finality-protected");
    BOOST_CHECK(!CarriesFailedStatus(tip));
    BOOST_CHECK(chainActive.Contains(tip));
}

// The DB-only variant (post-restart node) takes the second guard in InvalidateBlock
// and must behave identically.
BOOST_AUTO_TEST_CASE(invalidateblock_db_only_refusal_is_also_an_error)
{
    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();
    FinalizeInDB(tip);
    BOOST_REQUIRE(!finalityHandler->HasFinality(tip->nHeight, tip->GetBlockHash()));

    CValidationState state;
    BOOST_CHECK(!InvalidateBlock(state, Params(), tip));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK(!CarriesFailedStatus(tip));
}

// THE CONNECT SIDE, ALONE. Every other case that expects a refusal is satisfied by
// the DISCONNECT side, which short-circuits first — so deleting the connect-side loop
// entirely left the whole suite green (found by independent review). This case makes
// the disconnect span EMPTY (fork point == current tip) so only the connect side can
// answer: the candidate's own path crosses a height the local view holds finalized to
// a different hash. That is the "gossiped finality precedes the blocks" shape, and
// without the connect side the filter admits such a candidate and ConnectBlock then
// refuses it on every activation — the AUD-012 stall, restored.
BOOST_AUTO_TEST_CASE(connect_side_alone_refuses_a_conflicting_path)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    CBlockIndex* forkTip = ExtendCompetingBranch();

    LOCK(cs_main);
    CBlockIndex* tip = chainActive.Tip();
    BOOST_REQUIRE_MESSAGE(tip == originalTip, "precondition: still on the original chain");

    // Fork point == tip => the disconnect walk (tip, fork] is EMPTY, so a refusal can
    // only come from the connect side.
    // The tip IS locally final here (originalTip was finalized above); state that
    // as a fact rather than as a tautology — a `X || true` check can never fail and
    // read as asserting the opposite (flagged by independent review).
    BOOST_CHECK(BlockHasLocalFinality(tip));
    BOOST_CHECK_MESSAGE(LocalFinalityRefusesChain(forkTip, tip),
                        "the candidate's path crosses a finalized height with a different hash");

    // Control, and it must NOT be the degenerate candidate==fork==tip call (both
    // loops then have a false entry condition and the answer is false regardless of
    // the view, which proves nothing — flagged by independent review). Use the real
    // fork point: the same candidate, judged with a NON-empty disconnect span, is
    // refused for the other reason, so the two sides are both live here.
    BOOST_CHECK_MESSAGE(LocalFinalityRefusesChain(forkTip, chainActive.FindFork(forkTip)),
                        "with the real fork point the disconnect side also refuses");
}

// TWO refused candidates. With only one, `while` and `if` in the filter loop are
// indistinguishable (found by independent review): the `if` mutant would pick the
// SECOND refused candidate, reach ActivateBestChainStep and fail the activation,
// reintroducing the wedge class.
BOOST_AUTO_TEST_CASE(two_refused_candidates_are_both_skipped)
{
    WITH_LOCK(cs_main, FinalizeInHandler(originalTip));
    auto siblings = ExtendCompetingBranchTwice();

    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(siblings.first->nChainWork > originalTip->nChainWork &&
                              siblings.second->nChainWork > originalTip->nChainWork,
                              "both siblings must outweigh the original tip");
    }

    CValidationState state;
    BOOST_CHECK(ActivateBestChain(state));

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(chainActive.Tip() == originalTip,
                        "BOTH refused candidates must be skipped, not just the best one");
    BOOST_CHECK(!CarriesFailedStatus(siblings.first));
    BOOST_CHECK(!CarriesFailedStatus(siblings.second));
    BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// B1 — THE THREE BACKSTOPS, ACTUALLY EXECUTED
// ═══════════════════════════════════════════════════════════════════════════════
//
// These branches exist for a REAL race: the finality write path
// (ProcessHuSignature -> AddSignature) is deliberately lock-free — net_processing.cpp
// says so, and AddSignature avoids cs_main to keep the UpdateTip lock order — so the
// local view CAN change while ActivateBestChain holds cs_main, AFTER its candidate
// filter has run. Until now no test reached them, and that is exactly how an earlier
// round of this work package shipped a null-pointer dereference behind a green suite.
//
// g_lab_finality_step_hook fires at the top of ActivateBestChainStep, under cs_main,
// after the filter. It is compiled in ONLY with ./configure --enable-lab-finality-hook,
// is settable only from C++ test code, and is absent from release binaries (scanned).
#ifdef BATHRON_ENABLE_LAB_FINALITY_HOOK

//! RAII: install a phased hook, reset the phase counters, and guarantee both are
//! cleaned up — including when an assertion throws.
struct ScopedFinalityHook {
    explicit ScopedFinalityHook(std::function<void(LabFinalityPhase)> fn)
    {
        for (auto& h : g_lab_finality_phase_hits) h.store(0);
        for (auto& h : g_lab_finality_backstop_hits) h.store(0);
        g_lab_finality_hook = std::move(fn);
    }
    ~ScopedFinalityHook()
    {
        g_lab_finality_hook = nullptr;
        for (auto& h : g_lab_finality_phase_hits) h.store(0);
        for (auto& h : g_lab_finality_backstop_hits) h.store(0);
    }
    static int Hits(LabFinalityPhase p) { return g_lab_finality_phase_hits[static_cast<size_t>(p)].load(); }
    //! The counter that actually proves the REFUSAL BRANCH ran (a phase counter does not).
    static int Refusals(LabFinalityBackstop b) { return g_lab_finality_backstop_hits[static_cast<size_t>(b)].load(); }
};

//! Observes the validation interface: UpdatedBlockTip must NEVER receive nullptr
//! (B4), and BlockConnected must not be silently dropped (B5).
struct TipObserver final : public CValidationInterface {
    std::atomic<int> nullTips{0};
    std::atomic<int> tipUpdates{0};
    std::atomic<int> blocksConnected{0};
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex*, bool) override
    {
        ++tipUpdates;
        if (pindexNew == nullptr) ++nullTips;
    }
    void BlockConnected(const std::shared_ptr<const CBlock>&, const CBlockIndex*) override
    {
        ++blocksConnected;
    }
};

//! Every backstop case asserts the SAME battery, so no property is proven for one
//! branch and quietly assumed for the others. B1..B7 in one place.
#define LOT6_ASSERT_REFUSAL_IS_CLEAN(phase_, backstop_, forkTip_, observer_)                       \
    do {                                                                                           \
        BOOST_CHECK_MESSAGE(ScopedFinalityHook::Hits(phase_) > 0,                                  \
                            "B1: the phase was never reached — this case proves nothing");         \
        BOOST_CHECK_MESSAGE(ScopedFinalityHook::Refusals(backstop_) > 0,                           \
                            "B1: the REFUSAL BRANCH never executed — a phase counter is not proof"); \
        BOOST_CHECK_MESSAGE(lastSubmitAccepted,                                                    \
                            "B7: the backstop failed the activation -> node/init.cpp StartShutdown()"); \
        BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);                    /* B6 */          \
        BOOST_CHECK_MESSAGE((observer_).nullTips.load() == 0,                                      \
                            "B4: UpdatedBlockTip received nullptr — crashes net_processing");      \
        {                                                                                          \
            LOCK(cs_main);                                                                         \
            BOOST_CHECK_MESSAGE(!CarriesFailedStatus(forkTip_),                                    \
                                "B3: a local refusal must not persist BLOCK_FAILED_VALID/CHILD");  \
        }                                                                                          \
    } while (0)

// ───────────────────────────────────────────────────────────────────────────────
// BACKSTOP 1 — WouldViolateHuFinality (reads the finality DB ONLY)
// ───────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(backstop_reorg_db_finality_mid_step)
{
    TipObserver observer;
    RegisterValidationInterface(&observer);

    ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        // DB, because this backstop reads pFinalityDB and nothing else.
        if (phase == LabFinalityPhase::AFTER_FILTER && !BlockHasLocalFinality(originalTip)) {
            FinalizeInDB(originalTip);
        }
    });

    CBlockIndex* forkTip = ExtendCompetingBranch();
    SyncWithValidationInterfaceQueue();
    UnregisterValidationInterface(&observer);

    LOT6_ASSERT_REFUSAL_IS_CLEAN(LabFinalityPhase::AFTER_FILTER, LabFinalityBackstop::REORG, forkTip, observer);
    BOOST_CHECK_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == originalTip,
                        "the refused reorg must not have happened");
}

// ───────────────────────────────────────────────────────────────────────────────
// BACKSTOP 2 — DisconnectTip (reads the in-memory HANDLER only)
// ───────────────────────────────────────────────────────────────────────────────
// Reached only if backstop 1 did NOT fire, i.e. the DB must stay empty — so the view
// is changed at BEFORE_DISCONNECT, after the DB check, and only in the handler.
BOOST_AUTO_TEST_CASE(backstop_disconnect_handler_finality_mid_step)
{
    TipObserver observer;
    RegisterValidationInterface(&observer);

    ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase == LabFinalityPhase::BEFORE_DISCONNECT &&
            !finalityHandler->HasFinality(originalTip->nHeight, originalTip->GetBlockHash())) {
            MakeHandlerFinalOnly(originalTip);    // handler final, DB not: only DisconnectTip can refuse
        }
    });

    CBlockIndex* forkTip = ExtendCompetingBranch();
    SyncWithValidationInterfaceQueue();
    UnregisterValidationInterface(&observer);

    LOT6_ASSERT_REFUSAL_IS_CLEAN(LabFinalityPhase::BEFORE_DISCONNECT, LabFinalityBackstop::DISCONNECT, forkTip, observer);
    BOOST_CHECK_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == originalTip,
                        "DisconnectTip refused, so the chain must be unchanged");
    // And the DB backstop must NOT have been the one that fired.
    BOOST_CHECK_MESSAGE(!pFinalityDB->IsBlockFinal(originalTip->GetBlockHash()),
                        "the DB stayed empty: backstop 1 cannot be what refused");
}

// ───────────────────────────────────────────────────────────────────────────────
// BACKSTOP 3 — ConnectBlock's HasConflictingFinality
// ───────────────────────────────────────────────────────────────────────────────
// Reached only after the disconnect loop completed, so the view is changed at
// BEFORE_CONNECT: finalizing the ORIGINAL block at height H makes the competing
// block at the same height H conflict when ConnectBlock reaches it.
BOOST_AUTO_TEST_CASE(backstop_connect_conflicting_height_mid_step)
{
    TipObserver observer;
    RegisterValidationInterface(&observer);

    ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase == LabFinalityPhase::BEFORE_CONNECT &&
            !finalityHandler->HasFinality(originalTip->nHeight, originalTip->GetBlockHash())) {
            MakeHandlerFinalOnly(originalTip);
        }
    });

    CBlockIndex* forkTip = ExtendCompetingBranch();
    SyncWithValidationInterfaceQueue();
    UnregisterValidationInterface(&observer);

    LOT6_ASSERT_REFUSAL_IS_CLEAN(LabFinalityPhase::BEFORE_CONNECT, LabFinalityBackstop::CONNECT, forkTip, observer);
    // Pin WHICH chain won: without this the case passes even if the ConnectBlock
    // predicate is deleted outright (the branch simply connects) — a final independent
    // review demonstrated exactly that mutant surviving.
    BOOST_CHECK_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) != forkTip,
                        "the refused branch must NOT have become the active chain");
    LOCK(cs_main);
    BOOST_CHECK(chainActive.Tip() != nullptr);
    BOOST_CHECK_MESSAGE(!CarriesFailedStatus(chainActive.Tip()),
                        "the surviving tip must not be marked invalid");
}

// ───────────────────────────────────────────────────────────────────────────────
// B5 — connectTrace must not be discarded
// ───────────────────────────────────────────────────────────────────────────────
// The BEFORE_CONNECT case connects blocks before the refusal, so BlockConnected must
// fire for them. A `continue` in the refusal branch would swallow the trace and the
// wallet (Sapling witnesses included) would miss those blocks.
BOOST_AUTO_TEST_CASE(connect_trace_is_not_dropped_by_a_refusal)
{
    TipObserver observer;
    RegisterValidationInterface(&observer);

    ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase == LabFinalityPhase::BEFORE_CONNECT &&
            !finalityHandler->HasFinality(originalTip->nHeight, originalTip->GetBlockHash())) {
            MakeHandlerFinalOnly(originalTip);
        }
    });

    ExtendCompetingBranch();
    SyncWithValidationInterfaceQueue();
    const int connected = observer.blocksConnected.load();
    const int nullTips = observer.nullTips.load();
    UnregisterValidationInterface(&observer);

    BOOST_CHECK_MESSAGE(ScopedFinalityHook::Hits(LabFinalityPhase::BEFORE_CONNECT) > 0,
                        "B1: the connect phase was never reached");
    BOOST_CHECK_MESSAGE(nullTips == 0, "B4: UpdatedBlockTip received nullptr");
    // NOT `connected >= 0` — that is a tautology on an unsigned-monotonic counter and
    // can never fail (flagged by the final review). The refusal happens at
    // BEFORE_CONNECT, i.e. AFTER the disconnect loop, so the step really does connect
    // blocks before refusing: BlockConnected must have fired for them, which is the
    // property "connectTrace was not discarded" actually means.
    BOOST_CHECK_MESSAGE(connected > 0,
                        "B5: connectTrace was dropped — the wallet (Sapling witnesses) would miss blocks");
}

// ───────────────────────────────────────────────────────────────────────────────
// B6 — the counter survives an exception unwinding through ActivateBestChain
// ───────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(counter_is_exact_even_when_an_exception_unwinds)
{
    const int before = g_activating_best_chain.load();
    ScopedFinalityHook hook([](LabFinalityPhase phase) {
        if (phase == LabFinalityPhase::AFTER_FILTER) {
            throw std::runtime_error("lab: unwind through ActivateBestChain");
        }
    });

    bool threw = false;
    try {
        SubmitOnFork(1);     // ProcessNewBlock runs the activation that throws
    } catch (const std::runtime_error&) {
        threw = true;
    }

    BOOST_CHECK_MESSAGE(threw, "the exception must propagate, not be swallowed");
    BOOST_CHECK_MESSAGE(ScopedFinalityHook::Hits(LabFinalityPhase::AFTER_FILTER) > 0,
                        "the phase must have been reached for this to mean anything");
    BOOST_CHECK_MESSAGE(g_activating_best_chain.load() == before,
                        "B6: the RAII guard must restore the counter when the stack unwinds");
}

// ───────────────────────────────────────────────────────────────────────────────
// B7 — candidate re-admitted after the view changes; no spin
// ───────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(candidate_readmitted_after_a_mid_step_refusal_clears)
{
    CBlockIndex* forkTip = nullptr;
    {
        ScopedFinalityHook hook([&](LabFinalityPhase phase) {
            if (phase == LabFinalityPhase::BEFORE_DISCONNECT &&
                !finalityHandler->HasFinality(originalTip->nHeight, originalTip->GetBlockHash())) {
                MakeHandlerFinalOnly(originalTip);
            }
        });
        forkTip = ExtendCompetingBranch();
        BOOST_REQUIRE_MESSAGE(ScopedFinalityHook::Hits(LabFinalityPhase::BEFORE_DISCONNECT) > 0,
                              "the backstop phase must have been reached");
        BOOST_REQUIRE(WITH_LOCK(cs_main, return chainActive.Tip()) == originalTip);
    }

    ClearLocalFinalityView();                 // -reindex / restart with an empty view

    CValidationState state;
    BOOST_CHECK(ActivateBestChain(state));
    BOOST_CHECK_MESSAGE(WITH_LOCK(cs_main, return chainActive.Tip()) == forkTip,
                        "B7: the candidate must be re-admitted once the view stops refusing");
    BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
}

BOOST_AUTO_TEST_CASE(repeated_mid_step_refusals_do_not_spin)
{
    ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase == LabFinalityPhase::BEFORE_DISCONNECT &&
            !finalityHandler->HasFinality(originalTip->nHeight, originalTip->GetBlockHash())) {
            MakeHandlerFinalOnly(originalTip);
        }
    });
    ExtendCompetingBranch();

    for (int i = 0; i < 3; ++i) {
        CValidationState state;
        BOOST_CHECK(ActivateBestChain(state));
        BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
    }
    const int hits = ScopedFinalityHook::Hits(LabFinalityPhase::AFTER_FILTER);
    BOOST_CHECK_MESSAGE(hits > 0 && hits < 100,
                        "B7: the step ran " << hits << " times — that is a spin, not a bounded retry");
}

// ═══════════════════════════════════════════════════════════════════════════════
// B3 (r4) — InvalidateBlock is ALL-OR-NOTHING under a mid-operation finality race
// ═══════════════════════════════════════════════════════════════════════════════
//
// The span guard runs ONCE; the disconnect loop then does N disk reads and flushes
// while the finality writer runs lock-free. A final independent review proved the old
// shape left BLOCK_FAILED_VALID on pindex and BLOCK_FAILED_CHILD on the blocks already
// walked, with the chain stopped mid-rollback. Marking is now deferred until every
// disconnect has succeeded, so a mid-loop refusal leaves NOTHING behind.
//
// The race is injected at each of the four points the mission names, and every case
// asserts the SAME battery: no BLOCK_FAILED_* anywhere in the span, the chain still
// contains what it contained (or was fully rolled back on success), and the counter is
// clean.

//! Walk [pindex .. chainActive tip-at-entry] and assert nothing carries a failure bit.
static void AssertSpanUnmarked(const CBlockIndex* from, const CBlockIndex* to)
{
    for (const CBlockIndex* w = to; w != nullptr; w = w->pprev) {
        BOOST_CHECK_MESSAGE((w->nStatus & BLOCK_FAILED_MASK) == 0,
                            "B3: partial BLOCK_FAILED_* at height " << w->nHeight);
        if (w == from) break;
    }
}

BOOST_AUTO_TEST_CASE(invalidateblock_is_all_or_nothing_under_a_mid_operation_race)
{
    // Four injection points, one case body: same battery each time.
    const LabFinalityPhase points[] = {
        LabFinalityPhase::INV_AFTER_PREFLIGHT,
        LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT,
        LabFinalityPhase::INV_BETWEEN_DISCONNECTS,
        LabFinalityPhase::INV_BEFORE_MARKING,
    };

    for (LabFinalityPhase point : points) {
        // Fresh view for each point.
        ClearLocalFinalityView();

        CBlockIndex* target = WITH_LOCK(cs_main, return chainActive.Tip()->pprev);
        CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());
        BOOST_REQUIRE(target && tipAtEntry);

        int fired = 0;
        ScopedFinalityHook hook([&](LabFinalityPhase phase) {
            if (phase != point || fired++) return;
            // A REAL view change: make the block the disconnect loop is about to touch
            // locally final, in the handler (which is what DisconnectTip consults).
            LOCK(cs_main);
            MakeHandlerFinalOnly(chainActive.Tip());
        });

        CValidationState st;
        const bool ok = InvalidateBlock(st, Params(), target);

        BOOST_CHECK_MESSAGE(ScopedFinalityHook::Hits(point) > 0,
                            "B3: injection point " << static_cast<int>(point) << " was never reached");

        LOCK(cs_main);
        if (!ok) {
            // Refused mid-operation: NOTHING may be marked, and the chain must still
            // hold the target (nothing was permanently peeled away by a failed run).
            AssertSpanUnmarked(target, tipAtEntry);
            BOOST_CHECK_MESSAGE(st.IsError(), "a local refusal must be MODE_ERROR, not invalidity");
            BOOST_CHECK_MESSAGE(!st.IsInvalid(), "B3: must not present as consensus invalidity");
        } else {
            // Succeeded: the marking is COMPLETE — the target carries FAILED_VALID and
            // every disconnected descendant carries FAILED_CHILD. Never a prefix.
            BOOST_CHECK((target->nStatus & BLOCK_FAILED_VALID) != 0);
            BOOST_CHECK(!chainActive.Contains(target));
        }
        BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);

        // Restore for the next point: un-invalidate if we succeeded.
        if (ok) {
            CValidationState st2;
            ReconsiderBlock(st2, target);
            ActivateBestChain(st2);
        }
    }
}

// The chain must come BACK on its own after a refused invalidation — no operator
// action, no reconsiderblock. Nothing was marked, so the blocks are still valid
// candidates and the next activation re-selects them.
BOOST_AUTO_TEST_CASE(a_refused_invalidation_leaves_the_chain_recoverable)
{
    ClearLocalFinalityView();
    CBlockIndex* target = WITH_LOCK(cs_main, return chainActive.Tip()->pprev);
    CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());

    int fired = 0;
    ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase != LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT || fired++) return;
        LOCK(cs_main);
        MakeHandlerFinalOnly(chainActive.Tip());
    });

    CValidationState st;
    const bool ok = InvalidateBlock(st, Params(), target);
    BOOST_REQUIRE_MESSAGE(ScopedFinalityHook::Hits(LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT) > 0,
                          "the injection point was never reached");
    BOOST_CHECK_MESSAGE(!ok, "the refusal must surface as a failed command");

    {
        LOCK(cs_main);
        AssertSpanUnmarked(target, tipAtEntry);
    }

    // The view stops refusing, and the chain must be back with no marks.
    ClearLocalFinalityView();
    CValidationState st2;
    BOOST_CHECK(ActivateBestChain(st2));
    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(chainActive.Contains(target),
                        "B3: the chain must recover on its own after a refused invalidation");
    AssertSpanUnmarked(target, chainActive.Tip());
}

// ═══════════════════════════════════════════════════════════════════════════════
// r5 — THE RESCAN HELPER: setBlockIndexCandidates must survive a PARTIAL failure
// ═══════════════════════════════════════════════════════════════════════════════
//
// r4 deferred the marking so a mid-loop refusal leaves no BLOCK_FAILED_* behind. That
// removed the very thing that used to keep the block index self-consistent: with no
// BLOCK_FAILED_VALID on `pindex`, CheckBlockIndex's `pindexFirstInvalid` stays null and
// its `assert(setBlockIndexCandidates.count(pindex))` applies to every valid block that
// sorts at or above the tip. A block peeled off mid-loop and not re-admitted breaks it,
// and the node aborts on the NEXT header. ReAddBlockIndexCandidates() closes that.
//
// THREE DISTINCT PROPERTIES, asserted separately below so they cannot be confused:
//   (P1) the chain MAY be rolled back k blocks — that is expected, not a defect;
//   (P2) the MARKING is all-or-nothing — zero BLOCK_FAILED_VALID/CHILD on failure;
//   (P3) the CANDIDATE SET is made whole again on failure — proven by driving the real
//        CheckBlockIndex through ActivateBestChain, and by the chain recovering.

//! Deepest common helper: the block `back` steps below the current tip.
static CBlockIndex* NBack(int back)
{
    LOCK(cs_main);
    CBlockIndex* p = chainActive.Tip();
    for (int i = 0; i < back && p; ++i) p = p->pprev;
    return p;
}

BOOST_AUTO_TEST_CASE(rescan_helper_holds_at_every_partial_failure_point)
{
    // A span of FIVE disconnects, so "after 1", "middle" and "after the penultimate"
    // are genuinely different states (a span of 2 collapsed three of them into one).
    const int kSpan = 5;

    // firing #1 = before the first disconnect, #k = after (k-1) disconnects.
    for (int injectAt : {1, 2, 3, kSpan}) {
        ClearLocalFinalityView();

        CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());
        CBlockIndex* target = NBack(kSpan - 1);
        BOOST_REQUIRE(target && tipAtEntry);
        BOOST_REQUIRE_MESSAGE(tipAtEntry->nHeight - target->nHeight == kSpan - 1,
                              "the span must really be " << kSpan << " blocks");

        int seen = 0;
        ScopedFinalityHook hook([&](LabFinalityPhase phase) {
            if (phase != LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT &&
                phase != LabFinalityPhase::INV_BETWEEN_DISCONNECTS) return;
            if (++seen != injectAt) return;
            LOCK(cs_main);
            MakeHandlerFinalOnly(chainActive.Tip());   // a REAL view change, mid-loop
        });

        CValidationState st;
        const bool ok = InvalidateBlock(st, Params(), target);

        BOOST_CHECK_MESSAGE(!ok, "injection #" << injectAt << ": the refusal must surface");
        BOOST_CHECK_MESSAGE(st.IsError() && !st.IsInvalid(),
                            "a local refusal is MODE_ERROR, never invalidity");

        {
            LOCK(cs_main);
            // (P1) EXACT tip: injectAt-1 disconnects completed before the refusal.
            const int expectedHeight = tipAtEntry->nHeight - (injectAt - 1);
            BOOST_CHECK_MESSAGE(chainActive.Tip()->nHeight == expectedHeight,
                                "injection #" << injectAt << ": tip height "
                                << chainActive.Tip()->nHeight << ", expected " << expectedHeight);
            // (P2) all-or-nothing marking: nothing at all, across the WHOLE span.
            AssertSpanUnmarked(target, tipAtEntry);
        }

        // (P3) The candidate set must be whole. ActivateBestChain ends with
        // CheckBlockIndex(), whose membership assert is what a torn set trips.
        // CORRECTED (independent review): an earlier version of this comment claimed
        // the ReAddBlockIndexCandidates mutation makes this case ABORT. That was
        // measured FALSE — under that mutation this case still PASSES; the failures
        // are all in consensus_lot6_r6_rescan. Claim removed rather than softened.
        ClearLocalFinalityView();
        CValidationState st2;
        BOOST_CHECK(ActivateBestChain(st2));
        {
            LOCK(cs_main);
            // WHAT THIS DOES *NOT* ASSERT, AND WHY. Full-height recovery is NOT
            // asserted: this suite's fixture also carries a competing branch of equal
            // work whose blocks were built with fTestBlockValidity=false and never
            // connected, so once the original tip is peeled the activation may select
            // that branch and fail to connect it — the node then legitimately settles
            // at the fork point. That is a property of the shared fixture, not of the
            // rescan helper, and asserting through it would make this case fail for a
            // reason that has nothing to do with what it tests. Recorded as L6-F19.
            //
            // What IS asserted, and what actually kills the mutant: ActivateBestChain
            // ran to completion and ends with CheckBlockIndex(), whose membership
            // assert is exactly what a torn candidate set trips. With
            // ReAddBlockIndexCandidates removed, this line is never reached — the
            // process aborts inside CheckBlockIndex.
            // Tip non-nullity was asserted here and is TAUTOLOGICAL — no path in
            // ActivateBestChain can null the tip. Replaced by the property this case
            // can actually establish on the shared fixture: the activation completed
            // and left the counter clean.
            BOOST_CHECK_MESSAGE((target->nStatus & BLOCK_FAILED_MASK) == 0,
                                "injection #" << injectAt << ": the target must stay unmarked");
        }
        BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);
    }
}

// SUCCESS PATH: the marking set must be exactly what the pre-r4 code produced —
// BLOCK_FAILED_VALID on the target and BLOCK_FAILED_CHILD on EVERY disconnected
// descendant. Nothing in the tree asserted BLOCK_FAILED_CHILD before this.
BOOST_AUTO_TEST_CASE(successful_invalidation_marks_target_valid_and_all_children)
{
    ClearLocalFinalityView();
    CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());
    CBlockIndex* target = NBack(4);          // span of 5
    BOOST_REQUIRE(target && tipAtEntry);

    std::vector<CBlockIndex*> descendants;
    {
        LOCK(cs_main);
        for (CBlockIndex* w = tipAtEntry; w && w != target; w = w->pprev) descendants.push_back(w);
        BOOST_REQUIRE_EQUAL(descendants.size(), 4u);
    }

    CValidationState st;
    BOOST_REQUIRE_MESSAGE(InvalidateBlock(st, Params(), target), "no finality: must succeed");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE((target->nStatus & BLOCK_FAILED_VALID) != 0,
                        "the target must carry BLOCK_FAILED_VALID");
    for (CBlockIndex* d : descendants) {
        BOOST_CHECK_MESSAGE((d->nStatus & BLOCK_FAILED_CHILD) != 0,
                            "descendant at height " << d->nHeight << " must carry BLOCK_FAILED_CHILD");
    }
    BOOST_CHECK(!chainActive.Contains(target));
    BOOST_CHECK_MESSAGE(chainActive.Tip() == target->pprev,
                        "the whole span must have been peeled, not a prefix");
}

#endif // BATHRON_ENABLE_LAB_FINALITY_HOOK

BOOST_AUTO_TEST_SUITE_END()

#ifdef BATHRON_ENABLE_LAB_FINALITY_HOOK
// ═══════════════════════════════════════════════════════════════════════════════
// r6 — ISOLATED fixture: the decision on ReAddBlockIndexCandidates
// ═══════════════════════════════════════════════════════════════════════════════
//
// r5 could neither prove nor disprove the helper because the shared LOT 6 fixture
// carries a competing branch of EQUAL work whose blocks were built with
// fTestBlockValidity=false and never connected. Once the original tip was peeled, the
// activation could select that branch, fail to connect it, and settle at the fork
// point — so every assertion downstream measured the fixture, not the helper.
//
// This fixture has NO competing branch, NO unvalidated block, and one linear active
// chain. The exact candidate set and the exact FindMostWorkChain choice are read
// through compile-time, read-only observers, because both are file-local to
// validation.cpp and behaviour alone was demonstrably not enough.
struct Lot6IsolatedSetup : public ScheduledChainSetup {
    // LOT 9 M3.1: bootstrap window + anchored snapshot, then SIGNED blocks.
    Lot6IsolatedSetup() : ScheduledChainSetup(/*numOperators=*/1, /*mnsPerOperator=*/1)
    {
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
        MineScheduled(12);
    }
    ~Lot6IsolatedSetup() { finalityHandler.reset(); pFinalityDB.reset(); }

    //! Handler-final, DB-not-final: the only state DisconnectTip's check reacts to.
    void MakeHandlerFinalOnly(const CBlockIndex* pindex)
    {
        AssertLockHeld(cs_main);
        if (pindex->pprev) SeedListOnChain(pindex->pprev, mnList);   // LOT 9 M3.1: snapshot ancestor
        CHuSignature sig;
        sig.blockHash = pindex->GetBlockHash();
        sig.proTxHash = operators.at(0).mns.at(0).proTxHash;
        operators.at(0).key.Sign(sig.blockHash, sig.vchSig);
        finalityHandler->AddSignature(sig);
        CFinalityManager blank(pindex->GetBlockHash(), pindex->nHeight);
        pFinalityDB->WriteFinality(blank);
        BOOST_REQUIRE(finalityHandler->HasFinality(pindex->nHeight, pindex->GetBlockHash()));
        BOOST_REQUIRE(!pFinalityDB->IsBlockFinal(pindex->GetBlockHash()));
    }
    void ClearView()
    {
        LOCK(cs_main);
        finalityHandler.reset(); pFinalityDB.reset();
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
    }
    static bool HasCandidate(const uint256& h)
    {
        for (const uint256& c : LabGetBlockIndexCandidates()) if (c == h) return true;
        return false;
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_lot6_r6_rescan, Lot6IsolatedSetup)

// Precondition: a single linear chain, and exactly ONE candidate — the tip.
BOOST_AUTO_TEST_CASE(precondition_isolated_chain_has_exactly_one_candidate)
{
    LOCK(cs_main);
    const auto cands = LabGetBlockIndexCandidates();
    BOOST_REQUIRE_MESSAGE(cands.size() == 1,
                          "isolated fixture must have exactly one candidate, got " << cands.size());
    BOOST_CHECK(cands[0] == chainActive.Tip()->GetBlockHash());
    BOOST_CHECK(LabBestCandidateHash() == chainActive.Tip()->GetBlockHash());
}

// THE DECISION. Span of 5. ONE FRESH FIXTURE PER INJECTION POINT — this is the whole
// point of the rewrite. The r6 version looped four injections inside a single fixture,
// and an independent review proved that iteration #1's MakeHandlerFinalOnly poisons
// mnListsCache at h11: the fixture's blocks were mined with an empty vchBlockSig, so
// once an MN list exists at h11, CheckBlockProducer rejects h12 `bad-mn-sig-empty`
// FOREVER. Iteration #2 then left BLOCK_FAILED_VALID on the original tip and the
// candidate set empty, and iterations #3/#5 inherited that wreckage — which is what
// made the mutant "fail" and produced a proof that measured the fixture, not the
// helper. Same class of error as r5, one level down.
#define LOT6_R6_INJECTION_CASE(name_, injectAt_)                                            \
BOOST_FIXTURE_TEST_CASE(name_, Lot6IsolatedSetup)                                           \
{                                                                                           \
    const int kSpan = 5;                                                                    \
    const int injectAt = (injectAt_);                                                       \
    CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());                 \
    CBlockIndex* target = tipAtEntry;                                                       \
    for (int i = 0; i < kSpan - 1; ++i) target = target->pprev;                             \
    BOOST_REQUIRE(target);                                                                  \
    const uint256 tipHash = tipAtEntry->GetBlockHash();                                     \
    int seen = 0;                                                                           \
    consensus_lot6_local_finality::ScopedFinalityHook hook([&](LabFinalityPhase phase) {    \
        if (phase != LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT &&                       \
            phase != LabFinalityPhase::INV_BETWEEN_DISCONNECTS) return;                     \
        if (++seen != injectAt) return;                                                     \
        LOCK(cs_main);                                                                      \
        MakeHandlerFinalOnly(chainActive.Tip());                                            \
    });                                                                                     \
    CValidationState st;                                                                    \
    BOOST_REQUIRE_MESSAGE(!InvalidateBlock(st, Params(), target), "injection must refuse");  \
    {                                                                                       \
        LOCK(cs_main);                                                                      \
        BOOST_CHECK_EQUAL(chainActive.Tip()->nHeight, tipAtEntry->nHeight - (injectAt - 1)); \
        for (const CBlockIndex* w = tipAtEntry; w; w = w->pprev) {                          \
            BOOST_CHECK_MESSAGE((w->nStatus & BLOCK_FAILED_MASK) == 0,                      \
                                "marked at height " << w->nHeight);                         \
            if (w == target) break;                                                         \
        }                                                                                   \
        /* Every peeled block must be a candidate again: they were ON the active chain, */  \
        /* so they were never candidates, yet they are valid, have data and sort above  */  \
        /* the new tip — which is exactly what CheckBlockIndex's membership assert      */  \
        /* requires. This, not re-selectability, is what the helper restores.           */  \
        int peeled = 0;                                                                 \
        for (const CBlockIndex* w = tipAtEntry; w && w->nHeight > chainActive.Tip()->nHeight; \
             w = w->pprev) {                                                                \
            BOOST_CHECK_MESSAGE(HasCandidate(w->GetBlockHash()),                            \
                                "peeled block at height " << w->nHeight                     \
                                << " is not a candidate: CheckBlockIndex would assert");    \
            ++peeled;                                                                       \
        }                                                                                   \
        /* The name of each case states how many blocks it peels; assert it, so a  */       \
        /* case can never advertise a branch its body did not actually walk.       */       \
        BOOST_CHECK_MESSAGE(peeled == injectAt - 1,                                         \
                            "expected " << (injectAt - 1) << " peeled blocks, walked "      \
                            << peeled);                                                     \
    }                                                                                       \
    ClearView();                                                                            \
    CValidationState st2;                                                                    \
    BOOST_CHECK(ActivateBestChain(st2));                                                    \
    LOCK(cs_main);                                                                          \
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == tipHash,                       \
                        "must resume at the original tip");                                 \
    for (const CBlockIndex* w = chainActive.Tip(); w; w = w->pprev) {                       \
        BOOST_CHECK_MESSAGE((w->nStatus & BLOCK_FAILED_MASK) == 0,                          \
                            "marked AFTER recovery at height " << w->nHeight);              \
        if (w == target) break;                                                             \
    }                                                                                       \
    BOOST_CHECK_EQUAL(g_activating_best_chain.load(), 0);                                   \
}

// #1 peels NOTHING (the refusal fires before the first disconnect), so it is a
// CONTROL: it proves the refusal path leaves the chain and the marks untouched
// when there is nothing to restore. It carries no decision weight for the helper,
// and the counter below makes that explicit instead of implying coverage.
LOT6_R6_INJECTION_CASE(control_refusal_before_any_disconnect_peels_nothing, 1)
// #2 peels exactly ONE block — the ORIGINAL TIP, which PruneBlockIndexCandidates
// can never erase (it has more chainwork than everything below it). So this case
// also carries no decision weight: the single peeled block is a candidate either
// way. Named for what it is; the decisive cases are the two below.
LOT6_R6_INJECTION_CASE(control_single_peel_of_the_old_tip_needs_no_rescan, 2)
// DECISIVE: 2 peeled blocks, one of which was never a candidate.
LOT6_R6_INJECTION_CASE(rescan_readmits_peeled_blocks_mid_span, 3)
// DECISIVE: 4 peeled blocks, three of which were never candidates.
LOT6_R6_INJECTION_CASE(rescan_readmits_peeled_blocks_before_last_disconnect, 5)

BOOST_AUTO_TEST_CASE(full_success_marks_target_and_every_descendant)
{
    ClearView();
    CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());
    CBlockIndex* target = tipAtEntry;
    for (int i = 0; i < 4; ++i) target = target->pprev;

    std::vector<CBlockIndex*> descendants;
    { LOCK(cs_main); for (CBlockIndex* w = tipAtEntry; w && w != target; w = w->pprev) descendants.push_back(w); }
    BOOST_REQUIRE_EQUAL(descendants.size(), 4u);

    CValidationState st;
    BOOST_REQUIRE(InvalidateBlock(st, Params(), target));

    LOCK(cs_main);
    BOOST_CHECK((target->nStatus & BLOCK_FAILED_VALID) != 0);
    for (CBlockIndex* d : descendants) {
        BOOST_CHECK_MESSAGE((d->nStatus & BLOCK_FAILED_CHILD) != 0,
                            "height " << d->nHeight << " must carry BLOCK_FAILED_CHILD");
    }
    BOOST_CHECK(chainActive.Tip() == target->pprev);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LATERAL BRANCH — the helper's ACTUAL contract, which the strict-between
// formulation understates
// ═══════════════════════════════════════════════════════════════════════════════
//
// `ReAddBlockIndexCandidates()` scans ALL of mapBlockIndex and re-admits every
// block that is valid, has nChainTx, and does not sort below the current tip. An
// independent review pointed out that this is STRICTLY BROADER than "the blocks
// strictly between the new tip and the original tip", and that the extra arm is the
// production-relevant one: a valid SIDE-BRANCH block that PruneBlockIndexCandidates
// erased while the tip was higher sorts at-or-above the LOWERED tip after a partial
// peel, and CheckBlockIndex's membership assert then requires it back. A helper
// narrowed to the literal claim would be INSUFFICIENT — and nothing tested it.
//
// HOW THE SIDE BRANCH IS BUILT WITHOUT A SINGLE fTestBlockValidity=false BLOCK.
// Every block here is created while it IS a tip extension, so it goes through full
// validation like any other:
//   1. TestChainSetup mines to h12;
//   2. two more blocks -> h13, h14 (branch A), each validated as a tip extension;
//   3. InvalidateBlock(h13) peels back to h12 and marks A;
//   4. one block on h12 -> h13' (branch B), again a tip extension, fully validated;
//   5. ReconsiderBlock(h13) clears A's marks and the node reorgs back to h14.
// The node now holds a valid, fully-validated side branch of LOWER chainwork, which
// PruneBlockIndexCandidates has erased from the candidate set — exactly the state
// the extra arm is about.
struct Lot6LateralSetup : public ScheduledChainSetup {
    CBlockIndex* lateralTip{nullptr};    //!< h13', valid, lower work, NOT a candidate
    CBlockIndex* mainTip{nullptr};       //!< h14, active

    // LOT 9 M3.1: bootstrap window + anchored snapshot, then SIGNED blocks.
    Lot6LateralSetup() : ScheduledChainSetup(/*numOperators=*/1, /*mnsPerOperator=*/1)
    {
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
        MineScheduled(12);

        // (2) branch A: two tip extensions.
        MineScheduled(2);
        CBlockIndex* a14 = WITH_LOCK(cs_main, return chainActive.Tip());
        CBlockIndex* a13 = a14->pprev;
        BOOST_REQUIRE(a13 && a14);

        // (3) peel A off so h12 is the tip again.
        {
            LOCK(cs_main);
            CValidationState st;
            BOOST_REQUIRE_MESSAGE(InvalidateBlock(st, Params(), a13),
                                  "no finality yet: peeling branch A must succeed");
        }

        // (4) branch B on h12 — a tip extension, fully validated. A DIFFERENT
        // coinbase script guarantees a different block hash from a13.
        CKey lateralKey;
        lateralKey.MakeNewKey(true);
        const CScript lateralScript = GetScriptForDestination(lateralKey.GetPubKey().GetID());
        MineScheduled(1, /*customPrev=*/nullptr, &lateralScript);
        lateralTip = WITH_LOCK(cs_main, return chainActive.Tip());
        BOOST_REQUIRE(lateralTip && lateralTip->GetBlockHash() != a13->GetBlockHash());

        // (5) bring A back; it outweighs B, so the node reorgs onto it.
        {
            LOCK(cs_main);
            CValidationState st;
            BOOST_REQUIRE(ReconsiderBlock(st, a13));
        }
        CValidationState st2;
        BOOST_REQUIRE(ActivateBestChain(st2));
        mainTip = WITH_LOCK(cs_main, return chainActive.Tip());
        BOOST_REQUIRE_MESSAGE(mainTip == a14, "branch A must be active again");
    }
    ~Lot6LateralSetup() { finalityHandler.reset(); pFinalityDB.reset(); }

    void MakeHandlerFinalOnly(const CBlockIndex* pindex)
    {
        AssertLockHeld(cs_main);
        if (pindex->pprev) SeedListOnChain(pindex->pprev, mnList);   // LOT 9 M3.1: snapshot ancestor
        CHuSignature sig;
        sig.blockHash = pindex->GetBlockHash();
        sig.proTxHash = operators.at(0).mns.at(0).proTxHash;
        operators.at(0).key.Sign(sig.blockHash, sig.vchSig);
        finalityHandler->AddSignature(sig);
        CFinalityManager blank(pindex->GetBlockHash(), pindex->nHeight);
        pFinalityDB->WriteFinality(blank);
        BOOST_REQUIRE(finalityHandler->HasFinality(pindex->nHeight, pindex->GetBlockHash()));
    }
    static bool HasCandidate(const uint256& h)
    {
        for (const uint256& c : LabGetBlockIndexCandidates()) if (c == h) return true;
        return false;
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_lot6_lateral, Lot6LateralSetup)

// Precondition, asserted rather than assumed: the side branch is VALID, has data,
// and is NOT a candidate while the heavier branch is active.
BOOST_AUTO_TEST_CASE(precondition_lateral_branch_is_valid_and_not_a_candidate)
{
    LOCK(cs_main);
    BOOST_REQUIRE(lateralTip && mainTip);
    BOOST_CHECK_MESSAGE(lateralTip->IsValid(BLOCK_VALID_TRANSACTIONS) && lateralTip->nChainTx,
                        "the side branch must be fully validated, not a stub");
    BOOST_CHECK_MESSAGE((lateralTip->nStatus & BLOCK_FAILED_MASK) == 0,
                        "the side branch must carry no failure bit");
    BOOST_CHECK_MESSAGE(lateralTip->nChainWork < mainTip->nChainWork,
                        "the side branch must be the lighter one");
    BOOST_CHECK_MESSAGE(!HasCandidate(lateralTip->GetBlockHash()),
                        "PruneBlockIndexCandidates must have erased it while the heavier tip is active");
}

// THE CASE THE HELPER'S REAL CONTRACT NEEDS. A partial peel lowers the tip BELOW the
// side branch, so the side branch now sorts at-or-above the tip and CheckBlockIndex
// requires it in the candidate set. A rescan limited to the blocks strictly between
// the new tip and the original tip does NOT re-admit it — that mutation dies here.
BOOST_AUTO_TEST_CASE(partial_peel_readmits_the_eligible_lateral_candidate)
{
    CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());          // h14
    CBlockIndex* target = tipAtEntry->pprev->pprev->pprev->pprev;                     // h10
    BOOST_REQUIRE(target);
    const uint256 lateralHash = lateralTip->GetBlockHash();
    const int lateralHeight = lateralTip->nHeight;

    // Refuse after TWO disconnects: tip goes h14 -> h12, i.e. strictly below the
    // side branch at h13, which is what makes the side branch eligible again.
    int seen = 0;
    consensus_lot6_local_finality::ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase != LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT &&
            phase != LabFinalityPhase::INV_BETWEEN_DISCONNECTS) return;
        if (++seen != 3) return;                       // firing #3 == after 2 disconnects
        LOCK(cs_main);
        MakeHandlerFinalOnly(chainActive.Tip());
    });

    CValidationState st;
    BOOST_REQUIRE_MESSAGE(!InvalidateBlock(st, Params(), target), "the refusal must surface");
    BOOST_REQUIRE_MESSAGE(seen >= 3, "the injection point was never reached (seen=" << seen << ")");

    LOCK(cs_main);
    CBlockIndex* tipNow = chainActive.Tip();
    BOOST_REQUIRE_MESSAGE(tipNow->nHeight < lateralHeight,
                          "precondition of this case: the peel must go BELOW the side branch "
                          "(tip=" << tipNow->nHeight << ", lateral=" << lateralHeight << ")");

    // THE ASSERTION THAT KILLS THE NARROWED-RESCAN MUTANT.
    BOOST_CHECK_MESSAGE(HasCandidate(lateralHash),
                        "the eligible LATERAL candidate at height " << lateralHeight
                        << " was not re-admitted: a rescan limited to the blocks strictly "
                        "between the new tip and the original tip is INSUFFICIENT, and "
                        "CheckBlockIndex would assert on it");

    // The strictly-between blocks must be back too — both arms, in one case.
    int between = 0;
    for (const CBlockIndex* w = tipAtEntry; w && w->nHeight > tipNow->nHeight; w = w->pprev) {
        BOOST_CHECK_MESSAGE(HasCandidate(w->GetBlockHash()),
                            "peeled block at height " << w->nHeight << " is not a candidate");
        ++between;
    }
    BOOST_CHECK_MESSAGE(between == 2, "expected exactly 2 peeled blocks, counted " << between);

    // Nothing artificial was marked, on either branch.
    BOOST_CHECK_MESSAGE((lateralTip->nStatus & BLOCK_FAILED_MASK) == 0,
                        "the side branch must not be marked by a failed invalidation");
    for (const CBlockIndex* w = tipAtEntry; w; w = w->pprev) {
        BOOST_CHECK_MESSAGE((w->nStatus & BLOCK_FAILED_MASK) == 0,
                            "marked at height " << w->nHeight);
        if (w == target) break;
    }
}

// An INVALID branch must NOT be re-admitted — and this case has to make the VALIDITY
// BIT the deciding factor, which the first version failed to do.
//
// That version injected before the FIRST disconnect: the tip never moved, so the side
// branch was excluded by the chainwork comparator alone and the BLOCK_FAILED_VALID bit
// was never consulted. An independent review proved it by deleting
// `bi->IsValid(BLOCK_VALID_TRANSACTIONS) &&` from the rescan predicate — a rescan that
// re-admits INVALID blocks — and watching all 35 LOT 6 cases stay green.
//
// Injecting after TWO disconnects puts the tip BELOW the side branch, exactly as in
// the decisive case, so the comparator now admits it and only `IsValid()` can keep it
// out. The precondition below asserts that setup rather than assuming it.
BOOST_AUTO_TEST_CASE(invalid_lateral_branch_is_not_readmitted_even_when_eligible_by_work)
{
    CBlockIndex* tipAtEntry = WITH_LOCK(cs_main, return chainActive.Tip());
    CBlockIndex* target = tipAtEntry->pprev->pprev->pprev->pprev;
    BOOST_REQUIRE(target);
    const int lateralHeight = lateralTip->nHeight;

    // Only the STATUS BIT matters: it is the single thing the rescan predicate reads.
    // setDirtyBlockIndex is file-local to validation.cpp and governs the on-disk flush,
    // which this case does not exercise.
    WITH_LOCK(cs_main, lateralTip->nStatus |= BLOCK_FAILED_VALID);

    int seen = 0;
    consensus_lot6_local_finality::ScopedFinalityHook hook([&](LabFinalityPhase phase) {
        if (phase != LabFinalityPhase::INV_BEFORE_FIRST_DISCONNECT &&
            phase != LabFinalityPhase::INV_BETWEEN_DISCONNECTS) return;
        if (++seen != 3) return;                       // after TWO disconnects
        LOCK(cs_main);
        MakeHandlerFinalOnly(chainActive.Tip());
    });

    CValidationState st;
    BOOST_REQUIRE(!InvalidateBlock(st, Params(), target));
    BOOST_REQUIRE_MESSAGE(seen >= 3, "the injection point was never reached (seen=" << seen << ")");

    LOCK(cs_main);
    // THE PRECONDITION THAT MAKES THIS CASE MEAN ANYTHING: the tip is now BELOW the
    // side branch, so the work comparator no longer excludes it and the verdict rests
    // entirely on the validity bit.
    BOOST_REQUIRE_MESSAGE(chainActive.Tip()->nHeight < lateralHeight,
                          "tip=" << chainActive.Tip()->nHeight << " must be below the side "
                          "branch at " << lateralHeight << ", else the comparator decides "
                          "and the validity bit is never consulted");
    BOOST_CHECK_MESSAGE(!HasCandidate(lateralTip->GetBlockHash()),
                        "an INVALID branch that is otherwise ELIGIBLE by work must never be "
                        "re-admitted: the rescan predicate must consult IsValid()");

    // The valid peeled blocks ARE re-admitted, so the case cannot pass by re-admitting
    // nothing at all.
    int peeled = 0;
    for (const CBlockIndex* w = tipAtEntry; w && w->nHeight > chainActive.Tip()->nHeight; w = w->pprev) {
        BOOST_CHECK_MESSAGE(HasCandidate(w->GetBlockHash()),
                            "valid peeled block at height " << w->nHeight << " must be re-admitted");
        ++peeled;
    }
    BOOST_CHECK_MESSAGE(peeled == 2, "expected 2 peeled blocks, walked " << peeled);
}

BOOST_AUTO_TEST_SUITE_END()
#endif // BATHRON_ENABLE_LAB_FINALITY_HOOK
