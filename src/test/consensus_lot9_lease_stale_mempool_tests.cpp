// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 FINAL — STALE TX_OPERATOR_LEASE MUST NOT SURVIVE IN THE MEMPOOL
// =============================================================================
//
// The lease payload is deliberately decoupled from its funding: the signed
// message covers (chainId, version, proTxHash, sequence) and NOTHING about the
// inputs, so ANY third party can wrap the same signed renewal in its own
// transaction. Two wrappers A and B of the same payload therefore coexist on
// the network with distinct txids. When A is mined, B is deterministically
// dead — the chain now demands sequence minedSeq+1 and sequences only grow —
// yet before this remediation nothing evicted B:
//
//   * removeProTxConflicts had no TX_OPERATOR_LEASE case, so connecting A's
//     block left B untouched in every other node's pool;
//   * IsSpecialTxHeightPermanentlyInvalid did not classify the lease, so the
//     block assembler's terminal guard (TestPackageSpecialHeight) let the DMM
//     producer — which builds with fTestValidity=false — package B into a
//     block ConnectBlock rejects: a lost production slot;
//   * after a reorg, a now-premature renewal in the pool blocked the
//     re-acceptance of the disconnected (and again valid) one through
//     existsProviderTxConflict.
//
// These tests are the reproducer (they were run RED against the unfixed base)
// and the regression net. They cover the mandated matrix: competing-wrapper
// eviction, template hygiene, slot liveness, reorg re-acceptance, exact
// sequence scoping (q/q+1/q+2), reload behavior, no DoS escalation, and the
// negative control (an unrelated operator's renewal is untouched). The two
// mandated mutants — dropping the removeProTxConflicts lease case, dropping
// the permanently-invalid classification — are each killed by a direct unit
// case below (eviction_is_sequence_exact_and_operator_scoped, resp.
// stale_classification_is_exact_at_the_sequence_boundary).

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "blockassembler.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "key_io.h"
#include "keystore.h"
#include "masternode/deterministicmns.h"
#include "masternode/providertx.h"
#include "masternode/specialtx_validation.h"
#include "messagesigner.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "txmempool.h"
#include "util/validation.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

//! Two operators: [0] is the renewing one, [1] is the negative control.
struct TwoOpScheduledSetup : public ScheduledChainSetup {
    TwoOpScheduledSetup() : ScheduledChainSetup(/*numOperators=*/2, /*mnsPerOperator=*/1) {}
};

//! A signed lease payload for `proTxHash`/`sequence` — the SAME payload no
//! matter who wraps it (the signed message does not cover the funding).
OperatorLeasePL MakeSignedLeasePayload(const uint256& proTxHash, uint32_t sequence,
                                       const CKey& operatorKey)
{
    OperatorLeasePL pl;
    pl.nVersion = OperatorLeasePL::CURRENT_VERSION;
    pl.proTxHash = proTxHash;
    pl.nLeaseSequence = sequence;
    const uint256 sigHash = pl.GetSignatureHash(Params().GetConsensus().hashGenesisBlock);
    BOOST_REQUIRE(CHashSigner::SignHash(sigHash, operatorKey, pl.vchSig));
    return pl;
}

//! Wrap a signed payload in a transaction spending `fundOutpoint`. Distinct
//! funding => distinct txid, identical renewal.
CMutableTransaction WrapLeasePayload(const OperatorLeasePL& pl, const CKey& fundKey,
                                     const COutPoint& fundOutpoint, CAmount fundValue,
                                     const CScript& fundScript, CAmount fee = 100000)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_OPERATOR_LEASE;
    mtx.vin.emplace_back(fundOutpoint);
    mtx.vout.emplace_back(fundValue - fee, fundScript);
    SetTxPayload(mtx, pl);

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddKey(fundKey));
    BOOST_REQUIRE_MESSAGE(SignSignature(keystore, fundScript, mtx, 0, fundValue, SIGHASH_ALL),
                          "failed to sign the funding input");
    return mtx;
}

//! An UNFUNDED lease wrapper for direct-injection unit cases (the mempool
//! bookkeeping under test never looks at the inputs). `saltN` makes the dummy
//! prevout — and therefore the txid — unique per wrapper.
CMutableTransaction MakeInjectableLease(const uint256& proTxHash, uint32_t sequence,
                                        const CKey& operatorKey, uint32_t saltN)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_OPERATOR_LEASE;
    uint256 dummy;
    *dummy.begin() = (unsigned char)(0xA0 + (saltN & 0x0F));
    *(dummy.begin() + 1) = (unsigned char)(saltN >> 4);
    mtx.vin.emplace_back(COutPoint(dummy, 0));
    mtx.vout.emplace_back(10000, CScript() << OP_TRUE);
    SetTxPayload(mtx, MakeSignedLeasePayload(proTxHash, sequence, operatorKey));
    return mtx;
}

//! Inject a transaction straight into the pool (bypassing admission): this is
//! how a tx ACCEPTED EARLIER — on this node or, morally, on another node whose
//! pool we are modeling — sits in mapTx when the chain state moves under it.
void InjectIntoPool(const CMutableTransaction& mtx)
{
    LOCK2(cs_main, mempool.cs);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(mtx.GetHash(), entry.Fee(100000).FromTx(mtx));
    BOOST_REQUIRE(mempool.exists(mtx.GetHash()));
}

//! Sign as the scheduled producer and submit. Returns ProcessNewBlock's verdict.
bool SignAndSubmit(TwoOpScheduledSetup& setup, CBlock& block, const CBlockIndex* parent)
{
    BOOST_REQUIRE_MESSAGE(SignBlockAsScheduledProducer(block, parent, setup.operators),
                          "no scheduled producer for this block");
    return ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr);
}

bool BlockContains(const CBlock& block, const uint256& txid)
{
    for (const auto& tx : block.vtx) {
        if (tx && tx->GetHash() == txid) return true;
    }
    return false;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot9_lease_stale_mempool, TwoOpScheduledSetup)

// ─────────────────────────────────────────────────────────────────────────────
// Direct unit cases (no premine needed). These are the mutant killers: they
// call the two repaired functions in isolation, so no other layer can mask a
// regression in either one.
// ─────────────────────────────────────────────────────────────────────────────

// MUTANT KILLER for the removeProTxConflicts lease case. Pool holds renewals at
// sequences q, q+1, q+2 for operator P and one at q+1 for operator Q; a block
// mines a DIFFERENT wrapper of P's q+1. Exactly P/q and P/q+1 must go: the
// mined sequence retires everything at or below it, never the legitimate next
// renewal (P/q+2), never another operator (Q).
BOOST_AUTO_TEST_CASE(eviction_is_sequence_exact_and_operator_scoped)
{
    const uint256 P = operators[0].mns[0].proTxHash;
    const uint256 Q = operators[1].mns[0].proTxHash;
    const CKey& keyP = operators[0].key;
    const CKey& keyQ = operators[1].key;
    const uint32_t q = 5;

    const CMutableTransaction poolPq   = MakeInjectableLease(P, q,     keyP, 1);
    const CMutableTransaction poolPq1  = MakeInjectableLease(P, q + 1, keyP, 2);
    const CMutableTransaction poolPq2  = MakeInjectableLease(P, q + 2, keyP, 3);
    const CMutableTransaction poolQq1  = MakeInjectableLease(Q, q + 1, keyQ, 4);
    InjectIntoPool(poolPq);
    InjectIntoPool(poolPq1);
    InjectIntoPool(poolPq2);
    InjectIntoPool(poolQq1);

    // The mined transaction: SAME payload as poolPq1, DIFFERENT wrapper/txid.
    // removeForBlock is the exact call ConnectTip makes; its lease handling
    // lives in removeProTxConflicts (the mutation target).
    const CMutableTransaction minedPq1 = MakeInjectableLease(P, q + 1, keyP, 9);
    BOOST_REQUIRE(minedPq1.GetHash() != poolPq1.GetHash());
    mempool.removeForBlock({MakeTransactionRef(minedPq1)},
                           WITH_LOCK(cs_main, return chainActive.Height() + 1));

    BOOST_CHECK_MESSAGE(!mempool.exists(poolPq.GetHash()),
                        "a renewal BELOW the mined sequence survived eviction");
    BOOST_CHECK_MESSAGE(!mempool.exists(poolPq1.GetHash()),
                        "the competing wrapper AT the mined sequence survived eviction");
    BOOST_CHECK_MESSAGE(mempool.exists(poolPq2.GetHash()),
                        "the legitimate NEXT renewal (mined+1) was excessively evicted");
    BOOST_CHECK_MESSAGE(mempool.exists(poolQq1.GetHash()),
                        "another operator's renewal was evicted by P's confirmation");
}

// MUTANT KILLER for the IsSpecialTxHeightPermanentlyInvalid lease case, pinning
// the exact boundary against the fixture list (current sequence = 0, so the
// chain demands 1): at-or-below-current => permanently dead on this chain;
// exactly-next => live; above-next => premature, which a reorg can revive, so
// NOT permanent. An unknown operator is not classified either (its list entry
// — and with it the staleness claim — is reorg-dependent).
BOOST_AUTO_TEST_CASE(stale_classification_is_exact_at_the_sequence_boundary)
{
    LOCK(cs_main);
    const uint256 P = operators[0].mns[0].proTxHash;
    const CKey& keyP = operators[0].key;
    const uint32_t tipPlus1 = (uint32_t)(chainActive.Height() + 1);
    std::string reason;

    const CTransaction stale(MakeInjectableLease(P, 0, keyP, 11));
    BOOST_CHECK_MESSAGE(IsSpecialTxHeightPermanentlyInvalid(stale, *pcoinsTip, tipPlus1, reason),
                        "a renewal at the CURRENT sequence was not classified permanently invalid");
    BOOST_CHECK_EQUAL(reason, "bad-lease-sequence-stale");

    reason.clear();
    const CTransaction next(MakeInjectableLease(P, 1, keyP, 12));
    BOOST_CHECK_MESSAGE(!IsSpecialTxHeightPermanentlyInvalid(next, *pcoinsTip, tipPlus1, reason),
                        "the exactly-next renewal was classified permanently invalid");

    const CTransaction premature(MakeInjectableLease(P, 2, keyP, 13));
    BOOST_CHECK_MESSAGE(!IsSpecialTxHeightPermanentlyInvalid(premature, *pcoinsTip, tipPlus1, reason),
                        "a PREMATURE renewal was classified permanently invalid (a reorg can revive it)");

    uint256 unknown;
    *unknown.begin() = 0xEE;
    const CTransaction foreign(MakeInjectableLease(unknown, 1, keyP, 14));
    BOOST_CHECK_MESSAGE(!IsSpecialTxHeightPermanentlyInvalid(foreign, *pcoinsTip, tipPlus1, reason),
                        "an unknown-operator renewal was classified permanently invalid");
}

// Terminal defense: even if a stale renewal IS sitting in the pool (injected
// here, bypassing every admission/eviction layer), the assembler must refuse to
// package it — with fTestValidity=false, exactly like the DMM producer — and
// the produced block must still connect. No poisoned template, no lost slot.
BOOST_AUTO_TEST_CASE(the_assembler_never_packages_a_stale_renewal)
{
    const uint256 P = operators[0].mns[0].proTxHash;
    const CMutableTransaction stale = MakeInjectableLease(P, 0, operators[0].key, 21);
    InjectIntoPool(stale);

    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const CScript payout = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    CBlock block = CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                               /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                               /*customPrevBlock=*/parent);
    BOOST_CHECK_MESSAGE(!BlockContains(block, stale.GetHash()),
                        "the assembler packaged a stale renewal into the template");
    BOOST_CHECK_MESSAGE(SignAndSubmit(*this, block, parent),
                        "the produced block was rejected — production slot lost");
}

#ifdef BATHRON_ENABLE_LAB_PREMINE

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end cases over the real pipeline (funded transactions, real admission,
// real block connect). Funding comes from the lab-only regtest premine.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

struct PremineOut {
    const char* wif;
    int n;
};

//! Genesis premine outputs with published lab WIFs (see chainparams.cpp).
const PremineOut PREMINE_OUTS[] = {
    {"cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR", 0},
    {"cPP8PfQgEaStUECCpKFzpZt9hFis8tj6E2vtqr3gweLyZkuwuvvY", 4},
    {"cNYJdV6Muuu1oVRP2fsCHYeTx3pkaq7itEV45mK36gTziSLQ4Qox", 5},
    {"cUhVQbjcbttjN8yLVyY5maqweRZsFSRBsrbo3335AiPWscYAVa66", 6},
};

//! Wrap `pl` spending premine output #idx.
CMutableTransaction WrapFromPremine(const OperatorLeasePL& pl, int idx)
{
    const CKey fundKey = KeyIO::DecodeSecret(PREMINE_OUTS[idx].wif);
    BOOST_REQUIRE(fundKey.IsValid());
    const CTransactionRef genesisTx = Params().GenesisBlock().vtx[0];
    const int n = PREMINE_OUTS[idx].n;
    BOOST_REQUIRE((int)genesisTx->vout.size() > n && genesisTx->vout[n].nValue > 0);
    return WrapLeasePayload(pl, fundKey, COutPoint(genesisTx->GetHash(), n),
                            genesisTx->vout[n].nValue, genesisTx->vout[n].scriptPubKey);
}

bool SubmitToPool(const CMutableTransaction& mtx, CValidationState& state)
{
    bool fMissingInputs = false;
    LOCK(cs_main);
    const bool ok =
        AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), false, &fMissingInputs);
    BOOST_REQUIRE_MESSAGE(!fMissingInputs, "funding input not found for a lease wrapper");
    return ok;
}

} // namespace

// THE REPRODUCER (mandated PHASE A). Two wrappers A and B of the SAME signed
// renewal (same proTxHash, same sequence, same payload — distinct funding,
// distinct txids). B is admitted into this node's pool through the REAL
// admission path; A is mined in a block this pool never saw as a transaction
// (built before B's admission, exactly a block arriving from another node).
// After the connect:
//   1. B must be GONE from the pool (it is deterministically dead: the list
//      now demands sequence 2 and B carries 1);
//   2. the next template must NOT contain B;
//   3. the next produced block must CONNECT — no lost slot;
//   4. the negative control X (other operator, same sequence number) must
//      still be in the pool AND get mined in that next block.
BOOST_AUTO_TEST_CASE(a_mined_renewal_evicts_the_competing_wrapper_everywhere)
{
    const uint256 P = operators[0].mns[0].proTxHash;
    const uint256 Q = operators[1].mns[0].proTxHash;
    const OperatorLeasePL payload = MakeSignedLeasePayload(P, 1, operators[0].key);

    const CMutableTransaction txA = WrapFromPremine(payload, 0);
    const CMutableTransaction txB = WrapFromPremine(payload, 1);  // same payload, other funding
    BOOST_REQUIRE(txA.GetHash() != txB.GetHash());

    // Build the block carrying A on "another node": admit A, let the REAL
    // assembler select it (correct fees), then forget A from the local pool.
    CValidationState state;
    BOOST_REQUIRE_MESSAGE(SubmitToPool(txA, state),
                          "wrapper A refused: " << FormatStateMessage(state));
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const CScript payout = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    CBlock blockA = CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                                /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                /*customPrevBlock=*/parent);
    BOOST_REQUIRE_MESSAGE(BlockContains(blockA, txA.GetHash()),
                          "the assembler did not select wrapper A");
    {
        LOCK2(cs_main, mempool.cs);
        mempool.removeRecursive(CTransaction(txA), MemPoolRemovalReason::REPLACED);
    }

    // THIS node's pool: B (the competing wrapper) and X (the negative control),
    // both admitted by the real path while the renewal is still pending.
    BOOST_REQUIRE_MESSAGE(SubmitToPool(txB, state),
                          "wrapper B refused: " << FormatStateMessage(state));
    const CMutableTransaction txX =
        WrapFromPremine(MakeSignedLeasePayload(Q, 1, operators[1].key), 2);
    BOOST_REQUIRE_MESSAGE(SubmitToPool(txX, state),
                          "control lease X refused: " << FormatStateMessage(state));
    BOOST_REQUIRE(mempool.exists(txB.GetHash()) && mempool.exists(txX.GetHash()));

    // A's block arrives and connects.
    BOOST_REQUIRE_MESSAGE(SignAndSubmit(*this, blockA, parent),
                          "the block carrying wrapper A was rejected");
    {
        LOCK(cs_main);
        auto mn = deterministicMNManager->GetListAtChainTip().GetMN(P);
        BOOST_REQUIRE(mn);
        // B is now stale AGAINST THE DETERMINISTIC STATE: it carries the
        // sequence the chain just consumed.
        BOOST_REQUIRE_EQUAL(mn->pdmnState->nLeaseSequence, 1U);
    }

    // (1) The competing wrapper is evicted, (4a) the control is not.
    BOOST_CHECK_MESSAGE(!mempool.exists(txB.GetHash()),
                        "REPRODUCED: the stale competing wrapper B survived in the mempool");
    BOOST_CHECK_MESSAGE(mempool.exists(txX.GetHash()),
                        "the other operator's renewal was evicted by P's confirmation");

    // (2) Next template: no B. (3)+(4b) The produced block connects and carries X.
    CBlockIndex* tip = WITH_LOCK(cs_main, return chainActive.Tip());
    CBlock nextBlock = CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                                   /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                   /*customPrevBlock=*/tip);
    BOOST_CHECK_MESSAGE(!BlockContains(nextBlock, txB.GetHash()),
                        "REPRODUCED: the stale wrapper B was packaged into the next template");
    BOOST_CHECK_MESSAGE(BlockContains(nextBlock, txX.GetHash()),
                        "the control lease X was not packaged");
    BOOST_CHECK_MESSAGE(SignAndSubmit(*this, nextBlock, tip),
                        "the post-eviction block was rejected — production slot lost");
    {
        LOCK(cs_main);
        auto mnQ = deterministicMNManager->GetListAtChainTip().GetMN(Q);
        BOOST_REQUIRE(mnQ);
        BOOST_CHECK_EQUAL(mnQ->pdmnState->nLeaseSequence, 1U);
    }
}

// Reload behavior (mandate item 7) + no-DoS (PHASE B rule): after the renewal
// is mined, a surviving wrapper re-offered to admission — which is exactly what
// LoadMempool does with every persisted entry at startup — is refused, and the
// refusal carries NO ban score: at relay time a stale sequence is an honest
// race with block propagation, not malice.
BOOST_AUTO_TEST_CASE(a_stale_wrapper_is_refused_at_reload_with_no_ban_score)
{
    const uint256 P = operators[0].mns[0].proTxHash;
    const OperatorLeasePL payload = MakeSignedLeasePayload(P, 1, operators[0].key);

    // Mine wrapper A through the real pipeline.
    CValidationState state;
    BOOST_REQUIRE(SubmitToPool(WrapFromPremine(payload, 0), state));
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const CScript payout = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    CBlock blockA = CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                                /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                /*customPrevBlock=*/parent);
    BOOST_REQUIRE(SignAndSubmit(*this, blockA, parent));

    // Wrapper B of the same payload arrives at admission (relay or reload).
    CValidationState reloadState;
    BOOST_CHECK_MESSAGE(!SubmitToPool(WrapFromPremine(payload, 1), reloadState),
                        "a stale wrapper was re-admitted after the renewal was mined");
    BOOST_CHECK_EQUAL(reloadState.GetRejectReason(), "bad-lease-sequence");
    int nDoS = 0;
    reloadState.IsInvalid(nDoS);
    BOOST_CHECK_MESSAGE(nDoS == 0,
                        "a stale renewal at admission carries a ban score (" << nDoS
                            << ") — an honest relay race would get a peer banned");
}

// Reorg re-acceptance (mandate item 5). Mine A (sequence 1), then admit the
// legitimate NEXT renewal C (sequence 2) into the pool, then disconnect A's
// block. C is now premature (the chain wants 1 again) and must not linger to
// poison templates or block A's return; A — really valid again — must re-enter
// through the NORMAL mechanism (the reorg resurrection path re-runs admission)
// and get mined again. No lost slot at any point.
BOOST_AUTO_TEST_CASE(a_reorg_reaccepts_the_disconnected_renewal_and_drops_the_premature_one)
{
    const uint256 P = operators[0].mns[0].proTxHash;
    const CKey& keyP = operators[0].key;

    // Mine A (sequence 1).
    const CMutableTransaction txA = WrapFromPremine(MakeSignedLeasePayload(P, 1, keyP), 0);
    CValidationState state;
    BOOST_REQUIRE(SubmitToPool(txA, state));
    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const CScript payout = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    CBlock blockA = CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                                /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                /*customPrevBlock=*/parent);
    BOOST_REQUIRE(BlockContains(blockA, txA.GetHash()));
    BOOST_REQUIRE(SignAndSubmit(*this, blockA, parent));

    // The legitimate next renewal C (sequence 2) is admitted for real.
    const CMutableTransaction txC = WrapFromPremine(MakeSignedLeasePayload(P, 2, keyP), 3);
    BOOST_REQUIRE_MESSAGE(SubmitToPool(txC, state),
                          "the legitimate next renewal was refused: " << FormatStateMessage(state));

    // Disconnect A's block.
    {
        LOCK(cs_main);
        CBlockIndex* tip = chainActive.Tip();
        BOOST_REQUIRE(BlockContains(blockA, txA.GetHash()));
        CValidationState invState;
        BOOST_REQUIRE_MESSAGE(InvalidateBlock(invState, Params(), tip),
                              "could not disconnect the block carrying A: "
                                  << FormatStateMessage(invState));
    }

    // The chain wants sequence 1 again.
    {
        LOCK(cs_main);
        auto mn = deterministicMNManager->GetListAtChainTip().GetMN(P);
        BOOST_REQUIRE(mn);
        BOOST_CHECK_EQUAL(mn->pdmnState->nLeaseSequence, 0U);
    }
    // C (premature) is gone; A (valid again) was re-accepted by the normal path.
    BOOST_CHECK_MESSAGE(!mempool.exists(txC.GetHash()),
                        "a now-premature renewal lingered in the pool after the reorg");
    BOOST_CHECK_MESSAGE(mempool.exists(txA.GetHash()),
                        "the disconnected renewal — valid again — was not re-accepted");

    // And the next produced block carries A again: full liveness round-trip.
    CBlockIndex* tip2 = WITH_LOCK(cs_main, return chainActive.Tip());
    CBlock redo = CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                              /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                              /*customPrevBlock=*/tip2);
    BOOST_CHECK_MESSAGE(BlockContains(redo, txA.GetHash()),
                        "the re-accepted renewal was not packaged after the reorg");
    BOOST_CHECK_MESSAGE(SignAndSubmit(*this, redo, tip2),
                        "the post-reorg block was rejected — production slot lost");
    {
        LOCK(cs_main);
        auto mn = deterministicMNManager->GetListAtChainTip().GetMN(P);
        BOOST_REQUIRE(mn);
        BOOST_CHECK_EQUAL(mn->pdmnState->nLeaseSequence, 1U);
    }
}

#else  // !BATHRON_ENABLE_LAB_PREMINE

BOOST_AUTO_TEST_CASE(lease_stale_mempool_e2e_needs_spendable_coins)
{
    BOOST_TEST_MESSAGE("LOT9 stale-lease e2e SKIPPED: this build has no regtest premine "
                       "(configure with --enable-lab-premine), so no funded "
                       "TX_OPERATOR_LEASE can be constructed. The direct unit cases "
                       "above still ran.");
}

#endif // BATHRON_ENABLE_LAB_PREMINE

BOOST_AUTO_TEST_SUITE_END()
