// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M3 — TX_OPERATOR_LEASE, END TO END
// =============================================================================
//
// consensus_lot9_m3_lease_tests.cpp proves the RULES: it calls
// BuildNewListFromBlock directly with a synthetic, unfunded transaction. That is
// the right shape for a rule test, and it is exactly why it could stay green
// while NO construction path existed — for months the lease was imposed by
// consensus and unreachable by any operator, because no RPC and no wallet path
// built one. A test that models a renewal by writing state cannot notice that.
//
// This file closes that gap by submitting a REAL transaction:
//   * funded from a real UTXO, so the O-5 fee minimum is really paid;
//   * signed by the operator key over the chain-bound message;
//   * admitted by AcceptToMemoryPool, selected by the BLOCK ASSEMBLER, and
//     connected by ProcessNewBlock — the whole production pipeline;
//   * then read back from the deterministic MN list at the chain tip.
//
// And it does it TWICE, because a single renewal proves less than it looks:
// sequence 0->1 alone cannot distinguish "sequence must be previous + 1" from
// "sequence must be 1", and expiry at sequence 1 cannot distinguish the correct
// horizon from `sequence * horizon` (the M2 mutant survived exactly that gap).
//
// Funding note: the only spendable coins on a fresh regtest chain come from the
// convenience premine, which is compile-gated behind --enable-lab-premine. In a
// release-configured build there is no money at all, so no funded transaction is
// possible and this file reports a skip instead of pretending to have measured
// something.

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "key_io.h"
#include "keystore.h"
#include "masternode/deterministicmns.h"
#include "masternode/lease_renewer.h"
#include "masternode/providertx.h"
#include "messagesigner.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "state/settlement_logic.h"
#include "txmempool.h"
#include "util/validation.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m3_lease_e2e, ScheduledChainSetup)

// ── Pure properties of the renewal machinery (no chain, no premine needed) ───

// The auto-renewal start is deterministic, stays inside [expiry - L/2,
// expiry - L/4), and STAGGERS co-registered identities. This is what turns the
// genesis case — every initial lease expiring at nearly the same height — from
// "everyone broadcasts in the same block" into a spread schedule.
BOOST_AUTO_TEST_CASE(renewal_start_is_deterministic_staggered_and_keeps_margin)
{
    const uint256 genesisHash = Params().GetConsensus().hashGenesisBlock;
    const int L = 10080;              // the shipped horizon — NOT shortened here
    const int expiry = 20160;

    std::set<int> starts;
    for (int i = 0; i < 8; ++i) {
        uint256 proTx;
        *proTx.begin() = (unsigned char)(i + 1);   // 8 distinct identities
        const int start = LeaseRenewalStartHeight(genesisHash, proTx, /*nextSequence=*/1,
                                                  expiry, L);
        // Deterministic: same inputs, same answer.
        BOOST_CHECK_EQUAL(start, LeaseRenewalStartHeight(genesisHash, proTx, 1, expiry, L));
        // Window: [expiry - L/2, expiry - L/4) — the latest possible slot still
        // leaves L/4 blocks (~1.75 days at 60 s) of safety margin before expiry.
        BOOST_CHECK_MESSAGE(start >= expiry - L / 2, "start " << start << " before the window");
        BOOST_CHECK_MESSAGE(start < expiry - L / 4,
                            "start " << start << " eats into the safety margin");
        // The sequence is part of the hash: the NEXT renewal of the same identity
        // lands on a different slot (re-randomized each horizon).
        BOOST_CHECK(start != LeaseRenewalStartHeight(genesisHash, proTx, 2, expiry, L));
        starts.insert(start);
    }
    // Staggered: 8 identities must not collapse onto one block. (Deterministic
    // hash, fixed inputs — this either always passes or always fails.)
    BOOST_CHECK_MESSAGE(starts.size() >= 4,
                        "8 identities share only " << starts.size() << " start heights");

    // A degenerate horizon must not divide by zero or leave the window.
    const int tiny = LeaseRenewalStartHeight(genesisHash, uint256(), 1, /*expiry=*/8, /*L=*/4);
    BOOST_CHECK(tiny >= 8 - 4 / 2 && tiny < 8);
}

// The funding rate is DERIVED from the consensus floor with a real margin — not a
// restated constant that a floor change could silently strand below the rule.
BOOST_AUTO_TEST_CASE(lease_funding_rate_dominates_the_consensus_floor)
{
    const CAmount floorPerK = ComputeMinM1Fee(1000);
    BOOST_CHECK(LeaseFundingFeeRatePerK() >= 2 * floorPerK);
}

#ifdef BATHRON_ENABLE_LAB_PREMINE

namespace {

//! WIF of regtest genesis output 0 (the "Test Wallet" premine, see
//! CreateBathronRegtestGenesisBlock). Lab-only, worthless, and the only source of
//! spendable coins on a fresh regtest chain.
const char* PREMINE_WIF_OUT0 = "cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR";

//! A fee comfortably above BOTH the relay minimum and the O-5 settlement minimum;
//! the point here is the lease, not fee-edge arithmetic (which
//! `fee_minimum_applies_to_the_lease` already pins).
const CAmount E2E_FEE = 100000;

//! Build a funded, fully signed TX_OPERATOR_LEASE spending `fundOutpoint`.
CMutableTransaction MakeFundedLeaseTx(const uint256& proTxHash, uint32_t sequence,
                                      const CKey& operatorKey, const CKey& fundKey,
                                      const COutPoint& fundOutpoint, CAmount fundValue,
                                      const CScript& fundScript, CAmount fee = E2E_FEE)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_OPERATOR_LEASE;
    mtx.vin.emplace_back(fundOutpoint);
    // Change back to the funding script: the lease creates nothing, it only spends
    // and pays a fee (no mint, no A5/A6/A7 effect).
    mtx.vout.emplace_back(fundValue - fee, fundScript);

    OperatorLeasePL pl;
    pl.nVersion = OperatorLeasePL::CURRENT_VERSION;
    pl.proTxHash = proTxHash;
    pl.nLeaseSequence = sequence;
    const uint256 sigHash = pl.GetSignatureHash(Params().GetConsensus().hashGenesisBlock);
    BOOST_REQUIRE(CHashSigner::SignHash(sigHash, operatorKey, pl.vchSig));
    SetTxPayload(mtx, pl);

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddKey(fundKey));
    BOOST_REQUIRE_MESSAGE(SignSignature(keystore, fundScript, mtx, 0, fundValue, SIGHASH_ALL),
                          "failed to sign the funding input");
    return mtx;
}

//! Submit `mtx` to the mempool, mine ONE scheduled block that the assembler fills
//! from the mempool, and require the transaction to be in it. Returns the height
//! of the block that included it — the INCLUSION height consensus derives the new
//! expiry from.
int SubmitAndMine(ScheduledChainSetup& setup, const CMutableTransaction& mtx)
{
    const CTransactionRef txRef = MakeTransactionRef(mtx);

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(
            AcceptToMemoryPool(mempool, state, txRef, false, &fMissingInputs),
            "the lease was refused by the mempool: " << FormatStateMessage(state)
                << (fMissingInputs ? " (missing inputs)" : ""));
    }

    CBlockIndex* parent = WITH_LOCK(cs_main, return chainActive.Tip());
    const CScript payout = GetScriptForDestination(setup.coinbaseKey.GetPubKey().GetID());
    // fNoMempoolTx=false: the BLOCK ASSEMBLER selects the lease itself. A lease the
    // assembler refuses to package is a lease no operator can ever get mined.
    CBlock block = setup.CreateBlock({}, payout, /*fNoMempoolTx=*/false,
                                     /*fTestBlockValidity=*/false, /*fIncludeQfc=*/true,
                                     /*customPrevBlock=*/parent);
    BOOST_REQUIRE_MESSAGE(SignBlockAsScheduledProducer(block, parent, setup.operators),
                          "no scheduled producer for this block");

    bool found = false;
    for (const auto& tx : block.vtx) {
        if (tx && tx->GetHash() == txRef->GetHash()) { found = true; break; }
    }
    BOOST_REQUIRE_MESSAGE(found, "the block assembler did not include the lease transaction");

    BOOST_REQUIRE_MESSAGE(ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr),
                          "the block carrying the lease was rejected");

    LOCK(cs_main);
    const CBlockIndex* connected = LookupBlockIndex(block.GetHash());
    BOOST_REQUIRE(connected);
    BOOST_REQUIRE_MESSAGE(chainActive.Contains(connected),
                          "the block carrying the lease is not on the active chain");
    return connected->nHeight;
}

} // namespace

// A renewal that a real operator could actually perform: a funded, signed
// transaction goes in at one end and the on-chain lease moves at the other.
BOOST_AUTO_TEST_CASE(a_submitted_lease_advances_sequence_and_expiry_on_chain)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const uint256 proTx = operators[0].mns[0].proTxHash;
    const CKey& opKey = operators[0].key;

    const CKey fundKey = KeyIO::DecodeSecret(PREMINE_WIF_OUT0);
    BOOST_REQUIRE_MESSAGE(fundKey.IsValid(), "could not decode the premine WIF");

    const CTransactionRef genesisTx = Params().GenesisBlock().vtx[0];
    BOOST_REQUIRE_MESSAGE(genesisTx->vout.size() > 1 && genesisTx->vout[0].nValue > 0,
                          "regtest genesis carries no spendable premine");
    COutPoint fundOutpoint(genesisTx->GetHash(), 0);
    CAmount fundValue = genesisTx->vout[0].nValue;
    const CScript fundScript = genesisTx->vout[0].scriptPubKey;

    // The starting point is what registration granted, not something this test wrote.
    const auto before = deterministicMNManager->GetListAtChainTip().GetMN(proTx);
    BOOST_REQUIRE(before);
    const uint32_t seqBefore = before->pdmnState->nLeaseSequence;
    const int expiryBefore = before->pdmnState->nLeaseExpiryHeight;

    // ── Renewal #1 ──────────────────────────────────────────────────────────
    const int height1 = SubmitAndMine(
        *this, MakeFundedLeaseTx(proTx, seqBefore + 1, opKey, fundKey,
                                 fundOutpoint, fundValue, fundScript));

    auto after1 = deterministicMNManager->GetListAtChainTip().GetMN(proTx);
    BOOST_REQUIRE(after1);
    BOOST_CHECK_EQUAL(after1->pdmnState->nLeaseSequence, seqBefore + 1);
    BOOST_CHECK_MESSAGE(after1->pdmnState->nLeaseExpiryHeight
                            == height1 + consensus.nOperatorLeaseBlocks,
        "expiry must be derived from the INCLUSION height (got "
            << after1->pdmnState->nLeaseExpiryHeight << ", want "
            << (height1 + consensus.nOperatorLeaseBlocks) << ")");
    BOOST_CHECK_MESSAGE(after1->pdmnState->nLeaseExpiryHeight != expiryBefore,
                        "the on-chain expiry did not move at all");

    // ── Renewal #2, spending the change of #1 ───────────────────────────────
    // Two renewals are what make the assertions non-vacuous: sequence must track
    // the PREVIOUS value (+1 each time, not "always 1"), and the horizon must NOT
    // scale with the sequence.
    const CMutableTransaction tx1 = MakeFundedLeaseTx(proTx, seqBefore + 1, opKey, fundKey,
                                                      fundOutpoint, fundValue, fundScript);
    fundOutpoint = COutPoint(CTransaction(tx1).GetHash(), 0);
    fundValue = fundValue - E2E_FEE;

    // Mine a couple of blocks so the second inclusion height differs from the
    // first: an expiry that ignored the inclusion height would otherwise still
    // land on the right number by coincidence.
    MineScheduled(2);

    const int height2 = SubmitAndMine(
        *this, MakeFundedLeaseTx(proTx, seqBefore + 2, opKey, fundKey,
                                 fundOutpoint, fundValue, fundScript));
    BOOST_REQUIRE_MESSAGE(height2 > height1 + 1, "the two inclusions must differ in height");

    auto after2 = deterministicMNManager->GetListAtChainTip().GetMN(proTx);
    BOOST_REQUIRE(after2);
    BOOST_CHECK_EQUAL(after2->pdmnState->nLeaseSequence, seqBefore + 2);
    BOOST_CHECK_MESSAGE(after2->pdmnState->nLeaseExpiryHeight
                            == height2 + consensus.nOperatorLeaseBlocks,
        "the horizon must not scale with the sequence — expiry is inclusionHeight + "
        "nOperatorLeaseBlocks, every time (got "
            << after2->pdmnState->nLeaseExpiryHeight << ", want "
            << (height2 + consensus.nOperatorLeaseBlocks) << ")");

    // The horizon is the SAME both times: the difference between the two expiries
    // is exactly the difference between the two inclusion heights, nothing else.
    BOOST_CHECK_EQUAL(after2->pdmnState->nLeaseExpiryHeight - after1->pdmnState->nLeaseExpiryHeight,
                      height2 - height1);

    // Nobody else was renewed by the passage of these blocks.
    for (size_t i = 1; i < operators.size(); ++i) {
        auto other = deterministicMNManager->GetListAtChainTip()
                         .GetMN(operators[i].mns[0].proTxHash);
        BOOST_REQUIRE(other);
        BOOST_CHECK_EQUAL(other->pdmnState->nLeaseSequence, 0U);
    }
}

// The sequence rule survives the real pipeline: a replay of an already-mined
// renewal is refused at ADMISSION, so it never reaches a block.
BOOST_AUTO_TEST_CASE(a_replayed_lease_is_refused_by_the_mempool)
{
    const uint256 proTx = operators[0].mns[0].proTxHash;
    const CKey& opKey = operators[0].key;

    const CKey fundKey = KeyIO::DecodeSecret(PREMINE_WIF_OUT0);
    BOOST_REQUIRE(fundKey.IsValid());
    const CTransactionRef genesisTx = Params().GenesisBlock().vtx[0];
    BOOST_REQUIRE(genesisTx->vout.size() > 1 && genesisTx->vout[0].nValue > 0);
    const COutPoint fundOutpoint(genesisTx->GetHash(), 0);
    const CAmount fundValue = genesisTx->vout[0].nValue;
    const CScript fundScript = genesisTx->vout[0].scriptPubKey;

    const uint32_t seqBefore =
        deterministicMNManager->GetListAtChainTip().GetMN(proTx)->pdmnState->nLeaseSequence;

    SubmitAndMine(*this, MakeFundedLeaseTx(proTx, seqBefore + 1, opKey, fundKey,
                                           fundOutpoint, fundValue, fundScript));

    // Same sequence again, funded from a DIFFERENT premine output so the refusal
    // can only come from the lease rule and not from a double-spend.
    BOOST_REQUIRE(genesisTx->vout.size() > 4);
    const CKey fundKey2 = KeyIO::DecodeSecret("cPP8PfQgEaStUECCpKFzpZt9hFis8tj6E2vtqr3gweLyZkuwuvvY");
    BOOST_REQUIRE(fundKey2.IsValid());
    const CMutableTransaction replay =
        MakeFundedLeaseTx(proTx, seqBefore + 1, opKey, fundKey2,
                          COutPoint(genesisTx->GetHash(), 4), genesisTx->vout[4].nValue,
                          genesisTx->vout[4].scriptPubKey);

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(
            !AcceptToMemoryPool(mempool, state, MakeTransactionRef(replay), false, &fMissingInputs),
            "a replayed lease was ADMITTED to the mempool");
    }
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-lease-sequence");
}

// The fee floor survives the real pipeline: a lease that pays LESS than the O-5
// consensus minimum is refused at ADMISSION. This is the negative twin of the
// builder-side guarantee (BuildAndSendLeaseRenewal funds at a rate derived from
// the same floor and re-checks the SIGNED size) — and it is why the wallet
// having no fee-estimation data on a fresh chain can never produce a mineable
// underpaying lease.
BOOST_AUTO_TEST_CASE(an_underpaying_lease_is_refused_by_the_mempool)
{
    const uint256 proTx = operators[0].mns[0].proTxHash;
    const CKey& opKey = operators[0].key;

    const CKey fundKey = KeyIO::DecodeSecret(PREMINE_WIF_OUT0);
    BOOST_REQUIRE(fundKey.IsValid());
    const CTransactionRef genesisTx = Params().GenesisBlock().vtx[0];
    BOOST_REQUIRE(genesisTx->vout.size() > 1 && genesisTx->vout[0].nValue > 0);

    const uint32_t seqBefore =
        deterministicMNManager->GetListAtChainTip().GetMN(proTx)->pdmnState->nLeaseSequence;

    // Fee = 0: everything else about the transaction is valid (sequence, operator
    // signature, funding), so the refusal can only come from the fee rule.
    const CMutableTransaction underpaying =
        MakeFundedLeaseTx(proTx, seqBefore + 1, opKey, fundKey,
                          COutPoint(genesisTx->GetHash(), 0), genesisTx->vout[0].nValue,
                          genesisTx->vout[0].scriptPubKey, /*fee=*/0);

    CValidationState state;
    bool fMissingInputs = false;
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(
            !AcceptToMemoryPool(mempool, state, MakeTransactionRef(underpaying), false,
                                &fMissingInputs),
            "a zero-fee lease was ADMITTED to the mempool");
    }
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-lease-fee");
}

#else  // !BATHRON_ENABLE_LAB_PREMINE

BOOST_AUTO_TEST_CASE(lease_e2e_needs_spendable_coins)
{
    BOOST_TEST_MESSAGE("LOT9/M3 e2e SKIPPED: this build has no regtest premine "
                       "(configure with --enable-lab-premine), so no funded "
                       "TX_OPERATOR_LEASE can be constructed.");
}

#endif // BATHRON_ENABLE_LAB_PREMINE

BOOST_AUTO_TEST_SUITE_END()
