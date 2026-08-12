// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 M3 — TX_OPERATOR_LEASE: format, validation, state, undo, two-level
// schedule and finality population (spec §C, decisions O-2/O-3/O-5/O-6/O-7)
// =============================================================================
//
// Every decisive property here has a mutant defined against it (PHASE F); the
// cases are written so those mutants turn them red:
//   * expiry is EXACTLY inclusionHeight + nOperatorLeaseBlocks read from
//     chainparams (mutant: payload-chosen expiry / constant drift);
//   * the operator signature and the strict +1 sequence are load-bearing
//     (mutants: sig ignored / sequence unchecked);
//   * the fee minimum bites (mutant: fee check gutted);
//   * expired identities leave production but NEVER recovery (two mutants);
//   * renewals act only through a FUTURE snapshot (mutant: immediate effect /
//     tip-read);
//   * undo restores sequence AND expiry exactly (mutant: diff drops the fields);
//   * producing a block NEVER renews a lease (mutant: implicit renewal).

#include "test/test_bathron.h"
#include "test/util/mn_finality_setup.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "masternode/providertx.h"
#include "masternode/specialtx_validation.h"
#include "messagesigner.h"
#include "primitives/transaction.h"
#include "state/quorum.h"
#include "state/settlement_logic.h"
#include "sync.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

//! Build a signed TX_OPERATOR_LEASE for `proTxHash` with `sequence`, signed by
//! `opKey` over the message bound to `chainId`.
CMutableTransaction MakeLeaseTx(const uint256& proTxHash, uint32_t sequence,
                                const CKey& opKey, const uint256& chainId)
{
    OperatorLeasePL pl;
    pl.proTxHash = proTxHash;
    pl.nLeaseSequence = sequence;
    const uint256 hash = pl.GetSignatureHash(chainId);
    BOOST_REQUIRE(CHashSigner::SignHash(hash, opKey, pl.vchSig));

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_OPERATOR_LEASE;
    SetTxPayload(mtx, pl);
    return mtx;
}

//! A placeholder coinbase so lease txs sit at vtx[1+] (BuildNewListFromBlock
//! skips vtx[0]).
CTransactionRef DummyCoinbase()
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    return MakeTransactionRef(mtx);
}

//! Run the production per-tx check exactly as mempool/ConnectBlock do.
bool CheckLease(const CMutableTransaction& mtx, const CBlockIndex* pindexPrev,
                CValidationState& state)
{
    LOCK(cs_main);
    return CheckSpecialTx(CTransaction(mtx), pindexPrev, /*view=*/nullptr, state);
}

//! Mutate one MN's state inside `list` (clone-and-update).
template <typename F>
void MutateState(CDeterministicMNList& list, const uint256& proTx, F f)
{
    auto dmn = list.GetMN(proTx);
    BOOST_REQUIRE(dmn);
    auto st = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
    f(*st);
    list.UpdateMN(proTx, st);
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// PHASES B+C — payload format, per-tx validation, fee minimum
// ═════════════════════════════════════════════════════════════════════════════
BOOST_FIXTURE_TEST_SUITE(consensus_lot9_m3_lease, DMMScheduleChainSetup)

BOOST_AUTO_TEST_CASE(valid_renewal_accepted_and_every_forgery_rejected)
{
    SeedListAt(Parent());   // per-tx validation resolves the list at pindexPrev
    const uint256 chainId = Params().GetConsensus().hashGenesisBlock;
    const uint256 proTx = operators[0].mns[0].proTxHash;
    const CKey& opKey = operators[0].key;

    // Valid: sequence prev+1 (fixture registers at 0), current operator key,
    // right chain binding.
    {
        CValidationState st;
        BOOST_CHECK_MESSAGE(CheckLease(MakeLeaseTx(proTx, 1, opKey, chainId), Parent(), st),
                            "valid renewal rejected: " << st.GetRejectReason());
    }
    // Unknown operator.
    {
        CValidationState st;
        BOOST_CHECK(!CheckLease(MakeLeaseTx(uint256S("0xdead"), 1, opKey, chainId), Parent(), st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-lease-protx-hash");
    }
    // Replay (sequence not advanced) and skip (sequence gap): strict +1.
    {
        CValidationState st;
        BOOST_CHECK(!CheckLease(MakeLeaseTx(proTx, 0, opKey, chainId), Parent(), st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-lease-sequence");
        CValidationState st2;
        BOOST_CHECK(!CheckLease(MakeLeaseTx(proTx, 2, opKey, chainId), Parent(), st2));
        BOOST_CHECK_EQUAL(st2.GetRejectReason(), "bad-lease-sequence");
    }
    // Third-party signature: a DIFFERENT operator's key cannot renew this lease.
    {
        CValidationState st;
        BOOST_CHECK(!CheckLease(MakeLeaseTx(proTx, 1, operators[1].key, chainId), Parent(), st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-lease-sig");
    }
    // Cross-chain replay: signed for ANOTHER chain identity.
    {
        CValidationState st;
        BOOST_CHECK(!CheckLease(MakeLeaseTx(proTx, 1, opKey, uint256S("0x1234")), Parent(), st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-lease-sig");
    }
    // Renewal of an EXPIRED lease is ALLOWED (recovery exists for exactly this).
    {
        CDeterministicMNList expired = mnList;
        MutateState(expired, proTx, [](CDeterministicMNState& s){ s.nLeaseExpiryHeight = 1; });
        deterministicMNManager->SetListForTesting(Parent(), expired, /*asTip=*/false);
        CValidationState st;
        BOOST_CHECK_MESSAGE(CheckLease(MakeLeaseTx(proTx, 1, opKey, chainId), Parent(), st),
                            "renewing an expired lease must be allowed: " << st.GetRejectReason());
        deterministicMNManager->SetListForTesting(Parent(), mnList, /*asTip=*/false);
    }
    // Unconfirmed post-bootstrap operator cannot renew.
    {
        CDeterministicMNList unconf = mnList;
        MutateState(unconf, proTx, [&](CDeterministicMNState& s){
            s.nRegisteredHeight = Parent()->nHeight;   // >> bootstrap
            s.confirmedHash.SetNull();
        });
        deterministicMNManager->SetListForTesting(Parent(), unconf, /*asTip=*/false);
        CValidationState st;
        BOOST_CHECK(!CheckLease(MakeLeaseTx(proTx, 1, opKey, chainId), Parent(), st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-lease-operator-unconfirmed");
        deterministicMNManager->SetListForTesting(Parent(), mnList, /*asTip=*/false);
    }
}

// One renewal per proTxHash per block — rejected by a whole-block scan, so the
// verdict cannot depend on transaction order.
BOOST_AUTO_TEST_CASE(duplicate_renewal_in_block_rejected_order_independently)
{
    const uint256 chainId = Params().GetConsensus().hashGenesisBlock;
    const uint256 proTx = operators[0].mns[0].proTxHash;

    auto lease1 = MakeTransactionRef(MakeLeaseTx(proTx, 1, operators[0].key, chainId));
    auto lease2 = MakeTransactionRef(MakeLeaseTx(proTx, 2, operators[0].key, chainId));
    auto other  = MakeTransactionRef(MakeLeaseTx(operators[1].mns[0].proTxHash, 1,
                                                 operators[1].key, chainId));

    std::vector<CTransactionRef> forward{DummyCoinbase(), lease1, lease2};
    std::vector<CTransactionRef> reversed{DummyCoinbase(), lease2, lease1};
    CValidationState stF, stR;
    BOOST_CHECK(!CheckNoDuplicateOperatorLeasesInBlock(forward, stF));
    BOOST_CHECK(!CheckNoDuplicateOperatorLeasesInBlock(reversed, stR));
    BOOST_CHECK_EQUAL(stF.GetRejectReason(), "bad-lease-duplicate-in-block");
    BOOST_CHECK_EQUAL(stR.GetRejectReason(), stF.GetRejectReason());   // order-blind

    // Two DIFFERENT operators in one block are fine.
    std::vector<CTransactionRef> mixed{DummyCoinbase(), lease1, other};
    CValidationState stM;
    BOOST_CHECK(CheckNoDuplicateOperatorLeasesInBlock(mixed, stM));
}

// O-5: the lease pays the shared settlement minimum — no exemption. (The check
// is wired into BOTH fee loops right after GetSettlementTxFee.)
BOOST_AUTO_TEST_CASE(lease_fee_minimum_bites)
{
    const uint256 chainId = Params().GetConsensus().hashGenesisBlock;
    CMutableTransaction mtx = MakeLeaseTx(operators[0].mns[0].proTxHash, 1,
                                          operators[0].key, chainId);
    const CTransaction tx(mtx);
    const CAmount minFee = ComputeMinM1Fee(::GetSerializeSize(tx, PROTOCOL_VERSION));
    BOOST_REQUIRE(minFee >= 1);

    CValidationState stLow;
    BOOST_CHECK(!CheckSettlementMinFee(tx, minFee - 1, stLow));
    BOOST_CHECK_EQUAL(stLow.GetRejectReason(), "bad-lease-fee");
    CValidationState stZero;
    BOOST_CHECK(!CheckSettlementMinFee(tx, 0, stZero));
    CValidationState stOk;
    BOOST_CHECK(CheckSettlementMinFee(tx, minFee, stOk));

    // NORMAL txs are untouched by this rule (their minimums live elsewhere).
    CMutableTransaction normal;
    CValidationState stN;
    BOOST_CHECK(CheckSettlementMinFee(CTransaction(normal), 0, stN));
}

// ═════════════════════════════════════════════════════════════════════════════
// PHASES A+B+D — state transition, consensus-derived expiry, exact undo
// ═════════════════════════════════════════════════════════════════════════════

// The renewal applied by BuildNewListFromBlock: sequence taken from the payload,
// expiry derived from the INCLUSION height and the chainparams constant — the
// payload carries no expiry to choose from.
BOOST_AUTO_TEST_CASE(renewal_applies_consensus_derived_expiry)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    SeedListAt(Parent());
    const uint256 proTx = operators[2].mns[0].proTxHash;

    CBlock block;
    block.vtx.push_back(DummyCoinbase());
    block.vtx.push_back(MakeTransactionRef(
        MakeLeaseTx(proTx, 1, operators[2].key, consensus.hashGenesisBlock)));

    CValidationState st;
    CDeterministicMNList newList;
    {
        LOCK2(cs_main, deterministicMNManager->cs);
        BOOST_REQUIRE(deterministicMNManager->BuildNewListFromBlock(
            block, Parent(), st, newList, /*debugLogs=*/false));
    }

    auto dmn = newList.GetMN(proTx);
    BOOST_REQUIRE(dmn);
    BOOST_CHECK_EQUAL(dmn->pdmnState->nLeaseSequence, 1U);
    // EXACT arithmetic, pinned against the CANONICAL chainparams value (never a
    // re-copied literal): expiry = inclusionHeight + nOperatorLeaseBlocks.
    BOOST_CHECK_EQUAL(dmn->pdmnState->nLeaseExpiryHeight,
                      ChildHeight() + consensus.nOperatorLeaseBlocks);
    BOOST_CHECK_EQUAL(consensus.nOperatorLeaseBlocks, 10080);

    // THE EXPIRY IS INDEPENDENT OF THE PAYLOAD — measured, not assumed. Asserting
    // this at sequence 1 ALONE is vacuous: a `sequence * nOperatorLeaseBlocks`
    // implementation is numerically identical there (mutant M2 survived exactly
    // that gap). Renew again from sequence 1 -> 2 and require the SAME horizon.
    {
        CDeterministicMNList atSeq1 = mnList;
        MutateState(atSeq1, proTx, [](CDeterministicMNState& s){ s.nLeaseSequence = 1; });
        deterministicMNManager->SetListForTesting(Parent(), atSeq1, /*asTip=*/false);

        CBlock block2;
        block2.vtx.push_back(DummyCoinbase());
        block2.vtx.push_back(MakeTransactionRef(
            MakeLeaseTx(proTx, 2, operators[2].key, consensus.hashGenesisBlock)));

        CValidationState st2;
        CDeterministicMNList list2;
        {
            LOCK2(cs_main, deterministicMNManager->cs);
            BOOST_REQUIRE(deterministicMNManager->BuildNewListFromBlock(
                block2, Parent(), st2, list2, /*debugLogs=*/false));
        }
        auto dmn2 = list2.GetMN(proTx);
        BOOST_REQUIRE(dmn2);
        BOOST_CHECK_EQUAL(dmn2->pdmnState->nLeaseSequence, 2U);
        BOOST_CHECK_MESSAGE(dmn2->pdmnState->nLeaseExpiryHeight
                                == ChildHeight() + consensus.nOperatorLeaseBlocks,
            "the horizon must NOT scale with the payload's sequence — expiry is "
            "derived from the inclusion height alone (got "
            << dmn2->pdmnState->nLeaseExpiryHeight << ", want "
            << (ChildHeight() + consensus.nOperatorLeaseBlocks) << ")");
        deterministicMNManager->SetListForTesting(Parent(), mnList, /*asTip=*/false);
    }

    // The OTHER operators are untouched (no implicit renewal of anyone).
    for (int i = 0; i < (int)operators.size(); ++i) {
        if (operators[i].mns[0].proTxHash == proTx) continue;
        auto other = newList.GetMN(operators[i].mns[0].proTxHash);
        BOOST_REQUIRE(other);
        BOOST_CHECK_EQUAL(other->pdmnState->nLeaseSequence, 0U);
        BOOST_CHECK_EQUAL(other->pdmnState->nLeaseExpiryHeight, 2'000'000'000);
    }
}

// Producing a block NEVER renews a lease (spec O-7/D.20): a block with no lease
// tx leaves every lease byte-identical, whatever its nTime says about slots.
BOOST_AUTO_TEST_CASE(producing_a_block_never_renews_a_lease)
{
    SeedListAt(Parent());
    CBlock emptyBlock;
    emptyBlock.vtx.push_back(DummyCoinbase());
    emptyBlock.nTime = (unsigned int)ChildTimeAtSlot(7);   // deep recovery-ish slot

    CValidationState st;
    CDeterministicMNList newList;
    {
        LOCK2(cs_main, deterministicMNManager->cs);
        BOOST_REQUIRE(deterministicMNManager->BuildNewListFromBlock(
            emptyBlock, Parent(), st, newList, /*debugLogs=*/false));
    }
    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& before) {
        auto after = newList.GetMN(before->proTxHash);
        BOOST_REQUIRE(after);
        BOOST_CHECK_EQUAL(after->pdmnState->nLeaseSequence, before->pdmnState->nLeaseSequence);
        BOOST_CHECK_EQUAL(after->pdmnState->nLeaseExpiryHeight, before->pdmnState->nLeaseExpiryHeight);
    });
}

// Registration defines the initial lease state (sequence 0, full horizon from
// the registration height) — nothing user-supplied.
BOOST_AUTO_TEST_CASE(registration_initializes_the_lease)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    SeedListAt(Parent());

    ProRegPL pl;
    pl.nVersion = 3;
    CKey ownerKey; ownerKey.MakeNewKey(true);
    CKey opKey; opKey.MakeNewKey(true);
    pl.keyIDOwner = ownerKey.GetPubKey().GetID();
    pl.pubKeyOperator = opKey.GetPubKey();
    pl.keyIDVoting = pl.keyIDOwner;
    pl.collateralOutpoint = COutPoint(uint256S("0xabcd"), 0);

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::PROREG;
    SetTxPayload(mtx, pl);

    CBlock block;
    block.vtx.push_back(DummyCoinbase());
    block.vtx.push_back(MakeTransactionRef(mtx));

    CValidationState st;
    CDeterministicMNList newList;
    {
        LOCK2(cs_main, deterministicMNManager->cs);
        BOOST_REQUIRE(deterministicMNManager->BuildNewListFromBlock(
            block, Parent(), st, newList, /*debugLogs=*/false));
    }
    auto dmn = newList.GetMN(CTransaction(mtx).GetHash());
    BOOST_REQUIRE(dmn);
    BOOST_CHECK_EQUAL(dmn->pdmnState->nLeaseSequence, 0U);
    BOOST_CHECK_EQUAL(dmn->pdmnState->nLeaseExpiryHeight,
                      ChildHeight() + consensus.nOperatorLeaseBlocks);
}

// Undo exactness (PHASE D / mutant 9): the state diff carries BOTH lease fields,
// round-trips through serialization, and the inverse diff restores the previous
// sequence and expiry EXACTLY — this is the machinery DisconnectBlock/-reindex
// replay, so no partial renewal can survive a reorg.
BOOST_AUTO_TEST_CASE(undo_restores_sequence_and_expiry_exactly)
{
    CDeterministicMNState before;
    before.nLeaseSequence = 4;
    before.nLeaseExpiryHeight = 123456;
    CDeterministicMNState after = before;
    after.nLeaseSequence = 5;
    after.nLeaseExpiryHeight = 133536;

    // Forward diff carries the fields...
    CDeterministicMNStateDiff fwd(before, after);
    BOOST_CHECK(fwd.fields & CDeterministicMNStateDiff::Field_nLeaseSequence);
    BOOST_CHECK(fwd.fields & CDeterministicMNStateDiff::Field_nLeaseExpiryHeight);

    // ...survives serialization (the on-disk list-diff format)...
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << fwd;
    CDeterministicMNStateDiff fwdLoaded;
    ss >> fwdLoaded;
    CDeterministicMNState applied = before;
    fwdLoaded.ApplyToState(applied);
    BOOST_CHECK_EQUAL(applied.nLeaseSequence, 5U);
    BOOST_CHECK_EQUAL(applied.nLeaseExpiryHeight, 133536);

    // ...and the INVERSE diff restores the exact previous state (undo path).
    CDeterministicMNStateDiff inv(after, before);
    CDeterministicMNState restored = applied;
    inv.ApplyToState(restored);
    BOOST_CHECK_EQUAL(restored.nLeaseSequence, 4U);
    BOOST_CHECK_EQUAL(restored.nLeaseExpiryHeight, 123456);

    // List-level: BuildDiff/ApplyDiff round-trip restores the pre-renewal list.
    SeedListAt(Parent());
    const uint256 proTx = operators[1].mns[0].proTxHash;
    CDeterministicMNList renewed = mnList;
    MutateState(renewed, proTx, [](CDeterministicMNState& s){
        s.nLeaseSequence = 1; s.nLeaseExpiryHeight = 999999;
    });
    auto fwdList = mnList.BuildDiff(renewed);
    auto invList = renewed.BuildDiff(mnList);
    CDeterministicMNList roundtrip = mnList.ApplyDiff(Parent(), fwdList).ApplyDiff(Parent(), invList);
    auto rdmn = roundtrip.GetMN(proTx);
    BOOST_REQUIRE(rdmn);
    BOOST_CHECK_EQUAL(rdmn->pdmnState->nLeaseSequence, mnList.GetMN(proTx)->pdmnState->nLeaseSequence);
    BOOST_CHECK_EQUAL(rdmn->pdmnState->nLeaseExpiryHeight, mnList.GetMN(proTx)->pdmnState->nLeaseExpiryHeight);
}

// ═════════════════════════════════════════════════════════════════════════════
// PHASE E — two-level schedule + finality population on the lease
// ═════════════════════════════════════════════════════════════════════════════

// Expired identities leave the NORMAL calendar (production) but stay in the
// RECOVERY permutation; with everything expired, recovery is available from
// slot 0 and the chain does not brick.
BOOST_AUTO_TEST_CASE(expired_leaves_production_but_never_recovery)
{
    const int snapH = SnapshotIndex()->nHeight;

    // Expire operators 0 and 1 AT the snapshot (boundary: expiry == snapshotHeight
    // means EXPIRED; expiry == snapshotHeight+1 is still valid — pinned here).
    CDeterministicMNList snap = mnList;
    MutateState(snap, operators[0].mns[0].proTxHash,
                [&](CDeterministicMNState& s){ s.nLeaseExpiryHeight = snapH; });      // expired (equality)
    MutateState(snap, operators[1].mns[0].proTxHash,
                [&](CDeterministicMNState& s){ s.nLeaseExpiryHeight = snapH + 1; }); // still valid
    deterministicMNManager->SetListForTesting(SnapshotIndex(), snap, /*asTip=*/false);

    mn_consensus::EpochOperatorSets sets;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mn_consensus::ResolveEpochOperatorSets(Parent(), sets)
                      == mn_consensus::ScheduleStatus::OK);
    }
    BOOST_CHECK_EQUAL(sets.recovery.size(), 4U);      // everyone stays recoverable
    BOOST_CHECK_EQUAL(sets.production.size(), 3U);    // only op0 (equality) is out
    BOOST_CHECK(std::find(sets.production.begin(), sets.production.end(),
                          operators[0].mns[0].proTxHash) == sets.production.end());
    BOOST_CHECK(std::find(sets.production.begin(), sets.production.end(),
                          operators[1].mns[0].proTxHash) != sets.production.end());

    // Normal slots (rawSlot < P) never elect the expired identity.
    for (int64_t s = 0; s < (int64_t)sets.production.size(); ++s) {
        const int64_t t = (s == 0) ? MinChildTime() : ChildTimeAtSlot(s);
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        LOCK(cs_main);
        BOOST_REQUIRE(mn_consensus::ResolveScheduledProducer(Parent(), t, mn, res)
                      == mn_consensus::ScheduleStatus::OK);
        BOOST_CHECK(!res.fRecovery);
        BOOST_CHECK(mn->proTxHash != operators[0].mns[0].proTxHash);
    }
    // At rawSlot >= P the recovery permutation opens and CAN elect the expired one
    // (scan a few recovery slots; the domain-separated permutation must reach it).
    bool expiredElected = false;
    for (int64_t s = (int64_t)sets.production.size();
         s < (int64_t)(sets.production.size() + 2 * sets.recovery.size()); ++s) {
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        LOCK(cs_main);
        BOOST_REQUIRE(mn_consensus::ResolveScheduledProducer(Parent(), ChildTimeAtSlot(s), mn, res)
                      == mn_consensus::ScheduleStatus::OK);
        BOOST_CHECK(res.fRecovery);
        if (mn->proTxHash == operators[0].mns[0].proTxHash) expiredElected = true;
    }
    BOOST_CHECK_MESSAGE(expiredElected, "the recovery permutation must reach the expired identity");

    // ALL leases expired: production empty, recovery from slot 0 — no brick (D.14).
    CDeterministicMNList allExpired = mnList;
    for (const auto& op : operators) {
        MutateState(allExpired, op.mns[0].proTxHash,
                    [&](CDeterministicMNState& s){ s.nLeaseExpiryHeight = snapH; });
    }
    deterministicMNManager->SetListForTesting(SnapshotIndex(), allExpired, /*asTip=*/false);
    CDeterministicMNCPtr mn;
    mn_consensus::DMMScheduleResult res;
    LOCK(cs_main);
    BOOST_REQUIRE(mn_consensus::ResolveScheduledProducer(Parent(), MinChildTime(), mn, res)
                  == mn_consensus::ScheduleStatus::OK);
    BOOST_CHECK(res.fRecovery);
    BOOST_CHECK(mn != nullptr);
}

// Lease state changes act ONLY through a future snapshot: an expiry or renewal
// visible in the PARENT list (mid-epoch) changes nothing in the current epoch —
// the resolver and the finality population read the SNAPSHOT, never the tip.
BOOST_AUTO_TEST_CASE(midepoch_changes_have_no_effect_before_the_next_snapshot)
{
    // Snapshot: everyone valid (fixture default, already seeded).
    // Parent list (the "tip view"): operator 3 EXPIRED and operator 0 renewed with
    // a huge sequence — neither may leak into the current epoch.
    CDeterministicMNList tipView = mnList;
    MutateState(tipView, operators[3].mns[0].proTxHash,
                [](CDeterministicMNState& s){ s.nLeaseExpiryHeight = 1; });
    MutateState(tipView, operators[0].mns[0].proTxHash,
                [](CDeterministicMNState& s){ s.nLeaseSequence = 42; s.nLeaseExpiryHeight = 2'000'000'001; });
    deterministicMNManager->SetListForTesting(Parent(), tipView, /*asTip=*/true);

    mn_consensus::EpochOperatorSets sets;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mn_consensus::ResolveEpochOperatorSets(Parent(), sets)
                      == mn_consensus::ScheduleStatus::OK);
    }
    BOOST_CHECK_EQUAL(sets.production.size(), 4U);   // op3's mid-epoch expiry: NO effect
    BOOST_CHECK_EQUAL(sets.recovery.size(), 4U);

    // Finality population identical: 4 operators, from the snapshot.
    BOOST_CHECK_EQUAL(hu::GetEpochFinalityOperators(Parent()).size(), 4U);
}

// finalitySet == productionSet: expiries shrink N at the snapshot; below the
// Sybil floor the threshold goes UNREACHABLE (stall fail-closed) while the
// schedule keeps producing through recovery; renewals restore N and the
// threshold comes back — automatically.
BOOST_AUTO_TEST_CASE(finality_population_tracks_the_lease_and_stalls_below_floor)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int snapH = SnapshotIndex()->nHeight;

    // All four valid: N = 4 (== testnet floor), threshold ceil(2/3*4) = 3.
    BOOST_CHECK_EQUAL(hu::GetEpochFinalityOperators(Parent()).size(), 4U);
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 4), 3);

    // Three leases expired at the snapshot: N = 1 < nHuQuorumSize -> UNREACHABLE.
    CDeterministicMNList mostlyExpired = mnList;
    for (int i = 1; i < 4; ++i) {
        MutateState(mostlyExpired, operators[i].mns[0].proTxHash,
                    [&](CDeterministicMNState& s){ s.nLeaseExpiryHeight = snapH; });
    }
    deterministicMNManager->SetListForTesting(SnapshotIndex(), mostlyExpired, /*asTip=*/false);
    const int nStalled = (int)hu::GetEpochFinalityOperators(Parent()).size();
    BOOST_CHECK_EQUAL(nStalled, 1);
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, nStalled),
                      hu::HU_FINALITY_THRESHOLD_UNREACHABLE);
    // ...but production still resolves (recovery keeps the chain alive).
    {
        CDeterministicMNCPtr mn;
        mn_consensus::DMMScheduleResult res;
        LOCK(cs_main);
        BOOST_CHECK(mn_consensus::ResolveScheduledProducer(Parent(), MinChildTime(), mn, res)
                    == mn_consensus::ScheduleStatus::OK);
    }

    // Renewals land (modelled at the NEXT snapshot): N back to 4, threshold 3 —
    // finality restarts with no operator action beyond the renewals themselves.
    deterministicMNManager->SetListForTesting(SnapshotIndex(), mnList, /*asTip=*/false);
    const int nRestored = (int)hu::GetEpochFinalityOperators(Parent()).size();
    BOOST_CHECK_EQUAL(nRestored, 4);
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, nRestored), 3);
}

BOOST_AUTO_TEST_SUITE_END()
