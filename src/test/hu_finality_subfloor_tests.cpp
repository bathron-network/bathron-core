// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// P0 VALIDATION — Sybil-floor invariant on the irreversibility path.
//
// FINDING UNDER TEST (from the internal Sybil/finality audit): the Sybil floor
// `nHuQuorumSize` (min distinct operators required to finalize) is enforced ONLY
// on the finality-EMISSION path (CHuSignalingManager::HasQuorum, signaling.cpp),
// NOT on the persistence / irreversibility path (CFinalityManager::HasFinality,
// CFinalityManagerDB::IsBlockFinal, and hence WouldViolateHuFinality /
// InvalidateBlock, finality.cpp). Those derive the bar purely from
// HuActiveFinalityThreshold = ceil(2/3·min(E,N)) with the floor never applied.
//
// If true, a block backed by FEWER than nHuQuorumSize distinct operators (e.g.
// during bootstrap, or after mass operator loss) can still be recorded as final
// and lock the chain against reorg — a state the emission path refuses to cross.
//
// Reproduced on TESTNET params (nHuQuorumSize = 4) with an INJECTED population of
// N = 3 operators, WITHOUT modifying any network's chainparams. The fixture
// builds a short synthetic block chain (needed so HasQuorum can compute the
// finality-committee seed hash(H-k), k = nHuFinalitySeedOffset = 3 on testnet)
// and injects the same MN list at every block via the test-only seam.
//
// Threshold arithmetic at N=3 on testnet: ceil(2/3·min(128,3)) = 2.
//
// The suite is DESCRIPTIVE of current behaviour; cases that assert the finding
// also document, in comments, what the proposed invariant (INV-FLOOR: no
// persistence/irreversibility while eligibleDistinctOperators < nHuQuorumSize)
// would change. No fix is applied here.

#include "test/util/mn_finality_setup.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "masternode/blockproducer.h"
#include "state/finality.h"
#include "state/quorum.h"
#include "state/signaling.h"
#include "sync.h"
#include "uint256.h"
#include "validation.h"   // mapBlockIndex, cs_main, deterministicMNManager

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace hu;

namespace {

//! TestnetSetup (⇒ nHuQuorumSize = 4) + a short synthetic block chain with an
//! injected N-operator MN list at every block, and the HU-finality singletons
//! wired up. Lets us drive emission (HasQuorum, needs the seed→ancestor walk),
//! AddSignature, IsBlockFinal and HasConflictingFinality on one population.
struct SubFloorChain : public TestnetSetup {
    // > nHuFinalitySeedOffset (3) so hash(H-k) resolves, AND >= one epoch plus the
    // snapshot depth so the LOT 9 M3 epoch snapshot (which now defines the finality
    // population) resolves inside this synthetic chain, exactly as on a real node.
    // 100 blocks from 5'000'000 puts the TIP at 5'000'099 — the LAST block of its
    // epoch — so a child of the tip opens the next epoch and resolves a DIFFERENT
    // snapshot. The attrition case below needs exactly that.
    static const int NBLOCKS = 100;

    int numOps;
    std::vector<TestOperator> operators;
    CDeterministicMNList mnList;
    std::vector<uint256> hashes;    // stable storage backing phashBlock
    std::vector<CBlockIndex> idx;   // pre-sized: pprev pointers stay valid

    explicit SubFloorChain(int numOps_ = 3)
        : numOps(numOps_), hashes(NBLOCKS), idx(NBLOCKS)
    {
        mnList = BuildTestMNList(numOps, /*mnsPerOperator=*/1, operators);
        const Consensus::Params& consensus = Params().GetConsensus();
        const int act = consensus.DMMScheduleActivationHeight();
        const int len = consensus.nDMMScheduleEpochLength;
        const int kTipHeight = act + ((5'000'000 - act) / len) * len - 1;   // epoch-last
        const int kBaseHeight = kTipHeight - (NBLOCKS - 1);
        {
            LOCK(cs_main);
            for (int h = 0; h < NBLOCKS; ++h) {
                // Base varies with numOps: the finality-context cache (g_finalityCtx)
                // is a global keyed by block hash and persists across fixtures, so the
                // 3-op and 4-op fixtures MUST NOT share hashes (else a cached 3-op
                // context would be read for a 4-op block).
                hashes[h] = ArithToUint256(arith_uint256(0xF00D0000u + numOps * 0x10000u + h));
                // LOT 9 M3.1: the TIP must be the LAST block of an ANCHORED epoch
                // (activation + K*len - 1) so a child of the tip opens the next
                // epoch and resolves a DIFFERENT snapshot. Derived from the live
                // params, never a bare multiple of the epoch length.
                idx[h].nHeight = kBaseHeight + h;
                idx[h].phashBlock = &hashes[h];
                idx[h].pprev = (h == 0) ? nullptr : &idx[h - 1];
                deterministicMNManager->SetListForTesting(&idx[h], mnList,
                                                          /*asTip=*/(h == NBLOCKS - 1));
                mapBlockIndex[hashes[h]] = &idx[h];
            }
        }
        InitHuFinality(/*nCacheSize=*/1 << 16, /*fWipe=*/true);
        huSignalingManager = std::make_unique<CHuSignalingManager>();
    }

    ~SubFloorChain()
    {
        huSignalingManager.reset();
        finalityHandler.reset();
        pFinalityDB.reset();
        LOCK(cs_main);
        for (int h = 0; h < NBLOCKS; ++h) mapBlockIndex.erase(hashes[h]);
        if (deterministicMNManager) deterministicMNManager->SetTipIndex(nullptr);
    }

    const CBlockIndex* Tip() const { return &idx[NBLOCKS - 1]; }

    void AddSig(int opIdx, const uint256& blockHash)
    {
        CHuSignature s;
        s.blockHash = blockHash;
        s.proTxHash = operators.at(opIdx).mns.at(0).proTxHash;
        operators.at(opIdx).key.Sign(blockHash, s.vchSig);
        finalityHandler->AddSignature(s);
    }
};

struct SubFloorChain4 : public SubFloorChain {
    SubFloorChain4() : SubFloorChain(/*numOps=*/4) {}
};

} // namespace

BOOST_AUTO_TEST_SUITE(hu_finality_subfloor_tests)

// Precondition: on testnet the floor (4) is ABOVE the injected population (3),
// and the ordinary threshold at N=3 is 2 — the sub-floor regime.
BOOST_FIXTURE_TEST_CASE(precondition_floor_above_population, SubFloorChain)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    LOCK(cs_main);
    const uint256 blockHash = Tip()->GetBlockHash();

    BOOST_CHECK_EQUAL(consensus.nHuQuorumSize, 4);
    BOOST_CHECK_EQUAL(HuFinalityOperatorCount(blockHash), 3);
    BOOST_CHECK_LT(HuFinalityOperatorCount(blockHash), consensus.nHuQuorumSize);
    // LOT 4: below the floor the threshold is UNREACHABLE, not 2.
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 3),
                      hu::HU_FINALITY_THRESHOLD_UNREACHABLE);
    BOOST_CHECK(!hu::HuFinalityFloorMet(consensus, 3));
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 4), 3);   // control: at the floor
    BOOST_CHECK(hu::HuFinalityFloorMet(consensus, 4));
}

// EMISSION path ENFORCES the floor: HasQuorum refuses while eligible operators
// (3) < nHuQuorumSize (4), regardless of how many signatures arrive.
BOOST_FIXTURE_TEST_CASE(emission_hasquorum_refuses_below_floor, SubFloorChain)
{
    const uint256 blockHash = Tip()->GetBlockHash();

    AddSig(0, blockHash);
    AddSig(1, blockHash);   // 2/3 → ordinary threshold met, but N=3 < floor
    BOOST_CHECK(!huSignalingManager->HasQuorum(blockHash));

    AddSig(2, blockHash);   // 3/3 → still below the 4-operator floor
    BOOST_CHECK(!huSignalingManager->HasQuorum(blockHash));
}

// THE FINDING: the irreversibility path does NOT enforce the floor. With N=3 and
// only 2 signatures, HasFinality (handler) and IsBlockFinal (DB) both report
// FINAL — a state the emission path (above) refuses to cross.
BOOST_FIXTURE_TEST_CASE(db_isblockfinal_honors_below_floor, SubFloorChain)
{
    const uint256 blockHash = Tip()->GetBlockHash();
    const int height = Tip()->nHeight;

    AddSig(0, blockHash);   // 1/3 < threshold 2
    BOOST_CHECK(!pFinalityDB->IsBlockFinal(blockHash));
    BOOST_CHECK(!finalityHandler->HasFinality(height, blockHash));

    AddSig(1, blockHash);   // 2/3 — the OLD threshold; N=3 still below floor 4.
    // LOT 4 (AUD-002): the floor now lives in the threshold derivation, which BOTH
    // the write and the read side use — so this stays FALSE.
    BOOST_CHECK_MESSAGE(!pFinalityDB->IsBlockFinal(blockHash),
                        "AUD-002: sub-floor must not be final on the read side");
    BOOST_CHECK(!finalityHandler->HasFinality(height, blockHash));

    AddSig(2, blockHash);   // 3/3 — unanimous, still below the floor.
    BOOST_CHECK_MESSAGE(!pFinalityDB->IsBlockFinal(blockHash),
                        "AUD-002: unanimity below the floor is still not finality");
}

// The sub-floor record drives the chain-level conflict guard: once the tip is
// (sub-floor) final, a conflicting hash at the same height is rejected by
// HasConflictingFinality — the predicate WouldViolateHuFinality / InvalidateBlock
// consult to lock the chain. So the bypass reaches irreversibility, not just a
// status read.
BOOST_FIXTURE_TEST_CASE(subfloor_final_drives_conflict_guard, SubFloorChain)
{
    const uint256 blockHash = Tip()->GetBlockHash();
    const int height = Tip()->nHeight;

    AddSig(0, blockHash);
    AddSig(1, blockHash);
    AddSig(2, blockHash);   // unanimous at N=3 — still sub-floor
    BOOST_REQUIRE_MESSAGE(!finalityHandler->HasFinality(height, blockHash),
                          "AUD-002: precondition — sub-floor must not be final");

    uint256 conflicting = blockHash;
    *conflicting.begin() ^= 0xff;
    BOOST_REQUIRE(conflicting != blockHash);

    // LOT 4: the sub-floor record no longer reaches the chain-level guard that
    // ConnectBlock / AcceptBlockHeader / WouldViolateHuFinality consult.
    BOOST_CHECK_MESSAGE(!finalityHandler->HasConflictingFinality(height, conflicting),
                        "AUD-002: a sub-floor record must not drive the conflict guard");
    BOOST_CHECK(!finalityHandler->HasConflictingFinality(height, blockHash));
}

// CONTROL at/above the floor (N=4): threshold is 3, and emission and
// irreversibility AGREE — 2/4 is not final; 3/4 is final AND HasQuorum passes.
// Confirms the finding is the floor bypass, not a threshold error.
BOOST_FIXTURE_TEST_CASE(control_at_floor_needs_three_of_four, SubFloorChain4)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const uint256 blockHash = Tip()->GetBlockHash();

    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(HuFinalityOperatorCount(blockHash), 4);
        BOOST_REQUIRE_EQUAL(hu::HuActiveFinalityThreshold(consensus, 4), 3);
    }

    AddSig(0, blockHash);
    AddSig(1, blockHash);   // 2/4 < threshold 3
    BOOST_CHECK(!pFinalityDB->IsBlockFinal(blockHash));
    BOOST_CHECK(!huSignalingManager->HasQuorum(blockHash));

    AddSig(2, blockHash);   // 3/4 == threshold, and N=4 == floor
    BOOST_CHECK(pFinalityDB->IsBlockFinal(blockHash));
    BOOST_CHECK(huSignalingManager->HasQuorum(blockHash));   // floor satisfied → emission agrees
}

// Phase A.6 — transition 4 → 3 (an operator exits / is PoSe-banned / its lease
// expires). An OLD block finalized at N=4 stays protected; a NEW block whose
// population has dropped to 3 must NOT (per INV-FLOOR) acquire finality.
//
// LOT 9 M3 NOTE: the finality population is now resolved from the block's EPOCH
// SNAPSHOT (GetEpochFinalityOperators), not from a per-index injected list, so
// the attrition is modelled the way it actually happens on-chain — by changing
// the SNAPSHOT the new block resolves through. A detached index (the previous
// model) resolves no population at all, which is correct behaviour and not what
// this case is about.
BOOST_FIXTURE_TEST_CASE(transition_four_to_three_new_block_should_not_finalize, SubFloorChain4)
{
    // OLD block at N=4: finalize with 3/4 and confirm protected.
    const uint256 oldHash = Tip()->GetBlockHash();
    AddSig(0, oldHash);
    AddSig(1, oldHash);
    AddSig(2, oldHash);
    BOOST_REQUIRE(pFinalityDB->IsBlockFinal(oldHash));

    // NEW block in the NEXT EPOCH, whose own snapshot holds only 3 operators.
    // The epoch boundary matters: attrition applied to the snapshot the OLD block
    // ALSO resolves through would change that block's population too, and the
    // "stays final" assertion would fail for the wrong reason (it did, under one
    // random ordering, before this was pinned to a boundary).
    const Consensus::Params& consensus = Params().GetConsensus();
    uint256 newHash = ArithToUint256(arith_uint256(0xBEEF0001));
    CBlockIndex newIndex;
    newIndex.nHeight = Tip()->nHeight + 1;   // first block of the NEXT epoch (see NBLOCKS)
    newIndex.phashBlock = &newHash;
    newIndex.pprev = &idx[NBLOCKS - 1];

    std::vector<TestOperator> subOps;
    CDeterministicMNList list3 = BuildTestMNList(/*numOperators=*/3, /*mnsPerOperator=*/1, subOps);
    {
        LOCK(cs_main);
        const int snapNew = mn_consensus::GetEpochSnapshotHeight(newIndex.nHeight,
                                                                 consensus.DMMScheduleActivationHeight(),
                                                                 consensus.nDMMScheduleEpochLength,
                                                                 consensus.nDMMSetSnapshotDepth);
        // A block's population resolves from ITS PARENT (pprev->nHeight + 1), so the
        // old block's snapshot is the one derived from the tip's own height.
        const int snapOld = mn_consensus::GetEpochSnapshotHeight(Tip()->nHeight,
                                                                 consensus.DMMScheduleActivationHeight(),
                                                                 consensus.nDMMScheduleEpochLength,
                                                                 consensus.nDMMSetSnapshotDepth);
        BOOST_REQUIRE_MESSAGE(snapNew != snapOld,
                              "the two blocks must resolve DIFFERENT snapshots, else the "
                              "attrition would also rewrite the old block's population");
        BOOST_REQUIRE_MESSAGE(snapNew >= idx[0].nHeight && snapNew <= idx[NBLOCKS - 1].nHeight,
                              "the new epoch snapshot must fall inside the fixture chain");
        deterministicMNManager->SetListForTesting(&idx[snapNew - idx[0].nHeight], list3, /*asTip=*/false);
        deterministicMNManager->SetListForTesting(&newIndex, list3, /*asTip=*/true);
        mapBlockIndex[newHash] = &newIndex;
        BOOST_REQUIRE_EQUAL(HuFinalityOperatorCount(newHash), 3);
        BOOST_REQUIRE_EQUAL(HuFinalityOperatorCount(oldHash), 4);   // unchanged
    }

    for (int i = 0; i < 2; ++i) {   // 2 of 3 sign (threshold at N=3 is 2)
        CHuSignature s;
        s.blockHash = newHash;
        s.proTxHash = subOps.at(i).mns.at(0).proTxHash;
        subOps.at(i).key.Sign(newHash, s.vchSig);
        finalityHandler->AddSignature(s);
    }

    // LOT 4 (AUD-002) — the operator-attrition case, which is how the floor is
    // reached in practice. The NEW block, whose population dropped below the floor,
    // must NOT finalize; the OLD block, which was legitimately final AT the floor,
    // must remain final. This is also the "historical records" property: applying
    // the floor in the threshold derivation re-derives on READ, so it neither
    // grandfathers a sub-floor record nor retroactively un-finalizes a valid one.
    BOOST_CHECK_MESSAGE(!pFinalityDB->IsBlockFinal(newHash),
                        "AUD-002: a block whose population fell below the floor must not finalize");
    BOOST_CHECK_MESSAGE(pFinalityDB->IsBlockFinal(oldHash),
                        "an at-floor block that was legitimately final must STAY final");

    {
        LOCK(cs_main);
        mapBlockIndex.erase(newHash);
        deterministicMNManager->SetTipIndex(nullptr);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 4 — SENTINEL CONTAINMENT (regression guard for the review's F2/F3)
// ═══════════════════════════════════════════════════════════════════════════════
//
// LAB-FINALITY-SUBFLOOR-REGISTRATION-1 — ces deux cas étaient déclarés APRÈS
// BOOST_AUTO_TEST_SUITE_END(), donc au niveau du module et hors de toute suite.
//
// La règle %.cpp.test de src/Makefile.test.include construit son filtre à partir des
// seuls noms de SUITE trouvés dans le fichier. Le filtre produit ici est
// `-t hu_finality_subfloor_tests`, et Boost répondait alors :
//
//     Test case "unival_null_is_json_null_not_zero" is skipped because disabled
//     Test case "floor_predicate_identifies_the_unreachable_sentinel" is skipped because disabled
//
// 6 cas entrés sur 8. Ces deux gardes n'ont donc JAMAIS été exécutées par make check —
// alors qu'elles existent précisément parce qu'une mutation d'un relecteur avait survécu
// à toute la suite. La garde était elle-même inerte.
//
// Seule la position du marqueur de fin de suite change : les deux cas conservent leur
// fixture, leurs assertions et leur logique à l'identique. BOOST_FIXTURE_TEST_CASE porte
// sa propre fixture, indépendante de celle des autres cas de la suite.
//
// The floor makes HuActiveFinalityThreshold return HU_FINALITY_THRESHOLD_UNREACHABLE
// (INT_MAX) below nHuQuorumSize. That value is INTERNAL and must never surface to an
// operator. It nearly did: `pushKV("quorum_threshold", UniValue::VNULL)` published
// `0` — VNULL is an unscoped enum, so integral promotion selects the int overload —
// which reads as "no signatures required" during the exact emergency the branch
// exists for. A reviewer's mutation reverting both containment fixes survived the
// whole suite, so they are guarded here.

BOOST_FIXTURE_TEST_CASE(unival_null_is_json_null_not_zero, BasicTestingSetup)
{
    // The trap, pinned: the enum form is a NUMBER, the value-initialised form is null.
    UniValue trap(UniValue::VOBJ);
    trap.pushKV("threshold", UniValue::VNULL);
    BOOST_CHECK_MESSAGE(!trap["threshold"].isNull(),
                        "if this ever becomes null the compiler changed; re-check the RPC");
    BOOST_CHECK_MESSAGE(trap["threshold"].isNum() && trap["threshold"].get_int() == 0,
                        "UniValue::VNULL promotes to int 0 — this is why the RPC must not use it");

    // What the RPC must actually emit below the floor.
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("threshold", UniValue());
    BOOST_CHECK_MESSAGE(ok["threshold"].isNull(),
                        "LOT 4: the RPC must publish JSON null, never a number, below the floor");
    BOOST_CHECK(!ok["threshold"].isNum());
}

// The sentinel must be recognisable by the predicate the RPC and the logs branch on,
// and must never be mistaken for a plausible threshold.
BOOST_FIXTURE_TEST_CASE(floor_predicate_identifies_the_unreachable_sentinel, TestnetSetup)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    BOOST_REQUIRE_EQUAL(consensus.nHuQuorumSize, 4);

    // Below the floor: sentinel, and the predicate says "unreachable".
    for (int n : {1, 2, 3}) {
        BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, n),
                          hu::HU_FINALITY_THRESHOLD_UNREACHABLE);
        BOOST_CHECK_MESSAGE(!hu::HuFinalityFloorMet(consensus, n),
                            "N=" << n << " is below the floor and must be reported unreachable");
    }
    // At and above the floor: a real, small, printable threshold.
    for (int n : {4, 9, 128}) {
        const int t = hu::HuActiveFinalityThreshold(consensus, n);
        BOOST_CHECK(hu::HuFinalityFloorMet(consensus, n));
        BOOST_CHECK_MESSAGE(t != hu::HU_FINALITY_THRESHOLD_UNREACHABLE && t > 0 && t <= n,
                            "N=" << n << ": threshold " << t << " must be a real achievable count");
    }
    // The unresolved-block fallback (nOperators <= 0) is NOT the sentinel — it is the
    // conservative ceil(2/3*E). Documented fail-open; pinned so it cannot drift silently.
    BOOST_CHECK(hu::HuFinalityFloorMet(consensus, 0));
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 0),
                      hu::HuVrfFinalityThreshold(consensus.nHuExpectedCommitteeSize));
}

BOOST_AUTO_TEST_SUITE_END()
