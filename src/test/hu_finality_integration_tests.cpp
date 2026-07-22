// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Integration tests for operator-based HU quorum finality, built on the
// multi-MN fixture (test/util/mn_finality_setup.h).
//
// Phase 0 (this file): GREEN smoke tests that prove the fixture wires a real
// operator-resolved MN list into the global manager and that the operator-vs-
// signature counting helpers behave as documented. The RED tests that assert the
// finality DECISION (HasFinality must count operators, and must use the network
// threshold — findings hu-finality-0 / hu-finality-1) are added in Phase 1
// alongside the fix, so the suite stays green at the Lot-0 boundary.

#include "test/util/mn_finality_setup.h"

#include "arith_uint256.h"
#include "chainparams.h"
#include "key.h"
#include "masternode/deterministicmns.h"
#include "state/finality.h"
#include "state/quorum.h"
#include "uint256.h"
#include "vrf.h"

#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace hu;

BOOST_AUTO_TEST_SUITE(hu_finality_integration_tests)

// The fixture injects an operator-resolved MN list into the global manager:
// 3 operators each running 2 MNs => 6 MNs, 3 unique operators at the tip.
BOOST_FIXTURE_TEST_CASE(fixture_injects_operator_resolved_list, MultiMNFinalitySetup)
{
    // (defaults: 3 operators x 1 MN) — re-build explicitly for clarity.
    CDeterministicMNList tipList = deterministicMNManager->GetListAtChainTip();
    auto uniqueOps = GetUniqueOperators(tipList);
    BOOST_CHECK_EQUAL(uniqueOps.size(), operators.size());
    BOOST_CHECK(!uniqueOps.empty());
}

// Core of finding hu-finality-1, asserted on the COUNTING helpers (green today):
// several MNs of the SAME operator collapse to ONE unique operator, even though
// they contribute several distinct proTxHash signatures.
struct OneOperatorManyMNs : public MultiMNFinalitySetup {
    OneOperatorManyMNs() : MultiMNFinalitySetup(/*numOperators=*/1, /*mnsPerOperator=*/3) {}
};

BOOST_FIXTURE_TEST_CASE(same_operator_mns_collapse_to_one_operator, OneOperatorManyMNs)
{
    const uint256 blockHash = TipIndex()->GetBlockHash();
    CFinalityManager fm(blockHash, 5'000'000);
    for (int i = 0; i < 3; ++i) {
        CHuSignature s = SignAs(/*opIdx=*/0, /*mnIdx=*/i, blockHash);
        fm.mapSignatures[s.proTxHash] = s.vchSig;
    }

    // Three distinct MN signatures...
    BOOST_CHECK_EQUAL(fm.GetSignatureCount(), 3u);
    // ...but a single unique operator (the property finality must count).
    BOOST_CHECK_EQUAL(fm.GetUniqueOperatorCount(), 1u);
}

// Counterpart: distinct operators each contribute one operator-vote.
BOOST_FIXTURE_TEST_CASE(distinct_operators_each_count_once, MultiMNFinalitySetup)
{
    const uint256 blockHash = TipIndex()->GetBlockHash();
    CFinalityManager fm(blockHash, 5'000'000);
    for (size_t op = 0; op < operators.size(); ++op) {
        CHuSignature s = SignAs((int)op, /*mnIdx=*/0, blockHash);
        fm.mapSignatures[s.proTxHash] = s.vchSig;
    }
    BOOST_CHECK_EQUAL(fm.GetSignatureCount(), operators.size());
    BOOST_CHECK_EQUAL(fm.GetUniqueOperatorCount(), operators.size());
}

// ─── Phase 1: finality DECISION must be operator-based (findings hu-finality-1/0) ───

// hu-finality-1: one operator running `threshold` MNs must NOT reach finality
// alone. Spec (03-CONSENSUS, 02-SPEC, finality.h:62-66) = one vote per OPERATOR.
BOOST_FIXTURE_TEST_CASE(single_operator_cannot_finalize_alone, OneOperatorManyMNs)
{
    // Any small threshold works — the test asserts operator-counting semantics,
    // not a specific network value (the live threshold is ceil(2/3·min(E,N))).
    const int threshold = 3;
    BOOST_REQUIRE_GE((int)operators.at(0).mns.size(), threshold);

    const uint256 blockHash = TipIndex()->GetBlockHash();
    CFinalityManager fm(blockHash, 5'000'000);
    for (int i = 0; i < threshold; ++i) {
        CHuSignature s = SignAs(/*opIdx=*/0, /*mnIdx=*/i, blockHash);
        fm.mapSignatures[s.proTxHash] = s.vchSig;
    }

    // `threshold` MN signatures, but a single operator => NOT final.
    BOOST_CHECK(!fm.HasFinality(threshold));
}

// Counterpart: `threshold` DISTINCT operators DO reach finality.
struct ThresholdOperators : public MultiMNFinalitySetup {
    ThresholdOperators()
        : MultiMNFinalitySetup(/*nOperators=*/3, /*mnsPerOperator=*/1) {}
};

BOOST_FIXTURE_TEST_CASE(threshold_distinct_operators_finalize, ThresholdOperators)
{
    const int threshold = 3;
    const uint256 blockHash = TipIndex()->GetBlockHash();
    CFinalityManager fm(blockHash, 5'000'000);
    for (int op = 0; op < threshold; ++op) {
        CHuSignature s = SignAs(op, /*mnIdx=*/0, blockHash);
        fm.mapSignatures[s.proTxHash] = s.vchSig;
    }
    BOOST_CHECK(fm.HasFinality(threshold));
}

// Regression for the bootstrap finality-gap fix: GetUniqueOperators must mirror block
// production's bootstrap-MN trust — a MN registered during the bootstrap phase
// (nRegisteredHeight <= nDMMBootstrapHeight) is eligible WITHOUT a confirmedHash, while a
// post-bootstrap MN still needs one. Without this, a fresh network produces but never
// finalizes until collateral confirmation (60 blocks testnet / ~24h mainnet). The bug
// hid because confirmedHash was only ever set in test fixtures, never exercised null.
BOOST_FIXTURE_TEST_CASE(unique_operators_bootstrap_exemption, TestnetSetup)
{
    const int bootstrapH = Params().GetConsensus().nDMMBootstrapHeight;  // 250 on testnet
    CDeterministicMNList list;
    list.SetHeight(bootstrapH + 1000);

    auto addMN = [&](uint32_t id, int registeredHeight, bool confirmed) -> CPubKey {
        CKey opKey; opKey.MakeNewKey(true);
        CKey vrfKey; vrf::DeriveKeyFromOperator(opKey, vrfKey);
        auto state = std::make_shared<CDeterministicMNState>();
        CKey ownerKey; ownerKey.MakeNewKey(true);
        state->keyIDOwner = ownerKey.GetPubKey().GetID();
        state->pubKeyOperator = opKey.GetPubKey();
        state->pubKeyVRF = vrfKey.GetPubKey();
        state->nRegisteredHeight = registeredHeight;
        if (confirmed) state->confirmedHash = ArithToUint256(arith_uint256(0x20000000u + id));
        auto dmn = std::make_shared<CDeterministicMN>(uint64_t(id));
        dmn->proTxHash = ArithToUint256(arith_uint256(id));
        dmn->collateralOutpoint = COutPoint(ArithToUint256(arith_uint256(0x10000000u + id)), 0);
        dmn->pdmnState = state;
        list.AddMN(dmn);
        return state->pubKeyOperator;
    };

    const CPubKey opBootstrap   = addMN(1, /*registeredHeight=*/5,               /*confirmed=*/false);
    const CPubKey opPostUnconf  = addMN(2, /*registeredHeight=*/bootstrapH + 500, /*confirmed=*/false);
    const CPubKey opPostConf    = addMN(3, /*registeredHeight=*/bootstrapH + 500, /*confirmed=*/true);

    auto ops = GetUniqueOperators(list);
    BOOST_CHECK_MESSAGE(ops.count(opBootstrap) == 1, "bootstrap MN must be eligible without confirmedHash");
    BOOST_CHECK_MESSAGE(ops.count(opPostUnconf) == 0, "post-bootstrap unconfirmed MN must be excluded");
    BOOST_CHECK_MESSAGE(ops.count(opPostConf) == 1, "post-bootstrap confirmed MN must be eligible");
    BOOST_CHECK_EQUAL(ops.size(), 2u);
}

// NOTE: the legacy top-N committee-seam tests (finality_committee_matches_explicit_composition,
// finality_committee_null_pindex_empty) were removed with the top-N path itself —
// finality is now VRF-only (see vrf_sortition_tests for the ECVRF committee e2e).

BOOST_AUTO_TEST_SUITE_END()
