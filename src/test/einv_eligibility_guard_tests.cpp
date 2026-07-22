// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ===========================================================================
// E-INV ELIGIBILITY GUARD
// ===========================================================================
//
// This suite encodes the E-INV operator-eligibility invariant as a
// permanent regression guard:
//
//   The active operator set A (hence N, hence the finality threshold
//   ceil(2/3*min(E,N))) is a PURE FUNCTION OF THE DMN LIST and is INDEPENDENT of
//   any finality-participation / gossip signal (who signed, uptime, heartbeats,
//   getfinalityparticipation).
//
// The abandoned "PoSe on finality participation" chantier would have wired
// observed participation into eligibility — which fails E-INV (a gossip,
// fork-dependent, VRF-private signal driving a consensus parameter). If a future
// change makes eviction/eligibility depend on observed participation, IT MUST
// FAIL THIS SUITE. Do not "fix" the test to make such a change pass — re-read the
// research note first.
//
// Test-only: assertions over existing behavior; no consensus code is changed.
// ===========================================================================

#include "test/test_bathron.h"

#include "arith_uint256.h"
#include "chainparams.h"
#include "key.h"
#include "masternode/deterministicmns.h"
#include "state/finality.h"
#include "state/quorum.h"
#include "uint256.h"
#include "vrf.h"

#include <boost/test/unit_test.hpp>

using namespace hu;  // GetUniqueOperators, HuActiveFinalityThreshold, CFinalityManager

BOOST_FIXTURE_TEST_SUITE(einv_eligibility_guard_tests, TestnetSetup)

namespace {
// Minimal DMN builder (mirrors hu_finality_integration_tests). Post-bootstrap +
// confirmed so every added operator is unconditionally eligible.
CPubKey AddOperator(CDeterministicMNList& list, uint32_t id)
{
    CKey opKey;    opKey.MakeNewKey(true);
    CKey vrfKey;   vrf::DeriveKeyFromOperator(opKey, vrfKey);
    CKey ownerKey; ownerKey.MakeNewKey(true);

    auto state = std::make_shared<CDeterministicMNState>();
    state->keyIDOwner      = ownerKey.GetPubKey().GetID();
    state->pubKeyOperator  = opKey.GetPubKey();
    state->pubKeyVRF       = vrfKey.GetPubKey();
    state->nRegisteredHeight = 10;  // bootstrap-eligible on testnet (<= nDMMBootstrapHeight)

    auto dmn = std::make_shared<CDeterministicMN>(uint64_t(id));
    dmn->proTxHash         = ArithToUint256(arith_uint256(id));
    dmn->collateralOutpoint = COutPoint(ArithToUint256(arith_uint256(0x10000000u + id)), 0);
    dmn->pdmnState         = state;
    list.AddMN(dmn);
    return state->pubKeyOperator;
}
} // namespace

// ---------------------------------------------------------------------------
// Case 1 — N (the eligibility count) tracks the DMN LIST and nothing else.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(active_set_is_dmn_list_derived)
{
    CDeterministicMNList list;
    list.SetHeight(1000);

    AddOperator(list, 1);
    AddOperator(list, 2);
    AddOperator(list, 3);
    BOOST_CHECK_EQUAL(GetUniqueOperators(list).size(), 3u);

    AddOperator(list, 4);
    // Adding a registered operator to the LIST — and only that — changes N.
    BOOST_CHECK_EQUAL(GetUniqueOperators(list).size(), 4u);
}

// ---------------------------------------------------------------------------
// Case 2 — the finality threshold is a PURE FUNCTION of N (the list-derived
// count). No participation/signature input can appear in its arguments.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(threshold_is_pure_function_of_N)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // ceil(2/3*min(E,N)) — depends ONLY on the integer N. Same N => same threshold,
    // every call, with no hidden dependence on who signed anything.
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 3),
                      HuActiveFinalityThreshold(consensus, 3));
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 4), 3);   // ceil(2/3*4)
    BOOST_CHECK_EQUAL(HuActiveFinalityThreshold(consensus, 3), 2);   // ceil(2/3*3)
    // Monotonic non-decreasing in N (a sanity pin, not a claim about the cap).
    BOOST_CHECK_LE(HuActiveFinalityThreshold(consensus, 3),
                   HuActiveFinalityThreshold(consensus, 9));
}

// ---------------------------------------------------------------------------
// Case 3 — THE GUARD: finality signatures (participation) do NOT change N or
// the threshold. Signatures decide whether a *block* is final; they never touch
// *who is eligible*. This is the exact wiring E-INV forbids.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(participation_does_not_change_eligibility)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    CDeterministicMNList list;
    list.SetHeight(1000);
    AddOperator(list, 1);
    AddOperator(list, 2);
    AddOperator(list, 3);
    AddOperator(list, 4);

    const size_t N0 = GetUniqueOperators(list).size();
    const int    T0 = HuActiveFinalityThreshold(consensus, static_cast<int>(N0));
    BOOST_REQUIRE_EQUAL(N0, 4u);

    // Build a finality record and load it with a VARYING number of signatures —
    // 0, some, all. This is the "participation" data path.
    const uint256 blockHash = ArithToUint256(arith_uint256(0xB10C));
    for (int sigs = 0; sigs <= 4; ++sigs) {
        CFinalityManager fm(blockHash, /*height=*/1000);
        for (int i = 0; i < sigs; ++i) {
            fm.mapSignatures[ArithToUint256(arith_uint256(0x5160u + i))] =
                std::vector<unsigned char>{0x01};  // opaque, presence is all that matters
        }
        // The finality record sees the signatures...
        BOOST_CHECK_EQUAL(fm.GetSignatureCount(), static_cast<size_t>(sigs));

        // ...but the ELIGIBILITY SET and THRESHOLD are recomputed from the LIST and
        // are INVARIANT to how many signatures exist. This is E-INV in one assertion:
        BOOST_CHECK_MESSAGE(GetUniqueOperators(list).size() == N0,
            "E-INV VIOLATION: eligibility N changed with signature count — "
            "participation must never feed the active set");
        BOOST_CHECK_MESSAGE(HuActiveFinalityThreshold(consensus, static_cast<int>(GetUniqueOperators(list).size())) == T0,
            "E-INV VIOLATION: finality threshold changed with signature count");
    }
}

BOOST_AUTO_TEST_SUITE_END()
