// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// =============================================================================
// LOT 9 — pre-genesis adversarial audit: VRF finality arithmetic
// =============================================================================
//
// HISTORICAL NOTE (M1+M2). The `consensus_lot9_dmm` suite that used to open this
// file was the audit's MEASUREMENT of the legacy producer draw: it demonstrated
// that score = H(prevHash||height||proTxHash) let the producer of H-1 elect ANY
// chosen successor in a handful of free re-rolls (worst observed: 9 with 5
// operators), and that the temporal PoSe punished victims chosen by the
// producer's own timestamp. Those measurements JUSTIFIED LOT 9; the engine they
// measured has since been REMOVED from the tree (M1 wired the non-grindable
// epoch schedule everywhere, M2 deleted the temporal PoSe), so the cases are
// gone with it. The replacement guarantees live in:
//   * consensus_lot9_m1_schedule_tests — the pure engine (grinding immunity,
//     bijection, timing invariants, recovery boundaries);
//   * mn_blockproducer_tests — the WIRING, including the mutant guards that turn
//     red if the legacy draw or the temporal PoSe is ever restored.
//
// What remains below is the finality-side arithmetic of the audit.

#include "test/test_bathron.h"

#include "chainparams.h"
#include "consensus/params.h"
#include "masternode/blockproducer.h"
#include "state/quorum.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

// ═════════════════════════════════════════════════════════════════════════════
// Finality-side arithmetic: the N=5 / quorum=4 configuration the pre-genesis
// deployment gate calls for. These are the PURE functions both the write side
// (AddSignature) and the read side (IsBlockFinal/HasFinality) re-derive through.
// ═════════════════════════════════════════════════════════════════════════════
BOOST_FIXTURE_TEST_SUITE(consensus_lot9_finality_floor, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(five_operators_give_threshold_four)
{
    Consensus::Params consensus;
    consensus.nHuExpectedCommitteeSize = 128;   // shipped E (mainnet and testnet)
    consensus.nHuQuorumSize = 4;                // shipped Sybil floor

    // N=5 -> min(128,5)=5 -> ceil(2/3*5) = 4. This is the configuration the gate
    // requires: 5 operators, threshold 4.
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 5), 4);

    // Q8a — ONE operator down leaves 4 signers, which still meets the threshold.
    BOOST_CHECK_MESSAGE(4 >= hu::HuActiveFinalityThreshold(consensus, 5),
                        "with 5 operators, losing 1 must NOT stop finality");
    // Q8b — TWO down leaves 3 signers: below threshold, so the chain STALLS on
    // finality. A stall is the intended outcome; it is not a divergence, because
    // the threshold is a pure function of the block's own operator count and every
    // node computes the same 4.
    BOOST_CHECK_MESSAGE(3 < hu::HuActiveFinalityThreshold(consensus, 5),
                        "with 5 operators, losing 2 MUST stall finality (clean stop)");

    // The Sybil floor makes a sub-floor population UNREACHABLE rather than easy.
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 3), hu::HU_FINALITY_THRESHOLD_UNREACHABLE);
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 1), hu::HU_FINALITY_THRESHOLD_UNREACHABLE);

    // NEGATIVE CONTROL: the threshold really tracks N up to the cap, and is capped by E.
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 4), 3);
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 6), 4);
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 1000), (2 * 128 + 2) / 3);

    // The documented residual: an UNRESOLVED block (N<=0) skips the floor and falls
    // back to ceil(2/3*E) — conservative only because E >> nHuQuorumSize.
    BOOST_CHECK_EQUAL(hu::HuActiveFinalityThreshold(consensus, 0), (2 * 128 + 2) / 3);
    BOOST_CHECK_MESSAGE(hu::HuActiveFinalityThreshold(consensus, 0) > consensus.nHuQuorumSize,
                        "the fallback must be HARDER than the floor, or the fail-open bites");
}

// With E >= N every eligible operator is drawn, so the seed cannot change the
// committee at the shipped small-network parameters — the reason seed grinding has
// no committee effect today. Below E < N the draw becomes selective and the seed
// starts to matter; both regimes are pinned here.
BOOST_AUTO_TEST_CASE(sortition_regimes_are_pinned)
{
    vrf::Output lo{}; lo.fill(0x00);
    vrf::Output hi{}; hi.fill(0xff);

    BOOST_CHECK(hu::IsVrfSelected(lo, /*E=*/128, /*N=*/5));
    BOOST_CHECK(hu::IsVrfSelected(hi, /*E=*/128, /*N=*/5));   // E >= N -> everyone

    // Selective regime: the extremes must now differ, otherwise the threshold maths
    // is not being applied at all.
    BOOST_CHECK(hu::IsVrfSelected(lo, /*E=*/1, /*N=*/5));
    BOOST_CHECK(!hu::IsVrfSelected(hi, /*E=*/1, /*N=*/5));

    // Degenerate inputs never select.
    BOOST_CHECK(!hu::IsVrfSelected(lo, /*E=*/0, /*N=*/5));
    BOOST_CHECK(!hu::IsVrfSelected(lo, /*E=*/128, /*N=*/0));
}

BOOST_AUTO_TEST_SUITE_END()
