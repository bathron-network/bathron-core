// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Coinbase money rules (test-plan B5).
 *
 * BATHRON consensus rule C1: block_reward == 0 on every network, and the
 * coinbase output value must equal EXACTLY the block's collected fees (fees are
 * recycled, never minted). All M0 comes from TX_MINT_M0BTC — the coinbase can
 * never create money. This pins IsCoinbaseValueValid ("bad-cb-amount") and
 * GetBlockValue (==0), which the A5 no-inflation invariant leans on.
 */

#include "amount.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "test/test_bathron.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(coinbase_value_tests, BasicTestingSetup)

namespace {

CTransactionRef Coinbase(const std::vector<CAmount>& outs)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();                 // coinbase input
    for (CAmount v : outs) mtx.vout.emplace_back(v, CScript() << OP_TRUE);
    return MakeTransactionRef(std::move(mtx));
}

} // namespace

BOOST_AUTO_TEST_CASE(coinbase_equals_fees_accepted)
{
    CValidationState state;
    BOOST_CHECK(IsCoinbaseValueValid(Coinbase({5000}), 5000, state));
    // Multiple outputs summing to the fee total are fine.
    CValidationState state2;
    BOOST_CHECK(IsCoinbaseValueValid(Coinbase({3000, 2000}), 5000, state2));
    // Zero-fee block -> empty-value coinbase.
    CValidationState state3;
    BOOST_CHECK(IsCoinbaseValueValid(Coinbase({0}), 0, state3));
}

BOOST_AUTO_TEST_CASE(coinbase_over_fees_rejected)
{
    // One satoshi of block reward is inflation -> rejected (this is the guard).
    CValidationState state;
    BOOST_CHECK(!IsCoinbaseValueValid(Coinbase({5001}), 5000, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-amount");
}

BOOST_AUTO_TEST_CASE(coinbase_under_fees_rejected)
{
    // Under-paying is also invalid (coinbase must equal fees exactly).
    CValidationState state;
    BOOST_CHECK(!IsCoinbaseValueValid(Coinbase({4999}), 5000, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-cb-amount");
}

BOOST_AUTO_TEST_CASE(block_reward_is_zero_at_all_heights)
{
    // block_reward == 0 on all networks and heights (no subsidy, ever).
    for (int h : {0, 1, 2, 100, 250, 100000, 10000000}) {
        BOOST_CHECK_MESSAGE(GetBlockValue(h) == 0,
                            "GetBlockValue nonzero at height " << h);
    }
}

BOOST_AUTO_TEST_SUITE_END()
