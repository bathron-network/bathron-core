// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * M1 Fee Model Hardening Tests (BP30 v3.0 / v3.1)
 *
 * Tests for the shared fee primitives (IsExactlyOpTrueScript, ComputeMinM1Fee,
 * CheckFeeOutputAt) and the TX_TRANSFER_M1 OP_TRUE fee output. NOTE: since BP30
 * v3.1 the TX_UNLOCK fee is a real M0 coinbase fee (no OP_TRUE fee output), so the
 * old bad-unlock-fee-* codes no longer exist; only TX_TRANSFER_M1 still uses an
 * OP_TRUE M1 fee output validated by CheckFeeOutputAt.
 *
 * Rejection codes tested:
 * - bad-txtransfer-fee-missing
 * - bad-txtransfer-fee-script
 * - bad-txtransfer-fee-too-low
 * - bad-txtransfer-fee-index
 */

#include "state/settlement.h"
#include "state/settlementdb.h"
#include "state/settlement_logic.h"
#include "amount.h"
#include "clientversion.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_bathron.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(m1_fee_hardening_tests, BasicTestingSetup)

// =============================================================================
// Helper Functions
// =============================================================================

static CScript GetOpTrueScript()
{
    CScript script;
    script << OP_TRUE;
    return script;
}

static CScript GetP2PKHScript()
{
    // A dummy P2PKH script for testing
    CKey key;
    key.MakeNewKey(true);
    return GetScriptForDestination(key.GetPubKey().GetID());
}

static CScript GetBadOpTrueScript()
{
    // OP_TRUE with junk bytes appended - should be rejected
    CScript script;
    script << OP_TRUE << OP_NOP;
    return script;
}

// =============================================================================
// IsExactlyOpTrueScript Tests
// =============================================================================

BOOST_AUTO_TEST_CASE(is_exactly_optrue_accepts_valid)
{
    CScript opTrue = GetOpTrueScript();
    BOOST_CHECK(IsExactlyOpTrueScript(opTrue));
}

BOOST_AUTO_TEST_CASE(is_exactly_optrue_rejects_with_junk)
{
    CScript badScript = GetBadOpTrueScript();
    BOOST_CHECK(!IsExactlyOpTrueScript(badScript));
}

BOOST_AUTO_TEST_CASE(is_exactly_optrue_rejects_p2pkh)
{
    CScript p2pkh = GetP2PKHScript();
    BOOST_CHECK(!IsExactlyOpTrueScript(p2pkh));
}

BOOST_AUTO_TEST_CASE(is_exactly_optrue_rejects_empty)
{
    CScript empty;
    BOOST_CHECK(!IsExactlyOpTrueScript(empty));
}

BOOST_AUTO_TEST_CASE(is_exactly_optrue_rejects_op_return)
{
    CScript opReturn;
    opReturn << OP_RETURN;
    BOOST_CHECK(!IsExactlyOpTrueScript(opReturn));
}

// =============================================================================
// ComputeMinM1Fee Tests
// =============================================================================

BOOST_AUTO_TEST_CASE(compute_min_fee_deterministic)
{
    // Test deterministic fee calculation
    // fee = (size * rate) / 1000, minimum 1 sat

    // 200 bytes at 50 sat/kB = 10 sats
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(200, 50), 10);

    // 1000 bytes at 50 sat/kB = 50 sats
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(1000, 50), 50);

    // 100 bytes at 50 sat/kB = 5 sats
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(100, 50), 5);

    // Very small tx (10 bytes) should still have minimum 1 sat
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(10, 50), 1);

    // Zero size should still return 1 sat minimum
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(0, 50), 1);
}

BOOST_AUTO_TEST_CASE(compute_min_fee_scales_with_rate)
{
    // 500 bytes at different rates
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(500, 50), 25);   // 50 sat/kB
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(500, 100), 50);  // 100 sat/kB
    BOOST_CHECK_EQUAL(ComputeMinM1Fee(500, 200), 100); // 200 sat/kB
}

// =============================================================================
// TX_TRANSFER_M1 Fee Hardening Tests
// =============================================================================

// Note: These tests require settlement DB to be initialized
// and the input M1 receipt to exist. For unit tests, we test
// the helper functions directly. Integration tests would cover
// the full CheckTransfer flow.

BOOST_AUTO_TEST_CASE(transfer_fee_script_validation)
{
    // Test that fee script validation works correctly
    // This tests the helper function used by CheckTransfer

    CScript validFee = GetOpTrueScript();
    CScript invalidFee = GetP2PKHScript();
    CScript junkFee = GetBadOpTrueScript();

    BOOST_CHECK(IsExactlyOpTrueScript(validFee));
    BOOST_CHECK(!IsExactlyOpTrueScript(invalidFee));
    BOOST_CHECK(!IsExactlyOpTrueScript(junkFee));
}

// =============================================================================
// CheckFeeOutputAt Tests (helper function)
// =============================================================================

BOOST_AUTO_TEST_CASE(check_fee_output_validates_index)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // Only 1 output
    mtx.vout.emplace_back(CTxOut(1000, GetP2PKHScript()));

    CTransaction tx(mtx);
    CValidationState state;

    // Index 1 is out of range
    BOOST_CHECK(!CheckFeeOutputAt(tx, 1, 10, state, "test"));
    BOOST_CHECK(state.GetRejectReason() == "bad-test-fee-missing");
}

BOOST_AUTO_TEST_CASE(check_fee_output_validates_script)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vout[0] = P2PKH (not OP_TRUE)
    mtx.vout.emplace_back(CTxOut(1000, GetP2PKHScript()));

    CTransaction tx(mtx);
    CValidationState state;

    // Fee at index 0 should fail - script is not OP_TRUE
    BOOST_CHECK(!CheckFeeOutputAt(tx, 0, 10, state, "test"));
    BOOST_CHECK(state.GetRejectReason() == "bad-test-fee-script");
}

BOOST_AUTO_TEST_CASE(check_fee_output_validates_amount)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vout[0] = OP_TRUE with too low amount
    mtx.vout.emplace_back(CTxOut(5, GetOpTrueScript()));  // Only 5 sats

    CTransaction tx(mtx);
    CValidationState state;

    // Fee at index 0 should fail - amount too low (need 10)
    BOOST_CHECK(!CheckFeeOutputAt(tx, 0, 10, state, "test"));
    BOOST_CHECK(state.GetRejectReason() == "bad-test-fee-too-low");
}

BOOST_AUTO_TEST_CASE(check_fee_output_accepts_valid)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vout[0] = OP_TRUE with sufficient amount
    mtx.vout.emplace_back(CTxOut(100, GetOpTrueScript()));  // 100 sats

    CTransaction tx(mtx);
    CValidationState state;

    // Fee at index 0 should pass - valid script and amount
    BOOST_CHECK(CheckFeeOutputAt(tx, 0, 10, state, "test"));
}

BOOST_AUTO_TEST_CASE(check_fee_output_rejects_junk_optrue)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vout[0] = OP_TRUE + junk (should be rejected)
    mtx.vout.emplace_back(CTxOut(100, GetBadOpTrueScript()));

    CTransaction tx(mtx);
    CValidationState state;

    // Should fail - script is not EXACTLY OP_TRUE
    BOOST_CHECK(!CheckFeeOutputAt(tx, 0, 10, state, "test"));
    BOOST_CHECK(state.GetRejectReason() == "bad-test-fee-script");
}

BOOST_AUTO_TEST_SUITE_END()
