// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * OP_CHECKOUTPUTVALUE — amount introspection, verify form (Tier-2 step A,
 * gate UPGRADE_OUTPUTVALUE, doc/COVENANT-CAPABILITY-AUDIT.md §6).
 *
 * Stack, top first: <output_index> <min_amount 8-byte LE> (pushed amount
 * first, index second). Verifies
 * vout[index].nValue >= min_amount, fail-closed, nothing popped.
 *
 * Covers: gating (flag off = NOP7), the >=/</== boundary against a real
 * spending tx, out-of-range index (fail closed), shape errors (amount != 8
 * bytes, negative amount, missing args), and the composition that motivates
 * it — a covenant that releases only if a chosen output pays at least X
 * (amount-conditioned settlement), where CTV's rigid exact-match cannot.
 */

#include "test/test_bathron.h"

#include "key.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "primitives/transaction.h"

#include <boost/test/unit_test.hpp>

namespace {

std::vector<unsigned char> Amount8(int64_t v)
{
    std::vector<unsigned char> r(8);
    for (int k = 0; k < 8; ++k) r[k] = (unsigned char)((uint64_t)v >> (8 * k));
    return r;
}

// Run <min8> <index> OP_CHECKOUTPUTVALUE OP_2DROP OP_TRUE against a tx whose
// outputs are `vouts` (value only; script is OP_TRUE).
bool Run(const std::vector<unsigned char>& min8, int64_t index,
         const std::vector<int64_t>& vouts, ScriptError* err,
         unsigned int flags = SCRIPT_VERIFY_CHECKOUTPUTVALUE)
{
    CScript s;
    s << min8 << CScriptNum(index) << OP_CHECKOUTPUTVALUE << OP_2DROP << OP_TRUE;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("beef"), 0);
    for (int64_t v : vouts) tx.vout.emplace_back(v, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    return VerifyScript(CScript(), s, flags, checker,
                        CTransaction(tx).GetRequiredSigVersion(), err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(outputvalue_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(flag_off_is_nop)
{
    ScriptError err;
    // Without the flag, OP_CHECKOUTPUTVALUE is NOP7: args ignored, passes.
    CScript s;
    s << Amount8(999999999) << CScriptNum(5) << OP_CHECKOUTPUTVALUE << OP_2DROP << OP_TRUE;
    CMutableTransaction tx; tx.nVersion = 3; tx.vin.resize(1);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    BOOST_CHECK(VerifyScript(CScript(), s, /*flags=*/0, checker,
                             CTransaction(tx).GetRequiredSigVersion(), &err));
}

BOOST_AUTO_TEST_CASE(value_boundary)
{
    ScriptError err;
    // vout[0] pays 100000. ">= 100000" passes, ">= 100001" fails, ">= 1" passes.
    BOOST_CHECK_MESSAGE(Run(Amount8(100000), 0, {100000}, &err), ScriptErrorString(err));
    BOOST_CHECK_MESSAGE(Run(Amount8(1),      0, {100000}, &err), ScriptErrorString(err));
    BOOST_CHECK(!Run(Amount8(100001), 0, {100000}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(picks_the_right_output)
{
    ScriptError err;
    // Three outputs: 5000, 40000, 999. index 1 must pay >= 40000.
    BOOST_CHECK_MESSAGE(Run(Amount8(40000), 1, {5000, 40000, 999}, &err), ScriptErrorString(err));
    BOOST_CHECK(!Run(Amount8(40001), 1, {5000, 40000, 999}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);
    // index 2 pays 999, so ">= 1000" on index 2 fails.
    BOOST_CHECK(!Run(Amount8(1000), 2, {5000, 40000, 999}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(index_out_of_range_fails_closed)
{
    ScriptError err;
    // Only one output; index 1 is out of range -> fail closed.
    BOOST_CHECK(!Run(Amount8(1), 1, {100000}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(large_value_64bit)
{
    ScriptError err;
    // 100 BTC = 1e10 sats, well beyond 32-bit CScriptNum — the 8-byte operand
    // must handle it. vout pays 10_000_000_000; ">= 10_000_000_000" passes.
    const int64_t big = 10000000000LL;
    BOOST_CHECK_MESSAGE(Run(Amount8(big), 0, {big}, &err), ScriptErrorString(err));
    BOOST_CHECK(!Run(Amount8(big + 1), 0, {big}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(shape_errors)
{
    ScriptError err;
    // Amount not 8 bytes.
    BOOST_CHECK(!Run(std::vector<unsigned char>(7, 0x01), 0, {100000}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_INVALID);
    // Negative amount (high bit of the 8-byte LE set).
    BOOST_CHECK(!Run(Amount8(-1), 0, {100000}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_INVALID);
    // Negative index.
    BOOST_CHECK(!Run(Amount8(1), -1, {100000}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_INVALID);
    // Missing args.
    CScript s; s << OP_CHECKOUTPUTVALUE << OP_TRUE;
    CMutableTransaction tx; tx.nVersion = 3; tx.vin.resize(1);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    BOOST_CHECK(!VerifyScript(CScript(), s, SCRIPT_VERIFY_CHECKOUTPUTVALUE, checker,
                              CTransaction(tx).GetRequiredSigVersion(), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// The composition that motivates A: a P2SH covenant that releases only if a
// chosen output pays at least X — amount-conditioned settlement, flexible on
// the rest of the tx (unlike CTV's rigid exact template match).
BOOST_AUTO_TEST_CASE(amount_conditioned_release_p2sh)
{
    CKey key;
    key.MakeNewKey(true);
    const CAmount amount = 1000000;
    const int64_t required = 250000;

    // redeem: "pay >= 250000 to output 0, then owner sig" — the LP is assured
    // the counter-payment lands, without fixing the change/fee.
    CScript redeem;
    redeem << Amount8(required) << CScriptNum(0) << OP_CHECKOUTPUTVALUE << OP_2DROP
           << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    CMutableTransaction settle;
    settle.nVersion = 3;
    settle.vin.resize(1);
    settle.vin[0].prevout = COutPoint(uint256S("f00d"), 0);
    settle.vout.emplace_back(300000, CScript() << OP_TRUE);   // pays 300000 >= 250000 ✓
    settle.vout.emplace_back(690000, CScript() << OP_2);      // change, unconstrained

    uint256 sighash = SignatureHash(redeem, settle, 0, SIGHASH_ALL, amount, SIGVERSION_SAPLING);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);
    CScript scriptSig;
    scriptSig << sig << std::vector<unsigned char>(redeem.begin(), redeem.end());
    CScript scriptPubKey = GetScriptForDestination(CScriptID(redeem));

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKOUTPUTVALUE |
                               SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S;
    ScriptError err;
    MutableTransactionSignatureChecker checker(&settle, 0, amount);
    BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, flags, checker,
                                     SIGVERSION_SAPLING, &err),
                        "amount-conditioned release failed: " << ScriptErrorString(err));

    // Under-paying output 0 (249999 < 250000) fails even with a valid signature.
    CMutableTransaction cheat = settle;
    cheat.vout[0].nValue = 249999;
    uint256 ch = SignatureHash(redeem, cheat, 0, SIGHASH_ALL, amount, SIGVERSION_SAPLING);
    std::vector<unsigned char> csig;
    BOOST_REQUIRE(key.Sign(ch, csig));
    csig.push_back((unsigned char)SIGHASH_ALL);
    CScript cheatSig;
    cheatSig << csig << std::vector<unsigned char>(redeem.begin(), redeem.end());
    MutableTransactionSignatureChecker cheatChecker(&cheat, 0, amount);
    BOOST_CHECK(!VerifyScript(cheatSig, scriptPubKey, flags, cheatChecker, SIGVERSION_SAPLING, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);
}

BOOST_AUTO_TEST_SUITE_END()
