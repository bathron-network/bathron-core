// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * OP_CAT re-enabled (gate UPGRADE_OPCAT, BIP347 semantics — M1 bar item 3,
 * doc/COVENANT-CAPABILITY-AUDIT.md §6).
 *
 * (x1 x2 -- x1||x2), result capped at MAX_SCRIPT_ELEMENT_SIZE (520).
 * Without SCRIPT_VERIFY_OPCAT the opcode keeps the historical disabled rule:
 * it fails the script even inside an UNEXECUTED branch. With the flag it is
 * an ordinary opcode (skipped in unexecuted branches).
 *
 * Composition case: a Merkle step in script — HASH256(a||b) == parent — the
 * covenant building block CAT re-opens (paths in script, sighash assembly
 * with CSFS, etc.).
 */

#include "test/test_bathron.h"

#include "hash.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

namespace {

bool Run(const CScript& script, ScriptError* err,
         unsigned int flags = SCRIPT_VERIFY_OPCAT)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("beef"), 0);
    tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    return VerifyScript(CScript(), script, flags, checker,
                        CTransaction(tx).GetRequiredSigVersion(), err);
}

std::vector<unsigned char> Bytes(std::initializer_list<unsigned char> b)
{
    return std::vector<unsigned char>(b);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(opcat_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(disabled_without_flag)
{
    ScriptError err;
    // Executed: disabled opcode.
    CScript s;
    s << Bytes({0x01}) << Bytes({0x02}) << OP_CAT << OP_DROP << OP_TRUE;
    BOOST_CHECK(!Run(s, &err, /*flags=*/0));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);

    // The historical rule is stricter than a NOP gate: OP_CAT in an
    // UNEXECUTED branch also fails when the flag is off...
    CScript branch;
    branch << OP_0 << OP_IF << OP_CAT << OP_ENDIF << OP_TRUE;
    BOOST_CHECK(!Run(branch, &err, /*flags=*/0));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);

    // ...and is skipped like any other opcode when the flag is on.
    BOOST_CHECK_MESSAGE(Run(branch, &err), ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(basic_concat)
{
    ScriptError err;
    CScript s;
    s << Bytes({0x01}) << Bytes({0x02, 0x03}) << OP_CAT
      << Bytes({0x01, 0x02, 0x03}) << OP_EQUAL;
    BOOST_CHECK_MESSAGE(Run(s, &err), ScriptErrorString(err));

    // Order matters: x1 || x2, not x2 || x1.
    CScript wrong;
    wrong << Bytes({0x01}) << Bytes({0x02, 0x03}) << OP_CAT
          << Bytes({0x02, 0x03, 0x01}) << OP_EQUAL;
    BOOST_CHECK(!Run(wrong, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_CASE(empty_operands)
{
    ScriptError err;
    // empty || x = x
    CScript left;
    left << std::vector<unsigned char>{} << Bytes({0xaa}) << OP_CAT
         << Bytes({0xaa}) << OP_EQUAL;
    BOOST_CHECK_MESSAGE(Run(left, &err), ScriptErrorString(err));

    // x || empty = x
    CScript right;
    right << Bytes({0xaa}) << std::vector<unsigned char>{} << OP_CAT
          << Bytes({0xaa}) << OP_EQUAL;
    BOOST_CHECK_MESSAGE(Run(right, &err), ScriptErrorString(err));

    // empty || empty = empty
    CScript both;
    both << std::vector<unsigned char>{} << std::vector<unsigned char>{} << OP_CAT
         << OP_SIZE << OP_0 << OP_EQUAL << OP_NIP;
    BOOST_CHECK_MESSAGE(Run(both, &err), ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(size_cap_520)
{
    ScriptError err;
    // 260 + 260 = 520: exactly at the element cap, allowed.
    CScript ok;
    ok << std::vector<unsigned char>(260, 0x11) << std::vector<unsigned char>(260, 0x22)
       << OP_CAT << OP_SIZE << CScriptNum(520) << OP_EQUAL << OP_NIP;
    BOOST_CHECK_MESSAGE(Run(ok, &err), ScriptErrorString(err));

    // 261 + 260 = 521: one over, PUSH_SIZE.
    CScript over;
    over << std::vector<unsigned char>(261, 0x11) << std::vector<unsigned char>(260, 0x22)
         << OP_CAT << OP_DROP << OP_TRUE;
    BOOST_CHECK(!Run(over, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(stack_underflow)
{
    ScriptError err;
    CScript one;
    one << Bytes({0x01}) << OP_CAT << OP_TRUE;
    BOOST_CHECK(!Run(one, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    CScript none;
    none << OP_CAT << OP_TRUE;
    BOOST_CHECK(!Run(none, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// The composition CAT re-opens: a Merkle step verified in script.
// parent = HASH256(leafL || leafR); the script holds the parent, the spender
// supplies the two children.
BOOST_AUTO_TEST_CASE(merkle_step_in_script)
{
    const std::vector<unsigned char> leafL(32, 0x4c);
    const std::vector<unsigned char> leafR(32, 0x52);
    std::vector<unsigned char> concat = leafL;
    concat.insert(concat.end(), leafR.begin(), leafR.end());
    const uint256 parent = Hash(concat.begin(), concat.end());

    ScriptError err;
    CScript s;
    s << leafL << leafR << OP_CAT << OP_HASH256
      << ToByteVector(parent) << OP_EQUAL;
    BOOST_CHECK_MESSAGE(Run(s, &err), ScriptErrorString(err));

    // Swapped children: different parent — the step actually binds order.
    CScript swapped;
    swapped << leafR << leafL << OP_CAT << OP_HASH256
            << ToByteVector(parent) << OP_EQUAL;
    BOOST_CHECK(!Run(swapped, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_SUITE_END()
