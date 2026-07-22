// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * The Recursive Covenant Pair — OP_CHECKOUTPUTSCRIPT + OP_PUSHCURRENTSCRIPT
 * (gate UPGRADE_OUTPUTSCRIPT, doc/RECURSIVE-COVENANT-PAIR.md).
 *
 * OP_CHECKOUTPUTSCRIPT — script introspection, verify form. Stack, top first:
 * <output_index> <expected_scriptPubKey> (pushed spk first, index second).
 * Verifies vout[index].scriptPubKey == expected byte-for-byte, fail-closed,
 * nothing popped.
 *
 * OP_PUSHCURRENTSCRIPT — self-reference. Pushes the serialized bytes of the
 * currently-executing script (for P2SH, the redeemScript that the spent
 * scriptPubKey's HASH160 already authenticated).
 *
 * Separately each is limited; together they solve the quine problem: a
 * covenant that provably pays BACK INTO ITSELF (with updated state) without
 * knowing its own hash. The spender supplies a claimed decomposition
 * A||B of the script; the script checks it against OP_PUSHCURRENTSCRIPT
 * (so the body B cannot be substituted), pins the split (|A| == 9, the
 * state push), rebuilds the successor 0x08||newState||B with OP_CAT,
 * hashes it, and OP_CHECKOUTPUTSCRIPT forces vout[0] to it.
 *
 * Covers: gating (flags off = NOP8/NOP9), OP_CHECKOUTPUTSCRIPT semantics
 * (match/mismatch/index/shape, fail-closed), OP_PUSHCURRENTSCRIPT semantics
 * (byte-exact push, P2SH pushes the redeemScript — not scriptSig or
 * scriptPubKey — oversize fail-closed), and the flagship: a live
 * self-replicating covenant over TWO generations, plus the escape attacks
 * (body substitution, split shift, wrong output, state-size) all failing.
 */

#include "test/test_bathron.h"

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "primitives/transaction.h"

#include <boost/test/unit_test.hpp>

namespace {

typedef std::vector<unsigned char> valtype;

// Run <spk> <index> OP_CHECKOUTPUTSCRIPT OP_2DROP OP_TRUE against a tx whose
// output scripts are `vouts`.
bool RunCos(const valtype& spk, int64_t index,
            const std::vector<CScript>& vouts, ScriptError* err,
            unsigned int flags = SCRIPT_VERIFY_CHECKOUTPUTSCRIPT)
{
    CScript s;
    s << spk << CScriptNum(index) << OP_CHECKOUTPUTSCRIPT << OP_2DROP << OP_TRUE;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("beef"), 0);
    for (const CScript& o : vouts) tx.vout.emplace_back(10000, o);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    return VerifyScript(CScript(), s, flags, checker,
                        CTransaction(tx).GetRequiredSigVersion(), err);
}

// ---- The quine: a self-replicating covenant ---------------------------------

// The invariant covenant body B. The full covenant is R = <state8-push> || B
// (the leading 9-byte segment A = 0x08||state). The spender's scriptSig
// pushes, bottom-to-top: <newState8> <A> <B>. B then:
//   1. drops the state its own leading push just put on the stack,
//   2. proves A||B == the executing script (OP_PUSHCURRENTSCRIPT) — the body
//      cannot be substituted,
//   3. pins the split: |A| == 9 — the decomposition is unique,
//   4. pins |newState| == 8 — the successor's leading push stays well-formed,
//   5. rebuilds the successor 0x08||newState||B, hashes it into a P2SH
//      scriptPubKey, and OP_CHECKOUTPUTSCRIPT forces vout[0] to it.
CScript QuineBody()
{
    CScript b;
    b << OP_DROP
      << OP_2DUP << OP_CAT << OP_PUSHCURRENTSCRIPT << OP_EQUALVERIFY
      << OP_SWAP << OP_SIZE << OP_9 << OP_NUMEQUALVERIFY << OP_DROP
      << OP_SWAP << OP_SIZE << OP_8 << OP_NUMEQUALVERIFY
      << OP_8 << OP_SWAP << OP_CAT
      << OP_SWAP << OP_CAT
      << OP_HASH160
      << valtype{0xa9, 0x14} << OP_SWAP << OP_CAT
      << valtype{0x87} << OP_CAT
      << OP_0 << OP_CHECKOUTPUTSCRIPT
      << OP_2DROP << OP_1;
    return b;
}

CScript MakeQuine(const valtype& state8, const CScript& body)
{
    CScript r;
    r << state8;                                   // 0x08 || state — segment A
    r.insert(r.end(), body.begin(), body.end());   // || B
    return r;
}

CMutableTransaction BuildSpend(const CScript& vout0Spk)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("feed"), 0);
    tx.vout.emplace_back(90000, vout0Spk);
    tx.vout.emplace_back(9000, CScript() << OP_2);  // change, unconstrained
    return tx;
}

CScript SpendSig(const valtype& newState, const valtype& a, const valtype& b,
                 const CScript& r)
{
    CScript sig;
    sig << newState << a << b << valtype(r.begin(), r.end());
    return sig;
}

const unsigned int QUINE_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKOUTPUTSCRIPT |
                                 SCRIPT_VERIFY_OPCAT | SCRIPT_VERIFY_MINIMALDATA;

// Verify one covenant generation: spend P2SH(r) with the given decomposition
// and newState, in a tx paying vout[0] to `vout0Spk`.
bool SpendGeneration(const CScript& r, const valtype& newState,
                     const valtype& a, const valtype& b,
                     const CScript& vout0Spk, ScriptError* err)
{
    CMutableTransaction tx = BuildSpend(vout0Spk);
    MutableTransactionSignatureChecker checker(&tx, 0, 100000);
    return VerifyScript(SpendSig(newState, a, b, r),
                        GetScriptForDestination(CScriptID(r)),
                        QUINE_FLAGS, checker, SIGVERSION_SAPLING, err);
}

void SplitQuine(const CScript& r, valtype& a, valtype& b)
{
    const valtype bytes(r.begin(), r.end());
    a.assign(bytes.begin(), bytes.begin() + 9);
    b.assign(bytes.begin() + 9, bytes.end());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(outputscript_script_tests, BasicTestingSetup)

// ---- OP_CHECKOUTPUTSCRIPT ----------------------------------------------------

BOOST_AUTO_TEST_CASE(flag_off_is_nop)
{
    ScriptError err;
    // Without the flag both halves are NOPs: args ignored, passes.
    CScript s;
    s << valtype(23, 0xaa) << CScriptNum(5) << OP_CHECKOUTPUTSCRIPT
      << OP_PUSHCURRENTSCRIPT << OP_2DROP << OP_TRUE;
    CMutableTransaction tx; tx.nVersion = 3; tx.vin.resize(1);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    BOOST_CHECK(VerifyScript(CScript(), s, /*flags=*/0, checker,
                             CTransaction(tx).GetRequiredSigVersion(), &err));
}

BOOST_AUTO_TEST_CASE(matches_exact_script)
{
    ScriptError err;
    const CScript target = CScript() << OP_DUP << OP_HASH160
                                     << valtype(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_MESSAGE(RunCos(valtype(target.begin(), target.end()), 0, {target}, &err),
                        ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(mismatch_fails)
{
    ScriptError err;
    const CScript target = CScript() << OP_DUP << OP_HASH160
                                     << valtype(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    // One byte differs in the hash — byte-exact comparison must fail.
    const CScript nearMiss = CScript() << OP_DUP << OP_HASH160
                                       << valtype(20, 0x12) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK(!RunCos(valtype(target.begin(), target.end()), 0, {nearMiss}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_UNSATISFIED);
    // Same prefix, different length — must also fail.
    CScript longer = target; longer << OP_NOP;
    BOOST_CHECK(!RunCos(valtype(target.begin(), target.end()), 0, {longer}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(picks_the_right_output)
{
    ScriptError err;
    const CScript a = CScript() << OP_1;
    const CScript b = CScript() << OP_2;
    const CScript c = CScript() << OP_3;
    BOOST_CHECK_MESSAGE(RunCos(valtype(b.begin(), b.end()), 1, {a, b, c}, &err),
                        ScriptErrorString(err));
    BOOST_CHECK(!RunCos(valtype(b.begin(), b.end()), 2, {a, b, c}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(index_out_of_range_fails_closed)
{
    ScriptError err;
    const CScript t = CScript() << OP_1;
    BOOST_CHECK(!RunCos(valtype(t.begin(), t.end()), 1, {t}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(shape_errors)
{
    ScriptError err;
    const CScript t = CScript() << OP_1;
    // Empty expected script is malformed.
    BOOST_CHECK(!RunCos(valtype(), 0, {t}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_INVALID);
    // Negative index.
    BOOST_CHECK(!RunCos(valtype(t.begin(), t.end()), -1, {t}, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_INVALID);
    // Missing args.
    CScript s; s << OP_CHECKOUTPUTSCRIPT << OP_TRUE;
    CMutableTransaction tx; tx.nVersion = 3; tx.vin.resize(1);
    tx.vout.emplace_back(1, t);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    BOOST_CHECK(!VerifyScript(CScript(), s, SCRIPT_VERIFY_CHECKOUTPUTSCRIPT, checker,
                              CTransaction(tx).GetRequiredSigVersion(), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ---- OP_PUSHCURRENTSCRIPT ----------------------------------------------------

BOOST_AUTO_TEST_CASE(pushes_exact_script_bytes)
{
    ScriptError err;
    std::vector<valtype> stack;
    CScript s; s << OP_PUSHCURRENTSCRIPT;
    BaseSignatureChecker checker;
    BOOST_CHECK(EvalScript(stack, s, SCRIPT_VERIFY_CHECKOUTPUTSCRIPT, checker,
                           SIGVERSION_SAPLING, &err));
    BOOST_REQUIRE_EQUAL(stack.size(), 1u);
    BOOST_CHECK(stack[0] == valtype(s.begin(), s.end()));
}

BOOST_AUTO_TEST_CASE(p2sh_pushes_the_redeemscript)
{
    // redeem = PUSHCURRENTSCRIPT SIZE 4 NUMEQUAL — exactly 4 bytes. Inside a
    // P2SH spend the opcode must push the redeemScript (4 bytes), NOT the
    // scriptSig (5: the push wrapper) nor the scriptPubKey (23).
    ScriptError err;
    CScript redeem;
    redeem << OP_PUSHCURRENTSCRIPT << OP_SIZE << OP_4 << OP_NUMEQUAL;
    BOOST_REQUIRE_EQUAL(redeem.size(), 4u);
    CScript scriptSig;
    scriptSig << valtype(redeem.begin(), redeem.end());
    CMutableTransaction tx; tx.nVersion = 3; tx.vin.resize(1);
    tx.vout.emplace_back(1, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    BOOST_CHECK_MESSAGE(
        VerifyScript(scriptSig, GetScriptForDestination(CScriptID(redeem)),
                     SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKOUTPUTSCRIPT,
                     checker, SIGVERSION_SAPLING, &err),
        ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(oversize_script_fails_closed)
{
    // A bare script larger than the 520-byte element cap cannot push itself.
    // (Unreachable for P2SH redeemScripts — they arrive via a <=520 push —
    // this guards bare-script contexts.)
    ScriptError err;
    std::vector<valtype> stack;
    CScript s;
    s << valtype(519, 0x42) << OP_DROP << OP_PUSHCURRENTSCRIPT;
    BOOST_REQUIRE_GT(s.size(), MAX_SCRIPT_ELEMENT_SIZE);
    BaseSignatureChecker checker;
    BOOST_CHECK(!EvalScript(stack, s, SCRIPT_VERIFY_CHECKOUTPUTSCRIPT, checker,
                            SIGVERSION_SAPLING, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(discouraged_when_off)
{
    ScriptError err;
    std::vector<valtype> stack;
    CScript s; s << OP_PUSHCURRENTSCRIPT;
    BaseSignatureChecker checker;
    BOOST_CHECK(!EvalScript(stack, s, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, checker,
                            SIGVERSION_SAPLING, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// ---- The flagship: safe self-replication over two generations ----------------

BOOST_AUTO_TEST_CASE(self_replicating_covenant_two_generations)
{
    const CScript body = QuineBody();
    const valtype s0(8, 0x00), s1(8, 0x11), s2(8, 0x22);
    const CScript r0 = MakeQuine(s0, body);
    const CScript r1 = MakeQuine(s1, body);
    const CScript r2 = MakeQuine(s2, body);

    valtype a0, b0, a1, b1;
    SplitQuine(r0, a0, b0);
    SplitQuine(r1, a1, b1);
    // The body is the invariant: every generation shares it.
    BOOST_REQUIRE(b0 == b1);

    ScriptError err;
    // Generation 0 → 1: R(s0) forces vout[0] = P2SH(R(s1)).
    BOOST_CHECK_MESSAGE(
        SpendGeneration(r0, s1, a0, b0, GetScriptForDestination(CScriptID(r1)), &err),
        "generation 0->1 failed: " << ScriptErrorString(err));
    // Generation 1 → 2: the successor is spendable the SAME way with a brand-
    // new state — the covenant self-perpetuates. This is the recursion.
    BOOST_CHECK_MESSAGE(
        SpendGeneration(r1, s2, a1, b1, GetScriptForDestination(CScriptID(r2)), &err),
        "generation 1->2 failed: " << ScriptErrorString(err));
}

// The attack that kills the single-opcode design: without
// OP_PUSHCURRENTSCRIPT a spender could substitute his own body B' and walk
// away with the funds. With the pair, the substituted decomposition fails
// the identity check.
BOOST_AUTO_TEST_CASE(escape_by_body_substitution_fails)
{
    const CScript body = QuineBody();
    const valtype s0(8, 0x00), s1(8, 0x11);
    const CScript r0 = MakeQuine(s0, body);

    // Attacker's body: anyone-can-spend.
    const CScript evil = CScript() << OP_1;
    const valtype evilB(evil.begin(), evil.end());
    valtype a0, b0;
    SplitQuine(r0, a0, b0);

    // vout[0] pays the attacker's successor P2SH(0x08||s1||evil) — exactly
    // what OP_CHECKOUTPUTSCRIPT would be tricked into accepting if the body
    // were substitutable.
    CScript evilNext;
    evilNext << s1;
    evilNext.insert(evilNext.end(), evil.begin(), evil.end());

    ScriptError err;
    BOOST_CHECK(!SpendGeneration(r0, s1, a0, evilB,
                                 GetScriptForDestination(CScriptID(evilNext)), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EQUALVERIFY);
}

// A||B == script but the split is shifted: B loses its leading bytes, so the
// successor would be a different (attacker-favorable) program. The |A| == 9
// pin makes the decomposition unique.
BOOST_AUTO_TEST_CASE(escape_by_split_shift_fails)
{
    const CScript body = QuineBody();
    const valtype s0(8, 0x00), s1(8, 0x11);
    const CScript r0 = MakeQuine(s0, body);

    const valtype bytes(r0.begin(), r0.end());
    valtype aShift(bytes.begin(), bytes.begin() + 10);   // 10 bytes, not 9
    valtype bShift(bytes.begin() + 10, bytes.end());

    // Successor under the shifted split.
    CScript next;
    next << s1;
    next.insert(next.end(), bShift.begin(), bShift.end());

    ScriptError err;
    BOOST_CHECK(!SpendGeneration(r0, s1, aShift, bShift,
                                 GetScriptForDestination(CScriptID(next)), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_NUMEQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(wrong_output_fails)
{
    const CScript body = QuineBody();
    const valtype s0(8, 0x00), s1(8, 0x11);
    const CScript r0 = MakeQuine(s0, body);
    valtype a0, b0;
    SplitQuine(r0, a0, b0);

    // Honest decomposition, but vout[0] pays somewhere else entirely.
    ScriptError err;
    BOOST_CHECK(!SpendGeneration(r0, s1, a0, b0, CScript() << OP_TRUE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT_UNSATISFIED);
}

// A malformed state length would corrupt the successor's leading push (the
// 0x08 prefix would eat body bytes). The |newState| == 8 pin closes it.
BOOST_AUTO_TEST_CASE(state_size_pinned)
{
    const CScript body = QuineBody();
    const valtype s0(8, 0x00);
    const valtype shortState(7, 0x11);
    const CScript r0 = MakeQuine(s0, body);
    valtype a0, b0;
    SplitQuine(r0, a0, b0);

    CScript next;
    next << shortState;
    next.insert(next.end(), b0.begin(), b0.end());

    ScriptError err;
    BOOST_CHECK(!SpendGeneration(r0, shortState, a0, b0,
                                 GetScriptForDestination(CScriptID(next)), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_NUMEQUALVERIFY);
}

// Hard-test campaign #12: DETERMINISTIC ESCAPE-SEARCH over the recursive covenant.
// The 5 fixed cases above cover named attacks; this generalises them into a seeded
// search. For many random (state, successor-state) pairs it asserts:
//   (1) the HONEST decomposition paying the pinned successor ALWAYS verifies, and
//   (2) EVERY adversarial mutation — shifted split, substituted body, wrong newState
//       size, wrong output script, output body-drift — ALWAYS fails closed.
// A single mutation that verifies == a covenant escape (funds walk out of the
// covenant / a rogue successor is installed). escapes MUST be 0.
BOOST_AUTO_TEST_CASE(recursive_covenant_escape_search)
{
    const CScript body = QuineBody();
    uint64_t s = 0xC0FFEE1234567ULL;                 // fixed seed -> reproducible
    auto rnd = [&]() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; };
    auto rstate = [&]() { valtype v(8); for (auto& c : v) c = (unsigned char)(rnd() & 0xff); return v; };

    int honestOk = 0, mutRejected = 0, escapes = 0;
    ScriptError err;

    for (int iter = 0; iter < 300; ++iter) {
        const valtype s0 = rstate(), s1 = rstate();
        const CScript r0 = MakeQuine(s0, body);
        const CScript r1 = MakeQuine(s1, body);       // the pinned successor program
        valtype a0, b0; SplitQuine(r0, a0, b0);        // honest split: |a0| == 9
        const CScript okSpk = GetScriptForDestination(CScriptID(r1));

        // (1) honest spend MUST verify.
        if (SpendGeneration(r0, s1, a0, b0, okSpk, &err)) ++honestOk;
        else BOOST_ERROR("honest gen failed iter=" << iter << " err=" << ScriptErrorString(err));

        // (2) mutation battery — each MUST fail closed. A pass = escape.
        auto mustFail = [&](const valtype& ns, const valtype& a, const valtype& b, const CScript& spk) {
            if (SpendGeneration(r0, ns, a, b, spk, &err)) ++escapes; else ++mutRejected;
        };
        const valtype bytes(r0.begin(), r0.end());
        // a) split shifted -1 (|a|=8) and +1 (|a|=10) — a||b still == r0, but |A|!=9.
        mustFail(s1, valtype(bytes.begin(), bytes.begin() + 8), valtype(bytes.begin() + 8, bytes.end()), okSpk);
        if (bytes.size() >= 10)
            mustFail(s1, valtype(bytes.begin(), bytes.begin() + 10), valtype(bytes.begin() + 10, bytes.end()), okSpk);
        // b) body substitution: flip a random byte of b0 -> a0||b2 != PUSHCURRENTSCRIPT.
        { valtype b2 = b0; if (!b2.empty()) b2[rnd() % b2.size()] ^= 0x01; mustFail(s1, a0, b2, okSpk); }
        // c) wrong newState size (7 bytes) -> |newState|!=8.
        { valtype ns(7); for (auto& c : ns) c = (unsigned char)(rnd() & 0xff); mustFail(ns, a0, b0, okSpk); }
        // d) honest decomposition but paying an anyone-can-spend output (not the pin).
        mustFail(s1, a0, b0, GetScriptForDestination(CScriptID(CScript() << OP_1)));
        // e) output body-drift: pay P2SH(0x08||s1||B') with a mutated body -> CHECKOUTPUTSCRIPT mismatch.
        { valtype b2(body.begin(), body.end()); if (!b2.empty()) b2[rnd() % b2.size()] ^= 0x01;
          CScript succ2; succ2 << s1; succ2.insert(succ2.end(), b2.begin(), b2.end());
          mustFail(s1, a0, b0, GetScriptForDestination(CScriptID(succ2))); }
    }

    BOOST_TEST_MESSAGE("escape-search: " << honestOk << " honest ok, "
                       << mutRejected << " mutations rejected, " << escapes << " escapes");
    BOOST_CHECK_EQUAL(honestOk, 300);
    BOOST_CHECK_EQUAL(escapes, 0);
}

BOOST_AUTO_TEST_SUITE_END()
