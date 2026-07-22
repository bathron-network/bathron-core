// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the script INTERPRETER EXECUTION path (hard-test campaign #6).
//
// Before this, src/test/fuzz/ had no target that runs EvalScript: the existing
// `script_deserialize` fuzzes CScript *parsing* only. So every covenant opcode's
// EVALUATION — stack effects, the 520-byte OP_CAT boundary arithmetic, the
// recursive-pair enforcement (CHECKOUTPUTSCRIPT/PUSHCURRENTSCRIPT), the in-consensus
// Merkle-proof + raw-BTC-tx parsing in OP_BTCSTATEVERIFY/TX_CONFIRMED, the CTV
// template hash, per-opcode resource bounds — had ZERO fuzz coverage.
//
// This runs VerifyScript + EvalScript over attacker-controlled (flags, scriptSig,
// scriptPubKey) with the FULL covenant flag set and a real spending-transaction
// checker, so the introspection opcodes (CTV / OUTPUTVALUE / OUTPUTSCRIPT) have
// vout/prevout context. Under libFuzzer + ASan/UBSan any crash / OOM / UB /
// over-read / unbounded allocation is caught. It asserts nothing about the RESULT
// (accept/reject is data-dependent) — the property is "the interpreter never
// misbehaves on hostile bytes, gated on or off".
//
//   ./configure --enable-fuzz CC=clang CXX=clang++ \
//     CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1"
//   make -C src test/fuzz/script_eval && ./src/test/fuzz/script_eval corpus/
// Seed the corpus from the *_script_tests.cpp covenant fixtures.

#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "test/fuzz/fuzz.h"
#include "uint256.h"

#include <vector>

namespace {
// Distinct flag combinations so the fuzzer exercises each opcode both GATED-ON
// (covenant flags set) and GATED-OFF (so it must be a no-op / disabled reject).
const unsigned int kFlagSets[] = {
    SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG,
    // full covenant surface:
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_TEMPLATEVERIFY | SCRIPT_VERIFY_BTCSTATE |
        SCRIPT_VERIFY_CHECKSIGFROMSTACK | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
        SCRIPT_VERIFY_OPCAT | SCRIPT_VERIFY_CHECKOUTPUTVALUE |
        SCRIPT_VERIFY_CHECKOUTPUTSCRIPT,
    // covenant surface + strictness flags (mempool-standard-ish):
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_TEMPLATEVERIFY |
        SCRIPT_VERIFY_BTCSTATE | SCRIPT_VERIFY_CHECKSIGFROMSTACK |
        SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_OPCAT |
        SCRIPT_VERIFY_CHECKOUTPUTVALUE | SCRIPT_VERIFY_CHECKOUTPUTSCRIPT,
};
constexpr size_t kNumFlagSets = sizeof(kFlagSets) / sizeof(kFlagSets[0]);
} // namespace

void test_one_input(std::vector<uint8_t> buffer)
{
    if (buffer.empty()) return;
    const unsigned int flags = kFlagSets[buffer[0] % kNumFlagSets];

    // Split the remaining bytes into scriptSig | scriptPubKey.
    const size_t half = (buffer.size() - 1) / 2;
    CScript scriptSig(buffer.begin() + 1, buffer.begin() + 1 + half);
    CScript scriptPubKey(buffer.begin() + 1 + half, buffer.end());

    // A spending transaction so the introspection opcodes (CTV / OUTPUTVALUE /
    // OUTPUTSCRIPT) have real vout / prevout context to read.
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256(), 0);
    mtx.vin[0].scriptSig = scriptSig;
    mtx.vout.resize(2);
    mtx.vout[0] = CTxOut(1000, scriptPubKey);
    mtx.vout[1] = CTxOut(0, CScript() << OP_TRUE);
    const CTransaction tx(mtx);

    TransactionSignatureChecker checker(&tx, 0, 1000);
    ScriptError serror;

    // 1) Full P2SH-aware verification (redeemScript unwrap included).
    (void)VerifyScript(scriptSig, scriptPubKey, flags, checker, SIGVERSION_BASE, &serror);

    // 2) Direct EvalScript on each script, reaching opcodes the P2SH wrap may gate.
    {
        std::vector<std::vector<unsigned char> > stack;
        (void)EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_BASE, &serror);
    }
    {
        std::vector<std::vector<unsigned char> > stack;
        (void)EvalScript(stack, scriptSig, flags, checker, SIGVERSION_BASE, &serror);
    }
}
