// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Unit tests for Phase 4: OP_TEMPLATEVERIFY covenants
 *
 * Coverage:
 *   1. ComputeTemplateHash — determinism, field sensitivity, edge cases
 *   2. OP_TEMPLATEVERIFY — negative tests (bad commitment, too many outputs)
 *   3. Covenant script — create/decode roundtrip, opcode structure
 *   4. Branch B (refund timeout) — CLTV without covenant constraint
 */

#include "test/test_bathron.h"

#include "hash.h"
#include "key.h"
#include "script/conditional.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/template_hash.h"
#include "primitives/transaction.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(script_covenant_tests, BasicTestingSetup)

// =============================================================================
// Helper: build a simple template transaction
// =============================================================================

static CMutableTransaction MakeTemplateTx(int16_t nVersion, int16_t nType,
                                           uint32_t nLockTime,
                                           CAmount outAmount,
                                           const CScript& outScript)
{
    CMutableTransaction mtx;
    mtx.nVersion = nVersion;
    mtx.nType = nType;
    mtx.nLockTime = nLockTime;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = 0xFFFFFFFF;
    mtx.vout.emplace_back(outAmount, outScript);
    return mtx;
}

// =============================================================================
// 1. ComputeTemplateHash tests
// =============================================================================

BOOST_AUTO_TEST_CASE(template_hash_deterministic)
{
    // Same transaction must produce same hash
    CScript outScript;
    outScript << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xAA)
              << OP_EQUALVERIFY << OP_CHECKSIG;

    CMutableTransaction mtx = MakeTemplateTx(3, 41, 0, 50000, outScript);
    CTransaction tx(mtx);

    uint256 hash1 = ComputeTemplateHash(tx);
    uint256 hash2 = ComputeTemplateHash(tx);
    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(!hash1.IsNull());
}

BOOST_AUTO_TEST_CASE(template_hash_ignores_prevout)
{
    // Hash must NOT change when prevout changes (not committed)
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx1.vin[0].prevout = COutPoint(uint256S("aaaa"), 0);

    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx2.vin[0].prevout = COutPoint(uint256S("bbbb"), 1);

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) ==
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_ignores_scriptsig)
{
    // Hash must NOT change when scriptSig changes (not committed)
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx1.vin[0].scriptSig << std::vector<unsigned char>(32, 0x11);

    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx2.vin[0].scriptSig << std::vector<unsigned char>(32, 0x22);

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) ==
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_nversion)
{
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(1, 0, 0, 10000, outScript);
    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10000, outScript);

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_ntype)
{
    // nType is committed — prevents cross-type collisions
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);   // NORMAL
    CMutableTransaction mtx2 = MakeTemplateTx(3, 41, 0, 10000, outScript);  // HTLC_CLAIM

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_locktime)
{
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 500000, 10000, outScript);

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_output_amount)
{
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10001, outScript);

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_output_script)
{
    CScript outScript1;
    outScript1 << OP_TRUE;

    CScript outScript2;
    outScript2 << OP_FALSE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript1);
    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10000, outScript2);

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_sequence)
{
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx1.vin[0].nSequence = 0xFFFFFFFF;

    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx2.vin[0].nSequence = 0;

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_sensitive_to_output_count)
{
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx1 = MakeTemplateTx(3, 0, 0, 10000, outScript);

    CMutableTransaction mtx2 = MakeTemplateTx(3, 0, 0, 10000, outScript);
    mtx2.vout.emplace_back(5000, outScript);  // 2 outputs

    BOOST_CHECK(ComputeTemplateHash(CTransaction(mtx1)) !=
                ComputeTemplateHash(CTransaction(mtx2)));
}

BOOST_AUTO_TEST_CASE(template_hash_zero_amount)
{
    // Edge case: zero-value output should still produce valid hash
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx = MakeTemplateTx(3, 0, 0, 0, outScript);
    uint256 hash = ComputeTemplateHash(CTransaction(mtx));
    BOOST_CHECK(!hash.IsNull());
}

BOOST_AUTO_TEST_CASE(template_hash_empty_outputs)
{
    // Edge case: no outputs
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = 0;
    mtx.nLockTime = 0;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = 0xFFFFFFFF;
    // No outputs

    uint256 hash = ComputeTemplateHash(CTransaction(mtx));
    BOOST_CHECK(!hash.IsNull());
}

BOOST_AUTO_TEST_CASE(template_hash_max_outputs)
{
    // CTV_MAX_OUTPUTS = 4 outputs should work
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = 0;
    mtx.nLockTime = 0;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = 0xFFFFFFFF;
    for (size_t i = 0; i < CTV_MAX_OUTPUTS; i++) {
        mtx.vout.emplace_back(1000 * (i + 1), outScript);
    }

    uint256 hash = ComputeTemplateHash(CTransaction(mtx));
    BOOST_CHECK(!hash.IsNull());

    // 5 outputs: hash still computes (limit is enforced in checker, not hash fn)
    mtx.vout.emplace_back(5000, outScript);
    uint256 hashOver = ComputeTemplateHash(CTransaction(mtx));
    BOOST_CHECK(!hashOver.IsNull());
    BOOST_CHECK(hash != hashOver);
}

// =============================================================================
// 2. OP_TEMPLATEVERIFY negative tests
// =============================================================================

BOOST_AUTO_TEST_CASE(templateverify_matching_commitment)
{
    // Positive test: correct commitment should pass
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction spendTx = MakeTemplateTx(3, 41, 0, 50000, outScript);
    uint256 commitment = ComputeTemplateHash(CTransaction(spendTx));

    // Script: <commitment> OP_TEMPLATEVERIFY OP_DROP OP_TRUE
    CScript lockScript;
    lockScript << ToByteVector(commitment) << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;

    CScript unlockScript;  // empty — lock script pushes the commitment

    unsigned int flags = SCRIPT_VERIFY_TEMPLATEVERIFY;

    // Need input in spending TX
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);

    ScriptError err;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 50000);
    bool result = VerifyScript(unlockScript, lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK_MESSAGE(result, "Expected pass, got: " + std::string(ScriptErrorString(err)));
}

BOOST_AUTO_TEST_CASE(templateverify_wrong_commitment)
{
    // Wrong commitment should fail with SCRIPT_ERR_TEMPLATE_MISMATCH
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction spendTx = MakeTemplateTx(3, 41, 0, 50000, outScript);

    // Use a DIFFERENT commitment (wrong hash)
    uint256 wrongCommitment = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    CScript lockScript;
    lockScript << ToByteVector(wrongCommitment) << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;

    CScript unlockScript;

    unsigned int flags = SCRIPT_VERIFY_TEMPLATEVERIFY;
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);

    ScriptError err;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 50000);
    bool result = VerifyScript(unlockScript, lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK(!result);
    BOOST_CHECK(err == SCRIPT_ERR_TEMPLATE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(templateverify_short_commitment)
{
    // Commitment shorter than 32 bytes should fail
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction spendTx = MakeTemplateTx(3, 0, 0, 10000, outScript);

    std::vector<unsigned char> shortCommitment(16, 0xAA);  // Only 16 bytes

    CScript lockScript;
    lockScript << shortCommitment << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;

    CScript unlockScript;

    unsigned int flags = SCRIPT_VERIFY_TEMPLATEVERIFY;
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);

    ScriptError err;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 10000);
    bool result = VerifyScript(unlockScript, lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK(!result);
    BOOST_CHECK(err == SCRIPT_ERR_TEMPLATE_INVALID);
}

BOOST_AUTO_TEST_CASE(templateverify_empty_stack)
{
    // Empty stack should fail with SCRIPT_ERR_INVALID_STACK_OPERATION
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction spendTx = MakeTemplateTx(3, 0, 0, 10000, outScript);

    // OP_TEMPLATEVERIFY with nothing on stack
    CScript lockScript;
    lockScript << OP_TEMPLATEVERIFY;

    CScript unlockScript;

    unsigned int flags = SCRIPT_VERIFY_TEMPLATEVERIFY;
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);

    ScriptError err;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 10000);
    bool result = VerifyScript(unlockScript, lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK(!result);
    BOOST_CHECK(err == SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(templateverify_output_count_boundary)
{
    // Exactly CTV_MAX_OUTPUTS (64) passes; one more fails in the checker even
    // with a matching commitment.
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction spendTx;
    spendTx.nVersion = 3;
    spendTx.nType = 0;
    spendTx.nLockTime = 0;
    spendTx.vin.resize(1);
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);
    spendTx.vin[0].nSequence = 0xFFFFFFFF;
    for (size_t i = 0; i < CTV_MAX_OUTPUTS; i++) {
        spendTx.vout.emplace_back(1000, outScript);
    }

    const unsigned int flags = SCRIPT_VERIFY_TEMPLATEVERIFY;
    ScriptError err;

    {
        // 64 outputs, matching commitment: OK (the batching/fan-out case the
        // 4 -> 64 raise exists for).
        uint256 commitment = ComputeTemplateHash(CTransaction(spendTx));
        CScript lockScript;
        lockScript << ToByteVector(commitment) << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;
        MutableTransactionSignatureChecker checker(&spendTx, 0, 1000);
        BOOST_CHECK_MESSAGE(VerifyScript(CScript(), lockScript, flags, checker,
                                         SIGVERSION_BASE, &err),
                            "64-output template failed: " << ScriptErrorString(err));
    }

    // 65 outputs — exceeds CTV_MAX_OUTPUTS, rejected by the checker (the hash
    // function itself doesn't reject).
    spendTx.vout.emplace_back(1000, outScript);
    uint256 commitment = ComputeTemplateHash(CTransaction(spendTx));
    CScript lockScript;
    lockScript << ToByteVector(commitment) << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 1000);
    bool result = VerifyScript(CScript(), lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK(!result);
    BOOST_CHECK(err == SCRIPT_ERR_TEMPLATE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(templateverify_disabled_flag_nop)
{
    // Without SCRIPT_VERIFY_TEMPLATEVERIFY flag, OP_TEMPLATEVERIFY = NOP4
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction spendTx = MakeTemplateTx(3, 0, 0, 10000, outScript);

    // Wrong commitment, but flag disabled — should be treated as NOP
    uint256 wrongCommitment = uint256S("deadbeef");

    CScript lockScript;
    lockScript << ToByteVector(wrongCommitment) << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;

    CScript unlockScript;

    // NO SCRIPT_VERIFY_TEMPLATEVERIFY flag, NO discourage upgradable nops
    unsigned int flags = 0;
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);

    ScriptError err;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 10000);
    bool result = VerifyScript(unlockScript, lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK_MESSAGE(result, "NOP4 should pass when CTV flag disabled: " +
                        std::string(ScriptErrorString(err)));
}

BOOST_AUTO_TEST_CASE(templateverify_modified_output_amount)
{
    // Commitment computed for amount X, TX has amount Y — should fail
    CScript outScript;
    outScript << OP_TRUE;

    CMutableTransaction templateTx = MakeTemplateTx(3, 41, 0, 50000, outScript);
    uint256 commitment = ComputeTemplateHash(CTransaction(templateTx));

    // Modify amount in spending TX
    CMutableTransaction spendTx = templateTx;
    spendTx.vout[0].nValue = 99999;  // Different from committed 50000
    spendTx.vin[0].prevout = COutPoint(uint256S("dead"), 0);

    CScript lockScript;
    lockScript << ToByteVector(commitment) << OP_TEMPLATEVERIFY << OP_DROP << OP_TRUE;

    CScript unlockScript;

    unsigned int flags = SCRIPT_VERIFY_TEMPLATEVERIFY;

    ScriptError err;
    MutableTransactionSignatureChecker checker(&spendTx, 0, 50000);
    bool result = VerifyScript(unlockScript, lockScript, flags, checker,
                               SIGVERSION_BASE, &err);
    BOOST_CHECK(!result);
    BOOST_CHECK(err == SCRIPT_ERR_TEMPLATE_MISMATCH);
}

// =============================================================================
// 3. Covenant script create/decode roundtrip
// =============================================================================

BOOST_AUTO_TEST_CASE(covenant_script_create_and_detect)
{
    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0x42);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    uint32_t timelock = 200000;

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CKeyID destA = keyA.GetPubKey().GetID();
    CKeyID destB = keyB.GetPubKey().GetID();

    uint256 templateCommitment = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

    CScript script = CreateConditionalWithCovenantScript(
        hashlock, timelock, destA, destB, templateCommitment);

    // Must be recognized as covenant script
    BOOST_CHECK(IsConditionalWithCovenantScript(script));

    // Must NOT be recognized as regular conditional script
    BOOST_CHECK(!IsConditionalScript(script));
}

BOOST_AUTO_TEST_CASE(covenant_script_roundtrip)
{
    for (int i = 0; i < 10; i++) {
        // Random hashlock
        std::vector<unsigned char> secret(32);
        for (int j = 0; j < 32; j++) secret[j] = (unsigned char)(rand() % 256);
        uint256 hashlock;
        CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

        // Random timelock
        uint32_t timelock = 100000 + (rand() % 1000000);

        // Random keys
        CKey keyA, keyB;
        keyA.MakeNewKey(true);
        keyB.MakeNewKey(true);
        CKeyID destA = keyA.GetPubKey().GetID();
        CKeyID destB = keyB.GetPubKey().GetID();

        // Random commitment
        std::vector<unsigned char> commitBytes(32);
        for (int j = 0; j < 32; j++) commitBytes[j] = (unsigned char)(rand() % 256);
        uint256 templateCommitment(commitBytes);

        // Create
        CScript script = CreateConditionalWithCovenantScript(
            hashlock, timelock, destA, destB, templateCommitment);

        // Decode
        uint256 h, c;
        uint32_t t;
        CKeyID a, b;
        BOOST_CHECK(DecodeConditionalWithCovenantScript(script, h, t, a, b, c));
        BOOST_CHECK(h == hashlock);
        BOOST_CHECK(t == timelock);
        BOOST_CHECK(a == destA);
        BOOST_CHECK(b == destB);
        BOOST_CHECK(c == templateCommitment);
    }
}

BOOST_AUTO_TEST_CASE(covenant_script_opcode_structure)
{
    // Verify the exact opcode sequence for Branch A (covenant)
    uint256 hashlock = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    uint32_t timelock = 500000;

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    uint256 commitment = uint256S("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

    CScript script = CreateConditionalWithCovenantScript(
        hashlock, timelock, keyA.GetPubKey().GetID(), keyB.GetPubKey().GetID(), commitment);

    CScript::const_iterator it = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;

    // Branch A: OP_IF
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_IF);

    // OP_SIZE 32 OP_EQUALVERIFY (preimage size check)
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_SIZE);
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(CScriptNum(data, true).getint() == 32);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_EQUALVERIFY);

    // OP_SHA256 <hashlock> OP_EQUALVERIFY (hashlock check)
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_SHA256);
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(data.size() == 32);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_EQUALVERIFY);

    // <commitment> OP_TEMPLATEVERIFY OP_DROP (covenant)
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(data.size() == 32);  // 32-byte commitment
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_TEMPLATEVERIFY);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_DROP);

    // OP_DUP OP_HASH160 <destA> (P2PKH check for claimer)
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_DUP);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_HASH160);
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(data.size() == 20);  // CKeyID = 20 bytes

    // Branch B: OP_ELSE
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_ELSE);

    // <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP (CLTV refund)
    BOOST_CHECK(script.GetOp(it, opcode, data));
    // timelock is encoded as CScriptNum
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_CHECKLOCKTIMEVERIFY);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_DROP);

    // OP_DUP OP_HASH160 <destB>
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_DUP);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_HASH160);
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(data.size() == 20);

    // OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG (shared suffix)
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_ENDIF);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_EQUALVERIFY);
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_CHECKSIG);

    // No trailing garbage
    BOOST_CHECK(it == script.end());
}

BOOST_AUTO_TEST_CASE(covenant_script_not_regular_conditional)
{
    // A regular conditional script must NOT be detected as covenant
    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0x55);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CScript regular = CreateConditionalScript(hashlock, 100000,
        keyA.GetPubKey().GetID(), keyB.GetPubKey().GetID());

    BOOST_CHECK(IsConditionalScript(regular));
    BOOST_CHECK(!IsConditionalWithCovenantScript(regular));
}

// =============================================================================
// 4. Branch B refund timeout (CLTV without covenant)
// =============================================================================

BOOST_AUTO_TEST_CASE(covenant_branch_b_spend_script)
{
    // Branch B (refund) should use OP_FALSE for branch selection
    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0xBB);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    uint256 commitment = uint256S("1111111111111111111111111111111111111111111111111111111111111111");

    CScript redeemScript = CreateConditionalWithCovenantScript(
        hashlock, 300000, keyA.GetPubKey().GetID(), keyB.GetPubKey().GetID(), commitment);

    // Create dummy signature for Branch B (refund)
    std::vector<unsigned char> dummySig(72, 0x30);
    CScript spendB = CreateConditionalSpendB(dummySig, keyB.GetPubKey(), redeemScript);

    // Should not be empty
    BOOST_CHECK(!spendB.empty());

    // Should contain OP_FALSE for branch selection (selects ELSE path)
    bool hasOpFalse = false;
    for (size_t i = 0; i < spendB.size(); i++) {
        if (spendB[i] == OP_FALSE) hasOpFalse = true;
    }
    BOOST_CHECK(hasOpFalse);
}

BOOST_AUTO_TEST_CASE(covenant_branch_a_spend_script)
{
    // Branch A (claim with secret) should use OP_TRUE for branch selection
    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0xAA);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    uint256 commitment = uint256S("2222222222222222222222222222222222222222222222222222222222222222");

    CScript redeemScript = CreateConditionalWithCovenantScript(
        hashlock, 300000, keyA.GetPubKey().GetID(), keyB.GetPubKey().GetID(), commitment);

    std::vector<unsigned char> dummySig(72, 0x30);
    CScript spendA = CreateConditionalSpendA(dummySig, keyA.GetPubKey(), secret, redeemScript);

    BOOST_CHECK(!spendA.empty());

    // Should contain OP_TRUE for branch selection (selects IF path)
    bool hasOpTrue = false;
    for (size_t i = 0; i < spendA.size(); i++) {
        if (spendA[i] == OP_TRUE) hasOpTrue = true;
    }
    BOOST_CHECK(hasOpTrue);
}

// =============================================================================
// 5. Integration: covenant template hash matches in full script
// =============================================================================

BOOST_AUTO_TEST_CASE(covenant_template_hash_integration)
{
    // Create a realistic Settlement Pivot scenario:
    // 1. Compute C3 from a template PivotTx
    // 2. Create covenant script with C3
    // 3. Verify that a spending TX matching the template passes OP_TEMPLATEVERIFY

    CScript htlc3Script;
    htlc3Script << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xCC)
                << OP_EQUALVERIFY << OP_CHECKSIG;

    CAmount htlcAmount = 100000;
    CAmount covenantFee = 200;
    CAmount htlc3Amount = htlcAmount - covenantFee;

    // Build template PivotTx (what the Settlement Pivot should produce)
    CMutableTransaction templateTx;
    templateTx.nVersion = (int16_t)CTransaction::TxVersion::SAPLING;
    templateTx.nType = (int16_t)CTransaction::TxType::HTLC_CLAIM;
    templateTx.nLockTime = 0;
    templateTx.vin.resize(1);
    templateTx.vin[0].nSequence = 0xFFFFFFFF;
    templateTx.vout.emplace_back(htlc3Amount, htlc3Script);

    // Compute C3
    uint256 C3 = ComputeTemplateHash(CTransaction(templateTx));
    BOOST_CHECK(!C3.IsNull());

    // Verify: actual PivotTx with same structure should match C3
    CMutableTransaction pivotTx = templateTx;
    pivotTx.vin[0].prevout = COutPoint(uint256S("abcd1234"), 0);  // different prevout is OK

    uint256 actualHash = ComputeTemplateHash(CTransaction(pivotTx));
    BOOST_CHECK(actualHash == C3);

    // Verify: PivotTx with wrong amount should NOT match C3
    CMutableTransaction badPivot = templateTx;
    badPivot.vout[0].nValue = htlc3Amount + 1;  // off by 1
    BOOST_CHECK(ComputeTemplateHash(CTransaction(badPivot)) != C3);

    // Verify: PivotTx with extra output should NOT match C3
    CMutableTransaction extraOutput = templateTx;
    extraOutput.vout.emplace_back(100, htlc3Script);
    BOOST_CHECK(ComputeTemplateHash(CTransaction(extraOutput)) != C3);
}

BOOST_AUTO_TEST_SUITE_END()
