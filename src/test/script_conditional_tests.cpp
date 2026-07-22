// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bathron.h"

#include "hash.h"
#include "key.h"
#include "script/conditional.h"
#include "script/script.h"
#include "script/interpreter.h"
#include "utilstrencodings.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(script_conditional_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(create_conditional_script)
{
    // Test CreateConditionalScript
    uint256 hashlock;
    CSHA256().Write((unsigned char*)"test_secret_32_bytes_exactly!!", 32).Finalize(hashlock.begin());

    uint32_t timelock = 150000;

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CKeyID destA = keyA.GetPubKey().GetID();
    CKeyID destB = keyB.GetPubKey().GetID();

    CScript script = CreateConditionalScript(hashlock, timelock, destA, destB);

    // Script should not be empty
    BOOST_CHECK(!script.empty());

    // Script should start with OP_IF
    BOOST_CHECK(script[0] == OP_IF);

    // Script should be recognizable as conditional
    BOOST_CHECK(IsConditionalScript(script));
}

BOOST_AUTO_TEST_CASE(decode_conditional_script)
{
    // Create a conditional script
    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0x42); // 32 bytes of 0x42
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    uint32_t timelock = 200000;

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CKeyID destA = keyA.GetPubKey().GetID();
    CKeyID destB = keyB.GetPubKey().GetID();

    CScript script = CreateConditionalScript(hashlock, timelock, destA, destB);

    // Decode the script
    uint256 decodedHashlock;
    uint32_t decodedTimelock;
    CKeyID decodedDestA, decodedDestB;

    bool decoded = DecodeConditionalScript(script, decodedHashlock, decodedTimelock, decodedDestA, decodedDestB);

    BOOST_CHECK(decoded);
    BOOST_CHECK(decodedHashlock == hashlock);
    BOOST_CHECK(decodedTimelock == timelock);
    BOOST_CHECK(decodedDestA == destA);
    BOOST_CHECK(decodedDestB == destB);
}

BOOST_AUTO_TEST_CASE(is_conditional_script_negative)
{
    // Test that IsConditionalScript returns false for non-conditional scripts

    // P2PKH script
    CKey key;
    key.MakeNewKey(true);
    CScript p2pkh;
    p2pkh << OP_DUP << OP_HASH160 << ToByteVector(key.GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK(!IsConditionalScript(p2pkh));

    // Empty script
    CScript empty;
    BOOST_CHECK(!IsConditionalScript(empty));

    // Random script
    CScript random;
    random << OP_1 << OP_2 << OP_ADD;
    BOOST_CHECK(!IsConditionalScript(random));

    // Valid conditional script with trailing garbage (should be rejected)
    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0x42);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());
    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    CScript validScript = CreateConditionalScript(hashlock, 100000, keyA.GetPubKey().GetID(), keyB.GetPubKey().GetID());

    // Add trailing garbage
    CScript scriptWithGarbage = validScript;
    scriptWithGarbage << OP_NOP;
    BOOST_CHECK(!IsConditionalScript(scriptWithGarbage));
}

BOOST_AUTO_TEST_CASE(conditional_script_roundtrip)
{
    // Test multiple roundtrips with different parameters
    for (int i = 0; i < 10; i++) {
        // Generate random hashlock
        std::vector<unsigned char> secret(32);
        for (int j = 0; j < 32; j++) {
            secret[j] = (unsigned char)(rand() % 256);
        }
        uint256 hashlock;
        CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

        // Random timelock
        uint32_t timelock = 100000 + (rand() % 1000000);

        // Generate keys
        CKey keyA, keyB;
        keyA.MakeNewKey(true);
        keyB.MakeNewKey(true);

        CKeyID destA = keyA.GetPubKey().GetID();
        CKeyID destB = keyB.GetPubKey().GetID();

        // Create and decode
        CScript script = CreateConditionalScript(hashlock, timelock, destA, destB);

        uint256 h; uint32_t t; CKeyID a, b;
        BOOST_CHECK(DecodeConditionalScript(script, h, t, a, b));
        BOOST_CHECK(h == hashlock);
        BOOST_CHECK(t == timelock);
        BOOST_CHECK(a == destA);
        BOOST_CHECK(b == destB);
    }
}

BOOST_AUTO_TEST_CASE(conditional_spend_scripts)
{
    // Test CreateConditionalSpendA and CreateConditionalSpendB

    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0xAB);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    uint32_t timelock = 300000;

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CKeyID destA = keyA.GetPubKey().GetID();
    CKeyID destB = keyB.GetPubKey().GetID();

    CScript redeemScript = CreateConditionalScript(hashlock, timelock, destA, destB);

    // Create dummy signature
    std::vector<unsigned char> dummySig(72, 0x30);

    // Test SpendA (with secret)
    CScript spendA = CreateConditionalSpendA(dummySig, keyA.GetPubKey(), secret, redeemScript);
    BOOST_CHECK(!spendA.empty());
    // Should contain OP_TRUE for branch selection
    bool hasOpTrue = false;
    for (size_t i = 0; i < spendA.size(); i++) {
        if (spendA[i] == OP_TRUE) hasOpTrue = true;
    }
    BOOST_CHECK(hasOpTrue);

    // Test SpendB (timeout)
    CScript spendB = CreateConditionalSpendB(dummySig, keyB.GetPubKey(), redeemScript);
    BOOST_CHECK(!spendB.empty());
    // Should contain OP_FALSE for branch selection
    bool hasOpFalse = false;
    for (size_t i = 0; i < spendB.size(); i++) {
        if (spendB[i] == OP_FALSE) hasOpFalse = true;
    }
    BOOST_CHECK(hasOpFalse);
}

BOOST_AUTO_TEST_CASE(conditional_timelock_boundaries)
{
    // Test timelock boundary conditions

    uint256 hashlock;
    std::vector<unsigned char> secret(32, 0x99);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CKeyID destA = keyA.GetPubKey().GetID();
    CKeyID destB = keyB.GetPubKey().GetID();

    // Test with minimum valid timelock (1)
    CScript scriptMin = CreateConditionalScript(hashlock, 1, destA, destB);
    BOOST_CHECK(IsConditionalScript(scriptMin));
    uint256 h; uint32_t t; CKeyID a, b;
    BOOST_CHECK(DecodeConditionalScript(scriptMin, h, t, a, b));
    BOOST_CHECK(t == 1);

    // Test with large timelock (practical maximum - year 4000 at ~1 block/min)
    // Note: CScriptNum::getint() clamps to INT_MAX, so we test with realistic values
    CScript scriptLarge = CreateConditionalScript(hashlock, 0x7FFFFFFE, destA, destB);
    BOOST_CHECK(IsConditionalScript(scriptLarge));
    BOOST_CHECK(DecodeConditionalScript(scriptLarge, h, t, a, b));
    BOOST_CHECK(t == 0x7FFFFFFE);  // ~2 billion blocks = thousands of years

    // Test with typical block height
    CScript scriptTypical = CreateConditionalScript(hashlock, 1500000, destA, destB);
    BOOST_CHECK(IsConditionalScript(scriptTypical));
    BOOST_CHECK(DecodeConditionalScript(scriptTypical, h, t, a, b));
    BOOST_CHECK(t == 1500000);
}

BOOST_AUTO_TEST_CASE(conditional_script_bip199_compatible)
{
    // Verify script structure is BIP-199 compatible

    uint256 hashlock = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    uint32_t timelock = 500000;

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);

    CScript script = CreateConditionalScript(hashlock, timelock, keyA.GetPubKey().GetID(), keyB.GetPubKey().GetID());

    // Verify structure by checking opcodes in order
    CScript::const_iterator it = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;

    // OP_IF
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_IF);

    // OP_SIZE
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_SIZE);

    // 32 (push)
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(CScriptNum(data, true).getint() == 32);

    // OP_EQUALVERIFY
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_EQUALVERIFY);

    // OP_SHA256
    BOOST_CHECK(script.GetOp(it, opcode));
    BOOST_CHECK(opcode == OP_SHA256);

    // hashlock (32 bytes)
    BOOST_CHECK(script.GetOp(it, opcode, data));
    BOOST_CHECK(data.size() == 32);
}

BOOST_AUTO_TEST_SUITE_END()
