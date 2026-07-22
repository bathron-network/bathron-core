// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * OP_CHECKSIGFROMSTACK — verify an ECDSA signature over an ARBITRARY message
 * pulled from the stack (not a tx sighash). The oracle/delegation primitive
 * (doc/COVENANT-CAPABILITY-AUDIT.md §4, Tier 1).
 *
 * Stack: <sig> <msg> <pubkey>  ->  <bool>
 * Semantics: fOk = pubkey.Verify(SHA256(msg), sig). Pushes true/false like
 * OP_CHECKSIG, so it composes (add OP_VERIFY to make it terminal).
 */

#include "test/test_bathron.h"

#include "crypto/sha256.h"
#include "key.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(csfs_script_tests, BasicTestingSetup)

namespace {

uint256 Msg256(const std::vector<unsigned char>& msg)
{
    uint256 h;
    CSHA256().Write(msg.data(), msg.size()).Finalize(h.begin());
    return h;
}

std::vector<unsigned char> SignMsg(const CKey& key,
                                   const std::vector<unsigned char>& msg)
{
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(Msg256(msg), sig));  // raw ECDSA, no hashtype byte
    return sig;
}

bool Run(const CScript& s, ScriptError* err,
         unsigned int flags = SCRIPT_VERIFY_CHECKSIGFROMSTACK)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("feed"), 0);
    tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    return VerifyScript(CScript(), s, flags, checker,
                        CTransaction(tx).GetRequiredSigVersion(), err);
}

} // namespace

// ── Gating ──────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(flag_off_is_nop)
{
    // Without the flag OP_CHECKSIGFROMSTACK (=NOP6) is a no-op: the pushed
    // OP_TRUE below is what satisfies the script.
    CScript s;
    s << OP_9 << OP_9 << OP_9 << OP_CHECKSIGFROMSTACK << OP_DROP << OP_DROP
      << OP_DROP << OP_TRUE;
    ScriptError err;
    BOOST_CHECK(Run(s, &err, /*flags=*/0));
}

// ── Valid attestation ───────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(valid_signature_over_message)
{
    CKey oracle;
    oracle.MakeNewKey(true);
    std::vector<unsigned char> msg = {'B','T','C','=','1','0','0','k'};
    std::vector<unsigned char> sig = SignMsg(oracle, msg);

    CScript s;
    s << sig << msg << ToByteVector(oracle.GetPubKey())
      << OP_CHECKSIGFROMSTACK;   // leaves the bool on top
    ScriptError err;
    BOOST_CHECK_MESSAGE(Run(s, &err), ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(wrong_message_fails)
{
    CKey oracle;
    oracle.MakeNewKey(true);
    std::vector<unsigned char> msg = {'p','r','i','c','e'};
    std::vector<unsigned char> sig = SignMsg(oracle, msg);
    std::vector<unsigned char> tampered = {'P','R','I','C','E'};

    CScript s;
    s << sig << tampered << ToByteVector(oracle.GetPubKey())
      << OP_CHECKSIGFROMSTACK;
    ScriptError err;
    // pushes FALSE -> script evaluates false, not an error
    BOOST_CHECK(!Run(s, &err));
}

BOOST_AUTO_TEST_CASE(wrong_key_fails)
{
    CKey oracle, other;
    oracle.MakeNewKey(true);
    other.MakeNewKey(true);
    std::vector<unsigned char> msg = {'x'};
    std::vector<unsigned char> sig = SignMsg(oracle, msg);

    CScript s;
    s << sig << msg << ToByteVector(other.GetPubKey())
      << OP_CHECKSIGFROMSTACK;
    ScriptError err;
    BOOST_CHECK(!Run(s, &err));
}

BOOST_AUTO_TEST_CASE(too_few_args)
{
    CKey k; k.MakeNewKey(true);
    CScript s;
    s << std::vector<unsigned char>{0x01} << ToByteVector(k.GetPubKey())
      << OP_CHECKSIGFROMSTACK;   // only 2 items
    ScriptError err;
    BOOST_CHECK(!Run(s, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(garbage_signature_pushes_false)
{
    CKey oracle; oracle.MakeNewKey(true);
    std::vector<unsigned char> msg = {'a','b'};
    std::vector<unsigned char> junk(20, 0x11);

    CScript s;
    s << junk << msg << ToByteVector(oracle.GetPubKey())
      << OP_CHECKSIGFROMSTACK;
    ScriptError err;
    BOOST_CHECK(!Run(s, &err));   // false, not a crash
}

// ── Flagship composition: an oracle-gated branch ─────────────────────────
// "This coffer opens iff the oracle signed the outcome message." Reusable
// for DLC settlement, delegation, price attestations — the whole point.

BOOST_AUTO_TEST_CASE(oracle_gated_branch)
{
    CKey oracle, spender;
    oracle.MakeNewKey(true);
    spender.MakeNewKey(true);
    std::vector<unsigned char> outcome = {'W','I','N'};
    std::vector<unsigned char> sig = SignMsg(oracle, outcome);

    // redeem: <oracleSig> <outcome> <oraclePub> CSFS VERIFY  (spender auth omitted for brevity)
    CScript s;
    s << sig << outcome << ToByteVector(oracle.GetPubKey())
      << OP_CHECKSIGFROMSTACK << OP_VERIFY << OP_TRUE;
    ScriptError err;
    BOOST_CHECK_MESSAGE(Run(s, &err), ScriptErrorString(err));

    // Without the oracle's blessing (bad sig) the VERIFY aborts the script.
    CScript bad;
    std::vector<unsigned char> notsig(70, 0x30);
    bad << notsig << outcome << ToByteVector(oracle.GetPubKey())
        << OP_CHECKSIGFROMSTACK << OP_VERIFY << OP_TRUE;
    BOOST_CHECK(!Run(bad, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
}

BOOST_AUTO_TEST_SUITE_END()
