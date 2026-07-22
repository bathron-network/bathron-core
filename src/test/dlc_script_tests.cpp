// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * A3 — Script-sufficiency audit for DLC constructions
 * (doc/PREMAINNET-CONSENSUS-ADDITIONS.md §3)
 *
 * Proves the EXISTING script engine supports the on-chain shapes a DLC rail
 * needs, with no new opcode:
 *   1. 2-of-2 CHECKMULTISIG P2SH funding spend (full sign/verify)
 *   2. Multi-branch CET node — nested IF/ELSE, one OP_TEMPLATEVERIFY per branch
 *   3. Oracle-point branch — CTV + CHECKSIG(S_i) where the oracle attestation
 *      IS the private key (scalar reveal), pure ECDSA, anyone-can-execute
 *   4. CLTV refund branch — active at T, rejected before T
 *   5. Size/sigop budget — fanout per <=520-byte redeemScript, MAX_P2SH_SIGOPS
 *   6. Standardness — P2SH wrapper solves, spend shapes are push-only
 *   7. Full lifecycle at script level — outcome path + refund path
 */

#include "test/test_bathron.h"

#include "hash.h"
#include "key.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "script/template_hash.h"
#include "primitives/transaction.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dlc_script_tests, BasicTestingSetup)

// Flags a DLC spend must satisfy on this chain: consensus (P2SH + gated
// CLTV/CTV) plus the standardness set nodes actually relay with.
static const unsigned int DLC_FLAGS = SCRIPT_VERIFY_P2SH |
                                      SCRIPT_VERIFY_TEMPLATEVERIFY |
                                      SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                      SCRIPT_VERIFY_DERSIG |
                                      SCRIPT_VERIFY_LOW_S |
                                      SCRIPT_VERIFY_STRICTENC |
                                      SCRIPT_VERIFY_NULLDUMMY |
                                      SCRIPT_VERIFY_CLEANSTACK;

// =============================================================================
// Helpers
// =============================================================================

static CMutableTransaction MakeSpendTx(const std::vector<CTxOut>& outs,
                                       uint32_t nLockTime = 0,
                                       uint32_t nSequence = 0xFFFFFFFEU)
{
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nType = 0; // NORMAL
    mtx.nLockTime = nLockTime;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(uint256S("f00d"), 0);
    mtx.vin[0].nSequence = nSequence;
    mtx.vout = outs;
    return mtx;
}

static std::vector<unsigned char> SignRedeem(const CKey& key,
                                             const CScript& redeemScript,
                                             const CMutableTransaction& tx,
                                             CAmount amount)
{
    // v3 (Sapling-version) txs sign/verify with SIGVERSION_SAPLING — same as
    // production (CScriptCheck uses tx.GetRequiredSigVersion()).
    uint256 hash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL, amount,
                                 SIGVERSION_SAPLING);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);
    return sig;
}

static bool RunP2SH(const CScript& scriptSig, const CScript& redeemScript,
                    CMutableTransaction& spendTx, CAmount amount,
                    ScriptError* err)
{
    CScript scriptPubKey = GetScriptForDestination(CScriptID(redeemScript));
    MutableTransactionSignatureChecker checker(&spendTx, 0, amount);
    return VerifyScript(scriptSig, scriptPubKey, DLC_FLAGS, checker,
                        CTransaction(spendTx).GetRequiredSigVersion(), err);
}

// A CET-node branch body: <C_i> CTV DROP <pubkey_i> CHECKSIG
static void AppendCtvSigBranch(CScript& s, const uint256& commitment,
                               const CPubKey& pub)
{
    s << ToByteVector(commitment) << OP_TEMPLATEVERIFY << OP_DROP
      << ToByteVector(pub) << OP_CHECKSIG;
}

// =============================================================================
// 1. Funding: 2-of-2 CHECKMULTISIG under P2SH
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_funding_2of2_p2sh)
{
    CKey alice, bob;
    alice.MakeNewKey(true);
    bob.MakeNewKey(true);

    CScript redeem;
    redeem << OP_2 << ToByteVector(alice.GetPubKey())
           << ToByteVector(bob.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    const CAmount amount = 1000000; // 1,000,000 sats in the coffer
    CMutableTransaction spendTx =
        MakeSpendTx({CTxOut(amount - 1000, CScript() << OP_TRUE)});

    std::vector<unsigned char> sigA = SignRedeem(alice, redeem, spendTx, amount);
    std::vector<unsigned char> sigB = SignRedeem(bob, redeem, spendTx, amount);

    // NULLDUMMY: the CHECKMULTISIG bug slot must be OP_0
    CScript scriptSig;
    scriptSig << OP_0 << sigA << sigB
              << std::vector<unsigned char>(redeem.begin(), redeem.end());

    ScriptError err;
    BOOST_CHECK_MESSAGE(RunP2SH(scriptSig, redeem, spendTx, amount, &err),
                        "2-of-2 funding spend failed: "
                            << ScriptErrorString(err));

    // Negative: bob's signature replaced by a stranger's must fail
    CKey mallory;
    mallory.MakeNewKey(true);
    std::vector<unsigned char> sigM =
        SignRedeem(mallory, redeem, spendTx, amount);
    CScript badSig;
    badSig << OP_0 << sigA << sigM
           << std::vector<unsigned char>(redeem.begin(), redeem.end());
    BOOST_CHECK(!RunP2SH(badSig, redeem, spendTx, amount, &err));
}

// =============================================================================
// 2. CET node: 4 branches via nested IF/ELSE, one CTV template each
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_cet_node_four_branches)
{
    // Four oracle-outcome keys (in the real protocol these are the announced
    // outcome points S_i; the attestation reveals the scalar of exactly one).
    CKey k0, k1, k2, k3;
    k0.MakeNewKey(true); k1.MakeNewKey(true);
    k2.MakeNewKey(true); k3.MakeNewKey(true);

    const CAmount amount = 1000000;

    // Four distinct settlement splits (2 outputs each — well under CTV_MAX_OUTPUTS)
    CScript payA = CScript() << OP_TRUE;
    CScript payB = CScript() << OP_2;
    std::vector<CMutableTransaction> settles;
    std::vector<uint256> commits;
    for (int i = 0; i < 4; i++) {
        CAmount toA = 100000 + i * 200000;
        CMutableTransaction st = MakeSpendTx(
            {CTxOut(toA, payA), CTxOut(amount - 1000 - toA, payB)});
        settles.push_back(st);
        commits.push_back(ComputeTemplateHash(CTransaction(st)));
    }

    // redeem:
    // IF
    //   IF <branch0> ELSE <branch1> ENDIF
    // ELSE
    //   IF <branch2> ELSE <branch3> ENDIF
    // ENDIF
    CScript redeem;
    redeem << OP_IF << OP_IF;
    AppendCtvSigBranch(redeem, commits[0], k0.GetPubKey());
    redeem << OP_ELSE;
    AppendCtvSigBranch(redeem, commits[1], k1.GetPubKey());
    redeem << OP_ENDIF << OP_ELSE << OP_IF;
    AppendCtvSigBranch(redeem, commits[2], k2.GetPubKey());
    redeem << OP_ELSE;
    AppendCtvSigBranch(redeem, commits[3], k3.GetPubKey());
    redeem << OP_ENDIF << OP_ENDIF;

    const CKey* keys[4] = {&k0, &k1, &k2, &k3};
    // selector pushes for (outer, inner) — outer IF pops last-pushed first
    const opcodetype outerSel[4] = {OP_1, OP_1, OP_0, OP_0};
    const opcodetype innerSel[4] = {OP_1, OP_0, OP_1, OP_0};

    for (int i = 0; i < 4; i++) {
        std::vector<unsigned char> sig =
            SignRedeem(*keys[i], redeem, settles[i], amount);
        CScript scriptSig;
        scriptSig << sig << innerSel[i] << outerSel[i]
                  << std::vector<unsigned char>(redeem.begin(), redeem.end());
        ScriptError err;
        BOOST_CHECK_MESSAGE(
            RunP2SH(scriptSig, redeem, settles[i], amount, &err),
            "branch " << i << " failed: " << ScriptErrorString(err));
    }

    // Negative: settlement tx of outcome 2 forced through branch 0
    // must die on TEMPLATE_MISMATCH even with a valid branch-0 signature.
    std::vector<unsigned char> sig0on2 =
        SignRedeem(k0, redeem, settles[2], amount);
    CScript wrongBranch;
    wrongBranch << sig0on2 << OP_1 << OP_1
                << std::vector<unsigned char>(redeem.begin(), redeem.end());
    ScriptError err;
    BOOST_CHECK(!RunP2SH(wrongBranch, redeem, settles[2], amount, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);
}

// =============================================================================
// 3. Oracle-point branch: the attestation IS the key (scalar reveal, ECDSA)
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_oracle_point_branch_anyone_can_execute)
{
    // Announcement time: the oracle publishes outcome point S_i (a pubkey).
    // Attestation time: it reveals the scalar s_i. From then on ANYONE can
    // produce the CHECKSIG — and CTV forces the split, so "anyone" is safe.
    CKey oracleScalar;                 // s_i — secret until attestation
    oracleScalar.MakeNewKey(true);
    CPubKey outcomePoint = oracleScalar.GetPubKey(); // S_i — public at announce

    const CAmount amount = 500000;
    CMutableTransaction settle =
        MakeSpendTx({CTxOut(200000, CScript() << OP_TRUE),
                     CTxOut(299000, CScript() << OP_2)});
    uint256 commit = ComputeTemplateHash(CTransaction(settle));

    CScript redeem;
    AppendCtvSigBranch(redeem, commit, outcomePoint);

    // A third party (watchtower) holding only the PUBLIC attestation executes:
    std::vector<unsigned char> sig =
        SignRedeem(oracleScalar, redeem, settle, amount);
    CScript scriptSig;
    scriptSig << sig
              << std::vector<unsigned char>(redeem.begin(), redeem.end());
    ScriptError err;
    BOOST_CHECK_MESSAGE(RunP2SH(scriptSig, redeem, settle, amount, &err),
                        "oracle-point execute failed: "
                            << ScriptErrorString(err));

    // Without the attestation (any other key), the branch is locked.
    CKey notOracle;
    notOracle.MakeNewKey(true);
    std::vector<unsigned char> badSig =
        SignRedeem(notOracle, redeem, settle, amount);
    CScript badScriptSig;
    badScriptSig << badSig
                 << std::vector<unsigned char>(redeem.begin(), redeem.end());
    BOOST_CHECK(!RunP2SH(badScriptSig, redeem, settle, amount, &err));
}

// =============================================================================
// 4. Refund branch: CLTV enforced
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_refund_cltv)
{
    CKey user;
    user.MakeNewKey(true);
    const uint32_t T = 46350;
    const CAmount amount = 500000;

    CScript redeem;
    redeem << CScriptNum(T) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
           << ToByteVector(user.GetPubKey()) << OP_CHECKSIG;

    // At maturity: nLockTime = T, sequence non-final → refund succeeds
    CMutableTransaction refund =
        MakeSpendTx({CTxOut(amount - 1000, CScript() << OP_TRUE)}, T);
    std::vector<unsigned char> sig = SignRedeem(user, redeem, refund, amount);
    CScript scriptSig;
    scriptSig << sig
              << std::vector<unsigned char>(redeem.begin(), redeem.end());
    ScriptError err;
    BOOST_CHECK_MESSAGE(RunP2SH(scriptSig, redeem, refund, amount, &err),
                        "refund at T failed: " << ScriptErrorString(err));

    // Too early: nLockTime = T-1 → UNSATISFIED_LOCKTIME
    CMutableTransaction early =
        MakeSpendTx({CTxOut(amount - 1000, CScript() << OP_TRUE)}, T - 1);
    std::vector<unsigned char> sigEarly =
        SignRedeem(user, redeem, early, amount);
    CScript scriptSigEarly;
    scriptSigEarly << sigEarly
                   << std::vector<unsigned char>(redeem.begin(), redeem.end());
    BOOST_CHECK(!RunP2SH(scriptSigEarly, redeem, early, amount, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

// =============================================================================
// 5. Budget: branches per node under the 520-byte P2SH push limit + sigops
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_node_size_and_sigop_budget)
{
    // Linear selector ladder, k branches:
    //   IF <b0> ELSE IF <b1> ELSE IF <b2> ... ENDIF...ENDIF
    // Branch body = 34 (C push) + 1 (CTV) + 1 (DROP) + 34 (pub push) + 1 (SIG)
    // = 71 bytes; ladder overhead = 2 bytes per level + 1.
    CKey k;
    k.MakeNewKey(true);
    uint256 c = uint256S("ab");

    auto buildNode = [&](int nBranches) {
        CScript s;
        for (int i = 0; i < nBranches - 1; i++) {
            s << OP_IF;
            AppendCtvSigBranch(s, c, k.GetPubKey());
            s << OP_ELSE;
        }
        AppendCtvSigBranch(s, c, k.GetPubKey());
        for (int i = 0; i < nBranches - 1; i++) s << OP_ENDIF;
        return s;
    };

    CScript node6 = buildNode(6);
    BOOST_TEST_MESSAGE("6-branch node: " << node6.size() << " bytes, "
                       << node6.GetSigOpCount(true) << " sigops");
    // Must fit the 520-byte MAX_SCRIPT_ELEMENT_SIZE (P2SH redeemScript push)
    BOOST_CHECK_LE(node6.size(), MAX_SCRIPT_ELEMENT_SIZE);
    // Must fit the P2SH standardness sigop budget
    BOOST_CHECK_LE(node6.GetSigOpCount(true), (unsigned int)MAX_P2SH_SIGOPS);

    CScript node7 = buildNode(7);
    BOOST_TEST_MESSAGE("7-branch node: " << node7.size() << " bytes");
    // Document the actual frontier: whichever side of 520 the 7-branch node
    // lands on, the 6-branch node is the guaranteed-safe fanout.
    // Fanout 6 → 256 outcomes in ceil(log6(256)) = 4 chained node levels.

    // And a full 4-branch node must be executable end to end (test 2 above);
    // here we only assert it also fits with margin.
    CScript node4 = buildNode(4);
    BOOST_CHECK_LE(node4.size(), MAX_SCRIPT_ELEMENT_SIZE);
}

// =============================================================================
// 6. Standardness: the P2SH wrapper is a standard output type
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_p2sh_wrapper_is_standard)
{
    CKey k;
    k.MakeNewKey(true);
    uint256 c = uint256S("cd");
    CScript redeem;
    redeem << OP_IF;
    AppendCtvSigBranch(redeem, c, k.GetPubKey());
    redeem << OP_ELSE << CScriptNum(46350) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
           << ToByteVector(k.GetPubKey()) << OP_CHECKSIG << OP_ENDIF;

    CScript p2sh = GetScriptForDestination(CScriptID(redeem));
    txnouttype whichType;
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(p2sh, whichType, solutions));
    BOOST_CHECK_EQUAL(whichType, TX_SCRIPTHASH);

    // The spend-side scriptSig must be push-only (P2SH consensus rule);
    // selectors OP_0/OP_1 and data pushes all qualify.
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(71, 0x30) << OP_1
              << std::vector<unsigned char>(redeem.begin(), redeem.end());
    BOOST_CHECK(scriptSig.IsPushOnly());
}

// =============================================================================
// 7. Lifecycle at script level: outcome path, then refund path
// =============================================================================

BOOST_AUTO_TEST_CASE(dlc_lifecycle_outcome_and_refund)
{
    // One contract, two ways out:
    //   IF   — outcome: CTV(split) + oracle attestation key
    //   ELSE — refund : CLTV(T) + 2-of-2 back to the parties (here 1 key for
    //          brevity; funding test 1 already proves 2-of-2)
    CKey oracleScalar, user;
    oracleScalar.MakeNewKey(true);
    user.MakeNewKey(true);
    const uint32_t T = 50000;
    const CAmount amount = 1000000;

    CMutableTransaction settle =
        MakeSpendTx({CTxOut(400000, CScript() << OP_TRUE),
                     CTxOut(599000, CScript() << OP_2)});
    uint256 commit = ComputeTemplateHash(CTransaction(settle));

    CScript redeem;
    redeem << OP_IF;
    AppendCtvSigBranch(redeem, commit, oracleScalar.GetPubKey());
    redeem << OP_ELSE << CScriptNum(T) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
           << ToByteVector(user.GetPubKey()) << OP_CHECKSIG << OP_ENDIF;

    ScriptError err;

    // (a) Oracle attests → outcome branch executes with the forced split
    {
        std::vector<unsigned char> sig =
            SignRedeem(oracleScalar, redeem, settle, amount);
        CScript scriptSig;
        scriptSig << sig << OP_1
                  << std::vector<unsigned char>(redeem.begin(), redeem.end());
        BOOST_CHECK_MESSAGE(RunP2SH(scriptSig, redeem, settle, amount, &err),
                            "outcome path failed: " << ScriptErrorString(err));
    }

    // (b) Oracle silent → refund branch works at T…
    {
        CMutableTransaction refund =
            MakeSpendTx({CTxOut(amount - 1000, CScript() << OP_TRUE)}, T);
        std::vector<unsigned char> sig =
            SignRedeem(user, redeem, refund, amount);
        CScript scriptSig;
        scriptSig << sig << OP_0
                  << std::vector<unsigned char>(redeem.begin(), redeem.end());
        BOOST_CHECK_MESSAGE(RunP2SH(scriptSig, redeem, refund, amount, &err),
                            "refund path failed: " << ScriptErrorString(err));
    }

    // (c) …but not a block earlier.
    {
        CMutableTransaction early =
            MakeSpendTx({CTxOut(amount - 1000, CScript() << OP_TRUE)}, T - 1);
        std::vector<unsigned char> sig =
            SignRedeem(user, redeem, early, amount);
        CScript scriptSig;
        scriptSig << sig << OP_0
                  << std::vector<unsigned char>(redeem.begin(), redeem.end());
        BOOST_CHECK(!RunP2SH(scriptSig, redeem, early, amount, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    }
}

BOOST_AUTO_TEST_SUITE_END()
