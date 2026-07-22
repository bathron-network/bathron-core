// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * CSV — OP_CHECKSEQUENCEVERIFY (BIP112) + BIP68 relative lock-times
 * (gate UPGRADE_CSV, doc/COVENANT-CAPABILITY-AUDIT.md §6 item 1).
 *
 * Three layers:
 *   1. BIP112 interpreter/checker semantics through VerifyScript: gating
 *      (flag off = NOP3), height vs time type matching, operand disable-flag
 *      NOP, tx-sequence disable-flag fail, v1-tx fail, masked-bits
 *      insensitivity, negative operand, boundaries.
 *   2. BIP68 pure math (CalculateSequenceLocks / EvaluateSequenceLocks /
 *      SequenceLocks) on a hand-built 60 s-spaced header chain: height and
 *      MTP-time boundaries, disable flag, v1, no-flags, max-over-inputs.
 *   3. Composition: the vault timeout branch <seq> CSV DROP <pk> CHECKSIG
 *      under P2SH — the covenant shape CSV exists for.
 */

#include "test/test_bathron.h"

#include "chain.h"
#include "consensus/consensus.h"
#include "key.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "primitives/transaction.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

const uint32_t TYPE_FLAG = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
const uint32_t DISABLE_FLAG = CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;

// Run <operand> CSV DROP TRUE against a 1-in tx with the given nSequence/nVersion.
bool RunCsv(int64_t operand, uint32_t txSeq, int16_t nVersion, ScriptError* err,
            unsigned int flags = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
{
    CScript s;
    s << CScriptNum(operand) << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;

    CMutableTransaction tx;
    tx.nVersion = nVersion;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("beef"), 0);
    tx.vin[0].nSequence = txSeq;
    tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    return VerifyScript(CScript(), s, flags, checker,
                        CTransaction(tx).GetRequiredSigVersion(), err);
}

// A linked 60 s-spaced chain of block indexes (skip pointers built, so
// GetAncestor/GetMedianTimePast behave like the real chain).
struct FakeChain {
    std::vector<CBlockIndex> blocks;

    explicit FakeChain(size_t n, int64_t baseTime = 1700000000)
    {
        blocks.resize(n);
        for (size_t i = 0; i < n; i++) {
            blocks[i].nHeight = (int)i;
            blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
            blocks[i].nTime = (uint32_t)(baseTime + i * 60);
            blocks[i].BuildSkip();
        }
    }
    CBlockIndex& at(size_t h) { return blocks[h]; }
};

CMutableTransaction SeqTx(const std::vector<uint32_t>& sequences, int16_t nVersion = 3)
{
    CMutableTransaction tx;
    tx.nVersion = nVersion;
    tx.vin.resize(sequences.size());
    for (size_t i = 0; i < sequences.size(); i++) {
        tx.vin[i].prevout = COutPoint(uint256S("beef"), (uint32_t)i);
        tx.vin[i].nSequence = sequences[i];
    }
    tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    return tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(csv_script_tests, BasicTestingSetup)

// ── 1. BIP112 interpreter/checker semantics ──────────────────────────────

BOOST_AUTO_TEST_CASE(flag_off_is_nop)
{
    ScriptError err;
    // Garbage operand, hostile tx sequence: without the flag it's NOP3.
    BOOST_CHECK(RunCsv(-1 /*would be NEGATIVE_LOCKTIME*/, 0, 1, &err, /*flags=*/0));
}

BOOST_AUTO_TEST_CASE(height_lock)
{
    ScriptError err;
    // tx sequence >= operand (same type) satisfies.
    BOOST_CHECK_MESSAGE(RunCsv(10, 10, 3, &err), ScriptErrorString(err));
    BOOST_CHECK_MESSAGE(RunCsv(10, 11, 3, &err), ScriptErrorString(err));
    BOOST_CHECK(!RunCsv(10, 9, 3, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(time_lock_and_type_mismatch)
{
    ScriptError err;
    BOOST_CHECK_MESSAGE(RunCsv(TYPE_FLAG | 5, TYPE_FLAG | 5, 3, &err),
                        ScriptErrorString(err));
    BOOST_CHECK(!RunCsv(TYPE_FLAG | 5, TYPE_FLAG | 4, 3, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    // Apples to oranges: time operand vs height tx-sequence and vice versa.
    BOOST_CHECK(!RunCsv(TYPE_FLAG | 5, 5, 3, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK(!RunCsv(5, TYPE_FLAG | 5, 3, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(disable_flags)
{
    ScriptError err;
    // Disable flag in the OPERAND: soft-fork escape hatch, behaves as NOP —
    // passes even though the tx sequence could never satisfy it.
    BOOST_CHECK_MESSAGE(RunCsv((int64_t)(DISABLE_FLAG | 10), 0, 3, &err),
                        ScriptErrorString(err));

    // Disable flag in the TX SEQUENCE: the input opted out of BIP68 —
    // CHECKSEQUENCEVERIFY must fail (else the lock could be bypassed).
    BOOST_CHECK(!RunCsv(10, DISABLE_FLAG | 10, 3, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(version_and_shape)
{
    ScriptError err;
    // BIP68 requires tx version >= 2.
    BOOST_CHECK(!RunCsv(10, 10, 1, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    // Negative operand.
    BOOST_CHECK(!RunCsv(-1, 10, 3, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_NEGATIVE_LOCKTIME);

    // Missing operand entirely.
    CScript s;
    s << OP_CHECKSEQUENCEVERIFY << OP_TRUE;
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256S("beef"), 0);
    tx.vout.emplace_back(1000, CScript() << OP_TRUE);
    MutableTransactionSignatureChecker checker(&tx, 0, 1000);
    BOOST_CHECK(!VerifyScript(CScript(), s, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                              checker, CTransaction(tx).GetRequiredSigVersion(), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(masked_bits_ignored)
{
    ScriptError err;
    // Bits outside DISABLE|TYPE|MASK carry no consensus meaning on either
    // side of the comparison (soft-fork room).
    const int64_t extraBit = 1LL << 20;  // between MASK (16 bits) and TYPE (bit 22)
    BOOST_CHECK_MESSAGE(RunCsv(extraBit | 5, 5, 3, &err), ScriptErrorString(err));
    BOOST_CHECK_MESSAGE(RunCsv(5, (uint32_t)(extraBit | 5), 3, &err),
                        ScriptErrorString(err));
}

// ── 2. BIP68 pure math on a fake chain ───────────────────────────────────

BOOST_AUTO_TEST_CASE(bip68_height_lock_boundary)
{
    FakeChain chain(600);
    // Coin confirmed at height 100, relative lock of 10 blocks:
    // first block that can include the spend is height 110.
    CMutableTransaction mtx = SeqTx({10});
    const CTransaction tx(mtx);

    std::vector<int> prevheights{100};
    BOOST_CHECK(!SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(109)));
    prevheights = {100};
    BOOST_CHECK(SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(110)));

    // Without the verify flag (gate off) the lock does not bind.
    prevheights = {100};
    BOOST_CHECK(SequenceLocks(tx, 0, &prevheights, chain.at(101)));

    // v1 transactions are exempt.
    CMutableTransaction v1 = SeqTx({10}, 1);
    prevheights = {100};
    BOOST_CHECK(SequenceLocks(CTransaction(v1), LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(101)));

    // Disable flag on the input is exempt.
    CMutableTransaction dis = SeqTx({DISABLE_FLAG | 10});
    prevheights = {100};
    BOOST_CHECK(SequenceLocks(CTransaction(dis), LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(101)));
}

BOOST_AUTO_TEST_CASE(bip68_time_lock_boundary)
{
    FakeChain chain(600);
    // Coin at height 100, time lock of 2*512 = 1024 seconds, measured from
    // MTP(99) (the coin block's parent chain), satisfied when the PREVIOUS
    // block's MTP passes that point (BIP113-consistent).
    CMutableTransaction mtx = SeqTx({TYPE_FLAG | 2});
    const CTransaction tx(mtx);

    const int64_t lockUntil = chain.at(99).GetMedianTimePast() + 1024 - 1;
    // Find the boundary the same way consensus does, then assert both sides.
    int firstValid = -1;
    for (int h = 101; h < 599; h++) {
        if (chain.at(h - 1).GetMedianTimePast() > lockUntil) { firstValid = h; break; }
    }
    BOOST_REQUIRE(firstValid > 101);  // the lock actually binds for a while

    std::vector<int> prevheights{100};
    BOOST_CHECK(!SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(firstValid - 1)));
    prevheights = {100};
    BOOST_CHECK(SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(firstValid)));
}

BOOST_AUTO_TEST_CASE(bip68_max_over_inputs)
{
    FakeChain chain(600);
    // Two inputs: coin at 100 with lock 10 (ready at 110), coin at 150 with
    // lock 20 (ready at 170). The tx is bound by the LATEST lock.
    CMutableTransaction mtx = SeqTx({10, 20});
    const CTransaction tx(mtx);

    std::vector<int> prevheights{100, 150};
    BOOST_CHECK(!SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(110)));
    prevheights = {100, 150};
    BOOST_CHECK(!SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(169)));
    prevheights = {100, 150};
    BOOST_CHECK(SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, chain.at(170)));
}

BOOST_AUTO_TEST_CASE(bip68_calculate_pair)
{
    FakeChain chain(600);
    // Direct look at the (height, time) pair.
    CMutableTransaction mtx = SeqTx({10, TYPE_FLAG | 2});
    const CTransaction tx(mtx);

    std::vector<int> prevheights{100, 200};
    const auto lockPair = CalculateSequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE,
                                                 &prevheights, chain.at(300));
    BOOST_CHECK_EQUAL(lockPair.first, 100 + 10 - 1);
    BOOST_CHECK_EQUAL(lockPair.second, chain.at(199).GetMedianTimePast() + 1024 - 1);

    // No flag / v1: sentinel pair (-1, -1) = never binds.
    prevheights = {100, 200};
    const auto noFlag = CalculateSequenceLocks(tx, 0, &prevheights, chain.at(300));
    BOOST_CHECK_EQUAL(noFlag.first, -1);
    BOOST_CHECK_EQUAL(noFlag.second, -1);
}

// Regression: a TIME-based lock evaluated against a transient "next block"
// index whose skip pointer was never built (exactly the dummy CheckSequenceLocks
// makes) used to crash — GetAncestor followed a null pskip near genesis. With
// CSV ALWAYS_ACTIVE on testnet/regtest the tip can sit at height 1, so this is
// reachable. GetAncestor must fall through to the pprev walk, not dereference
// null. (Fix: restored the upstream pskip!=nullptr guard in CBlockIndex::GetAncestor.)
BOOST_AUTO_TEST_CASE(bip68_time_lock_dummy_next_block_no_crash)
{
    FakeChain chain(3);   // genesis(0), 1, 2 — real indexes with skip pointers
    // The mempool builds this: a next-block index at tip+1 with NO skip pointer.
    CBlockIndex dummy;
    dummy.pprev = &chain.at(1);      // tip at height 1
    dummy.nHeight = 2;
    // dummy.pskip stays null (BuildSkip never called) — the crash trigger.

    // Coin confirmed at height 1, time-based relative lock -> targets ancestor
    // height max(1-1,0)=0. Pre-fix this null-derefs; post-fix it resolves to
    // genesis and returns a finite time.
    CMutableTransaction mtx = SeqTx({TYPE_FLAG | 1});
    const CTransaction tx(mtx);
    std::vector<int> prevheights{1};
    const auto pair = CalculateSequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE,
                                             &prevheights, dummy);
    // The time component is anchored on MTP(genesis) + 512 - 1, i.e. finite.
    BOOST_CHECK_EQUAL(pair.second, chain.at(0).GetMedianTimePast() + 512 - 1);

    // And GetAncestor(0) on the skip-less dummy returns genesis, not null.
    BOOST_CHECK(dummy.GetAncestor(0) == &chain.at(0));
}

// ── 3. Composition: the vault timeout branch under P2SH ──────────────────
// "After 20 blocks of quiet, the owner key can sweep" — the canonical CSV
// covenant clause (pairs with an immediate recovery-key branch app-side).

BOOST_AUTO_TEST_CASE(vault_timeout_branch_p2sh)
{
    CKey key;
    key.MakeNewKey(true);
    const CAmount amount = 500000;

    CScript redeem;
    redeem << CScriptNum(20) << OP_CHECKSEQUENCEVERIFY << OP_DROP
           << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    CMutableTransaction sweep;
    sweep.nVersion = 3;
    sweep.vin.resize(1);
    sweep.vin[0].prevout = COutPoint(uint256S("f00d"), 0);
    sweep.vin[0].nSequence = 20;  // asserts >= 20 confirmations of the vault
    sweep.vout.emplace_back(499000, CScript() << OP_TRUE);

    uint256 sighash = SignatureHash(redeem, sweep, 0, SIGHASH_ALL, amount,
                                    SIGVERSION_SAPLING);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);

    CScript scriptSig;
    scriptSig << sig << std::vector<unsigned char>(redeem.begin(), redeem.end());
    CScript scriptPubKey = GetScriptForDestination(CScriptID(redeem));

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                               SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S |
                               SCRIPT_VERIFY_CLEANSTACK;
    ScriptError err;
    MutableTransactionSignatureChecker checker(&sweep, 0, amount);
    BOOST_CHECK_MESSAGE(
        VerifyScript(scriptSig, scriptPubKey, flags, checker,
                     SIGVERSION_SAPLING, &err),
        "vault timeout failed: " << ScriptErrorString(err));

    // Premature sweep: sequence says 19 confirmations — dies on CSV even
    // though the signature is valid for that tx.
    CMutableTransaction early = sweep;
    early.vin[0].nSequence = 19;
    uint256 earlyHash = SignatureHash(redeem, early, 0, SIGHASH_ALL, amount,
                                      SIGVERSION_SAPLING);
    std::vector<unsigned char> earlySig;
    BOOST_REQUIRE(key.Sign(earlyHash, earlySig));
    earlySig.push_back((unsigned char)SIGHASH_ALL);
    CScript earlyScriptSig;
    earlyScriptSig << earlySig << std::vector<unsigned char>(redeem.begin(), redeem.end());
    MutableTransactionSignatureChecker earlyChecker(&early, 0, amount);
    BOOST_CHECK(!VerifyScript(earlyScriptSig, scriptPubKey, flags, earlyChecker,
                              SIGVERSION_SAPLING, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_SUITE_END()
