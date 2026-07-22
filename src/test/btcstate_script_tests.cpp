// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * A1 — OP_BTCSTATEVERIFY unit tests (doc/PREMAINNET-CONSENSUS-ADDITIONS.md §1)
 *
 * Interpreter semantics with a MOCK provider (deterministic, no DB):
 *   gating (flag off = NOP5), arity/shape errors, all five query types,
 *   fail-closed without provider, and the flagship composition — a hedge
 *   settlement branch: BTCSTATE(difficulty) + CTV(split) + CHECKSIG.
 * Pure helpers of the real provider (compact-difficulty compare, MTP).
 *
 * TX_CONFIRMED (0x05) additionally gets a REAL-provider suite: in-memory
 * btcheadersdb + real Merkle proofs against a crafted BTC block, through the
 * full P2SH covenant spend (the trustless BTC->BATHRON OTC leg) and the
 * adversarial variants (wrong amount/script/proof/index, not deep enough,
 * insufficient confirmations, fake-node 64-byte tx, trailing bytes).
 */

#include "test/test_bathron.h"

#include "btcheaders/btcheadersdb.h"
#include "btcheaders/btcstate_provider.h"
#include "btcspv/btcspv.h"
#include "burnclaim/burnclaim.h"   // ParseBtcTransaction / BtcParsedTx (regression test)
#include "chainparamsbase.h"
#include "hash.h"
#include "key.h"
#include "script/btcstate.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "script/template_hash.h"
#include "primitives/transaction.h"

#include <boost/test/unit_test.hpp>

namespace {

// ── Mock provider: a tiny fake BTC world ────────────────────────────────
// Buried region: heights <= 1000. Difficulty at 500 = nBits 0x1a123456.
// MTP at 500 = 1700000000. (The mock enforces its own burial rule so tests
// exercise the not-deep-enough path too.)
const uint32_t MOCK_FLOOR = 1000;
const uint32_t MOCK_NBITS_AT_500 = 0x1a123456;
const int64_t MOCK_MTP_AT_500 = 1700000000;

// TX_CONFIRMED canned world: the mock accepts exactly ONE query, so the
// marshalling test proves every field crosses the seam unchanged.
const std::vector<unsigned char> MOCK_TARGET = {0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
const int64_t MOCK_AMOUNT = 150000;
const uint32_t MOCK_DEPTH = 6;
const uint32_t MOCK_TXHEIGHT = 700;
const uint32_t MOCK_TXINDEX = 1;
const std::vector<unsigned char> MOCK_PROOF(32, 0xab);
const std::vector<unsigned char> MOCK_RAWTX(100, 0x77);

bool MockProvider(const BtcStateQuery& q)
{
    switch (q.qtype) {
    case BTCSTATE_HEIGHT_GTE:
        return q.btcHeight <= MOCK_FLOOR;
    case BTCSTATE_DIFF_GTE:
        if (q.btcHeight != 500) return false;
        return CompactDifficultyGte(MOCK_NBITS_AT_500, q.nBitsOperand);
    case BTCSTATE_DIFF_LT:
        if (q.btcHeight != 500) return false;
        return !CompactDifficultyGte(MOCK_NBITS_AT_500, q.nBitsOperand);
    case BTCSTATE_MTP_GTE:
        if (q.btcHeight != 500) return false;
        return MOCK_MTP_AT_500 >= q.timeOperand;
    case BTCSTATE_TX_CONFIRMED:
        return q.targetScript == MOCK_TARGET && q.amountOperand == MOCK_AMOUNT &&
               q.minDepth == MOCK_DEPTH && q.btcHeight == MOCK_TXHEIGHT &&
               q.txIndex == MOCK_TXINDEX && q.merkleProof == MOCK_PROOF &&
               q.rawBtcTx == MOCK_RAWTX;
    }
    return false;
}

std::vector<unsigned char> Bits(uint32_t nBits)
{
    return {(unsigned char)(nBits & 0xff), (unsigned char)((nBits >> 8) & 0xff),
            (unsigned char)((nBits >> 16) & 0xff),
            (unsigned char)((nBits >> 24) & 0xff)};
}

// TX_CONFIRMED min-amount operand: exactly 8 raw bytes, LE.
std::vector<unsigned char> Amount8(int64_t v)
{
    std::vector<unsigned char> r(8);
    for (int k = 0; k < 8; ++k) r[k] = (unsigned char)((uint64_t)v >> (8 * k));
    return r;
}

// Bare (non-P2SH) TX_CONFIRMED script: witness items then committed items,
// so the stack ends, top-first: qtype target amount depth height index proof rawtx.
CScript TxConfirmedScript(const std::vector<unsigned char>& rawtx,
                          const std::vector<unsigned char>& proof,
                          int64_t txindex, int64_t height, int64_t depth,
                          const std::vector<unsigned char>& amount8,
                          const std::vector<unsigned char>& target)
{
    CScript s;
    s << rawtx << proof << CScriptNum(txindex) << CScriptNum(height)
      << CScriptNum(depth) << amount8 << target
      << CScriptNum(BTCSTATE_TX_CONFIRMED) << OP_BTCSTATEVERIFY
      << OP_2DROP << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE;
    return s;
}

bool Run(const CScript& script, ScriptError* err,
         unsigned int flags = SCRIPT_VERIFY_BTCSTATE)
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

struct BtcStateFixture : public BasicTestingSetup {
    BtcStateFixture() { SetBtcStateProvider(&MockProvider); }
    ~BtcStateFixture() { SetBtcStateProvider(nullptr); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(btcstate_script_tests, BtcStateFixture)

// ── Gating ───────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(flag_off_is_nop)
{
    // Without the flag, OP_BTCSTATEVERIFY is NOP5: garbage args don't matter.
    CScript s;
    s << OP_9 << OP_BTCSTATEVERIFY << OP_DROP << OP_TRUE;
    ScriptError err;
    BOOST_CHECK(Run(s, &err, /*flags=*/0));
}

BOOST_AUTO_TEST_CASE(no_provider_fails_closed)
{
    SetBtcStateProvider(nullptr);
    CScript s;
    s << CScriptNum(500) << CScriptNum(BTCSTATE_HEIGHT_GTE)
      << OP_BTCSTATEVERIFY << OP_2DROP << OP_TRUE;
    ScriptError err;
    BOOST_CHECK(!Run(s, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);
    SetBtcStateProvider(&MockProvider);
}

// ── HEIGHT_GTE ───────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(height_gte)
{
    ScriptError err;
    CScript ok;
    ok << CScriptNum(1000) << CScriptNum(BTCSTATE_HEIGHT_GTE)
       << OP_BTCSTATEVERIFY << OP_2DROP << OP_TRUE;
    BOOST_CHECK_MESSAGE(Run(ok, &err), ScriptErrorString(err));

    CScript notYet;
    notYet << CScriptNum(1001) << CScriptNum(BTCSTATE_HEIGHT_GTE)
           << OP_BTCSTATEVERIFY << OP_2DROP << OP_TRUE;
    BOOST_CHECK(!Run(notYet, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);
}

// ── DIFF_GTE / DIFF_LT ───────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(diff_queries)
{
    ScriptError err;
    // header at 500 has nBits 0x1a123456; an EASIER operand target (higher
    // exponent) means difficulty(500) >= difficulty(operand) -> GTE true.
    CScript gte;
    gte << Bits(0x1c00ffff) << CScriptNum(500) << CScriptNum(BTCSTATE_DIFF_GTE)
        << OP_BTCSTATEVERIFY << OP_2DROP << OP_DROP << OP_TRUE;
    BOOST_CHECK_MESSAGE(Run(gte, &err), ScriptErrorString(err));

    // HARDER operand (lower target): GTE false, LT true.
    CScript gteFail;
    gteFail << Bits(0x18000001) << CScriptNum(500)
            << CScriptNum(BTCSTATE_DIFF_GTE)
            << OP_BTCSTATEVERIFY << OP_2DROP << OP_DROP << OP_TRUE;
    BOOST_CHECK(!Run(gteFail, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);

    CScript lt;
    lt << Bits(0x18000001) << CScriptNum(500) << CScriptNum(BTCSTATE_DIFF_LT)
       << OP_BTCSTATEVERIFY << OP_2DROP << OP_DROP << OP_TRUE;
    BOOST_CHECK_MESSAGE(Run(lt, &err), ScriptErrorString(err));

    // Malformed operand: 3 bytes instead of 4 -> BTCSTATE_INVALID
    CScript bad;
    bad << std::vector<unsigned char>{0x01, 0x02, 0x03} << CScriptNum(500)
        << CScriptNum(BTCSTATE_DIFF_GTE)
        << OP_BTCSTATEVERIFY << OP_2DROP << OP_DROP << OP_TRUE;
    BOOST_CHECK(!Run(bad, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);
}

// ── MTP_GTE ──────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(mtp_gte)
{
    ScriptError err;
    CScript ok;
    ok << CScriptNum(MOCK_MTP_AT_500) << CScriptNum(500)
       << CScriptNum(BTCSTATE_MTP_GTE)
       << OP_BTCSTATEVERIFY << OP_2DROP << OP_DROP << OP_TRUE;
    BOOST_CHECK_MESSAGE(Run(ok, &err), ScriptErrorString(err));

    CScript notYet;
    notYet << CScriptNum(MOCK_MTP_AT_500 + 1) << CScriptNum(500)
           << CScriptNum(BTCSTATE_MTP_GTE)
           << OP_BTCSTATEVERIFY << OP_2DROP << OP_DROP << OP_TRUE;
    BOOST_CHECK(!Run(notYet, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);
}

// ── Shape errors ─────────────────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(shape_errors)
{
    ScriptError err;
    // Unknown query type 6 (5 is TX_CONFIRMED now)
    CScript badType;
    badType << CScriptNum(500) << CScriptNum(6)
            << OP_BTCSTATEVERIFY << OP_2DROP << OP_TRUE;
    BOOST_CHECK(!Run(badType, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // Missing args entirely
    CScript empty;
    empty << OP_BTCSTATEVERIFY << OP_TRUE;
    BOOST_CHECK(!Run(empty, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

    // Negative height
    CScript neg;
    neg << CScriptNum(-1) << CScriptNum(BTCSTATE_HEIGHT_GTE)
        << OP_BTCSTATEVERIFY << OP_2DROP << OP_TRUE;
    BOOST_CHECK(!Run(neg, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);
}

// ── TX_CONFIRMED: field marshalling through the seam (mock provider) ─────

BOOST_AUTO_TEST_CASE(tx_confirmed_field_marshalling)
{
    ScriptError err;
    // The mock accepts exactly one query: a pass proves every field reached
    // the provider unchanged.
    BOOST_CHECK_MESSAGE(
        Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                              MOCK_TXHEIGHT, MOCK_DEPTH, Amount8(MOCK_AMOUNT),
                              MOCK_TARGET), &err),
        ScriptErrorString(err));

    // Each field off by one -> the provider sees a different query -> UNSATISFIED.
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT + 1), MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);

    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT + 1, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT), MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);

    std::vector<unsigned char> otherTarget = MOCK_TARGET;
    otherTarget[2] ^= 0x01;
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT), otherTarget), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);

    std::vector<unsigned char> otherProof = MOCK_PROOF;
    otherProof[0] ^= 0x01;
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, otherProof, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT), MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);
}

// ── TX_CONFIRMED: shape errors (all deterministic, provider never reached) ─

BOOST_AUTO_TEST_CASE(tx_confirmed_shape_errors)
{
    ScriptError err;

    // 7 stack items instead of 8
    {
        CScript s;
        s << MOCK_PROOF << CScriptNum(MOCK_TXINDEX) << CScriptNum(MOCK_TXHEIGHT)
          << CScriptNum(MOCK_DEPTH) << Amount8(MOCK_AMOUNT) << MOCK_TARGET
          << CScriptNum(BTCSTATE_TX_CONFIRMED) << OP_BTCSTATEVERIFY << OP_TRUE;
        BOOST_CHECK(!Run(s, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // Amount not 8 bytes
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH,
                                       std::vector<unsigned char>(7, 0x01),
                                       MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // Amount zero
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH, Amount8(0),
                                       MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // Amount negative (high bit set)
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH, Amount8(-1),
                                       MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // Depth zero
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, 0, Amount8(MOCK_AMOUNT),
                                       MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // Empty target script
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, MOCK_PROOF, MOCK_TXINDEX,
                                       MOCK_TXHEIGHT, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT),
                                       std::vector<unsigned char>{}), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // Proof not a multiple of 32 bytes
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX,
                                       std::vector<unsigned char>(33, 0xab),
                                       MOCK_TXINDEX, MOCK_TXHEIGHT, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT), MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // txIndex not addressable by the proof depth (empty proof -> only index 0)
    BOOST_CHECK(!Run(TxConfirmedScript(MOCK_RAWTX, std::vector<unsigned char>{},
                                       1, MOCK_TXHEIGHT, MOCK_DEPTH,
                                       Amount8(MOCK_AMOUNT), MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);

    // 64-byte raw tx (Merkle inner-node ambiguity) and empty raw tx
    BOOST_CHECK(!Run(TxConfirmedScript(std::vector<unsigned char>(64, 0x77),
                                       MOCK_PROOF, MOCK_TXINDEX, MOCK_TXHEIGHT,
                                       MOCK_DEPTH, Amount8(MOCK_AMOUNT),
                                       MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);
    BOOST_CHECK(!Run(TxConfirmedScript(std::vector<unsigned char>{},
                                       MOCK_PROOF, MOCK_TXINDEX, MOCK_TXHEIGHT,
                                       MOCK_DEPTH, Amount8(MOCK_AMOUNT),
                                       MOCK_TARGET), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_INVALID);
}

// ── The flagship composition: hedge settlement branch ────────────────────
// "If difficulty at BTC height 500 reached D, this coffer pays the miner's
//  split (forced by CTV), executable by anyone holding the branch key."

BOOST_AUTO_TEST_CASE(hedge_branch_btcstate_ctv_checksig)
{
    CKey branchKey;
    branchKey.MakeNewKey(true);
    const CAmount amount = 1000000;

    CMutableTransaction settle;
    settle.nVersion = 3;
    settle.nType = 0;
    settle.vin.resize(1);
    settle.vin[0].prevout = COutPoint(uint256S("f00d"), 0);
    settle.vin[0].nSequence = 0xFFFFFFFE;
    settle.vout.emplace_back(700000, CScript() << OP_TRUE);   // miner
    settle.vout.emplace_back(299000, CScript() << OP_2);      // sans-pioche
    uint256 commit = ComputeTemplateHash(CTransaction(settle));

    CScript redeem;
    redeem << Bits(0x1c00ffff) << CScriptNum(500)
           << CScriptNum(BTCSTATE_DIFF_GTE) << OP_BTCSTATEVERIFY
           << OP_2DROP << OP_DROP
           << ToByteVector(commit) << OP_TEMPLATEVERIFY << OP_DROP
           << ToByteVector(branchKey.GetPubKey()) << OP_CHECKSIG;

    uint256 sighash = SignatureHash(redeem, settle, 0, SIGHASH_ALL, amount,
                                    SIGVERSION_SAPLING);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(branchKey.Sign(sighash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);

    CScript scriptSig;
    scriptSig << sig << std::vector<unsigned char>(redeem.begin(), redeem.end());
    CScript scriptPubKey = GetScriptForDestination(CScriptID(redeem));

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_BTCSTATE |
                               SCRIPT_VERIFY_TEMPLATEVERIFY |
                               SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S |
                               SCRIPT_VERIFY_CLEANSTACK;
    ScriptError err;
    MutableTransactionSignatureChecker checker(&settle, 0, amount);
    BOOST_CHECK_MESSAGE(
        VerifyScript(scriptSig, scriptPubKey, flags, checker,
                     SIGVERSION_SAPLING, &err),
        "hedge branch failed: " << ScriptErrorString(err));

    // Same branch with a WRONG split (template mismatch) must die even
    // though the difficulty condition holds and the signature is valid.
    CMutableTransaction cheat = settle;
    cheat.vout[0].nValue = 900000;
    cheat.vout[1].nValue = 99000;
    uint256 cheatHash = SignatureHash(redeem, cheat, 0, SIGHASH_ALL, amount,
                                      SIGVERSION_SAPLING);
    std::vector<unsigned char> cheatSig;
    BOOST_REQUIRE(branchKey.Sign(cheatHash, cheatSig));
    cheatSig.push_back((unsigned char)SIGHASH_ALL);
    CScript cheatScriptSig;
    cheatScriptSig << cheatSig
                   << std::vector<unsigned char>(redeem.begin(), redeem.end());
    MutableTransactionSignatureChecker cheatChecker(&cheat, 0, amount);
    BOOST_CHECK(!VerifyScript(cheatScriptSig, scriptPubKey, flags, cheatChecker,
                              SIGVERSION_SAPLING, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TEMPLATE_MISMATCH);
}

// ── Pure helpers of the real provider ────────────────────────────────────

BOOST_AUTO_TEST_CASE(compact_difficulty_compare)
{
    // Lower target (harder) >= higher target (easier)
    BOOST_CHECK(CompactDifficultyGte(0x19000001, 0x1b000001));
    BOOST_CHECK(!CompactDifficultyGte(0x1b000001, 0x19000001));
    // Equal
    BOOST_CHECK(CompactDifficultyGte(0x1a123456, 0x1a123456));
    // Invalid compacts fail closed both ways
    BOOST_CHECK(!CompactDifficultyGte(0, 0x1a123456));
    BOOST_CHECK(!CompactDifficultyGte(0x1a123456, 0));
}

BOOST_AUTO_TEST_CASE(median_time_past)
{
    // Bitcoin-style: median of the last up-to-11 values
    BOOST_CHECK_EQUAL(MedianTimePast({5}), 5);
    BOOST_CHECK_EQUAL(MedianTimePast({1, 2, 3}), 2);
    // Unsorted input (timestamps aren't monotone on BTC)
    BOOST_CHECK_EQUAL(MedianTimePast({3, 1, 2}), 2);
    // More than 11: only the last 11 count
    std::vector<int64_t> t;
    for (int i = 0; i < 20; i++) t.push_back(i);  // last 11 = 9..19, median 14
    BOOST_CHECK_EQUAL(MedianTimePast(t), 14);
    BOOST_CHECK_EQUAL(MedianTimePast({}), 0);
}

BOOST_AUTO_TEST_SUITE_END()

// ═════════════════════════════════════════════════════════════════════════
// TX_CONFIRMED against the REAL provider: in-memory btcheadersdb, real
// Merkle proofs over a crafted BTC block, real strict-Bitcoin tx parsing.
// This is the trustless BTC->BATHRON leg, unit-tested end to end.
// ═════════════════════════════════════════════════════════════════════════

namespace {

void PushLE32(std::vector<unsigned char>& v, uint32_t x)
{
    for (int k = 0; k < 4; ++k) v.push_back((unsigned char)(x >> (8 * k)));
}
void PushLE64(std::vector<unsigned char>& v, uint64_t x)
{
    for (int k = 0; k < 8; ++k) v.push_back((unsigned char)(x >> (8 * k)));
}

// Minimal strict-serialized (non-segwit) BTC tx: 1 input, N outputs.
std::vector<unsigned char> MakeBtcTx(
    const std::vector<std::pair<int64_t, std::vector<unsigned char>>>& outs,
    unsigned char prevoutByte = 0x51)
{
    std::vector<unsigned char> tx;
    PushLE32(tx, 2);                                       // version
    tx.push_back(1);                                       // vin count
    for (int i = 0; i < 32; ++i) tx.push_back(prevoutByte); // prevout txid
    PushLE32(tx, 0);                                       // prevout n
    tx.push_back(0);                                       // empty scriptSig
    PushLE32(tx, 0xfffffffe);                              // sequence
    tx.push_back((unsigned char)outs.size());              // vout count
    for (const auto& o : outs) {
        PushLE64(tx, (uint64_t)o.first);
        tx.push_back((unsigned char)o.second.size());
        tx.insert(tx.end(), o.second.begin(), o.second.end());
    }
    PushLE32(tx, 0);                                       // locktime
    return tx;
}

uint256 TxidOf(const std::vector<unsigned char>& raw)
{
    return Hash(raw.begin(), raw.end());
}

const uint32_t PAY_H = 1300;  // BTC height carrying the payment
const uint32_t TIP_H = 1500;  // snapshot tip -> reorg floor at 1356

// A fake P2WPKH-shaped target scriptPubKey.
const std::vector<unsigned char> TARGET = {0x00, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                                           9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
const std::vector<unsigned char> CHANGE = {0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                           7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
const int64_t PAID = 150000;

void InsertHeaderAt(uint32_t height, const uint256& merkleRoot)
{
    BtcBlockHeader hdr;
    hdr.nVersion = 4;
    hdr.hashPrevBlock = ArithToUint256(arith_uint256(height));
    hdr.hashMerkleRoot = merkleRoot;
    hdr.nTime = 1700000000 + height;
    hdr.nBits = 0x1d00ffff;
    hdr.nNonce = height;
    auto batch = g_btcheadersdb->CreateBatch();
    batch.WriteHeader(height, hdr);
    batch.WriteTip(TIP_H, ArithToUint256(arith_uint256(999999)));
    BOOST_REQUIRE(batch.Commit());
    BtcStateCaptureSnapshot();
}

BtcStateQuery TxConfirmedQuery(const std::vector<unsigned char>& raw,
                               const std::vector<unsigned char>& proofBytes,
                               uint32_t idx, uint32_t height, uint32_t depth,
                               int64_t amount,
                               const std::vector<unsigned char>& target)
{
    BtcStateQuery q;
    q.qtype = BTCSTATE_TX_CONFIRMED;
    q.rawBtcTx = raw;
    q.merkleProof = proofBytes;
    q.txIndex = idx;
    q.btcHeight = height;
    q.minDepth = depth;
    q.amountOperand = amount;
    q.targetScript = target;
    return q;
}

struct TxConfirmedRealSetup : public BasicTestingSetup {
    std::vector<unsigned char> payTx;    // pays PAID to TARGET (+ change)
    std::vector<unsigned char> proof;    // 1-level branch: the sibling txid
    uint256 root;                        // merkle root of the 2-tx block

    TxConfirmedRealSetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
        InstallBtcStateProvider();

        payTx = MakeBtcTx({{PAID, TARGET}, {999, CHANGE}});
        const std::vector<unsigned char> sibTx = MakeBtcTx({{50000, CHANGE}}, 0x52);
        const uint256 payTxid = TxidOf(payTx);
        const uint256 sibTxid = TxidOf(sibTx);
        proof.assign(sibTxid.begin(), sibTxid.end());
        // payment at index 0 (left leaf)
        root = Hash(payTxid.begin(), payTxid.end(), sibTxid.begin(), sibTxid.end());
        InsertHeaderAt(PAY_H, root);
    }
    ~TxConfirmedRealSetup()
    {
        SetBtcStateProvider(nullptr);
        g_btcheadersdb.reset();
        g_btc_spv.reset();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(btcstate_txconfirmed_real_tests, TxConfirmedRealSetup)

// The flagship: a P2SH covenant "spendable once a BTC tx paying >= 150000 sat
// to TARGET is buried >= 6 confirmations", spent with a REAL proof through the
// full interpreter + provider + btcheadersdb stack.
BOOST_AUTO_TEST_CASE(otc_leg_full_p2sh_spend)
{
    CKey key;
    key.MakeNewKey(true);
    const CAmount amount = 1000000;

    CScript redeem;
    redeem << CScriptNum(6) << Amount8(PAID) << TARGET
           << CScriptNum(BTCSTATE_TX_CONFIRMED) << OP_BTCSTATEVERIFY
           << OP_2DROP << OP_2DROP << OP_2DROP << OP_2DROP
           << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    CMutableTransaction settle;
    settle.nVersion = 3;
    settle.vin.resize(1);
    settle.vin[0].prevout = COutPoint(uint256S("f00d"), 0);
    settle.vin[0].nSequence = 0xFFFFFFFE;
    settle.vout.emplace_back(999000, CScript() << OP_TRUE);

    uint256 sighash = SignatureHash(redeem, settle, 0, SIGHASH_ALL, amount,
                                    SIGVERSION_SAPLING);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back((unsigned char)SIGHASH_ALL);

    CScript scriptSig;
    scriptSig << sig << payTx << proof << CScriptNum(0) << CScriptNum(PAY_H)
              << std::vector<unsigned char>(redeem.begin(), redeem.end());
    CScript scriptPubKey = GetScriptForDestination(CScriptID(redeem));

    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_BTCSTATE |
                               SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S |
                               SCRIPT_VERIFY_CLEANSTACK;
    ScriptError err;
    MutableTransactionSignatureChecker checker(&settle, 0, amount);
    BOOST_CHECK_MESSAGE(
        VerifyScript(scriptSig, scriptPubKey, flags, checker,
                     SIGVERSION_SAPLING, &err),
        "OTC leg failed: " << ScriptErrorString(err));

    // Same spend with a corrupted proof byte dies in the provider even though
    // the signature is valid.
    std::vector<unsigned char> badProof = proof;
    badProof[0] ^= 0x01;
    CScript badScriptSig;
    badScriptSig << sig << payTx << badProof << CScriptNum(0) << CScriptNum(PAY_H)
                 << std::vector<unsigned char>(redeem.begin(), redeem.end());
    BOOST_CHECK(!VerifyScript(badScriptSig, scriptPubKey, flags, checker,
                              SIGVERSION_SAPLING, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BTCSTATE_UNSATISFIED);
}

// Provider semantics, adversarial: every trust boundary, straight through
// BtcStateEvaluate (what the interpreter calls).
BOOST_AUTO_TEST_CASE(provider_adversarial)
{
    // Baseline holds.
    BOOST_CHECK(BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H, 6, PAID, TARGET)));

    // Paying less than demanded.
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H, 6, PAID + 1, TARGET)));

    // Wrong target script (the change output's 999 sats don't count).
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H, 6, 1000, CHANGE)));
    // ...but what IS paid to CHANGE is provable.
    BOOST_CHECK(BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H, 6, 999, CHANGE)));

    // Corrupted proof / wrong index -> Merkle mismatch.
    std::vector<unsigned char> badProof = proof;
    badProof[5] ^= 0x01;
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, badProof, 0, PAY_H, 6, PAID, TARGET)));
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 1, PAY_H, 6, PAID, TARGET)));

    // Wrong height: no header there.
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H + 1, 6, PAID, TARGET)));

    // Above the reorg floor: same proof anchored at 1400 (floor = 1356) is
    // NOT yet readable — CLTV-style not-yet-valid.
    InsertHeaderAt(1400, root);
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, 1400, 6, PAID, TARGET)));

    // Confirmation boundary vs the snapshot tip: 1500 - 1300 + 1 = 201.
    BOOST_CHECK(BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H, 201, PAID, TARGET)));
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(payTx, proof, 0, PAY_H, 202, PAID, TARGET)));

    // Trailing byte after locktime: strict parse rejects.
    std::vector<unsigned char> padded = payTx;
    padded.push_back(0x00);
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(padded, proof, 0, PAY_H, 6, PAID, TARGET)));

    // 64-byte blob (inner-node ambiguity) refused by the proof check too
    // (the interpreter already rejects it as malformed).
    BOOST_CHECK(!BtcTxConfirmedProofCheck(
        TxConfirmedQuery(std::vector<unsigned char>(64, 0x77), proof, 0,
                         PAY_H, 6, PAID, TARGET), root));
}

// Sum semantics across outputs + the single-tx-block edge (empty proof:
// the txid IS the merkle root, index must be 0).
BOOST_AUTO_TEST_CASE(sum_and_single_tx_block)
{
    const std::vector<unsigned char> twoOuts =
        MakeBtcTx({{100000, TARGET}, {60000, TARGET}}, 0x53);
    const uint32_t H2 = 1310;
    InsertHeaderAt(H2, TxidOf(twoOuts));

    const std::vector<unsigned char> emptyProof;
    // 100000 + 60000 = 160000 >= 150000 (sum over ALL outputs paying TARGET)
    BOOST_CHECK(BtcStateEvaluate(
        TxConfirmedQuery(twoOuts, emptyProof, 0, H2, 6, 150000, TARGET)));
    BOOST_CHECK(BtcStateEvaluate(
        TxConfirmedQuery(twoOuts, emptyProof, 0, H2, 6, 160000, TARGET)));
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(twoOuts, emptyProof, 0, H2, 6, 160001, TARGET)));
    // Empty proof addresses only index 0.
    BOOST_CHECK(!BtcStateEvaluate(
        TxConfirmedQuery(twoOuts, emptyProof, 1, H2, 6, 150000, TARGET)));
}

// Regression (pre-freeze review): the 64-byte anti-fake-inclusion guard must
// test the txid PREIMAGE (non-witness serialization), not the raw witness
// bytes. A SegWit tx can have a 64-byte non-witness form while its raw size is
// larger, slipping past a `rawBtcTx.size()==64` check. Here: 1-in/1-out SegWit
// tx, 4-byte scriptPubKey -> non-witness = 64 bytes, raw = 69 bytes.
BOOST_AUTO_TEST_CASE(segwit_64byte_preimage_rejected)
{
    std::vector<unsigned char> raw = {
        0x02,0x00,0x00,0x00,              // version
        0x00,0x01,                        // segwit marker+flag
        0x01,                             // vin count
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,  // prevout hash (32)
        0x00,0x00,0x00,0x00,              // prevout n
        0x00,                             // scriptSig len 0
        0xfe,0xff,0xff,0xff,              // sequence
        0x01,                             // vout count
        0xa0,0x86,0x01,0x00,0x00,0x00,0x00,0x00,  // value 100000
        0x04, 0x51,0x52,0x53,0x54,        // 4-byte scriptPubKey
        0x01, 0x01, 0x00,                 // witness: 1 item, len 1, data 0x00
        0x00,0x00,0x00,0x00,              // locktime
    };
    BOOST_CHECK_EQUAL(raw.size(), 69u);   // raw != 64 -> would pass a naive guard

    // Sanity: the reconstructed non-witness serialization is exactly 64 bytes.
    BtcParsedTx parsed;
    BOOST_REQUIRE(ParseBtcTransaction(raw, parsed));
    BOOST_CHECK_EQUAL(parsed.nonWitnessSerialization.size(), 64u);

    // The proof check must reject it (guard on the non-witness length), before
    // any Merkle work — regardless of the root passed.
    BtcStateQuery q = TxConfirmedQuery(raw, std::vector<unsigned char>{}, 0,
                                       PAY_H, 6, 1, parsed.vout[0].scriptPubKey);
    BOOST_CHECK(!BtcTxConfirmedProofCheck(q, root));
}

BOOST_AUTO_TEST_SUITE_END()
