// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "consensus/upgrades.h"
#include "script/btcstate.h"
#include "script/template_hash.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "pubkey.h"
#include "script/script.h"


typedef std::vector<unsigned char> valtype;

namespace {

inline bool set_success(ScriptError* ret)
{
    if (ret)
        *ret = SCRIPT_ERR_OK;
    return true;
}

inline bool set_error(ScriptError* ret, const ScriptError serror)
{
    if (ret)
        *ret = serror;
    return false;
}

} // anon namespace

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(std::vector<valtype>& stack)
{
    if (stack.empty())
        throw std::runtime_error("popstack() : stack empty");
    stack.pop_back();
}

bool static IsCompressedOrUncompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() < CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != CPubKey::PUBLIC_KEY_SIZE) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
          //  Non-canonical public key: neither compressed nor uncompressed
          return false;
    }
    return true;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool static IsValidSignatureEncoding(const std::vector<unsigned char> &sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

bool static IsLowDERSignature(const valtype &vchSig, ScriptError* serror) {
    if (!IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    // https://bitcoin.stackexchange.com/a/12556:
    //     Also note that inside transaction signatures, an extra hashtype byte
    //     follows the actual signature data.
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    // If the S value is above the order of the curve divided by two, its
    // complement modulo the order could have been used instead, which is
    // one byte shorter when encoded correctly.
    if (!CPubKey::CheckLowS(vchSigCopy))
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);

    return true;
}

bool static IsDefinedHashtypeSignature(const valtype &vchSig) {
    if (vchSig.size() == 0) {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror) {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0) {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    } else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
        // serror is set
        return false;
    } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool static CheckPubKeyEncoding(const valtype &vchSig, unsigned int flags, ScriptError* serror) {
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchSig)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    return true;
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode) {
    if (data.size() == 0) {
        // Could have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Could have used OP_1 .. OP_16.
        return opcode == OP_1 + (data[0] - 1);
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Could have used OP_1NEGATE.
        return opcode == OP_1NEGATE;
    } else if (data.size() <= 75) {
        // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Could have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Could have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const valtype vchFalse(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    std::vector<bool> vfExec;
    std::vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if (script.size() > MAX_SCRIPT_SIZE)
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;

    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > 201)
                return set_error(serror, SCRIPT_ERR_OP_COUNT);

            // OP_CAT is re-enabled by UPGRADE_OPCAT (gate carried by the
            // flag): when off it keeps the historical disabled-opcode rule —
            // fails the script even inside an unexecuted branch.
            if ((opcode == OP_CAT && !(flags & SCRIPT_VERIFY_OPCAT)) ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes.

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // CLTV is gated by UPGRADE_BIP65 (NetworkUpgradeActive);
                    // when inactive the opcode is treated as a NOP above.

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    // Compare the specified sequence number with the input.
                    if (!checker.CheckSequence(nSequence))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_CHECKOUTPUTVALUE:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKOUTPUTVALUE)) {
                        // Not enabled; treat as NOP7.
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    // A (amount introspection, verify form). Stack, top first:
                    //   <output_index> <min_amount 8-byte LE>
                    // (i.e. the script pushes the amount, then the index.)
                    // Verify vout[index].nValue >= min_amount. Nothing popped
                    // (the script DROPs after), fail-closed.
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const CScriptNum idxNum(stacktop(-1), fRequireMinimal, 5);
                    if (idxNum < 0 || idxNum > 0x7FFFFFFFLL)
                        return set_error(serror, SCRIPT_ERR_OUTPUTVALUE_INVALID);

                    // Min amount: exactly 8 raw bytes LE (satoshi range exceeds
                    // CScriptNum's 5-byte window). Negative (high bit set) is
                    // malformed — "pays >= negative" would be meaningless.
                    const valtype& vchAmt = stacktop(-2);
                    if (vchAmt.size() != 8)
                        return set_error(serror, SCRIPT_ERR_OUTPUTVALUE_INVALID);
                    int64_t minAmount = 0;
                    for (size_t k = 0; k < 8; ++k)
                        minAmount |= (int64_t)((uint64_t)vchAmt[k] << (8 * k));
                    if (minAmount < 0)
                        return set_error(serror, SCRIPT_ERR_OUTPUTVALUE_INVALID);

                    if (!checker.CheckOutputValue((uint32_t)idxNum.getint(), minAmount))
                        return set_error(serror, SCRIPT_ERR_OUTPUTVALUE_UNSATISFIED);

                    break;
                }

                case OP_CHECKOUTPUTSCRIPT:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKOUTPUTSCRIPT)) {
                        // Not enabled; treat as NOP8.
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    // CCV/MATT (script introspection, verify form). Stack, top first:
                    //   <output_index> <expected_scriptPubKey>
                    // (i.e. the script pushes the expected spk, then the index.)
                    // Verify vout[index].scriptPubKey == expected. Nothing popped
                    // (the script DROPs after), fail-closed. Recursion is built by
                    // composing this with OP_CAT + OP_HASH160 in-script (the next
                    // covenant's P2SH scriptPubKey is computed at spend time).
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const CScriptNum idxNum(stacktop(-1), fRequireMinimal, 5);
                    if (idxNum < 0 || idxNum > 0x7FFFFFFFLL)
                        return set_error(serror, SCRIPT_ERR_OUTPUTSCRIPT_INVALID);

                    // The demanded scriptPubKey. Empty is malformed: "pay to an
                    // empty script" is never a legitimate covenant target and
                    // would silently match a degenerate output. Bounded for free
                    // by the element cap (came off the stack).
                    const valtype& vchSpk = stacktop(-2);
                    if (vchSpk.empty())
                        return set_error(serror, SCRIPT_ERR_OUTPUTSCRIPT_INVALID);

                    if (!checker.CheckOutputScript((uint32_t)idxNum.getint(), vchSpk))
                        return set_error(serror, SCRIPT_ERR_OUTPUTSCRIPT_UNSATISFIED);

                    break;
                }

                case OP_PUSHCURRENTSCRIPT:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKOUTPUTSCRIPT)) {
                        // Not enabled; treat as NOP9. Same gate as
                        // OP_CHECKOUTPUTSCRIPT: the Recursive Covenant Pair
                        // activates as one unit (UPGRADE_OUTPUTSCRIPT).
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    // Recursive Covenant Pair, self-reference half: push the
                    // serialized bytes of the currently-executing script (for
                    // a P2SH spend, the redeemScript — the exact byte string
                    // whose HASH160 the spent scriptPubKey committed to; P2SH
                    // has already authenticated it). This is what lets a
                    // covenant know its own identity: the spender supplies a
                    // claimed decomposition of the script, the script checks
                    // it against this push (CAT + EQUALVERIFY), rebuilds the
                    // successor with new state, and OP_CHECKOUTPUTSCRIPT pins
                    // the output to it. Without this opcode the spender could
                    // substitute an arbitrary body and escape the covenant.
                    // Pushes the WHOLE script, unaffected by OP_CODESEPARATOR.
                    // Fail closed if the script exceeds the element cap
                    // (impossible for P2SH redeemScripts, which arrive via a
                    // <=520-byte push; guards bare-script contexts).
                    if (script.size() > MAX_SCRIPT_ELEMENT_SIZE)
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                    stack.push_back(valtype(script.begin(), script.end()));
                    break;
                }

                case OP_TEMPLATEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_TEMPLATEVERIFY)) {
                        // Not enabled; treat as NOP4
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Pop 32-byte commitment from stack
                    const valtype& vchCommitment = stacktop(-1);
                    if (vchCommitment.size() != 32)
                        return set_error(serror, SCRIPT_ERR_TEMPLATE_INVALID);

                    // Verify commitment against spending transaction
                    if (!checker.CheckTemplateVerify(vchCommitment))
                        return set_error(serror, SCRIPT_ERR_TEMPLATE_MISMATCH);

                    break;
                }

                case OP_BTCSTATEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_BTCSTATE)) {
                        // Not enabled; treat as NOP5
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    // Stack (top first): <qtype> <btc_height> [<operand>]
                    // TX_CONFIRMED has its own, deeper shape (see below).
                    // Verify semantics: nothing is popped (script DROPs after).
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const CScriptNum qtypeNum(stacktop(-1), fRequireMinimal, 1);
                    if (qtypeNum < BTCSTATE_DIFF_GTE || qtypeNum > BTCSTATE_TX_CONFIRMED)
                        return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);
                    const uint8_t qtype = (uint8_t)qtypeNum.getint();

                    BtcStateQuery q;
                    q.qtype = qtype;

                    if (qtype == BTCSTATE_TX_CONFIRMED) {
                        // Stack (top first):
                        //   <qtype=0x05> <target_spk> <min_amount8> <min_depth>   (committed by the covenant script)
                        //   <btc_height> <tx_index> <merkle_proof> <raw_btc_tx>   (supplied by the spender's scriptSig)
                        // "A BTC tx paying >= min_amount sats to target_spk is
                        // included at btc_height (Merkle proof) with >= min_depth
                        // confirmations, under the reorg floor."
                        if (stack.size() < 8)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchTarget = stacktop(-2);
                        if (vchTarget.empty())
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        // Min amount: exactly 8 raw bytes, LE (satoshi range
                        // exceeds CScriptNum's 5-byte window). High bit set
                        // (negative) or zero is malformed — "pays >= 0" would
                        // be trivially true.
                        const valtype& vchAmount = stacktop(-3);
                        if (vchAmount.size() != 8)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);
                        int64_t amount = 0;
                        for (size_t k = 0; k < 8; ++k)
                            amount |= (int64_t)((uint64_t)vchAmount[k] << (8 * k));
                        if (amount < 1)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        const CScriptNum depthNum(stacktop(-4), fRequireMinimal, 5);
                        if (depthNum < 1 || depthNum > 0x7FFFFFFFLL)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        const CScriptNum heightNum(stacktop(-5), fRequireMinimal, 5);
                        if (heightNum < 0 || heightNum > 0x7FFFFFFFLL)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        const CScriptNum idxNum(stacktop(-6), fRequireMinimal, 5);
                        if (idxNum < 0 || idxNum > 0x7FFFFFFFLL)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        // Merkle proof: concatenated 32-byte hashes, leaf -> root.
                        // Empty = single-tx block (txid IS the root). The element
                        // size cap (520) already bounds depth at 16; check anyway.
                        const valtype& vchProof = stacktop(-7);
                        if (vchProof.size() % 32 != 0 ||
                            vchProof.size() / 32 > BTCSTATE_MAX_MERKLE_DEPTH)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        // The tx index must be addressable by the proof depth
                        // (rejects padded proofs / out-of-range positions).
                        if ((uint64_t)idxNum.getint() >= (1ULL << (vchProof.size() / 32)))
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        // Raw BTC tx. A 64-byte Merkle leaf is byte-ambiguous
                        // with an inner node (CVE-2017-12842). This is a cheap
                        // EARLY reject of the trivial non-SegWit case; the
                        // AUTHORITATIVE guard is provider-side, on the txid
                        // preimage (the non-witness serialization that enters
                        // the Merkle tree), because a SegWit tx's raw size can
                        // differ from its 64-byte preimage — see
                        // BtcTxConfirmedProofCheck in btcstate_provider.cpp.
                        const valtype& vchTx = stacktop(-8);
                        if (vchTx.empty() || vchTx.size() == 64)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                        q.targetScript = vchTarget;
                        q.amountOperand = amount;
                        q.minDepth = (uint32_t)depthNum.getint();
                        q.btcHeight = (uint32_t)heightNum.getint();
                        q.txIndex = (uint32_t)idxNum.getint();
                        q.merkleProof = vchProof;
                        q.rawBtcTx = vchTx;

                        if (!EvalBtcStateQuery(q))
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_UNSATISFIED);

                        break;
                    }

                    const CScriptNum heightNum(stacktop(-2), fRequireMinimal, 5);
                    if (heightNum < 0 || heightNum > 0x7FFFFFFFLL)
                        return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);

                    q.btcHeight = (uint32_t)heightNum.getint();

                    if (qtype == BTCSTATE_DIFF_GTE || qtype == BTCSTATE_DIFF_LT) {
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        // Compact nBits operand: exactly 4 raw bytes, LE
                        const valtype& vchBits = stacktop(-3);
                        if (vchBits.size() != 4)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);
                        q.nBitsOperand = (uint32_t)vchBits[0] |
                                         ((uint32_t)vchBits[1] << 8) |
                                         ((uint32_t)vchBits[2] << 16) |
                                         ((uint32_t)vchBits[3] << 24);
                    } else if (qtype == BTCSTATE_MTP_GTE) {
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        const CScriptNum timeNum(stacktop(-3), fRequireMinimal, 5);
                        if (timeNum < 0)
                            return set_error(serror, SCRIPT_ERR_BTCSTATE_INVALID);
                        // Reconstruct the (non-negative, <=5-byte minimal) value
                        // without CScriptNum::getint()'s int32 clamp (2038-safe).
                        int64_t t = 0;
                        const valtype& vchT = stacktop(-3);
                        for (size_t k = 0; k < vchT.size(); ++k)
                            t |= (int64_t)vchT[k] << (8 * k);
                        q.timeOperand = t;
                    }
                    // BTCSTATE_HEIGHT_GTE: no operand

                    // Fail closed: unknown fact / not deep enough / condition
                    // false all land here (CLTV-style not-yet-valid).
                    if (!EvalBtcStateQuery(q))
                        return set_error(serror, SCRIPT_ERR_BTCSTATE_UNSATISFIED);

                    break;
                }

                case OP_CHECKSIGFROMSTACK:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSIGFROMSTACK)) {
                        // Not enabled; treat as NOP6
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        break;
                    }
                    // (sig msg pubkey -- bool)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vchSig    = stacktop(-3);
                    valtype& vchMsg    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);
                    bool fOk = checker.CheckSigFromStack(vchSig, vchMsg, vchPubKey);
                    popstack(stack); popstack(stack); popstack(stack);
                    stack.push_back(fOk ? vchTrue : vchFalse);
                    break;
                }

                case OP_NOP1:
                case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.back() = !vfExec.back();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_CAT:
                {
                    // Re-enabled under UPGRADE_OPCAT (BIP347 semantics):
                    // (x1 x2 -- x1||x2), result bounded by the element size
                    // cap. Only reachable with SCRIPT_VERIFY_OPCAT — without
                    // it the disabled-opcode filter above already failed.
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    const valtype& vch2 = stacktop(-1);
                    if (vch1.size() + vch2.size() > MAX_SCRIPT_ELEMENT_SIZE)
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                    vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                    popstack(stack);
                }
                break;


                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH160)
                        CHash160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH256)
                        CHash256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature, since there's no way for a signature to sign itself
                    scriptCode.FindAndDelete(CScript(vchSig));

                    if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                        //serror is set
                        return false;
                    }
                    bool fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    nOpCount += nKeysCount;
                    if (nOpCount > 201)
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    int ikey = ++i;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signatures, since there's no way for a signature to sign itself
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig-k);
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }

                    bool fSuccess = true;
                    while (fSuccess && nSigsCount > 0)
                    {
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);

                        // Note how this makes the exact order of pubkey/signature evaluation
                        // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        // See the script_(in)valid tests for details.
                        if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, serror)) {
                            // serror is set
                            return false;
                        }

                        // Check signature
                        bool fOk = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }

                    // Clean up stack of actual arguments
                    while (i-- > 1)
                        popstack(stack);

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                        return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                    popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                    }
                }
                break;

                default:
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }

            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    const CTransaction &txTo;  //! reference to the spending transaction (the one being serialized)
    const CScript &scriptCode; //! output script being consumed
    const unsigned int nIn;    //! input index of txTo being signed
    const bool fAnyoneCanPay;  //! whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //! whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //! whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout);
        assert(nInput != NOT_AN_INPUT);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScript());
        else
            SerializeScriptCode(s);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
            ::Serialize(s, txTo.vout[nOutput]);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion);
        // Serialize nType
        ::Serialize(s, txTo.nType);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
             SerializeInput(s, nInput);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
             SerializeOutput(s, nOutput);
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime);
    }
};

const unsigned char BATHRON_PREVOUTS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'P','I','V','X','P','r','e','v','o','u','t','H','a','s','h'};
const unsigned char BATHRON_SEQUENCE_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'P','I','V','X','S','e','q','u','e','n','c','H','a','s','h'};
const unsigned char BATHRON_OUTPUTS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'P','I','V','X','O','u','t','p','u','t','s','H','a','s','h'};
const unsigned char BATHRON_SHIELDED_SPENDS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'P','I','V','X','S','S','p','e','n','d','s','H','a','s','h'};
const unsigned char BATHRON_SHIELDED_OUTPUTS_HASH_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
        {'P','I','V','X','S','O','u','t','p','u','t','H','a','s','h'};



uint256 GetPrevoutHash(const CTransaction& txTo) {
    CBLAKE2bWriter ss(SER_GETHASH, 0, BATHRON_PREVOUTS_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction& txTo) {
    CBLAKE2bWriter ss(SER_GETHASH, 0, BATHRON_SEQUENCE_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction& txTo) {
    CBLAKE2bWriter ss(SER_GETHASH, 0, BATHRON_OUTPUTS_HASH_PERSONALIZATION);
    for (unsigned int n = 0; n < txTo.vout.size(); n++) {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}

uint256 GetShieldedSpendsHash(const CTransaction& txTo) {
    assert(txTo.sapData);
    CBLAKE2bWriter ss(SER_GETHASH, 0, BATHRON_SHIELDED_SPENDS_HASH_PERSONALIZATION);
    auto sapData = txTo.sapData;
    for (const auto& n : sapData->vShieldedSpend) {
        ss << n.cv;
        ss << n.anchor;
        ss << n.nullifier;
        ss << n.rk;
        ss << n.zkproof;
    }
    return ss.GetHash();
}

uint256 GetShieldedOutputsHash(const CTransaction& txTo) {
    assert(txTo.sapData);
    CBLAKE2bWriter ss(SER_GETHASH, 0, BATHRON_SHIELDED_OUTPUTS_HASH_PERSONALIZATION);
    auto sapData = txTo.sapData;
    for (const auto& n : sapData->vShieldedOutput) {
        ss << n;
    }
    return ss.GetHash();
}

} // anon namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo)
{
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
    if (txTo.sapData) {
        hashShieldedSpends = GetShieldedSpendsHash(txTo);
        hashShieldedOutputs = GetShieldedOutputsHash(txTo);
    }
}

uint256 SignatureHash(const CScript& scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache)
{
    if (nIn >= txTo.vin.size() && nIn != NOT_AN_INPUT) {
        //  nIn out of range
        return UINT256_ONE;
    }

    if (txTo.isSaplingVersion() && sigversion != SIGVERSION_SAPLING) {
        throw std::runtime_error("SignatureHash in Sapling tx with wrong sigversion " + std::to_string(sigversion));
    }

    if (sigversion == SIGVERSION_SAPLING) {

        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;
        uint256 hashShieldedSpends;
        uint256 hashShieldedOutputs;
        bool hasSapData = false;

        if (!(nHashType & SIGHASH_ANYONECANPAY)) {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        }

        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size()) {
            CBLAKE2bWriter ss(SER_GETHASH, 0, BATHRON_OUTPUTS_HASH_PERSONALIZATION);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        if (txTo.sapData) {
            if (!txTo.sapData->vShieldedSpend.empty()) {
                hashShieldedSpends = cache ? cache->hashShieldedSpends : GetShieldedSpendsHash(txTo);
                hasSapData = true;
            }

            if (!txTo.sapData->vShieldedOutput.empty()) {
                hashShieldedOutputs = cache ? cache->hashShieldedOutputs : GetShieldedOutputsHash(txTo);
                hasSapData = true;
            }
        }

        // todo: complete branch id with the active network upgrade
        uint32_t leConsensusBranchId = htole32(0);
        unsigned char personalization[16] = {};
        memcpy(personalization, "BATHRONSigHash", 12);
        memcpy(personalization+12, &leConsensusBranchId, 4);

        CBLAKE2bWriter ss(SER_GETHASH, 0, personalization);
        // Version
        ss << txTo.nVersion;
        // Type
        ss << txTo.nType;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;

        if (hasSapData) {
            // Spend descriptions
            ss << hashShieldedSpends;
            // Output descriptions
            ss << hashShieldedOutputs;
            // Sapling value balance
            ss << txTo.sapData->valueBalance;
        }

        if (nIn != NOT_AN_INPUT) {
            // The input being signed (replacing the scriptSig with scriptCode + amount)
            // The prevout may already be contained in hashPrevout, and the nSequence
            // may already be contained in hashSequence.
            ss << txTo.vin[nIn].prevout;
            ss << scriptCode;
            ss << amount;
            ss << txTo.vin[nIn].nSequence;
        }

        // Extra payload for special transactions
        if (txTo.IsSpecialTx()) {
            ss << *(txTo.extraPayload);
        }

        // Locktime
        ss << txTo.nLockTime;
        // Sighash type
        ss << nHashType;

        return ss.GetHash();
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            //  nOut out of range
            return UINT256_ONE;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

bool TransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

bool TransactionSignatureChecker::CheckSig(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Hash type is one byte tacked on to the end of the signature
    std::vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    int nHashType = vchSig.back();
    vchSig.pop_back();

    const uint256& sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, this->precomTxData);

    if (!VerifySignature(vchSig, pubkey, sighash))
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two times of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!(
        (txTo->nLockTime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
        (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
    ))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (txTo->vin[nIn].IsFinal())
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum& nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t)txTo->vin[nIn].nSequence;

    // Fail if the transaction's version number is not set high
    // enough to trigger BIP 68 rules.
    if (txTo->nVersion < 2)
        return false;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number does not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!(
        (txToSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
    ))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckOutputValue(uint32_t index, int64_t minAmount) const
{
    // A (amount introspection, verify form): does the spending tx's output at
    // `index` pay at least `minAmount` satoshis? Pure function of the spending
    // transaction — deterministic, no external state, DoS-trivial. Fail closed
    // when the index is out of range.
    if (index >= txTo->vout.size())
        return false;
    return txTo->vout[index].nValue >= minAmount;
}

bool TransactionSignatureChecker::CheckOutputScript(uint32_t index, const std::vector<unsigned char>& expectedSpk) const
{
    // CCV/MATT (script introspection, verify form): does the spending tx's
    // output at `index` have EXACTLY the scriptPubKey `expectedSpk`? Byte-exact
    // equality — CScript is a raw byte vector, so no re-serialization / parsing
    // / canonicalization. Pure function of the spending tx (deterministic), one
    // bounded memcmp (DoS-trivial), read-only. Fail closed on out-of-range.
    if (index >= txTo->vout.size())
        return false;
    const CScript& spk = txTo->vout[index].scriptPubKey;
    return spk.size() == expectedSpk.size() &&
           std::equal(spk.begin(), spk.end(), expectedSpk.begin());
}

bool TransactionSignatureChecker::CheckTemplateVerify(
    const std::vector<unsigned char>& commitment) const
{
    if (commitment.size() != 32)
        return false;

    if (txTo->vout.size() > CTV_MAX_OUTPUTS)
        return false;

    // Compute template hash of the spending transaction
    uint256 computed = ComputeTemplateHash(*txTo);

    return computed == uint256(commitment);
}

bool TransactionSignatureChecker::CheckSigFromStack(
    const std::vector<unsigned char>& vchSig,
    const std::vector<unsigned char>& vchMsg,
    const std::vector<unsigned char>& vchPubKey) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;
    // Message is hashed once with SHA256 (no tx sighash, no hashtype byte —
    // this is a signature over arbitrary data, e.g. an oracle attestation).
    uint256 hash;
    CSHA256().Write(vchMsg.data(), vchMsg.size()).Finalize(hash.begin());
    return pubkey.Verify(hash, vchSig);
}

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, sigversion, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, sigversion, serror))
        // serror is set
        return false;
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());

        const valtype& pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);

        if (!EvalScript(stack, pubKey2, flags, checker, sigversion, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain).
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (stack.size() != 1) {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    return set_success(serror);
}
