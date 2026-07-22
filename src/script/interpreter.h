// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin developers
// Copyright (c) 2018-2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_SCRIPT_INTERPRETER_H
#define BATHRON_SCRIPT_INTERPRETER_H

#include "primitives/transaction.h"
#include "script_error.h"
#include "uint256.h"

#include <vector>
#include <stdint.h>
#include <string>

/** Special case nIn for signing Sapling txs. */
const unsigned int NOT_AN_INPUT = UINT_MAX;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // Treat as UNKNOWN before 5.6 activation

    // Verify OP_TEMPLATEVERIFY (CTV-lite covenant)
    // Constrain spending TX outputs to match a template commitment
    SCRIPT_VERIFY_TEMPLATEVERIFY = (1U << 11),

    // Verify OP_BTCSTATEVERIFY (A1 — BTC header facts in script)
    // Treat as NOP5 before UPGRADE_BTCSTATE activation
    SCRIPT_VERIFY_BTCSTATE = (1U << 12),

    // Verify OP_CHECKSIGFROMSTACK (verify a signature over an arbitrary
    // message from the stack — oracles/delegation). NOP6 before activation.
    SCRIPT_VERIFY_CHECKSIGFROMSTACK = (1U << 13),

    // Verify OP_CHECKSEQUENCEVERIFY (BIP112 relative lock-time, on the BIP68
    // sequence-lock plumbing). Treat as NOP3 before UPGRADE_CSV activation.
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 14),

    // Re-enable OP_CAT (BIP347 semantics: pop 2, push concat, result capped
    // at MAX_SCRIPT_ELEMENT_SIZE). Without the flag OP_CAT stays a disabled
    // opcode (fails even in unexecuted branches, as since 2010).
    SCRIPT_VERIFY_OPCAT = (1U << 15),

    // Verify OP_CHECKOUTPUTVALUE (A / Tier-2 amount introspection, verify
    // form): assert vout[index].nValue >= min_amount. NOP7 before activation.
    SCRIPT_VERIFY_CHECKOUTPUTVALUE = (1U << 16),

    // Verify OP_CHECKOUTPUTSCRIPT (CCV/MATT — recursive covenants, verify
    // form): assert vout[index].scriptPubKey == expected. NOP8 before
    // activation. Recursion is COMPOSED with OP_CAT + OP_HASH160 (no new op).
    SCRIPT_VERIFY_CHECKOUTPUTSCRIPT = (1U << 17),
};

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror);

struct PrecomputedTransactionData
{
    uint256 hashPrevouts, hashSequence, hashOutputs, hashShieldedSpends, hashShieldedOutputs;

    explicit PrecomputedTransactionData(const CTransaction& tx);
};

uint256 SignatureHash(const CScript &scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache = nullptr);

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
         return false;
    }

    virtual bool CheckSequence(const CScriptNum& nSequence) const
    {
         return false;
    }

    // A (amount introspection, verify form): does the spending tx's output at
    // `index` pay at least `minAmount` satoshis? Pure function of the spending
    // transaction (deterministic). False if the index is out of range.
    virtual bool CheckOutputValue(uint32_t index, int64_t minAmount) const
    {
         return false;
    }

    // CCV/MATT (script introspection, verify form): does the spending tx's
    // output at `index` have EXACTLY the scriptPubKey `expectedSpk`? Byte-exact,
    // pure function of the spending tx (deterministic). False if out of range.
    // Recursion is built by composing this with OP_CAT/OP_HASH160 in-script.
    virtual bool CheckOutputScript(uint32_t index, const std::vector<unsigned char>& expectedSpk) const
    {
         return false;
    }

    virtual bool CheckTemplateVerify(const std::vector<unsigned char>& commitment) const
    {
        return false;
    }

    // CSFS: verify vchSig over SHA256(vchMsg) under vchPubKey (ECDSA). Pure —
    // no tx context — but kept on the checker for interface consistency.
    virtual bool CheckSigFromStack(const std::vector<unsigned char>& vchSig,
                                   const std::vector<unsigned char>& vchMsg,
                                   const std::vector<unsigned char>& vchPubKey) const
    {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const CTransaction* txTo;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData* precomTxData;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), precomTxData(nullptr) {}
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& cachedHashesIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), precomTxData(&cachedHashesIn) {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override ;
    bool CheckLockTime(const CScriptNum& nLockTime) const override;
    bool CheckSequence(const CScriptNum& nSequence) const override;
    bool CheckOutputValue(uint32_t index, int64_t minAmount) const override;
    bool CheckOutputScript(uint32_t index, const std::vector<unsigned char>& expectedSpk) const override;
    bool CheckTemplateVerify(const std::vector<unsigned char>& commitment) const override;
    bool CheckSigFromStack(const std::vector<unsigned char>& vchSig,
                           const std::vector<unsigned char>& vchMsg,
                           const std::vector<unsigned char>& vchPubKey) const override;
};

class MutableTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    const CTransaction txTo;

public:
    MutableTransactionSignatureChecker(const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amount) : TransactionSignatureChecker(&txTo, nInIn, amount), txTo(*txToIn) {}
};

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* error = nullptr);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror = nullptr);

#endif // BATHRON_SCRIPT_INTERPRETER_H
