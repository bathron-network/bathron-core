// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_PRIMITIVES_TRANSACTION_H
#define BATHRON_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "memusage.h"
#include "net/netaddress.h"
#include "optional.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

#include "sapling/sapling_transaction.h"

#include <atomic>
#include <list>

class CTransaction;

enum SigVersion
{
    SIGVERSION_BASE = 0,
    SIGVERSION_SAPLING = 1,
};

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class BaseOutPoint
{
public:
    uint256 hash;
    uint32_t n;
    bool isTransparent{true};

    BaseOutPoint() { SetNull(); }
    BaseOutPoint(const uint256& hashIn, const uint32_t nIn, bool isTransparentIn = true) :
        hash(hashIn), n(nIn), isTransparent(isTransparentIn) { }

    SERIALIZE_METHODS(BaseOutPoint, obj) { READWRITE(obj.hash, obj.n); }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    std::string ToStringShort() const;

    size_t DynamicMemoryUsage() const { return 0; }

};

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint : public BaseOutPoint
{
public:
    COutPoint() : BaseOutPoint() {};
    COutPoint(const uint256& hashIn, const uint32_t nIn) : BaseOutPoint(hashIn, nIn, true) {};
    std::string ToString() const;
};

/** An outpoint - a combination of a transaction hash and an index n into its sapling
 * output description (vShieldedOutput) */
class SaplingOutPoint : public BaseOutPoint
{
public:
    SaplingOutPoint() : BaseOutPoint() {};
    SaplingOutPoint(const uint256& hashIn, const uint32_t nIn) : BaseOutPoint(hashIn, nIn, false) {};
    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68 (relative lock-times).
     * If this flag is set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1U << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1U << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average (BTC; BATHRON uses the
     * same encoding for parity), the minimum granularity for
     * time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn() { nSequence = SEQUENCE_FINAL; }
    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    SERIALIZE_METHODS(CTxIn, obj) { READWRITE(obj.prevout, obj.scriptSig, obj.nSequence); }

    bool IsFinal() const { return nSequence == SEQUENCE_FINAL; }
    bool IsNull() const { return prevout.IsNull() && scriptSig.empty() && IsFinal(); }


    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

    size_t DynamicMemoryUsage() const { return scriptSig.DynamicMemoryUsage(); }
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;
    int nRounds;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    SERIALIZE_METHODS(CTxOut, obj) { READWRITE(obj.nValue, obj.scriptPubKey); }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
        nRounds = -10; // an initial value, should be no way to get this by calculations
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    void SetEmpty()
    {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool IsEmpty() const
    {
        return (nValue == 0 && scriptPubKey.empty());
    }

    uint256 GetHash() const;

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey &&
                a.nRounds      == b.nRounds);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

    size_t DynamicMemoryUsage() const { return scriptPubKey.DynamicMemoryUsage(); }
};

struct CMutableTransaction;

/**
 * Transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 * - Optional<SaplingTxData> sapData
 * - Optional<std::vector<uint8_t>> extraPayload
 */
template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType& tx, Stream& s) {
    tx.vin.clear();
    tx.vout.clear();

    s >> tx.nVersion;
    s >> tx.nType;
    s >> tx.vin;
    s >> tx.vout;
    s >> tx.nLockTime;
    if (tx.isSaplingVersion()) {
        s >> tx.sapData;
        if (!tx.IsNormalType()) {
            s >> tx.extraPayload;
        }
    }
}

template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType& tx, Stream& s) {
    s << tx.nVersion;
    s << tx.nType;
    s << tx.vin;
    s << tx.vout;
    s << tx.nLockTime;
    if (tx.isSaplingVersion()) {
        s << tx.sapData;
        if (!tx.IsNormalType()) {
            s << tx.extraPayload;
        }
    }
}

/** The basic transaction that is broadcasted on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    /** Transaction Versions */
    enum TxVersion: int16_t {
        LEGACY      = 1,
        SAPLING     = 3,
        TOOHIGH
    };

    /** Transaction types */
    // HU Transaction Types (BP30 Lock-Based Settlement)
    enum TxType: int16_t {
        NORMAL = 0,
        PROREG = 1,          // DMN ProReg
        PROUPSERV = 2,       // DMN ProUpServ
        PROUPREG = 3,        // DMN ProUpReg
        PROUPREV = 4,        // DMN ProUpRev
        // BP30 Lock-Based Settlement (M0/M1 model)
        TX_LOCK = 20,         // M0 → Vault + M1 Receipt
        TX_UNLOCK = 21,       // Vault + Receipt → M0
        TX_TRANSFER_M1 = 22,  // M1 Receipt → new owner
        // BP10 BTC Burn Claims
        TX_BURN_CLAIM = 31,   // Claim M0BTC from BTC burn proof
        // BP11 M0BTC Minting
        TX_MINT_M0BTC = 32,   // Create spendable M0BTC UTXOs (finalization)
        // BP-SPVMNPUB: On-chain BTC header publication
        TX_BTC_HEADERS = 33,  // BTC SPV headers published by MNs
        // BP02 HTLC Settlement (M1 atomic swaps)
        HTLC_CREATE_M1 = 40,  // M1 Receipt -> HTLC P2SH
        HTLC_CLAIM = 41,      // HTLC P2SH + preimage -> M1 Receipt
        HTLC_REFUND = 42,     // HTLC P2SH (expired) -> M1 Receipt
        // BP02-3S: 3-secret HTLC for FlowSwap protocol
        HTLC_CREATE_3S = 43,  // M1 Receipt -> HTLC3S P2SH (3 secrets)
        HTLC_CLAIM_3S = 44,   // HTLC3S P2SH + 3 preimages -> M1 Receipt
        HTLC_REFUND_3S = 45,  // HTLC3S P2SH (expired) -> M1 Receipt
    };

    static const int16_t CURRENT_VERSION = TxVersion::LEGACY;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    const int16_t nVersion;
    const int16_t nType;
    const uint32_t nLockTime;
    Optional<SaplingTxData> sapData{SaplingTxData()}; // Future: Don't initialize it by default
    Optional<std::vector<uint8_t>> extraPayload{nullopt};     // only available for special transaction types

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    CTransaction(const CTransaction& tx) = default;

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
      *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        return hash;
    }

    bool hasSaplingData() const
    {
        return sapData != nullopt &&
            (!sapData->vShieldedOutput.empty() ||
            !sapData->vShieldedSpend.empty() ||
            sapData->valueBalance != 0 ||
            sapData->hasBindingSig());
    };

    bool isSaplingVersion() const
    {
        return nVersion >= TxVersion::SAPLING;
    }

    bool IsShieldedTx() const
    {
        return isSaplingVersion() && hasSaplingData();
    }

    bool hasExtraPayload() const
    {
        return extraPayload != nullopt && !extraPayload->empty();
    }

    bool IsSpecialTx() const
    {
        return isSaplingVersion() && nType != TxType::NORMAL && hasExtraPayload();
    }

    bool IsNormalType() const { return nType == TxType::NORMAL; }

    bool IsProRegTx() const
    {
        return IsSpecialTx() && nType == TxType::PROREG;
    }

    // SF2: settlement / HTLC tx types whose outputs (vault / M1 receipt / HTLC)
    // are gated by the COMMITTED settlement DB when later spent, so on a reorg
    // that resurrects one of them the mempool spenders of its outputs must be
    // evicted (see CTxMemPool::removeSettlementReferences).
    //
    // Discriminate on nType ALONE — do NOT gate on IsSpecialTx(), which requires
    // hasExtraPayload(): TX_LOCK / TX_UNLOCK / TX_TRANSFER_M1 carry no extra
    // payload (their state lives in the vin/vout structure), so IsSpecialTx()
    // returns false for them and would silently disable SF2 for exactly the
    // types that need it. nType is the authoritative discriminator.
    bool CreatesSettlementOutputs() const
    {
        switch (nType) {
            case TxType::TX_LOCK:
            case TxType::TX_UNLOCK:
            case TxType::TX_TRANSFER_M1:
            case TxType::HTLC_CREATE_M1:
            case TxType::HTLC_CLAIM:
            case TxType::HTLC_REFUND:
            case TxType::HTLC_CREATE_3S:
            case TxType::HTLC_CLAIM_3S:
            case TxType::HTLC_REFUND_3S:
                return true;
            default:
                return false;
        }
    }

    // Ensure that special and sapling fields are signed
    SigVersion GetRequiredSigVersion() const
    {
        return isSaplingVersion() ? SIGVERSION_SAPLING : SIGVERSION_BASE;
    }

    /*
     * Context for the two methods below:
     * We can think of the Sapling shielded part of the transaction as an input
     * or output according to whether valueBalance - the sum of shielded input
     * values minus the sum of shielded output values - is positive or negative.
     */

    // Return sum of txouts.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Return sum of (positive valueBalance or zero) and JoinSplit vpub_new
    CAmount GetShieldedValueIn() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }


    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    unsigned int GetTotalSize() const;

    std::string ToString() const;

    size_t DynamicMemoryUsage() const;

private:
    /** Memory only. */
    const uint256 hash;
    uint256 ComputeHash() const;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    int16_t nVersion;
    int16_t nType;
    uint32_t nLockTime;
    Optional<SaplingTxData> sapData{SaplingTxData()}; // Future: Don't initialize it by default
    Optional<std::vector<uint8_t>> extraPayload{nullopt};

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    bool isSaplingVersion() const { return nVersion >= CTransaction::TxVersion::SAPLING; }
    bool IsNormalType() const { return nType == CTransaction::TxType::NORMAL; }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    bool hasExtraPayload() const
    {
        return extraPayload != nullopt && !extraPayload->empty();
    }

    // Ensure that special and sapling fields are signed
    SigVersion GetRequiredSigVersion() const
    {
        return isSaplingVersion() ? SIGVERSION_SAPLING : SIGVERSION_BASE;
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
static inline CTransactionRef MakeTransactionRef() { return std::make_shared<const CTransaction>(); }
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }
static inline CTransactionRef MakeTransactionRef(const CTransactionRef& txIn) { return txIn; }
static inline CTransactionRef MakeTransactionRef(CTransactionRef&& txIn) { return std::move(txIn); }

/* Special tx payload handling */
template <typename T>
inline bool GetTxPayload(const std::vector<unsigned char>& payload, T& obj)
{
    CDataStream ds(payload, SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    try {
        ds >> obj;
    } catch (std::exception& e) {
        return false;
    }
    return ds.empty();
}
template <typename T>
inline bool GetTxPayload(const CMutableTransaction& tx, T& obj)
{
    return tx.hasExtraPayload() && GetTxPayload(*tx.extraPayload, obj);
}
template <typename T>
inline bool GetTxPayload(const CTransaction& tx, T& obj)
{
    return tx.hasExtraPayload() && GetTxPayload(*tx.extraPayload, obj);
}

template <typename T>
void SetTxPayload(CMutableTransaction& tx, const T& payload)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    ds << payload;
    tx.extraPayload.emplace(ds.begin(), ds.end());
}

#endif // BATHRON_PRIMITIVES_TRANSACTION_H
