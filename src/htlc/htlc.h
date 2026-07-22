// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_HTLC_H
#define BATHRON_HTLC_H

/**
 * HTLC Settlement Layer - Hash Time Locked Contracts for M1
 *
 * Ref: doc/blueprints/todo/02-HTLC-M1.md, 02b-HTLC-IMPL.md
 *
 * HTLC enables atomic swaps between M1 and external assets (BTC, USDC, etc.)
 * by locking M1 in a P2SH script with hash and time conditions.
 *
 * Bearer Asset Model Adaptation:
 * - M1 in HTLC is "M1 in a special state" - still counts toward M1_supply
 * - Communal vault pool backs all M1, including HTLC'd M1
 * - No vault locking needed - A6 maintained throughout lifecycle
 *
 * Lifecycle:
 * - HTLC_CREATE_M1: M1Receipt -> HTLC P2SH (M1_supply unchanged)
 * - HTLC_CLAIM: HTLC P2SH + preimage -> new M1Receipt (M1_supply unchanged)
 * - HTLC_REFUND: HTLC P2SH (expired) -> M1Receipt back to creator (M1_supply unchanged)
 *
 * DB Keys:
 * 'H' + outpoint -> HTLCRecord
 * 'L' + hashlock -> vector<COutPoint> (for cross-chain matching)
 * 'C' + txid -> HTLCCreateUndoData
 * 'Z' + txid -> HTLCResolveUndoData
 */

#include "amount.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <vector>

// DB Key prefixes
static const char DB_HTLC = 'H';              // HTLC by outpoint
static const char DB_HTLC_HASHLOCK = 'L';     // HTLCs by hashlock (index)
static const char DB_HTLC_CREATE_UNDO = 'C';  // Create undo data (keyed by txid)
static const char DB_HTLC_RESOLVE_UNDO = 'Z'; // Claim/Refund undo data (keyed by txid)
static const char DB_HTLC_BEST_BLOCK = 'B';   // Best block hash for consistency
static const char DB_HTLC_PRUNE_SCHED = 'X';  // Prune schedule: (height, outpoint) -> is3S

// DB Key prefixes for 3-Secret HTLC (FlowSwap)
static const char DB_HTLC3S = '3';                    // HTLC3S by outpoint
static const char DB_HTLC3S_HASHLOCK_USER = 'U';      // Index by H_user
static const char DB_HTLC3S_HASHLOCK_LP1 = 'P';       // Index by H_lp1
static const char DB_HTLC3S_HASHLOCK_LP2 = 'Q';       // Index by H_lp2
static const char DB_HTLC3S_CREATE_UNDO = 'D';        // 3S create undo
static const char DB_HTLC3S_RESOLVE_UNDO = 'R';       // 3S resolve undo

// Constants
static const uint32_t HTLC_DEFAULT_EXPIRY_BLOCKS = 288;  // ~2 days at 1 block/min
static const uint32_t HTLC_MIN_EXPIRY_BLOCKS = 6;        // Minimum 6 blocks (~6 min)
static const uint32_t HTLC_MAX_EXPIRY_BLOCKS = 4320;     // Maximum ~3 days

/**
 * F-HTLC-2 (ADR-HTLC3S-EXPIRY-CONSTRAINT, USER GO 2026-07-21): minimum number
 * of blocks the pivot child (HTLC3) must live from its birth (the parent's
 * claim height) before its refund can open. Enforced at creation (R1:
 * htlc3ExpiryHeight >= expiryHeight + HTLC3S_MIN_LIFETIME) and at the claim
 * that births the child (R2: htlc3ExpiryHeight >= nHeight + HTLC3S_MIN_LIFETIME).
 * This is the STRUCTURAL consensus floor (1 block to see the parent claim +
 * 1 block earliest inclusion of the child claim) — NOT an operational-safety
 * promise; wallets/CP/LP may enforce larger margins as local policy.
 * All comparisons must be evaluated in int64 (heights are uint32).
 */
static const uint32_t HTLC3S_MIN_LIFETIME = 2;
static const size_t HTLC_PREIMAGE_SIZE = 32;             // SHA256 preimage is 32 bytes
static const uint8_t HTLC_CREATE_PAYLOAD_VERSION = 1;    // vExtraPayload version (no covenant)
static const uint8_t HTLC_CREATE_PAYLOAD_VERSION_CTV = 2; // vExtraPayload v2 (with covenant)
static const uint8_t HTLC3S_CREATE_PAYLOAD_VERSION = 1;  // 3S vExtraPayload version (no covenant)
static const uint8_t HTLC3S_CREATE_PAYLOAD_VERSION_CTV = 2; // 3S vExtraPayload v2 (with covenant)
static const CAmount CTV_FIXED_FEE = 200;                // Fixed fee for covenant PivotTx (sats)

// GC of RESOLVED (CLAIMED/REFUNDED) HTLC records. Once an HTLC is resolved its
// P2SH outpoint is a SPENT UTXO — no transaction can ever reference it again (the
// UTXO layer, not htlcdb, is the double-claim guard), so the record is dead weight
// used only by the reorg-undo path. It is therefore safe to erase once the
// resolution is deeper than any possible reorg. HU finality makes blocks
// irreversible within ~1 block, and the reorg-below-finalized guards forbid deeper
// rewrites, so 100 blocks (~100 min) is a large safety margin. Pruning is
// deterministic (every node prunes the same records at the same height) and
// consensus-neutral (it never changes a block-validity decision: a re-claim of a
// pruned outpoint is already rejected at the UTXO layer). This bounds htlcdb to a
// ~PRUNE_DEPTH window of resolved records instead of growing forever.
static const uint32_t HTLC_PRUNE_DEPTH = 100;

/**
 * HTLCCreatePayload - Data in vExtraPayload of HTLC_CREATE_M1 transactions
 *
 * Contains the HTLC parameters that cannot be extracted from the P2SH output.
 * The P2SH only contains the hash of the redeemScript, so we need to store
 * the actual HTLC parameters in the payload for consensus processing.
 */
struct HTLCCreatePayload
{
    uint8_t nVersion{HTLC_CREATE_PAYLOAD_VERSION};
    uint256 hashlock;           // 32 bytes - SHA256(preimage)
    uint32_t expiryHeight;      // 4 bytes - Block height when refund allowed
    CKeyID claimKeyID;          // 20 bytes - Who can claim (with preimage)
    CKeyID refundKeyID;         // 20 bytes - Who can refund (after expiry)

    // v2: Covenant fields (Settlement Pivot)
    uint256 templateCommitment;     // C3 hash (null = no covenant)
    uint32_t htlc3ExpiryHeight{0};  // HTLC3 refund timeout
    CKeyID htlc3ClaimKeyID;         // LP claim key for HTLC3
    CKeyID htlc3RefundKeyID;        // Retail refund key for HTLC3

    HTLCCreatePayload() : nVersion(HTLC_CREATE_PAYLOAD_VERSION), expiryHeight(0) {}

    bool HasCovenant() const { return !templateCommitment.IsNull(); }

    SERIALIZE_METHODS(HTLCCreatePayload, obj)
    {
        READWRITE(obj.nVersion);
        READWRITE(obj.hashlock);
        READWRITE(obj.expiryHeight);
        READWRITE(obj.claimKeyID);
        READWRITE(obj.refundKeyID);
        if (obj.nVersion >= HTLC_CREATE_PAYLOAD_VERSION_CTV) {
            READWRITE(obj.templateCommitment);
            READWRITE(obj.htlc3ExpiryHeight);
            READWRITE(obj.htlc3ClaimKeyID);
            READWRITE(obj.htlc3RefundKeyID);
        }
    }

    bool IsTriviallyValid(std::string& strError) const
    {
        if (nVersion != HTLC_CREATE_PAYLOAD_VERSION &&
            nVersion != HTLC_CREATE_PAYLOAD_VERSION_CTV) {
            strError = "bad-htlc-version";
            return false;
        }
        if (hashlock.IsNull()) {
            strError = "bad-htlc-null-hashlock";
            return false;
        }
        if (expiryHeight == 0) {
            strError = "bad-htlc-zero-expiry";
            return false;
        }
        if (claimKeyID.IsNull()) {
            strError = "bad-htlc-null-claim";
            return false;
        }
        if (refundKeyID.IsNull()) {
            strError = "bad-htlc-null-refund";
            return false;
        }
        // v2 covenant field validation
        if (nVersion >= HTLC_CREATE_PAYLOAD_VERSION_CTV && HasCovenant()) {
            if (htlc3ExpiryHeight == 0) {
                strError = "bad-htlc-covenant-zero-expiry";
                return false;
            }
            if (htlc3ClaimKeyID.IsNull()) {
                strError = "bad-htlc-covenant-null-claim";
                return false;
            }
            if (htlc3RefundKeyID.IsNull()) {
                strError = "bad-htlc-covenant-null-refund";
                return false;
            }
        }
        return true;
    }
};

/**
 * HTLCStatus - State of an HTLC
 */
enum class HTLCStatus : uint8_t {
    ACTIVE = 0,     // M1 locked in HTLC P2SH, awaiting claim or refund
    CLAIMED = 1,    // Preimage revealed, new M1 receipt created for claimer
    REFUNDED = 2    // Expired and refunded, M1 receipt returned to creator
};

/**
 * HTLCRecord - HTLC state record
 *
 * Stored in htlcdb at key 'H' + htlcOutpoint.
 *
 * Bearer Asset Model: No linkedVault field because M1 has no per-receipt
 * vault link. The communal vault pool backs all M1 including HTLC'd M1.
 */
struct HTLCRecord
{
    // === Identifiers ===
    COutPoint htlcOutpoint;      // 36 bytes - The HTLC P2SH output (txid:vout)
    uint256 hashlock;            // 32 bytes - SHA256(preimage)

    // === M1 Info (Bearer Model - NO vault link) ===
    COutPoint sourceReceipt;     // 36 bytes - Original M1 receipt consumed (for undo)
    CAmount amount;              // 8 bytes - M1 amount locked

    // === Script ===
    CScript redeemScript;        // Variable - Full P2SH redeem script

    // === Addresses ===
    CKeyID claimKeyID;           // 20 bytes - Who can claim (with preimage)
    CKeyID refundKeyID;          // 20 bytes - Who can refund (after expiry)

    // === Covenant (Settlement Pivot) ===
    uint256 templateCommitment;  // 32 bytes - C3 (null = no covenant)
    uint32_t htlc3ExpiryHeight{0}; // HTLC3 refund timeout
    CKeyID htlc3ClaimKeyID;      // LP claim key for HTLC3
    CKeyID htlc3RefundKeyID;     // Retail refund key for HTLC3
    CAmount covenantFee{0};      // PivotTx fee (200 sats default)

    // === Timing ===
    uint32_t createHeight;       // 4 bytes - Block when HTLC was created
    uint32_t expiryHeight;       // 4 bytes - Refund available after this height

    // === Resolution ===
    HTLCStatus status;           // 1 byte - Current status
    uint256 resolveTxid;         // 32 bytes - TX that claimed/refunded (if resolved)
    uint256 preimage;            // 32 bytes - Revealed preimage (if claimed)
    COutPoint resultReceipt;     // 36 bytes - New M1 receipt created (claim or refund)

    HTLCRecord() { SetNull(); }

    bool HasCovenant() const { return !templateCommitment.IsNull(); }

    void SetNull()
    {
        htlcOutpoint.SetNull();
        hashlock.SetNull();
        sourceReceipt.SetNull();
        amount = 0;
        redeemScript.clear();
        claimKeyID.SetNull();
        refundKeyID.SetNull();
        templateCommitment.SetNull();
        htlc3ExpiryHeight = 0;
        htlc3ClaimKeyID.SetNull();
        htlc3RefundKeyID.SetNull();
        covenantFee = 0;
        createHeight = 0;
        expiryHeight = 0;
        status = HTLCStatus::ACTIVE;
        resolveTxid.SetNull();
        preimage.SetNull();
        resultReceipt.SetNull();
    }

    bool IsNull() const { return htlcOutpoint.IsNull(); }

    bool IsActive() const { return status == HTLCStatus::ACTIVE; }

    bool IsRefundable(uint32_t currentHeight) const
    {
        return status == HTLCStatus::ACTIVE && currentHeight >= expiryHeight;
    }

    bool IsResolved() const
    {
        return status == HTLCStatus::CLAIMED || status == HTLCStatus::REFUNDED;
    }

    SERIALIZE_METHODS(HTLCRecord, obj)
    {
        READWRITE(obj.htlcOutpoint);
        READWRITE(obj.hashlock);
        READWRITE(obj.sourceReceipt);
        READWRITE(obj.amount);
        READWRITE(obj.redeemScript);
        READWRITE(obj.claimKeyID);
        READWRITE(obj.refundKeyID);
        READWRITE(obj.templateCommitment);
        READWRITE(obj.htlc3ExpiryHeight);
        READWRITE(obj.htlc3ClaimKeyID);
        READWRITE(obj.htlc3RefundKeyID);
        READWRITE(obj.covenantFee);
        READWRITE(obj.createHeight);
        READWRITE(obj.expiryHeight);
        // Serialize enum class as uint8_t
        uint8_t statusByte = static_cast<uint8_t>(obj.status);
        READWRITE(statusByte);
        SER_READ(obj, obj.status = static_cast<HTLCStatus>(statusByte));
        READWRITE(obj.resolveTxid);
        READWRITE(obj.preimage);
        READWRITE(obj.resultReceipt);
    }
};

/**
 * HTLCCreateUndoData - Data required for UndoHTLCCreate (reorg support)
 *
 * Stores the original M1Receipt that was consumed to create the HTLC.
 * On reorg, the HTLC is erased and the original receipt is restored.
 */
struct HTLCCreateUndoData
{
    COutPoint originalReceiptOutpoint;  // Original M1 receipt consumed
    CAmount originalAmount;             // Amount (for verification)
    uint32_t originalCreateHeight;      // Creation height of original receipt

    HTLCCreateUndoData() : originalAmount(0), originalCreateHeight(0) {}

    SERIALIZE_METHODS(HTLCCreateUndoData, obj)
    {
        READWRITE(obj.originalReceiptOutpoint);
        READWRITE(obj.originalAmount);
        READWRITE(obj.originalCreateHeight);
    }
};

/**
 * HTLCResolveUndoData - Data required for UndoHTLCClaim/UndoHTLCRefund
 *
 * Stores the full HTLCRecord before resolution.
 * On reorg, the result receipt is erased and HTLC is restored to ACTIVE.
 */
struct HTLCResolveUndoData
{
    HTLCRecord htlcRecord;              // Full HTLC record before resolution
    COutPoint resultReceiptErased;      // Receipt created by claim/refund (to erase)

    SERIALIZE_METHODS(HTLCResolveUndoData, obj)
    {
        READWRITE(obj.htlcRecord);
        READWRITE(obj.resultReceiptErased);
    }
};

// =============================================================================
// HTLC3S - 3-Secret HTLC for FlowSwap Protocol
// =============================================================================

/**
 * HTLC3SCreatePayload - Data in vExtraPayload of HTLC_CREATE_3S transactions
 *
 * Contains 3 hashlocks for FlowSwap 3-secret protocol.
 * Canonical order: (H_user, H_lp1, H_lp2)
 *
 * Ref: doc/flowswap.md
 */
struct HTLC3SCreatePayload
{
    uint8_t nVersion{HTLC3S_CREATE_PAYLOAD_VERSION};
    uint256 hashlock_user;      // 32 bytes - SHA256(S_user)
    uint256 hashlock_lp1;       // 32 bytes - SHA256(S_lp1)
    uint256 hashlock_lp2;       // 32 bytes - SHA256(S_lp2)
    uint32_t expiryHeight;      // 4 bytes - Block height when refund allowed
    CKeyID claimKeyID;          // 20 bytes - Who can claim (with all 3 preimages)
    CKeyID refundKeyID;         // 20 bytes - Who can refund (after expiry)

    // v2: Covenant fields (Per-Leg Settlement Pivot)
    uint256 templateCommitment;     // C3 hash (null = no covenant)
    CKeyID covenantDestKeyID;       // LP_OUT address forced by covenant

    HTLC3SCreatePayload() : nVersion(HTLC3S_CREATE_PAYLOAD_VERSION), expiryHeight(0) {}

    bool HasCovenant() const { return !templateCommitment.IsNull(); }

    SERIALIZE_METHODS(HTLC3SCreatePayload, obj)
    {
        READWRITE(obj.nVersion);
        READWRITE(obj.hashlock_user);
        READWRITE(obj.hashlock_lp1);
        READWRITE(obj.hashlock_lp2);
        READWRITE(obj.expiryHeight);
        READWRITE(obj.claimKeyID);
        READWRITE(obj.refundKeyID);
        if (obj.nVersion >= HTLC3S_CREATE_PAYLOAD_VERSION_CTV) {
            READWRITE(obj.templateCommitment);
            READWRITE(obj.covenantDestKeyID);
        }
    }

    bool IsTriviallyValid(std::string& strError) const
    {
        if (nVersion != HTLC3S_CREATE_PAYLOAD_VERSION &&
            nVersion != HTLC3S_CREATE_PAYLOAD_VERSION_CTV) {
            strError = "bad-htlc3s-version";
            return false;
        }
        if (hashlock_user.IsNull()) {
            strError = "bad-htlc3s-null-hashlock-user";
            return false;
        }
        if (hashlock_lp1.IsNull()) {
            strError = "bad-htlc3s-null-hashlock-lp1";
            return false;
        }
        if (hashlock_lp2.IsNull()) {
            strError = "bad-htlc3s-null-hashlock-lp2";
            return false;
        }
        if (expiryHeight == 0) {
            strError = "bad-htlc3s-zero-expiry";
            return false;
        }
        if (claimKeyID.IsNull()) {
            strError = "bad-htlc3s-null-claim";
            return false;
        }
        if (refundKeyID.IsNull()) {
            strError = "bad-htlc3s-null-refund";
            return false;
        }
        // v2 covenant validation
        if (nVersion >= HTLC3S_CREATE_PAYLOAD_VERSION_CTV && HasCovenant()) {
            if (covenantDestKeyID.IsNull()) {
                strError = "bad-htlc3s-covenant-null-dest";
                return false;
            }
        }
        return true;
    }
};

/**
 * HTLC3SRecord - 3-Secret HTLC state record
 *
 * Stored in htlcdb at key '3' + htlcOutpoint.
 * Extends HTLCRecord pattern for FlowSwap 3-secret protocol.
 *
 * Bearer Asset Model: No vault link. Communal vault pool backs all M1.
 */
struct HTLC3SRecord
{
    // === Identifiers ===
    COutPoint htlcOutpoint;      // 36 bytes - The HTLC P2SH output (txid:vout)

    // === 3 Hashlocks (canonical order: user, lp1, lp2) ===
    uint256 hashlock_user;       // 32 bytes - SHA256(S_user)
    uint256 hashlock_lp1;        // 32 bytes - SHA256(S_lp1)
    uint256 hashlock_lp2;        // 32 bytes - SHA256(S_lp2)

    // === M1 Info (Bearer Model - NO vault link) ===
    COutPoint sourceReceipt;     // 36 bytes - Original M1 receipt consumed
    CAmount amount;              // 8 bytes - M1 amount locked

    // === Script ===
    CScript redeemScript;        // Variable - Full P2SH redeem script

    // === Addresses ===
    CKeyID claimKeyID;           // 20 bytes - Who can claim (with all 3 preimages)
    CKeyID refundKeyID;          // 20 bytes - Who can refund (after expiry)

    // === Covenant (Per-Leg Settlement Pivot) ===
    uint256 templateCommitment;  // 32 bytes - C3 (null = no covenant)
    CKeyID covenantDestKeyID;    // 20 bytes - LP_OUT address forced by covenant

    // === Timing ===
    uint32_t createHeight;       // 4 bytes - Block when HTLC was created
    uint32_t expiryHeight;       // 4 bytes - Refund available after this height

    // === Resolution ===
    HTLCStatus status;           // 1 byte - Current status
    uint256 resolveTxid;         // 32 bytes - TX that claimed/refunded

    // === 3 Preimages (if claimed) ===
    uint256 preimage_user;       // 32 bytes - Revealed S_user
    uint256 preimage_lp1;        // 32 bytes - Revealed S_lp1
    uint256 preimage_lp2;        // 32 bytes - Revealed S_lp2

    COutPoint resultReceipt;     // 36 bytes - New M1 receipt created

    HTLC3SRecord() { SetNull(); }

    bool HasCovenant() const { return !templateCommitment.IsNull(); }

    void SetNull()
    {
        htlcOutpoint.SetNull();
        hashlock_user.SetNull();
        hashlock_lp1.SetNull();
        hashlock_lp2.SetNull();
        sourceReceipt.SetNull();
        amount = 0;
        redeemScript.clear();
        claimKeyID.SetNull();
        refundKeyID.SetNull();
        templateCommitment.SetNull();
        covenantDestKeyID.SetNull();
        createHeight = 0;
        expiryHeight = 0;
        status = HTLCStatus::ACTIVE;
        resolveTxid.SetNull();
        preimage_user.SetNull();
        preimage_lp1.SetNull();
        preimage_lp2.SetNull();
        resultReceipt.SetNull();
    }

    bool IsNull() const { return htlcOutpoint.IsNull(); }
    bool IsActive() const { return status == HTLCStatus::ACTIVE; }


    bool IsResolved() const
    {
        return status == HTLCStatus::CLAIMED || status == HTLCStatus::REFUNDED;
    }

    SERIALIZE_METHODS(HTLC3SRecord, obj)
    {
        READWRITE(obj.htlcOutpoint);
        READWRITE(obj.hashlock_user);
        READWRITE(obj.hashlock_lp1);
        READWRITE(obj.hashlock_lp2);
        READWRITE(obj.sourceReceipt);
        READWRITE(obj.amount);
        READWRITE(obj.redeemScript);
        READWRITE(obj.claimKeyID);
        READWRITE(obj.refundKeyID);
        READWRITE(obj.templateCommitment);
        READWRITE(obj.covenantDestKeyID);
        READWRITE(obj.createHeight);
        READWRITE(obj.expiryHeight);
        uint8_t statusByte = static_cast<uint8_t>(obj.status);
        READWRITE(statusByte);
        SER_READ(obj, obj.status = static_cast<HTLCStatus>(statusByte));
        READWRITE(obj.resolveTxid);
        READWRITE(obj.preimage_user);
        READWRITE(obj.preimage_lp1);
        READWRITE(obj.preimage_lp2);
        READWRITE(obj.resultReceipt);
    }
};

/**
 * HTLC3SCreateUndoData - Data required for UndoHTLC3SCreate
 */
struct HTLC3SCreateUndoData
{
    COutPoint originalReceiptOutpoint;  // Original M1 receipt consumed
    CAmount originalAmount;             // Amount (for verification)
    uint32_t originalCreateHeight;      // Creation height of original receipt

    HTLC3SCreateUndoData() : originalAmount(0), originalCreateHeight(0) {}

    SERIALIZE_METHODS(HTLC3SCreateUndoData, obj)
    {
        READWRITE(obj.originalReceiptOutpoint);
        READWRITE(obj.originalAmount);
        READWRITE(obj.originalCreateHeight);
    }
};

/**
 * HTLC3SResolveUndoData - Data required for UndoHTLC3SClaim/UndoHTLC3SRefund
 */
struct HTLC3SResolveUndoData
{
    HTLC3SRecord htlcRecord;            // Full HTLC3S record before resolution
    COutPoint resultReceiptErased;      // Receipt created by claim/refund (to erase)

    SERIALIZE_METHODS(HTLC3SResolveUndoData, obj)
    {
        READWRITE(obj.htlcRecord);
        READWRITE(obj.resultReceiptErased);
    }
};

// === Helper Functions (declared here, defined in htlc.cpp) ===

/**
 * ExtractPreimageFromScriptSig - Extract preimage from HTLC claim scriptSig
 *
 * The scriptSig for branch A (claim) has format:
 * <sig> <pubkey> <preimage> OP_TRUE <redeemScript>
 *
 * @param scriptSig The scriptSig to parse
 * @param redeemScript The expected redeemScript (for verification)
 * @param preimage Output: extracted preimage
 * @return true if valid preimage extracted
 */
bool ExtractPreimageFromScriptSig(
    const CScript& scriptSig,
    const CScript& redeemScript,
    std::vector<unsigned char>& preimage
);

/**
 * VerifyPreimage - Verify preimage matches hashlock
 *
 * @param preimage The preimage to verify (must be 32 bytes)
 * @param hashlock The expected SHA256 hash
 * @return true if SHA256(preimage) == hashlock
 */
bool VerifyPreimage(
    const std::vector<unsigned char>& preimage,
    const uint256& hashlock
);

// === 3-Secret HTLC Helper Functions ===

/**
 * ExtractPreimagesFromScriptSig3S - Extract 3 preimages from HTLC3S claim scriptSig
 *
 * The scriptSig for claim path has format:
 * <sig> <pubkey> <S_lp2> <S_lp1> <S_user> OP_TRUE <redeemScript>
 *
 * Returns preimages in canonical order (user, lp1, lp2)
 *
 * @param scriptSig The scriptSig to parse
 * @param redeemScript The expected redeemScript (for verification)
 * @param preimage_user Output: S_user
 * @param preimage_lp1 Output: S_lp1
 * @param preimage_lp2 Output: S_lp2
 * @return true if all 3 preimages extracted successfully
 */
bool ExtractPreimagesFromScriptSig3S(
    const CScript& scriptSig,
    const CScript& redeemScript,
    std::vector<unsigned char>& preimage_user,
    std::vector<unsigned char>& preimage_lp1,
    std::vector<unsigned char>& preimage_lp2
);

/**
 * VerifyPreimages3S - Verify all 3 preimages match their hashlocks
 *
 * @param preimage_user S_user (must be 32 bytes)
 * @param preimage_lp1 S_lp1 (must be 32 bytes)
 * @param preimage_lp2 S_lp2 (must be 32 bytes)
 * @param hashlock_user SHA256(S_user)
 * @param hashlock_lp1 SHA256(S_lp1)
 * @param hashlock_lp2 SHA256(S_lp2)
 * @return true if all 3 match
 */
bool VerifyPreimages3S(
    const std::vector<unsigned char>& preimage_user,
    const std::vector<unsigned char>& preimage_lp1,
    const std::vector<unsigned char>& preimage_lp2,
    const uint256& hashlock_user,
    const uint256& hashlock_lp1,
    const uint256& hashlock_lp2
);

#endif // BATHRON_HTLC_H
