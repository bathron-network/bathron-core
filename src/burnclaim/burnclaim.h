// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BURNCLAIM_H
#define BATHRON_BURNCLAIM_H

#include "hash.h"
#include "pubkey.h"
#include "serialize.h"
#include "uint256.h"

#include <memory>
#include <string>
#include <vector>

/**
 * BP10 - BTC Burn Verification
 *
 * This module handles verification of Bitcoin burn transactions for M0BTC minting.
 *
 * CRITICAL: BTC transactions use STRICT Bitcoin serialization, NOT BATHRON's CTransaction.
 * Do not use CTransaction/CTransactionRef for BTC data - they are incompatible.
 */

// DoS limits (from BP10 spec)
static const size_t MAX_BTC_TX_SIZE_SANITY = 200000;     // 200 KB sanity ceiling
static const size_t MAX_MERKLE_PROOF_LENGTH = 40;        // ~log2(max txs per block)
static const size_t MAX_BTC_TX_VOUT_COUNT = 100;         // Sanity limit
static const size_t MAX_BURN_CLAIMS_PER_BLOCK = 50;      // Hard limit per block

// Confirmation constants (BP10)
static const uint32_t K_CONFIRMATIONS_MAINNET = 24;      // ~4 hours BTC confirmations
// Reverted 100->6 now that R2 ships (commit c940bf4): a btcheaders reorg below a
// finalized burn is rejected outright, so the deep-confirmation belt-and-suspenders
// (temporary mitigation after the 2026-06-24 6-block signet reorg) is no longer the
// real protection — it only slowed testnet burns. R2 is the consensus-level guard.
static const uint32_t K_CONFIRMATIONS_TESTNET = 6;       // ~1h (Signet)

// K_FINALITY constants (BP11) - BATHRON blocks before PENDING → FINAL
// Same K for ALL burns (genesis and post-genesis) - no exceptions
static const uint32_t K_FINALITY_MAINNET = 100;          // ~100 minutes
static const uint32_t K_FINALITY_TESTNET = 20;           // ~20 minutes

// Max claims per TX_MINT_M0BTC (BP11)
static const size_t MAX_MINT_CLAIMS_PER_BLOCK = 100;

// Minimum burn amount in satoshis (dust protection)
static const int64_t MIN_BURN_SATS = 1000;

// Get required confirmations for current network (BP10)
uint32_t GetRequiredConfirmations();

// R2: highest BTC height among FINALIZED (minted) burns, or 0 if none.
// Used by the btcheaders V2 reorg guard to refuse a reorg that would fork at/
// below a finalized burn's anchor (which would orphan an already-minted M0).
uint32_t GetHighestFinalizedBtcHeight();

// Get K_FINALITY for current network (BP11)
// Used for ALL burns - genesis and post-genesis use same K
uint32_t GetKFinality();

//
// BTC Transaction Types (strict Bitcoin serialization)
//

struct BtcOutPoint {
    uint256 hash;
    uint32_t n;

    SERIALIZE_METHODS(BtcOutPoint, obj)
    {
        READWRITE(obj.hash, obj.n);
    }
};

struct BtcTxIn {
    BtcOutPoint prevout;
    std::vector<uint8_t> scriptSig;
    uint32_t nSequence;
    std::vector<std::vector<uint8_t>> scriptWitness;  // Witness data (SegWit)

    SERIALIZE_METHODS(BtcTxIn, obj)
    {
        READWRITE(obj.prevout, obj.scriptSig, obj.nSequence);
        // Note: witness is NOT serialized here - handled separately
    }
};

struct BtcTxOut {
    int64_t nValue;
    std::vector<uint8_t> scriptPubKey;

    SERIALIZE_METHODS(BtcTxOut, obj)
    {
        READWRITE(obj.nValue, obj.scriptPubKey);
    }
};

struct BtcParsedTx {
    int32_t nVersion;
    std::vector<BtcTxIn> vin;
    std::vector<BtcTxOut> vout;
    uint32_t nLockTime;
    bool hasWitness;

    // For SegWit: non-witness serialization for txid calculation
    std::vector<uint8_t> nonWitnessSerialization;

    BtcParsedTx() : nVersion(0), nLockTime(0), hasWitness(false) {}
};

/**
 * Parse raw BTC transaction bytes using strict Bitcoin serialization.
 *
 * @param btcTxBytes Raw transaction bytes (Bitcoin format)
 * @param tx Output: Parsed transaction structure
 * @return true if parsing succeeded, false if malformed
 */
bool ParseBtcTransaction(const std::vector<uint8_t>& btcTxBytes, BtcParsedTx& tx);

/**
 * Compute Bitcoin txid (double SHA256).
 *
 * CRITICAL: For SegWit transactions, this uses the non-witness serialization.
 * DO NOT simply hash the raw bytes for SegWit - that produces wtxid, not txid!
 *
 * @param tx Parsed BTC transaction
 * @return The txid (32 bytes)
 */
uint256 ComputeBtcTxid(const BtcParsedTx& tx);

/**
 * Compute Bitcoin wtxid (includes witness data).
 *
 * @param btcTxBytes Raw transaction bytes
 * @return The wtxid (32 bytes)
 */
uint256 ComputeBtcWtxid(const std::vector<uint8_t>& btcTxBytes);

//
// Burn Information
//

// BCS v02 destination types (A2, doc/PREMAINNET-CONSENSUS-ADDITIONS.md §2)
static const uint8_t BURN_DEST_P2PKH = 0x00;  // hash160 = CKeyID
static const uint8_t BURN_DEST_P2SH  = 0x01;  // hash160 = CScriptID (mint-to-covenant)

struct BurnInfo {
    uint8_t version;        // Protocol version (1 = v01, 2 = v02)
    uint8_t network;        // Network byte (0x00=mainnet, 0x01=testnet)
    uint8_t destType;       // BURN_DEST_P2PKH (implicit for v01) or BURN_DEST_P2SH
    uint160 bathronDest;       // BATHRON destination (hash160)
    uint64_t burnedSats;    // Amount burned (satoshis)

    BurnInfo() : version(0), network(0), destType(BURN_DEST_P2PKH), burnedSats(0) {}
};

/**
 * Parse burn outputs from a BTC transaction.
 *
 * Validates:
 * - Exactly 1 OP_RETURN metadata output with BATHRON format
 * - Exactly 1 P2WSH(OP_FALSE) burn output with value > 0
 *
 * @param btcTx Parsed BTC transaction
 * @param info Output: Burn information
 * @return true if valid burn format, false otherwise
 */
bool ParseBurnOutputs(const BtcParsedTx& btcTx, BurnInfo& info);

/**
 * Check if output is OP_RETURN.
 */
bool IsOpReturnOutput(const BtcTxOut& out);

/**
 * Check if output is the BATHRON metadata format.
 * v01: OP_RETURN, 29 bytes: "BATHRON" + 0x01 + network + dest20
 * v02: OP_RETURN, 30 bytes: "BATHRON" + 0x02 + network + destType + dest20
 */
bool IsBathronMetadataOutput(const BtcTxOut& out);

/**
 * Check if output is P2WSH(OP_FALSE) burn address.
 * P2WSH script: OP_0 + PUSH32 + SHA256(0x00)
 */
bool IsP2WSHBurnOutput(const BtcTxOut& out);

/**
 * Extract data from OP_RETURN output.
 */
bool ExtractOpReturnData(const std::vector<uint8_t>& scriptPubKey, std::vector<uint8_t>& data);

//
// Burn Claim Payload (TX_BURN_CLAIM)
//

static const uint8_t BURN_CLAIM_PAYLOAD_VERSION = 1;

struct BurnClaimPayload {
    uint8_t nVersion;                       // Payload version (1)
    std::vector<uint8_t> btcTxBytes;        // Raw BTC transaction (strict Bitcoin serialization)
    uint256 btcBlockHash;                   // Bitcoin block containing the burn
    uint32_t btcBlockHeight;                // Block height (for confirmation check)
    std::vector<uint256> merkleProof;       // Merkle path to root
    uint32_t txIndex;                       // Transaction index in block
    // No signature needed - burn proof is self-authenticating:
    // - BTC tx signed by burner, BATHRON metadata encodes dest
    // - Anyone can submit claim, M0BTC always goes to encoded dest

    BurnClaimPayload() : nVersion(BURN_CLAIM_PAYLOAD_VERSION), btcBlockHeight(0), txIndex(0) {}

    SERIALIZE_METHODS(BurnClaimPayload, obj)
    {
        READWRITE(obj.nVersion, obj.btcTxBytes, obj.btcBlockHash, obj.btcBlockHeight,
                  obj.merkleProof, obj.txIndex);
    }

    /**
     * Trivial validation (format checks, DoS limits).
     * Does NOT verify against SPV chain.
     */
    bool IsTriviallyValid(std::string& strError) const;

    /**
     * Get the BTC txid from the payload.
     */
    uint256 GetBtcTxid() const;
};

//
// Consensus Validation
//

class CValidationState;

/**
 * Full consensus validation of a burn claim.
 *
 * Validates:
 * - BTC TX format and burn outputs
 * - SPV proof (block exists, in best chain, merkle proof)
 * - Network byte matches
 * - Claimant matches destination
 * - Not already claimed (anti-replay)
 *
 * NOTE: Does NOT check K confirmations - that's for finalization (BP11).
 */
bool CheckBurnClaim(const BurnClaimPayload& payload,
                    CValidationState& state,
                    uint32_t nHeight);

class CTransaction;

/**
 * B4.6 (hardtest track #9) — block-level burn-claim checks.
 *
 * 1. Intra-block dedup. The anti-replay in CheckBurnClaim
 *    ("burn-claim-duplicate") and the mempool P1 check both read burnclaimdb,
 *    which is only WRITTEN at connect time — so two TX_BURN_CLAIM for the
 *    SAME BTC txid inside ONE block each pass per-tx validation.
 *    StoreBurnClaim is a by-txid upsert, so this cannot double-mint, but a
 *    block carrying duplicate claims is malformed: reject
 *    ("bad-burnclaim-duplicate-in-block").
 * 2. Per-block claim cap. Enforces the BP10 MAX_BURN_CLAIMS_PER_BLOCK spec
 *    constant, declared since BP10 but never wired ("bad-burnclaim-too-many").
 *
 * Undecodable/unparseable claims are SKIPPED here (still counted for the
 * cap) — CheckSpecialTx rejects them with the precise reason.
 *
 * Unconditional consensus tightening (no upgrade gate): verified 2026-07-08
 * that no historical testnet block violates either rule (block 4 carries 39
 * claims, all-distinct, under the cap), so the chain replays cleanly.
 */
bool CheckNoDuplicateBurnClaimsInBlock(const std::vector<std::shared_ptr<const CTransaction>>& vtx,
                                       CValidationState& state);

/**
 * Check if a BTC txid is already claimed or pending.
 */
bool IsBtcTxidAlreadyClaimed(const uint256& btcTxid);

//==============================================================================
// BP11 - M0BTC Minting State Machine
//==============================================================================

/**
 * Burn Claim Status (BP11)
 *
 * ONLY {PENDING, FINAL} are persisted in consensus DB.
 * "Orphaned" is a DISPLAY label derived from:
 *   record.status == PENDING && !g_btc_spv->IsInBestChain(record.btcBlockHash)
 */
enum class BurnClaimStatus : uint8_t {
    PENDING = 0,  // Claim accepted, waiting for finality (K_FINALITY BATHRON blocks)
    FINAL   = 1   // Fully confirmed, M0BTC spendable via TX_MINT_M0BTC
};

/**
 * Burn Claim Record (BP11)
 *
 * Stored in LevelDB with key: 'Cc' || btc_txid (32 bytes)
 * One record per btc_txid. Re-claims (after BTC reorg) overwrite in-place.
 */
struct BurnClaimRecord {
    uint256 btcTxid;           // Bitcoin TX hash (primary key)
    uint256 btcBlockHash;      // BTC block containing burn
    uint32_t btcHeight;        // BTC block height
    uint64_t burnedSats;       // Amount burned (satoshis)
    uint160 bathronDest;          // Destination address (hash160)
    uint8_t destType;          // BCS v02: BURN_DEST_P2PKH or BURN_DEST_P2SH
    uint32_t claimHeight;      // BATHRON height when TX_BURN_CLAIM mined
    uint32_t finalHeight;      // BATHRON height when TX_MINT_M0BTC mined (0 if pending)
    BurnClaimStatus status;    // PENDING or FINAL only

    BurnClaimRecord()
        : btcHeight(0), burnedSats(0), destType(BURN_DEST_P2PKH),
          claimHeight(0), finalHeight(0),
          status(BurnClaimStatus::PENDING) {}

    // DB format change (destType appended): requires a fresh burnclaimdb —
    // deployed via disposable-genesis reset, per pre-mainnet rules.
    SERIALIZE_METHODS(BurnClaimRecord, obj)
    {
        READWRITE(obj.btcTxid, obj.btcBlockHash, obj.btcHeight, obj.burnedSats,
                  obj.bathronDest, obj.destType, obj.claimHeight, obj.finalHeight);
        // Serialize status as uint8_t
        uint8_t statusByte = static_cast<uint8_t>(obj.status);
        READWRITE(statusByte);
        SER_READ(obj, obj.status = static_cast<BurnClaimStatus>(statusByte));
    }

    // Derived status: is this claim "orphaned"? (UI only, not consensus)
    // Returns true if PENDING but BTC block no longer in best chain
    bool IsOrphaned() const;
};

/**
 * Mint Payload (BP11) - TX_MINT_M0BTC (Type 32)
 *
 * This transaction creates spendable M0BTC UTXOs for finalized claims.
 * Generated by block producer, validated by all nodes for strict equality.
 *
 * Structure:
 * - vin: [] (empty - this is money creation)
 * - vout: [P2PKH outputs for each finalized claim]
 * - extraPayload: MintPayload
 */
static const uint8_t MINT_PAYLOAD_VERSION = 1;

struct MintPayload {
    uint8_t nVersion;                   // Payload version (1)
    std::vector<uint256> btcTxids;      // BTC txids being finalized (MUST be sorted)

    MintPayload() : nVersion(MINT_PAYLOAD_VERSION) {}

    SERIALIZE_METHODS(MintPayload, obj)
    {
        READWRITE(obj.nVersion, obj.btcTxids);
    }

    /**
     * Trivial validation (format checks).
     */
    bool IsTriviallyValid(std::string& strError) const;
};

//==============================================================================
// BP11 - Anti-Replay with Deterministic Release
//==============================================================================

/**
 * Check if a BTC txid is blocked by an existing claim record.
 *
 * Deterministic release rule (from BP11 spec):
 * - FINAL: always blocks (immutable)
 * - PENDING + IsInBestChain(btcBlockHash): blocks (prevents spam)
 * - PENDING + !IsInBestChain(btcBlockHash): releases (allows re-claim after BTC reorg)
 *
 * This replaces IsBtcTxidAlreadyClaimed() for consensus.
 */
bool IsBtcTxidBlockedByClaimRecord(const uint256& btcTxid);

//==============================================================================
// BP11 - Finalization Logic (Consensus)
//==============================================================================

/**
 * Check if a burn claim is still valid for finalization.
 *
 * CONSENSUS function - MUST be deterministic (no GetTime()!)
 * Used in CheckMintM0BTC and CreateMintM0BTC.
 *
 * Checks:
 * - BTC block still in SPV best chain
 * - Has sufficient confirmations (K_CONFIRMATIONS)
 */
bool IsBtcBurnStillValidConsensus(const BurnClaimRecord& record);

/**
 * Mint output script for a claim record (BCS v02, A2).
 * BURN_DEST_P2PKH → P2PKH(CKeyID) ; BURN_DEST_P2SH → P2SH(CScriptID).
 * CONSENSUS function — shared by CreateMintM0BTC and CheckMintM0BTC so the
 * producer and the validators can never diverge on the destination form.
 */
class CScript;
CScript GetMintDestScript(const BurnClaimRecord& record);

/**
 * Create TX_MINT_M0BTC for block at given height.
 *
 * Called by block producer. MUST be deterministic:
 * - Finds all PENDING claims with claimHeight <= height - K_FINALITY
 * - Filters by IsBtcBurnStillValidConsensus()
 * - Sorts btcTxids canonically
 * - Applies MAX_MINT_CLAIMS_PER_BLOCK cap
 *
 * @param blockHeight Height of block being created
 * @return Transaction (empty if no claims to finalize)
 */
class CTransaction;
CTransaction CreateMintM0BTC(uint32_t blockHeight);

/**
 * Validate TX_MINT_M0BTC consensus rules.
 *
 * @param tx The mint transaction
 * @param state Validation state for error reporting
 * @param blockHeight Height of block containing TX
 * @return true if valid
 */
bool CheckMintM0BTC(const CTransaction& tx,
                    CValidationState& state,
                    uint32_t blockHeight);

/**
 * Connect TX_MINT_M0BTC - apply finalization to DB.
 *
 * Called when block containing TX_MINT_M0BTC is connected.
 * - Sets status = FINAL for each claim
 * - Increments M0BTC supply counter
 *
 * @param tx The mint transaction
 * @param blockHeight Height of block
 */
void ConnectMintM0BTC(const CTransaction& tx, uint32_t blockHeight);

/**
 * Disconnect TX_MINT_M0BTC - revert finalization (reorg).
 *
 * Called when block containing TX_MINT_M0BTC is disconnected.
 * - Sets status = PENDING for each claim
 * - Decrements M0BTC supply counter
 *
 * @param tx The mint transaction
 * @param blockHeight Height of block
 */
void DisconnectMintM0BTC(const CTransaction& tx, uint32_t blockHeight);

/**
 * Enter PENDING state for a burn claim.
 *
 * Called when TX_BURN_CLAIM is mined.
 *
 * @param payload The burn claim payload
 * @param bathronHeight Height of BATHRON block containing TX_BURN_CLAIM
 * @return true if successful
 */
bool EnterPendingState(const BurnClaimPayload& payload, uint32_t bathronHeight);

/**
 * Undo burn claim (BATHRON reorg disconnecting TX_BURN_CLAIM).
 *
 * ONLY removes the PENDING claim record.
 * Does NOT touch M0BTC_supply or claimed markers (that's DisconnectMintM0BTC).
 *
 * @param payload The burn claim payload
 * @param height Height of block being disconnected
 * @return true if successful
 */
bool UndoBurnClaim(const BurnClaimPayload& payload, uint32_t height);

#endif // BATHRON_BURNCLAIM_H
