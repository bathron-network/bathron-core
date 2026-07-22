// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SETTLEMENT_LOGIC_H
#define SETTLEMENT_LOGIC_H

/**
 * Settlement Layer Logic - TX processing functions
 *
 * Ref: doc/blueprints/settlement/LOCK-SETTLEMENT-v1.3.2.md
 *
 * TX_LOCK canonical output order (A11):
 *   vout[0] = Vault (P amount, M0)
 *   vout[1] = M1 Receipt (P amount)
 */

#include "primitives/transaction.h"
#include "state/settlement.h"
#include "state/settlementdb.h"
#include "htlc/htlcdb.h"

class CValidationState;
class CCoinsViewCache;

// =============================================================================
// M1 Fee Model Helpers (BP30 v3.0)
// =============================================================================

/**
 * IsExactlyOpTrueScript - Check if script is exactly OP_TRUE (1 byte: 0x51)
 *
 * Used for fee output validation. Rejects any variation:
 * - OP_TRUE + junk bytes
 * - OP_1 (alias) if serialized differently
 * - Any other script that might "evaluate to true"
 *
 * @param script Script to check
 * @return true if script is exactly [OP_TRUE] (1 byte)
 */
bool IsExactlyOpTrueScript(const CScript& script);

/**
 * ComputeMinM1Fee - Calculate minimum M1 fee for transaction
 *
 * Deterministic fee calculation for consensus.
 * Uses: fee = (txSize * feeRate) / 1000
 *
 * @param txSize Transaction size in bytes
 * @param feeRate Fee rate in sat/kB (default: minRelayTxFee)
 * @return Minimum required M1 fee in satoshis
 */
CAmount ComputeMinM1Fee(size_t txSize, CAmount feeRate = 50);  // 50 sat/kB default

/**
 * GetSettlementTxFee - the M0 (coinbase) fee of a tx, settlement-aware.
 *
 * SINGLE SOURCE OF TRUTH shared by mempool acceptance (AcceptToMemoryPoolWorker)
 * and block connection (ConnectBlock). The two MUST agree: the block assembler
 * builds the coinbase from the sum of mempool fees, while ConnectBlock recomputes
 * the fee and enforces `coinbase == nFees` (IsCoinbaseValueValid). Any divergence
 * makes every block carrying the offending tx fail with bad-cb-amount (an honest
 * producer cannot mine it) OR lets a malicious producer mint the difference into
 * the coinbase. Keeping one function removes that footgun by construction.
 *
 *   TX_LOCK  : fee = valueIn - (outputs except vout[1]). The vout[1] M1 receipt is
 *              newly-minted M1 backed by the vault, NOT spent M0, so it is excluded.
 *   TX_UNLOCK: fee = M1_in - M0_out - M1_change (BP30 v3.1 producer-incentive),
 *              recomputed from the settlement-DB receipt inputs — NOT the raw sat
 *              delta (valueIn - valueOut == m0Out + 2*fee, dominated by the M1
 *              burn). The fee is real vault M0 released to the coinbase: CheckUnlock
 *              enforces totalVault == M0_out + fee + vault_backing, and ApplyUnlock
 *              drops M0_vaulted and M1_supply by M0_out + fee — the coinbased sat is
 *              backed, never minted (A5/A6 exact).
 *   others   : fee = valueIn - valueOut (standard raw-sat fee).
 *
 * @param tx        The transaction.
 * @param valueIn   Total input value (sats) as computed by the caller.
 * @param valueOut  Total output value (sats), i.e. tx.GetValueOut().
 * @return The M0 fee credited to the coinbase for this tx.
 */
CAmount GetSettlementTxFee(const CTransaction& tx, CAmount valueIn, CAmount valueOut);

/**
 * CheckFeeOutputAt - Validate fee output at specific index
 *
 * Enforces:
 * - Index in range
 * - Script is exactly OP_TRUE
 * - Value >= minFee (or == minFee if strict)
 *
 * @param tx Transaction to check
 * @param feeIndex Expected fee output index
 * @param minFee Minimum fee amount
 * @param state Validation state for error reporting
 * @param txType TX type prefix for error codes ("unlock" or "txtransfer")
 * @return true if valid, false with error in state
 */
bool CheckFeeOutputAt(const CTransaction& tx,
                      size_t feeIndex,
                      CAmount minFee,
                      CValidationState& state,
                      const std::string& txType);

// =============================================================================
// TX_LOCK - Lock M0 into Vault + Receipt pair
// =============================================================================

/**
 * CheckLock - Validate TX_LOCK transaction structure
 *
 * Rules:
 * - All inputs must be M0 standard (not in V/R/P/Y indexes)
 * - Exactly 2 outputs: vout[0] = Vault, vout[1] = Receipt
 * - vout[0].amount == vout[1].amount (backing invariant)
 * - vout[0] must be spendable (not OP_RETURN)
 * - vout[1] must have M1 marker (OP_RETURN or special script)
 *
 * @param tx Transaction to validate
 * @param view Coins view for input validation
 * @param state Validation state for error reporting
 * @return true if valid, false otherwise
 */
bool CheckLock(const CTransaction& tx,
               const CCoinsViewCache& view,
               CValidationState& state);

/**
 * ApplyLock - Apply TX_LOCK to settlement layer state
 *
 * Effects:
 * - Create VaultEntry at vout[0]
 * - Create M1Receipt at vout[1]
 * - Update SettlementState: M0_vaulted += P, M1_supply += P
 *
 * @param tx Transaction to apply
 * @param view Coins view
 * @param settlementState Settlement state to update
 * @param nHeight Block height
 * @param batch DB batch for atomic writes
 * @return true if applied successfully
 */
bool ApplyLock(const CTransaction& tx,
               const CCoinsViewCache& view,
               SettlementState& settlementState,
               uint32_t nHeight,
               CSettlementDB::Batch& batch);


/**
 * UndoLock - Undo TX_LOCK during reorg
 *
 * Effects:
 * - Erase VaultEntry at vout[0]
 * - Erase M1Receipt at vout[1]
 * - Update SettlementState: M0_vaulted -= P, M1_supply -= P
 */
bool UndoLock(const CTransaction& tx,
              SettlementState& settlementState,
              CSettlementDB::Batch& batch);

// =============================================================================
// TX_UNLOCK - Release M0 from Vault+Receipt pair (Bearer Asset Model)
// =============================================================================

// UnlockUndoData is defined in settlement.h

/**
 * CheckUnlock - Validate TX_UNLOCK transaction structure (Bearer Asset Model)
 *
 * BP30 v2.1 TX_UNLOCK canonical structure:
 *   vin[0..N] = M1 Receipt outpoints (must exist in R index)
 *   vin[N+1..K] = Vault outpoints (must exist in V index)
 *   vout[0] = M0 output (unlocked funds)
 *   vout[1+] = M1 change receipts (optional)
 *
 * Conservation rule:
 *   sum(M1_in) >= M0_out + sum(M1_change)
 *   fee = sum(M1_in) - M0_out - sum(M1_change)
 *
 * Security:
 *   M0_out <= sum(vaults) (cannot create M0 from thin air)
 */
bool CheckUnlock(const CTransaction& tx,
                 const CCoinsViewCache& view,
                 CValidationState& state);

/**
 * ApplyUnlock - Apply TX_UNLOCK to settlement layer state (BP30 v2.1)
 *
 * Effects:
 * - Erase all M1Receipts from vin
 * - Erase all VaultEntries from vin
 * - Create M1 change receipts at vout[1+]
 * - Update SettlementState:
 *     M0_vaulted -= M0_out
 *     M1_supply -= (sum(M1_in) - sum(M1_change))  // net burn
 *
 * @param tx Transaction to apply
 * @param view Coins view
 * @param settlementState Settlement state to update
 * @param batch DB batch for atomic writes
 * @param undoData Output: data needed for UndoUnlock
 * @return true if applied successfully
 */
bool ApplyUnlock(const CTransaction& tx,
                 const CCoinsViewCache& view,
                 SettlementState& settlementState,
                 CSettlementDB::Batch& batch,
                 UnlockUndoData& undoData);

/**
 * UndoUnlock - Undo TX_UNLOCK during reorg (BP30 v2.1)
 *
 * Effects (reverse of ApplyUnlock):
 * - Erase M1 change receipts at vout[1+]
 * - Restore all M1Receipts from undoData
 * - Restore all VaultEntries from undoData
 * - Update SettlementState:
 *     M0_vaulted += undoData.m0Released
 *     M1_supply += undoData.netM1Burned
 *
 * @param tx The TX_UNLOCK transaction
 * @param undoData Data saved during ApplyUnlock
 * @param settlementState Settlement state to update
 * @param batch DB batch for atomic writes
 */
bool UndoUnlock(const CTransaction& tx,
                const UnlockUndoData& undoData,
                SettlementState& settlementState,
                CSettlementDB::Batch& batch);


// =============================================================================
// TX_TRANSFER_M1 - Transfer M1 Receipt to new owner
// =============================================================================

/**
 * ParseTransferM1Outputs - Canonical M1 output detection for TX_TRANSFER_M1
 *
 * BP30 v2.5: Single source of truth for M1 vs M0 output classification.
 *
 * CANONICAL ORDER RULE (consensus-enforced):
 *   TX_TRANSFER_M1 vout layout:
 *     vout[0..splitIndex-1] = M1 receipt outputs (amounts sum to m1In)
 *     vout[splitIndex..N-1] = M0 fee change outputs
 *
 * ALGORITHM (cumsum-based):
 *   Iterate vout left-to-right. Each output is M1 until cumsum reaches m1In.
 *   Once cumsum == m1In exactly, all remaining outputs are M0 fee change.
 *
 * STRICT CONSERVATION:
 *   sum(M1_out) MUST equal m1In exactly. No implicit burn allowed.
 *
 * USAGE:
 *   - CheckTransfer() - consensus validation
 *   - ApplyTransfer() - DB updates (create receipts only for M1 outputs)
 *   - validation.cpp AcceptToMemoryPool - fee calculation
 *   - Wallet builder - fee estimation
 *
 * @param tx         TX_TRANSFER_M1 transaction
 * @param m1In       M1 input amount (from vin[0] receipt)
 * @param splitIndex Output: index of first M0 output (or tx.vout.size() if all M1)
 * @param m1Out      Output: total M1 output amount (should equal m1In)
 * @return true if parsing succeeded, false if invalid structure
 */
bool ParseTransferM1Outputs(const CTransaction& tx,
                            CAmount m1In,
                            size_t& splitIndex,
                            CAmount& m1Out);

/**
 * CheckTransfer - Validate TX_TRANSFER_M1 transaction structure
 *
 * TX_TRANSFER_M1 canonical structure:
 *   vin[0] = M1 Receipt outpoint (must exist in R index)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = New M1 Receipt (same amount as old)
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == TX_TRANSFER_M1
 * - Exactly 1 M1 Receipt input (must be vin[0])
 * - vout[0].nValue == old_receipt.amount (strict 1:1)
 * - Linked vault must exist
 * - No GlobalState change (supply/backing unchanged)
 */
bool CheckTransfer(const CTransaction& tx,
                   const CCoinsViewCache& view,
                   CValidationState& state);

/**
 * ApplyTransfer - Apply TX_TRANSFER_M1 to settlement layer state (BP30 v2.2)
 *
 * Effects:
 * - Erase old M1Receipt
 * - Create new M1Receipt(s) at vout[0..N]
 * - No GlobalState change (M1_supply unchanged)
 *
 * @param tx Transaction to apply
 * @param view Coins view
 * @param batch DB batch for atomic writes
 * @param undoData Output: data needed for UndoTransfer
 * @return true if applied successfully
 */
bool ApplyTransfer(const CTransaction& tx,
                   const CCoinsViewCache& view,
                   CSettlementDB::Batch& batch,
                   TransferUndoData& undoData);

/**
 * UndoTransfer - Undo TX_TRANSFER_M1 during reorg (BP30 v2.2)
 *
 * Effects:
 * - Erase all new M1Receipts
 * - Restore old M1Receipt from undoData
 *
 * @param tx The TX_TRANSFER_M1 transaction
 * @param undoData Data saved during ApplyTransfer
 * @param batch DB batch for atomic writes
 */
bool UndoTransfer(const CTransaction& tx,
                  const TransferUndoData& undoData,
                  CSettlementDB::Batch& batch);

// =============================================================================
// HTLC_CREATE_M1 - Lock M1 in Hash Time Locked Contract
// =============================================================================

/**
 * CheckHTLCCreate - Validate HTLC_CREATE_M1 transaction structure
 *
 * HTLC_CREATE_M1 canonical structure:
 *   vin[0] = M1 Receipt outpoint (must exist in R index)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = HTLC P2SH output (amount == M1 receipt amount)
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == HTLC_CREATE_M1
 * - vin[0] must be M1 Receipt
 * - vout[0] must be P2SH with valid conditional script
 * - vout[0].nValue == receipt.amount (strict conservation)
 *
 * @param tx Transaction to validate
 * @param view Coins view for input validation
 * @param state Validation state for error reporting
 * @return true if valid, false otherwise
 */
bool CheckHTLCCreate(const CTransaction& tx,
                     const CCoinsViewCache& view,
                     CValidationState& state,
                     bool fCheckUTXO = true,
                     uint32_t nHeight = 0);

/**
 * ApplyHTLCCreate - Apply HTLC_CREATE_M1 to state
 *
 * Effects:
 * - Erase M1Receipt from settlement DB
 * - Create HTLCRecord in htlc DB
 * - Create HTLCCreateUndoData
 * - M1_supply unchanged (M1 is in HTLC state, not destroyed)
 *
 * @param tx Transaction to apply
 * @param view Coins view
 * @param nHeight Block height
 * @param settlementBatch Settlement DB batch
 * @param htlcBatch HTLC DB batch
 * @return true if applied successfully
 */
bool ApplyHTLCCreate(const CTransaction& tx,
                     const CCoinsViewCache& view,
                     uint32_t nHeight,
                     CSettlementDB::Batch& settlementBatch,
                     class CHtlcDB::Batch& htlcBatch);

/**
 * UndoHTLCCreate - Undo HTLC_CREATE_M1 during reorg
 *
 * Effects:
 * - Erase HTLCRecord from htlc DB
 * - Restore M1Receipt to settlement DB
 */
bool UndoHTLCCreate(const CTransaction& tx,
                    CSettlementDB::Batch& settlementBatch,
                    class CHtlcDB::Batch& htlcBatch);

// =============================================================================
// HTLC_CLAIM - Claim HTLC with preimage
// =============================================================================

/**
 * CheckHTLCClaim - Validate HTLC_CLAIM transaction structure
 *
 * HTLC_CLAIM canonical structure:
 *   vin[0] = HTLC P2SH outpoint (with preimage in scriptSig)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = New M1 Receipt (to claimer)
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == HTLC_CLAIM
 * - vin[0] must be active HTLC
 * - Preimage in scriptSig must match hashlock (SHA256)
 * - Output goes to claim address from HTLC record
 *
 * @param tx Transaction to validate
 * @param view Coins view
 * @param state Validation state
 * @return true if valid
 */
bool CheckHTLCClaim(const CTransaction& tx,
                    const CCoinsViewCache& view,
                    uint32_t nHeight,
                    CValidationState& state);

/**
 * ApplyHTLCClaim - Apply HTLC_CLAIM to state
 *
 * Effects:
 * - Update HTLCRecord status to CLAIMED
 * - Create new M1Receipt for claimer
 * - M1_supply unchanged
 */
bool ApplyHTLCClaim(const CTransaction& tx,
                    const CCoinsViewCache& view,
                    uint32_t nHeight,
                    CSettlementDB::Batch& settlementBatch,
                    class CHtlcDB::Batch& htlcBatch);

/**
 * UndoHTLCClaim - Undo HTLC_CLAIM during reorg
 */
bool UndoHTLCClaim(const CTransaction& tx,
                   CSettlementDB::Batch& settlementBatch,
                   class CHtlcDB::Batch& htlcBatch);

// =============================================================================
// HTLC_REFUND - Refund expired HTLC
// =============================================================================

/**
 * CheckHTLCRefund - Validate HTLC_REFUND transaction structure
 *
 * HTLC_REFUND canonical structure:
 *   vin[0] = HTLC P2SH outpoint (with timeout scriptSig)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = M1 Receipt back to creator
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == HTLC_REFUND
 * - vin[0] must be active HTLC
 * - tx.nLockTime >= htlc.expiryHeight
 * - Output goes to refund address from HTLC record
 *
 * @param tx Transaction to validate
 * @param view Coins view
 * @param nHeight Current chain height (for expiry check)
 * @param state Validation state
 * @return true if valid
 */
bool CheckHTLCRefund(const CTransaction& tx,
                     const CCoinsViewCache& view,
                     uint32_t nHeight,
                     CValidationState& state);

/**
 * ApplyHTLCRefund - Apply HTLC_REFUND to state
 *
 * Effects:
 * - Update HTLCRecord status to REFUNDED
 * - Create M1Receipt for original creator
 * - M1_supply unchanged
 */
bool ApplyHTLCRefund(const CTransaction& tx,
                     const CCoinsViewCache& view,
                     uint32_t nHeight,
                     CSettlementDB::Batch& settlementBatch,
                     class CHtlcDB::Batch& htlcBatch);

/**
 * UndoHTLCRefund - Undo HTLC_REFUND during reorg
 */
bool UndoHTLCRefund(const CTransaction& tx,
                    CSettlementDB::Batch& settlementBatch,
                    class CHtlcDB::Batch& htlcBatch);

// =============================================================================
// HTLC_CREATE_3S - Lock M1 in 3-Secret Hash Time Locked Contract (FlowSwap)
// =============================================================================

/**
 * CheckHTLC3SCreate - Validate HTLC_CREATE_3S transaction structure
 *
 * HTLC_CREATE_3S canonical structure:
 *   vin[0] = M1 Receipt outpoint (must exist in R index)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = HTLC3S P2SH output (amount == M1 receipt amount)
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == HTLC_CREATE_3S
 * - vin[0] must be M1 Receipt
 * - vout[0] must be P2SH with valid 3-secret conditional script
 * - vout[0].nValue == receipt.amount (strict conservation)
 * - extraPayload must contain valid HTLC3SCreatePayload with 3 hashlocks
 *
 * @param tx Transaction to validate
 * @param view Coins view for input validation
 * @param state Validation state for error reporting
 * @param fCheckUTXO If true, verify UTXO exists (false during block connect)
 * @param nHeight Block height for legacy mode check
 * @return true if valid, false otherwise
 */
bool CheckHTLC3SCreate(const CTransaction& tx,
                       const CCoinsViewCache& view,
                       CValidationState& state,
                       bool fCheckUTXO = true,
                       uint32_t nHeight = 0);

/**
 * ApplyHTLC3SCreate - Apply HTLC_CREATE_3S to state
 *
 * Effects:
 * - Erase M1Receipt from settlement DB
 * - Create HTLC3SRecord in htlc DB
 * - Create 3 hashlock indices (user, lp1, lp2) for cross-chain matching
 * - Create HTLC3SCreateUndoData
 * - M1_supply unchanged (M1 is in HTLC state, not destroyed)
 *
 * @param tx Transaction to apply
 * @param view Coins view
 * @param nHeight Block height
 * @param settlementBatch Settlement DB batch
 * @param htlcBatch HTLC DB batch
 * @return true if applied successfully
 */
bool ApplyHTLC3SCreate(const CTransaction& tx,
                       const CCoinsViewCache& view,
                       uint32_t nHeight,
                       CSettlementDB::Batch& settlementBatch,
                       class CHtlcDB::Batch& htlcBatch);

/**
 * UndoHTLC3SCreate - Undo HTLC_CREATE_3S during reorg
 *
 * Effects:
 * - Erase HTLC3SRecord from htlc DB
 * - Erase 3 hashlock indices
 * - Restore M1Receipt to settlement DB
 */
bool UndoHTLC3SCreate(const CTransaction& tx,
                      CSettlementDB::Batch& settlementBatch,
                      class CHtlcDB::Batch& htlcBatch);

// =============================================================================
// HTLC_CLAIM_3S - Claim 3-Secret HTLC with 3 preimages
// =============================================================================

/**
 * CheckHTLC3SClaim - Validate HTLC_CLAIM_3S transaction structure
 *
 * HTLC_CLAIM_3S canonical structure:
 *   vin[0] = HTLC3S P2SH outpoint (with 3 preimages in scriptSig)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = New M1 Receipt (to claimer)
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == HTLC_CLAIM_3S
 * - vin[0] must be active HTLC3S
 * - 3 preimages in scriptSig must match 3 hashlocks (SHA256)
 * - Output goes to claim address from HTLC3S record
 *
 * @param tx Transaction to validate
 * @param view Coins view
 * @param state Validation state
 * @return true if valid
 */
bool CheckHTLC3SClaim(const CTransaction& tx,
                      const CCoinsViewCache& view,
                      CValidationState& state);

/**
 * ApplyHTLC3SClaim - Apply HTLC_CLAIM_3S to state
 *
 * Effects:
 * - Update HTLC3SRecord status to CLAIMED
 * - Store all 3 revealed preimages in record
 * - Create new M1Receipt for claimer
 * - Erase 3 hashlock indices (HTLC no longer active)
 * - M1_supply unchanged
 */
bool ApplyHTLC3SClaim(const CTransaction& tx,
                      const CCoinsViewCache& view,
                      uint32_t nHeight,
                      CSettlementDB::Batch& settlementBatch,
                      class CHtlcDB::Batch& htlcBatch);

/**
 * UndoHTLC3SClaim - Undo HTLC_CLAIM_3S during reorg
 */
bool UndoHTLC3SClaim(const CTransaction& tx,
                     CSettlementDB::Batch& settlementBatch,
                     class CHtlcDB::Batch& htlcBatch);

// =============================================================================
// HTLC_REFUND_3S - Refund expired 3-Secret HTLC
// =============================================================================

/**
 * CheckHTLC3SRefund - Validate HTLC_REFUND_3S transaction structure
 *
 * HTLC_REFUND_3S canonical structure:
 *   vin[0] = HTLC3S P2SH outpoint (with timeout scriptSig)
 *   vin[1+] = M0 fee inputs (optional)
 *   vout[0] = M1 Receipt back to creator
 *   vout[1+] = M0 change (optional)
 *
 * Rules:
 * - nType == HTLC_REFUND_3S
 * - vin[0] must be active HTLC3S
 * - nHeight >= htlc.expiryHeight
 * - Output goes to refund address from HTLC3S record
 *
 * @param tx Transaction to validate
 * @param view Coins view
 * @param nHeight Current chain height (for expiry check)
 * @param state Validation state
 * @return true if valid
 */
bool CheckHTLC3SRefund(const CTransaction& tx,
                       const CCoinsViewCache& view,
                       uint32_t nHeight,
                       CValidationState& state);

/**
 * ApplyHTLC3SRefund - Apply HTLC_REFUND_3S to state
 *
 * Effects:
 * - Update HTLC3SRecord status to REFUNDED
 * - Create M1Receipt for original creator
 * - Erase 3 hashlock indices (HTLC no longer active)
 * - M1_supply unchanged
 */
bool ApplyHTLC3SRefund(const CTransaction& tx,
                       const CCoinsViewCache& view,
                       uint32_t nHeight,
                       CSettlementDB::Batch& settlementBatch,
                       class CHtlcDB::Batch& htlcBatch);

/**
 * UndoHTLC3SRefund - Undo HTLC_REFUND_3S during reorg
 */
bool UndoHTLC3SRefund(const CTransaction& tx,
                      CSettlementDB::Batch& settlementBatch,
                      class CHtlcDB::Batch& htlcBatch);

// =============================================================================
// A6 Invariant Enforcement
// =============================================================================

/**
 * AddNoOverflow - Overflow-safe CAmount addition using __int128
 *
 * @param a First operand
 * @param b Second operand
 * @param result Output: a + b if no overflow
 * @return true if no overflow, false if overflow would occur
 */
bool AddNoOverflow(CAmount a, CAmount b, CAmount& result);

/**
 * CheckA6P1 - Verify A6 invariant: M0_vaulted == M1_supply
 *
 * @param state SettlementState to verify
 * @param validationState Output: error details if check fails
 * @return true if A6 holds, false if broken
 */
bool CheckA6P1(const SettlementState& state, CValidationState& validationState);

/**
 * CheckA7 - Verify the A4/A7 supply cap (circuit breaker).
 *
 * M0 is backed 1:1 by burned BTC, whose supply is capped at 21M
 * (nMaxMoneyOut sats). M0_total_supply must therefore stay in [0, nMaxMoneyOut]:
 * negative catches an overflow, > cap catches inflation beyond the BTC supply
 * (or a runaway burn-claim accounting bug). A violation rejects the block.
 *
 * @param state SettlementState to verify (reads M0_total_supply)
 * @param nMaxMoneyOut The 21M cap in satoshis (consensus.nMaxMoneyOut)
 * @param validationState Output: error details if the cap is violated
 * @return true if within [0, cap], false otherwise
 */
bool CheckA7(const SettlementState& state, CAmount nMaxMoneyOut,
             CValidationState& validationState);

/**
 * CheckA5 - Verify A5 monetary conservation invariant
 *
 * A5: M0_total_supply(N) = M0_total_supply(N-1) + BurnClaims
 *
 * This is the ANTI-INFLATION invariant. Even if 90% of masternodes are
 * compromised, they cannot create M0 ex-nihilo. The ONLY way to increase
 * M0 supply is a verified BTC burn claim (block reward = 0, always).
 *
 * @param currentState Current block's settlement state (with coinbase_block set)
 * @param prevState Previous block's settlement state
 * @param validationState Output: error details if check fails
 * @return true if A5 holds, false if monetary conservation violated
 */
bool CheckA5(const SettlementState& currentState,
             const SettlementState& prevState,
             CValidationState& validationState);

/**
 *
 * @param coinbaseTx The coinbase transaction (block.vtx[0])
 * @return Total amount minted by coinbase
 */

// =============================================================================
// ParseSettlementTx - Robust M0/M1/Vault classification WITHOUT DB lookup
// =============================================================================

/**
 * SettlementTxView - Classification result for settlement transaction components
 *
 * This structure provides a DB-independent view of which inputs/outputs are:
 * - M0 (standard transparent)
 * - M1 (receipts)
 * - Vault (OP_TRUE locked funds)
 *
 * BP30 v2.6: Single source of truth for M0 fee calculation in RPC layer.
 * Uses canonical position rules and OP_TRUE detection, NOT settlement DB.
 */
struct SettlementTxView {
    // Transaction type
    std::string txType;

    // Input classification (by index)
    std::vector<size_t> m1_input_indices;
    std::vector<size_t> vault_input_indices;
    std::vector<size_t> m0_input_indices;

    // Output classification (by index)
    std::vector<size_t> m1_output_indices;
    std::vector<size_t> vault_output_indices;
    std::vector<size_t> m0_output_indices;

    // Computed amounts (if complete)
    CAmount m1_in = 0;
    CAmount vault_in = 0;
    CAmount m0_in = 0;
    CAmount m1_out = 0;
    CAmount vault_out = 0;
    CAmount m0_out = 0;

    // M0 fee = m0_in - m0_out (only meaningful if complete)
    CAmount m0_fee = 0;

    // Completeness indicator
    bool complete = false;         // True if all inputs were resolvable
    size_t missing_inputs = 0;     // Count of inputs that couldn't be fetched
    size_t unclassified_inputs = 0; // Count of inputs that couldn't be classified

    // Reason for incompleteness (for debugging)
    std::string reason_incomplete; // "missing_prevouts" | "spent_prevouts" | etc.
};

/**
 * IsVaultScript - Check if script is vault script (OP_TRUE)
 *
 * Vaults use a single-byte OP_TRUE (0x51) script, making them
 * trivially identifiable without DB lookup.
 *
 * @param script Script to check
 * @return true if script is OP_TRUE vault script
 */
inline bool IsVaultScript(const CScript& script) {
    return script.size() == 1 && script[0] == OP_TRUE;
}

/**
 * ParseSettlementTx - Classify settlement TX inputs/outputs WITHOUT DB lookup
 *
 * BP30 v2.6: Robust classification using canonical position rules and OP_TRUE detection.
 *
 * CLASSIFICATION RULES (no DB required):
 *
 * TX_LOCK:
 *   Inputs:  All M0 (by definition)
 *   Outputs: vout[0]=Vault(OP_TRUE check), vout[1]=M1, vout[2+]=M0 change
 *
 * TX_TRANSFER_M1:
 *   Inputs:  vin[0]=M1 (canonical), vin[1+]=M0 fee
 *   Outputs: Cumsum algorithm (ParseTransferM1Outputs) with m1_in from vin[0]
 *
 * TX_UNLOCK:
 *   Inputs:  Classified by prevout script via AccessCoin():
 *            - Before first OP_TRUE: M1 receipts
 *            - OP_TRUE scripts: Vaults
 *            - After vaults: M0 fee
 *   Outputs: vout[0]=M0, then cumsum for M1 change, OP_TRUE=vault change, rest=M0
 *
 * @param tx          Transaction to parse
 * @param pcoinsView  Coins view for input value/script lookup (can be nullptr)
 * @param view        Output: populated SettlementTxView
 * @return true if parsing succeeded (view.complete indicates if fully resolved)
 */
bool ParseSettlementTx(const CTransaction& tx,
                       const CCoinsViewCache* pcoinsView,
                       SettlementTxView& view);

#endif // SETTLEMENT_LOGIC_H
