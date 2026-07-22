// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SETTLEMENT_BUILDER_H
#define SETTLEMENT_BUILDER_H

/**
 * Settlement TX Builders (BP30)
 *
 * Wallet-level transaction construction for settlement layer operations.
 * These builders create properly formatted transactions for:
 * - TX_LOCK: M0 → Vault + Receipt (M1)
 * - TX_UNLOCK: Receipt (M1) + Vault → M0
 * - TX_TRANSFER_M1: Receipt → Receipt (new owner)
 *
 * Design principles:
 * - A11: Canonical output order enforced
 * - A8: Fees always in M0 (native)
 * - Atomic: All-or-nothing construction
 *
 * Ref: doc/blueprints/done/BP30-SETTLEMENT.md
 */

#include "primitives/transaction.h"
#include "script/script.h"
#include "state/settlement.h"

#include <string>
#include <vector>

/**
 * LockInput - Input for BuildLockTransaction
 */
struct LockInput
{
    COutPoint outpoint;     // M0 UTXO to spend
    CAmount amount;         // Amount available
    CScript scriptPubKey;   // For signing
};

/**
 * LockResult - Result from BuildLockTransaction
 */
struct LockResult
{
    bool success;
    std::string error;
    CMutableTransaction mtx;
    COutPoint vaultOutpoint;    // vout[0]
    COutPoint receiptOutpoint;  // vout[1]
    CAmount lockedAmount;       // P
    CAmount fee;
};

/**
 * BuildLockTransaction - Construct TX_LOCK (Bearer Asset Model)
 *
 * BP30 v2.0: Vault uses OP_TRUE script (consensus-protected).
 *
 * Takes M0 inputs and creates:
 * - vout[0] = Vault (amount P, OP_TRUE script - consensus-locked)
 * - vout[1] = Receipt (amount P, to receiptDest)
 * - vout[2+] = M0 change (optional)
 *
 * The vault is anyone-can-spend at script level, but consensus
 * rules only allow spending via TX_UNLOCK.
 *
 * @param inputs M0 UTXOs to use
 * @param lockAmount Amount to lock (P)
 * @param receiptDest Script for Receipt output (M1 bearer asset)
 * @param changeDest Script for M0 change (if any)
 * @param feeRate Fee rate in satoshis per byte
 * @return LockResult with constructed transaction
 */
LockResult BuildLockTransaction(
    const std::vector<LockInput>& inputs,
    CAmount lockAmount,
    const CScript& receiptDest,
    const CScript& changeDest,
    CAmount feeRate = 500);  // 0.5 sat/vB (1 M0 = 1 sat model)

/**
 * M1Input - M1 Receipt input for BuildUnlockTransaction (bearer model)
 */
struct M1Input
{
    COutPoint outpoint;     // M1 receipt UTXO
    CAmount amount;         // M1 amount
    CScript scriptPubKey;   // For signing
};

/**
 * VaultInput - Vault input for BuildUnlockTransaction (bearer model)
 *
 * No signature required - vaults use OP_TRUE script.
 * Consensus protects vault spending to TX_UNLOCK only.
 */
struct VaultInput
{
    COutPoint outpoint;     // Vault UTXO
    CAmount amount;         // M0 amount in vault
    // NOTE: No scriptPubKey needed - OP_TRUE requires no signature
};

/**
 * UnlockResult - Result from BuildUnlockTransaction (BP30 v2.1)
 */
struct UnlockResult
{
    bool success;
    std::string error;
    CMutableTransaction mtx;
    CAmount unlockedAmount;             // M0 output (vout[0])
    CAmount m1Burned;                   // Net M1 burned (M1_in - M1_change)
    CAmount m1Change;                   // M1 change amount (vout[1] if any)
    COutPoint m1ChangeOutpoint;         // M1 change receipt outpoint
    CAmount fee;
};

/**
 * BuildUnlockTransaction - Construct TX_UNLOCK (Bearer Asset Model)
 *
 * BP30 v3.0: M1 fee model - NO M0 FEE INPUTS REQUIRED.
 * Fee is paid in M1 (deducted from unlock amount).
 * This solves the UX deadlock where users with 0 M0 couldn't unlock.
 *
 * M1 is a bearer asset with partial unlock support.
 * Any M1 holder can burn M1 to claim M0 from any vault.
 *
 * Takes M1 receipts + vaults and creates:
 * - vin[0..N] = M1 Receipts (signed by M1 holders)
 * - vin[N+1..K] = Vaults (no signature - OP_TRUE)
 * - NO M0 fee inputs required
 * - vout[0] = M0 output (unlockAmount) - to user
 * - vout[1] = M1 change receipt (if any) - to user
 * - vout[2] = M1 fee (OP_TRUE) - claimable by block producer
 * - vout[3] = Vault backing for M1 fee (OP_TRUE) - preserves A6
 * - vout[4] = Vault change (if any excess)
 *
 * Conservation rule:
 *   sum(M1_in) == M0_out + M1_change + M1_fee
 *   Vault_in >= M0_out + M1_fee (fee needs backing)
 *
 * A6 Preservation:
 *   M1_fee is transferred to producer (not burned)
 *   Vault backing stays locked, so A6 (M0_vaulted == M1_supply) holds
 *
 * Security:
 *   M0_out + M1_fee <= sum(vaults) (cannot create from thin air)
 *
 * @param m1Inputs M1 receipt inputs
 * @param vaultInputs Vault inputs to claim M0 from
 * @param unlockAmount Amount of M0 to unlock (0 = unlock all minus fee)
 * @param destScript Destination for unlocked M0
 * @param changeScript Destination for M1 change (if any)
 * @param feeRate Fee rate in sat/kB (used to calculate M1 fee)
 * @return UnlockResult with constructed transaction and M1 fee info
 */
UnlockResult BuildUnlockTransaction(
    const std::vector<M1Input>& m1Inputs,
    const std::vector<VaultInput>& vaultInputs,
    CAmount unlockAmount,
    const CScript& destScript,
    const CScript& changeScript,
    CAmount feeRate = 500);

/**
 * TransferInput - M1 Receipt for transfer
 */
struct TransferInput
{
    COutPoint receiptOutpoint;
    CAmount amount;
    CScript scriptPubKey;
};

/**
 * TransferResult - Result from BuildTransferTransaction
 */
struct TransferResult
{
    bool success;
    std::string error;
    CMutableTransaction mtx;
    COutPoint newReceiptOutpoint;
};

/**
 * BuildTransferTransaction - Construct TX_TRANSFER_M1 (M1 Fee Model)
 *
 * BP30 v3.0: M1 fee model - NO M0 FEE INPUTS REQUIRED.
 * Fee is paid in M1 (deducted from transfer amount).
 * This solves the UX deadlock where users with 0 M0 couldn't transfer M1.
 *
 * Takes M1 Receipt and creates new Receipt at destination.
 * - vin[0] = M1 Receipt (mandatory, only input)
 * - vout[0] = New M1 Receipt (amount - fee, to newDest)
 * - vout[1] = M1 fee (OP_TRUE script, block producer claims)
 *
 * Conservation rule:
 *   receipt.amount == vout[0].nValue + vout[1].nValue (M1 fee)
 *
 * @param receipt M1 Receipt to transfer
 * @param newDest New owner's script
 * @param feeRate Fee rate in sat/kB (used to calculate M1 fee)
 * @return TransferResult with constructed transaction
 */
TransferResult BuildTransferTransaction(
    const TransferInput& receipt,
    const CScript& newDest,
    CAmount feeRate = 500);

/**
 * SplitOutput - Destination and amount for split operation
 */
struct SplitOutput
{
    CScript destination;    // Recipient address script
    CAmount amount;         // Amount for this recipient
};

/**
 * SplitResult - Result from BuildSplitTransaction
 */
struct SplitResult
{
    bool success;
    std::string error;
    CMutableTransaction mtx;
    std::vector<COutPoint> newReceipts;  // New receipt outpoints
    CAmount fee;                          // Implicit fee (input - sum(outputs))
};

/**
 * BuildSplitTransaction - Construct TX_TRANSFER_M1 with multiple outputs (split)
 *
 * BP30 v3.0: M1 fee model - NO M0 FEE INPUTS REQUIRED.
 * Split a single M1 receipt into multiple smaller receipts.
 * This enables partial unlocks in the UTXO model (like "making change").
 * Fee is paid in M1 (deducted from split, goes to block producer).
 *
 * STRICT M1 CONSERVATION: sum(recipient outputs) + M1_fee == receipt.amount
 *
 * - vin[0] = M1 Receipt (mandatory, only input)
 * - vout[0..N-1] = New M1 Receipts to recipients
 * - vout[N] = M1 fee (OP_TRUE script, block producer claims)
 *
 * @param receipt M1 Receipt to split
 * @param outputs Split destinations with amounts (sum + fee = receipt.amount)
 * @param feeRate Fee rate in sat/kB (used for M1 fee calculation)
 * @return SplitResult with constructed transaction
 */
SplitResult BuildSplitTransaction(
    const TransferInput& receipt,
    const std::vector<SplitOutput>& outputs,
    CAmount feeRate = 500);

#endif // SETTLEMENT_BUILDER_H
