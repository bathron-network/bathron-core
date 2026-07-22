// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SETTLEMENT_H
#define SETTLEMENT_H

/**
 * Lock-Based Settlement v2 (P1-Only) - UTXO Receipt + Vault
 *
 * Ref: doc/blueprints/done/BP30-SETTLEMENT.md
 *
 * M0/M1 Model (P1):
 * - M0 = Native UTXO (standard transparent UTXO)
 * - M1 = Receipt UTXO (CEX-listable, backed by Vault)
 *
 * A6 Invariant (P1): M0_vaulted == M1_supply
 *
 * DB Keys (all use CDBBatch):
 * 'V' + outpoint        -> VaultEntry
 * 'R' + outpoint        -> M1Receipt
 * 'G' + height          -> SettlementState (snapshots)
 * 'U' + txid            -> UnlockUndoData (BP30 v2.1)
 * 'T' + txid            -> TransferUndoData (BP30 v2.2)
 * 'B'                   -> Best block hash (DB consistency)
 */

#include "amount.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "serialize.h"
#include "uint256.h"

#include <stdint.h>

// DB Key prefixes (P1 active)
static const char DB_VAULT = 'V';
static const char DB_RECEIPT = 'R';
static const char DB_SETTLEMENT_STATE = 'G';
static const char DB_UNLOCK_UNDO = 'U';  // BP30 v2.1: Unlock undo data (keyed by txid)
static const char DB_TRANSFER_UNDO = 'T';  // BP30 v2.2: Transfer undo data (keyed by txid)
static const char DB_UNDO_PRUNE_SCHED = 'P';  // GC schedule: (height, txid) -> undoType (0=unlock,1=transfer)
static const char DB_FEE_OWNER = 'F';  // B4.4 O2b: fee-receipt outpoint -> owner CScript (including block's coinbase vout[0])

// GC of TX_UNLOCK/TX_TRANSFER_M1 undo data. Undo records (keyed by txid) are
// written on every unlock/transfer and erased only on reorg-disconnect, so they
// accumulate forever on the forward chain (a monotonic leak even under honest use,
// and an amplifier under settlement spam). They are read ONLY by
// UndoSpecialTxsInBlock, so once a tx is deeper than any possible reorg its undo
// data is dead weight and safe to erase. Same reorg-safety argument and margin as
// HTLC_PRUNE_DEPTH (HU finality makes >~1-block reorgs impossible; 100 blocks is a
// large margin). Deterministic + consensus-neutral (never changes block validity).
static const uint32_t SETTLEMENT_UNDO_PRUNE_DEPTH = 100;
static const char DB_BEST_BLOCK = 'B';  // BP30 v2.2: Best block hash for DB consistency
static const char DB_ALL_COMMITTED = 'A';  // ATOMICITY FIX: All DBs committed marker
static const char DB_BURNSCAN_HEIGHT = 'H';  // F3: Last processed BTC height for burnscan
static const char DB_BURNSCAN_HASH = 'Z';  // F3: Last processed BTC block hash for reorg detection

/**
 * VaultEntry - M0 UTXO locked to back M1 supply (bearer asset model)
 *
 * A Vault is created by TX_LOCK and destroyed by TX_UNLOCK.
 * Vaults form a communal pool backing the total M1 supply.
 * Any M1 holder can burn M1 to claim M0 from any vault.
 *
 * BP30 v2.0 (Bearer Asset):
 * - Vault uses OP_TRUE script (anyone-can-spend)
 * - Consensus rule: vault spend allowed ONLY via TX_UNLOCK
 * - No link to specific receipt - all vaults back all M1
 * - No unlock key needed - M1 ownership is sufficient
 */
struct VaultEntry
{
    COutPoint outpoint;          // 36 bytes - Vault UTXO location
    CAmount amount;              // 8 bytes - M0 amount locked
    uint32_t nLockHeight;        // 4 bytes - Block where locked
    // NOTE: No receiptOutpoint or unlockPubKey - bearer asset model

    VaultEntry() { SetNull(); }

    void SetNull()
    {
        outpoint.SetNull();
        amount = 0;
        nLockHeight = 0;
    }

    bool IsNull() const { return outpoint.IsNull(); }

    SERIALIZE_METHODS(VaultEntry, obj)
    {
        READWRITE(obj.outpoint);
        READWRITE(obj.amount);
        READWRITE(obj.nLockHeight);
    }
};

/**
 * M1Receipt - Receipt UTXO (CEX-listable, bearer asset)
 *
 * BP30 v2.0 (Bearer Asset Model):
 * - Created by TX_LOCK (alongside a Vault)
 * - Transferable via TX_TRANSFER_M1
 * - Burned by TX_UNLOCK to claim M0 from ANY vault
 *
 * M1 is a bearer asset: whoever holds the M1 UTXO can burn it.
 * No link to specific vault - all vaults back all M1.
 */
struct M1Receipt
{
    COutPoint outpoint;          // 36 bytes - Receipt UTXO location
    CAmount amount;              // 8 bytes - M1 amount
    uint32_t nCreateHeight;      // 4 bytes - Block where created
    // NOTE: No vaultOutpoint - bearer asset model (any vault can be used)

    M1Receipt() { SetNull(); }

    void SetNull()
    {
        outpoint.SetNull();
        amount = 0;
        nCreateHeight = 0;
    }

    bool IsNull() const { return outpoint.IsNull(); }

    SERIALIZE_METHODS(M1Receipt, obj)
    {
        READWRITE(obj.outpoint);
        READWRITE(obj.amount);
        READWRITE(obj.nCreateHeight);
    }
};

/**
 * UnlockUndoData - Data required for UndoUnlock (BP30 v2.2)
 *
 * Must capture all state to restore on reorg:
 * - All M1Receipts consumed (from vin)
 * - All VaultEntries consumed (from vin)
 * - M1 change receipts created (at vout[1])
 * - Vault change created (at vout[2] if OP_TRUE)
 * - M0 released and net M1 burned for state restoration
 */
struct UnlockUndoData
{
    std::vector<M1Receipt> receiptsSpent;   // M1 receipts consumed
    std::vector<VaultEntry> vaultsSpent;    // Vaults consumed
    CAmount m0Released;                      // M0 output (vout[0].nValue)
    CAmount netM1Burned;                     // M1_in - M1_change
    uint32_t changeReceiptsCreated;          // Number of M1 change outputs (vout[1])
    bool vaultChangeCreated;                 // BP30 v2.2: vault change at vout[2]
    COutPoint vaultChangeOutpoint;           // BP30 v2.2: vault change location

    UnlockUndoData() : m0Released(0), netM1Burned(0), changeReceiptsCreated(0), vaultChangeCreated(false) {}

    SERIALIZE_METHODS(UnlockUndoData, obj)
    {
        READWRITE(obj.receiptsSpent, obj.vaultsSpent);
        READWRITE(obj.m0Released, obj.netM1Burned, obj.changeReceiptsCreated);
        READWRITE(obj.vaultChangeCreated, obj.vaultChangeOutpoint);
    }
};

/**
 * TransferUndoData - Data required for UndoTransfer (BP30 v2.3)
 *
 * Must capture original receipt and number of M1 outputs to restore on reorg.
 * Required because transfer mode (external fees) and split mode differ.
 *
 * BP30 v2.3:
 * - Transfer mode (vin.size() > 1): only vout[0] is M1, numM1Outputs = 1
 * - Split mode (vin.size() == 1): all vouts are M1, numM1Outputs = vout.size()
 */
struct TransferUndoData
{
    M1Receipt originalReceipt;               // Original receipt consumed
    uint32_t numM1Outputs;                   // Number of M1 receipts created (v2.3)

    TransferUndoData() : numM1Outputs(0) {}

    SERIALIZE_METHODS(TransferUndoData, obj)
    {
        READWRITE(obj.originalReceipt);
        READWRITE(obj.numM1Outputs);
    }
};

/**
 * SettlementState - Settlement layer state snapshot
 *
 * Stored at 'G' + height for quick access.
 *
 * Consensus Invariants:
 *   A5: M0_total_supply(N) = M0_total_supply(N-1) + BurnClaims
 *       (Monetary conservation - M0 only created from BTC burns)
 *   A6: M0_vaulted == M1_supply
 *       (Settlement backing - all M1 fully backed by vaulted M0)
 */
struct SettlementState
{
    CAmount M0_vaulted;          // M0 in active Vaults (backing M1)
    CAmount M1_supply;           // M1 receipts in circulation
    CAmount M0_shielded;         // Informative: Sapling Z-funds (orthogonal to settlement)

    // A5 Monetary Conservation fields
    CAmount M0_total_supply;     // Total M0 in circulation (cumulative)
    CAmount burnclaims_block;    // M0BTC minted this block from TX_MINT_M0BTC (BP11)

    // Block linkage
    uint32_t nHeight;
    uint256 hashBlock;

    SettlementState() { SetNull(); }

    void SetNull()
    {
        M0_vaulted = 0;
        M1_supply = 0;
        M0_shielded = 0;
        M0_total_supply = 0;
        burnclaims_block = 0;
        nHeight = 0;
        hashBlock.SetNull();
    }

    bool IsNull() const { return nHeight == 0 && hashBlock.IsNull(); }

    /**
     * CheckInvariants - Verify settlement layer invariants
     *
     * A6: M0_vaulted == M1_supply
     */
    bool CheckInvariants() const
    {
        // All amounts must be non-negative
        if (M0_vaulted < 0 || M1_supply < 0) {
            return false;
        }

        // A6: M0 backing == M1
        if (M0_vaulted != M1_supply) {
            return false;
        }

        return true;
    }

    /**
     * CheckA5 - Verify A5 monetary conservation against previous state
     *
     * A5: M0_total_supply(N) = M0_total_supply(N-1) + BurnClaims
     *
     * This prevents ANY inflation attack, even if 90% of MNs are compromised.
     * M0 can ONLY be created through BTC burns (TX_MINT_M0BTC).
     * Block reward = 0 (M0 supply from BTC burns only).
     *
     * @param prevState Previous block's settlement state
     * @return true if A5 holds, false if monetary conservation violated
     */
    bool CheckA5(const SettlementState& prevState) const
    {
        // Formula: M0_supply(N) = M0_supply(N-1) + BurnClaims
        CAmount expected = prevState.M0_total_supply + burnclaims_block;
        return M0_total_supply == expected;
    }

    /**
     * GetA5Delta - Get the expected supply delta for this block
     *
     * @return BurnClaims (only source of new M0)
     */
    CAmount GetA5Delta() const
    {
        return burnclaims_block;
    }

    SERIALIZE_METHODS(SettlementState, obj)
    {
        READWRITE(obj.M0_vaulted);
        READWRITE(obj.M1_supply);
        READWRITE(obj.M0_shielded);
        READWRITE(obj.M0_total_supply);
        READWRITE(obj.burnclaims_block);
        READWRITE(obj.nHeight);
        READWRITE(obj.hashBlock);
    }
};

#endif // SETTLEMENT_H
