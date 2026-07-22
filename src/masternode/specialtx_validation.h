// Copyright (c) 2017 The Dash Core developers
// Copyright (c) 2020-2022 The PIVX Core developers
// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_EVO_SPECIALTX_VALIDATION_H
#define BATHRON_EVO_SPECIALTX_VALIDATION_H

// HU: Legacy commitment validation removed
#include "validation.h" // cs_main
#include "version.h"

class CBlock;
class CBlockIndex;
class CCoinsViewCache;
class CValidationState;
class CTransaction;
class uint256;

/** The maximum allowed size of the extraPayload (for any TxType) */
static const unsigned int MAX_SPECIALTX_EXTRAPAYLOAD = 10000;

/** Payload validity checks (including duplicate unique properties against list at pindexPrev)*/
// Note: for +v2, if the tx is not a special tx, this method returns true.
// Note2: This function only performs extra payload related checks, it does NOT checks regular inputs and outputs.
bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache* view, CValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// Basic non-contextual checks for special txes
// Note: for +v2, if the tx is not a special tx, this method returns true.
bool CheckSpecialTxNoContext(const CTransaction& tx, CValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// F-HTLC-2 rollover-liveness guard.
//
// Some special-tx consensus rules are HEIGHT-MONOTONIC-TIGHTENING: once a tx is
// rejected by one at height H it is rejected at every height > H (its target
// expiry is fixed in the tx/record while the chain height only grows). Such a
// tx can be admitted to the mempool valid for the next block, then silently
// become permanently invalid as the tip advances — poisoning block templates
// (the DMM producer assembles with fTestValidity=false, so it would otherwise
// include it and produce a block ConnectBlock rejects).
//
// Returns true iff `tx` is a special tx that is PERMANENTLY invalid at `nHeight`
// for such a tightening rule. It re-runs the real Check* at `nHeight` and only
// reports the registered tightening reject reasons — premature/loosening
// rejects (e.g. refund "not-expired", which only ever enters the mempool
// already-valid and never tightens) and non-height rejects (same-block-pending
// parent "not-htlc", amount, etc.) return false: they are NOT this guard's
// concern and are left to normal inclusion timing / ConnectBlock. The exact
// consensus rule is NOT duplicated here — production Check* is the sole source
// of truth; this only interprets its reject reason. `strReason` gets the code.
bool IsSpecialTxHeightPermanentlyInvalid(const CTransaction& tx, const CCoinsViewCache& view,
                                         uint32_t nHeight, std::string& strReason) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// B4.4 O2b — fee-receipt destination covenant (ENFORCEMENT half). Caller gates it
// on UPGRADE_FEE_RECEIPT_PINNED. Exposed for the adversarial property test.
bool CheckFeeReceiptOwnerCovenant(const CTransaction& tx, CValidationState& state);

// Update internal tiertwo data when blocks containing special txes get connected/disconnected
// fSettlementOnly: if true, skip CheckSpecialTx and MN validation, only process settlement state (for rebuild)
bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, const CCoinsViewCache* view, CValidationState& state, bool fJustCheck, bool fSettlementOnly = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck = false);

// HU: Legacy commitment validation removed

uint256 CalcTxInputsHash(const CTransaction& tx);

template <typename T>
bool GetValidatedTxPayload(const CTransaction& tx, T& obj, CValidationState& state);

#endif // BATHRON_EVO_SPECIALTX_VALIDATION_H
