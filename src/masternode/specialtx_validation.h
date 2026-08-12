// Copyright (c) 2017 The Dash Core developers
// Copyright (c) 2020-2022 The PIVX Core developers
// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_EVO_SPECIALTX_VALIDATION_H
#define BATHRON_EVO_SPECIALTX_VALIDATION_H

// HU: Legacy commitment validation removed
#include <functional>
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
// LOT 7 (L6-F16) — which derived DB(s) a special tx's validity DEPENDS ON. The
// gate CheckLocalStateConsistency below runs only for reads against these DBs.
enum class LocalStateDB { NONE = 0, SETTLEMENT = 1, HTLC = 2, BOTH = 3 };

/**
 * LOT 7 (L6-F16) — the central local-state consistency gate.
 *
 * The settlement/HTLC checks read DERIVED, node-LOCAL databases. PHASE 1 measured
 * that in normal operation ReadBestBlock() of both DBs equals pindexPrev at read
 * time (deferred batch, committed only at PHASE C). So:
 *   - marker == pindexPrev  -> the DB IS the canonical parent state; a present or
 *     ABSENT record is authoritative, and the caller's real consensus check stands;
 *   - marker missing / read fails / marker != parent -> the DB is behind or torn,
 *     a purely LOCAL fact that must NEVER become block invalidity or a peer ban.
 *
 * On a local inconsistency: on the block-connect path it fires the LOT 1 fatal
 * latch (AbortConsensusDBState) so the node halts and demands -reindex instead of
 * silently retrying; on the mempool/RPC path it returns a non-persisting state.Error
 * (the tx is simply not accepted, no ban). Beyond genesis, an empty DB under a real
 * parent is a local inconsistency, not a free pass.
 *
 * GENESIS BOUNDARY is the one exemption: the best-block marker is written only by a
 * block's own commit, so at the genesis parent (nHeight==0) it is legitimately ABSENT
 * on a fresh / -reindex-replayed chain (both DBs' startup checks document "no marker is
 * normal, set on next connect"), and no settlement/HTLC record can predate block 1 —
 * so block-1 validation returns true. Without this the gate fatal-latched block 1 of
 * every fresh chain.
 *
 * `need`==NONE or pindexPrev==null (non-contextual CheckBlock, where DB reads are
 * skipped anyway) -> returns true.
 */
bool CheckLocalStateConsistency(const CBlockIndex* pindexPrev, LocalStateDB need,
                                bool fBlockConnect, CValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache* view, CValidationState& state, bool fBlockConnect = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * LOT 8 — architecture C: full-chain A5 audit (EXPLICIT, never automatic).
 *
 * Recomputes, from the CANONICAL blocks on disk only (never trusting the
 * accumulators it audits): every TX_BURN_CLAIM's parsed burnedSats, every
 * PENDING->FINAL transition driven by a TX_MINT_M0BTC payload, the Σ of mint
 * outputs (auditS) and the Σ of finalized burn amounts (auditL) — then reads the
 * two live accumulators (settlement M0_total_supply, burnclaim m0btcSupply) for
 * comparison by the caller. If any block is unreadable (pruned/missing) or a
 * payload undecodable, fComplete=false with the reason: the caller must report
 * UNAVAILABLE/UNVERIFIED, NEVER "verified".
 *
 * SCOPE (honest): this audits the node's LOCAL canonical chain. It does NOT
 * re-verify the Bitcoin burns against the live BTC network (this codebase has no
 * BTC P2P client; burn authenticity rests on the operator-published header chain,
 * cf. the findings register). On regtest it runs against harness burns (Route C) —
 * NEVER real mainnet BTC.
 */
struct A5AuditResult {
    bool fComplete = false;          //!< every block read and every payload decoded
    std::string strError;            //!< why incomplete (when !fComplete)
    CAmount auditS = 0;              //!< recomputed Σ TX_MINT_M0BTC outputs
    CAmount auditL = 0;              //!< recomputed Σ finalized burnedSats
    CAmount dbS = -1;                //!< live settlement M0_total_supply
    CAmount dbL = -1;                //!< live burnclaim m0btcSupply
    bool haveDbS = false;
    bool haveDbL = false;
    int nBlocksScanned = 0;
    int nClaimsSeen = 0;             //!< TX_BURN_CLAIM parsed
    int nMintsSeen = 0;              //!< TX_MINT_M0BTC processed
    int nUnknownMintRefs = 0;        //!< mint payload txids with no matching claim
};
bool AuditA5Supply(A5AuditResult& out) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

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
//
// LOT 9 final: TX_OPERATOR_LEASE is covered as the STATE-monotonic analogue —
// the operator's on-chain lease sequence only grows along a chain, so a renewal
// at a sequence <= the current one ("bad-lease-sequence-stale") is permanently
// dead here. It is classified by decoding (payload vs the list at the tip), not
// by probing CheckOperatorLeaseTx: no signature work on this hot path, and a
// PREMATURE sequence (reorg-revivable) must return false, which the production
// Check's single "bad-lease-sequence" reject cannot distinguish.
bool IsSpecialTxHeightPermanentlyInvalid(const CTransaction& tx, const CCoinsViewCache& view,
                                         uint32_t nHeight, std::string& strReason) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// B4.4 O2b — fee-receipt destination covenant (ENFORCEMENT half). Caller gates it
// on UPGRADE_FEE_RECEIPT_PINNED. Exposed for the adversarial property test.
bool CheckFeeReceiptOwnerCovenant(const CTransaction& tx, CValidationState& state);

// Update internal tiertwo data when blocks containing special txes get connected/disconnected
// fSettlementOnly: if true, skip CheckSpecialTx and MN validation, only process settlement state (for rebuild)
/**
 * Commit strategy for the final multi-DB commit phase (LOT 1 round 7).
 *
 * Production passes nullptr and every batch commits directly — there is NO runtime
 * flag, no RPC and no startup argument that can alter this, so release behaviour is
 * not configurable. Tests inject a strategy to make the Nth Commit() return false and
 * assert that the function fails loudly rather than reporting a partial success.
 *
 * `step` is the commit index in order: 1 settlement, 2 btcheaders, 3 htlc,
 * 4 burnclaim, 5 all-committed marker.
 */
//! Outcome of the terminal multi-DB commit phase (LOT 1 round 14).
enum class CommitPhaseResult {
    SUCCESS,
    FAILED_BEFORE_ANY_COMMIT,   //!< nothing durable; the block/undo can be cleanly abandoned
    FAILED_AFTER_PARTIAL_COMMIT //!< some DBs are ahead of others — local storage is torn
};

struct ConsensusCommitStrategy {
    virtual ~ConsensusCommitStrategy() = default;

    //! OBSERVATION-ONLY notification of the abort (LOT 1 round 15). Whether or not a
    //! strategy is injected, EVERY commit failure first goes through the single fatal
    //! primitive AbortConsensusDBState (validation.h): process-local latch, first
    //! context preserved, real AbortNode, shutdown request. This hook merely lets a
    //! test RECORD that it happened (step, partial flag, message); it runs AFTER the
    //! primitive and cannot veto, replace or soften it. PURE VIRTUAL on purpose: there
    //! is no base no-op, so no strategy can silently discard the notification.
    virtual void Abort(int step, bool partial, const std::string& msg) = 0;
    //! Return what the real commit should return; may substitute false to inject a failure.
    virtual bool Commit(int step, const std::function<bool()>& realCommit) = 0;

    //! STAGE-PHASE injection (LOT 2, restoring a LOT 1 guard). Forces the last
    //! fallible pre-commit step (PHASE B, ConnectMintM0BTC) to fail.
    //!
    //! Why this exists: the round-11 invariant is "nothing fallible runs after the
    //! first Commit()". LOT 1 guarded it with a block whose mint failed at STAGING —
    //! reachable only because -enablemint=0 skipped CheckMintM0BTC. LOT 2 removed
    //! that bypass, so no input can make staging fail any more and the guard went
    //! blind (proven by mutation: moving the staging step back into the commit phase
    //! kept the suite green). This hook restores a failure at exactly that point, so
    //! a test can assert NO commit step was reached — which fails loudly if the step
    //! is ever moved below the commit boundary.
    //!
    //! Default false = no injection. Production passes NO strategy at all.
    virtual bool ForceStagingFailure() { return false; }
};

bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, const CCoinsViewCache* view, CValidationState& state, bool fJustCheck, bool fSettlementOnly = false, ConsensusCommitStrategy* commitStrategy = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck = false, ConsensusCommitStrategy* commitStrategy = nullptr);

// HU: Legacy commitment validation removed

uint256 CalcTxInputsHash(const CTransaction& tx);

//! LOT 9 M3 — at most one TX_OPERATOR_LEASE per proTxHash per block
//! (order-independent whole-block scan; reason bad-lease-duplicate-in-block).
bool CheckNoDuplicateOperatorLeasesInBlock(const std::vector<std::shared_ptr<const CTransaction>>& vtx,
                                           CValidationState& state);

template <typename T>
bool GetValidatedTxPayload(const CTransaction& tx, T& obj, CValidationState& state);

#endif // BATHRON_EVO_SPECIALTX_VALIDATION_H
