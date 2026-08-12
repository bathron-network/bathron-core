// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_MASTERNODE_LEASE_RENEWER_H
#define BATHRON_MASTERNODE_LEASE_RENEWER_H

#include "amount.h"
#include "operationresult.h"
#include "uint256.h"

#include <string>

class CKey;
class CScheduler;
class CWallet;

/**
 * LOT 9 M3 — operator lease construction and monitoring.
 *
 * The lease is a DECLARATION OF PRESENCE that expires: every identity gets
 * `nLeaseExpiryHeight = registrationHeight + nOperatorLeaseBlocks` at
 * registration, and only a valid TX_OPERATOR_LEASE moves it. Consensus derives
 * the new expiry from the INCLUSION height — the operator never chooses it.
 *
 * An expired lease drops the identity from the epoch productionSet AND, since
 * hu::GetEpochFinalityOperators derives N from that same set, from the finality
 * population. Enough expiries and the threshold becomes unreachable: the chain
 * keeps producing (the recoverySet holds every confirmed identity) but never
 * finalizes again. Renewal is therefore not optional maintenance — it is what
 * keeps the finality population alive.
 *
 * Two ways to renew, one construction path (BuildAndSendLeaseRenewal):
 *   * `protx_renew_lease` — the manual primitive. Always available, and the ONLY
 *     route for a lease that already expired while the node was down, an
 *     operator key held offline, or a payer wallet that is not the operator
 *     (consensus explicitly allows payer != operator).
 *   * `-leaseautorenew=1` — the daemon renews on its own, starting at a
 *     deterministically jittered height inside [expiry - L/2, expiry - L/4)
 *     (see LeaseRenewalStartHeight). OPT-IN: it requires a funded, unlocked
 *     wallet on the operator node, which is an operational-security decision
 *     the operator must make deliberately, so it is never a default.
 *
 * The monitor itself runs whenever the node is a masternode, auto-renewal or
 * not: a lease drifting toward expiry is logged loudly either way, because a
 * silent renewal failure and no renewal at all have the same ending.
 */

/** Seconds between monitor passes. */
static const int DEFAULT_LEASE_RENEW_INTERVAL = 300;
/** Auto-renewal is OPT-IN — a daemon that spends funds by itself is not a default. */
static const bool DEFAULT_LEASE_AUTORENEW = false;

/**
 * Last auto-renewal attempt for one identity — the observability a failing
 * renewal owes its operator. A silent failure and no renewal at all have the
 * same ending (the identity leaves the production and finality sets), so every
 * attempt and every skip is recorded here and surfaced by `getactivemnstatus`.
 */
struct LeaseAutoRenewStatus {
    int nLastAttemptHeight{-1};      //!< tip height of the last attempt/skip (-1 = never)
    int64_t nLastAttemptTime{0};     //!< unix time of the last attempt/skip
    bool fLastSuccess{false};        //!< the last attempt broadcast a renewal
    std::string strLastReason;       //!< classified: "success", "pending-in-mempool",
                                     //!< "wallet-locked", "no-wallet", "operator-key-not-loaded",
                                     //!< "insufficient-funds", "fee-below-minimum", "tx-rejected", ...
    std::string strLastError;        //!< human-readable detail of the last failure
    uint256 lastTxid;                //!< txid of the last successful renewal
};

/** Read the last auto-renewal attempt for `proTxHash`. False if none recorded. */
bool GetLeaseAutoRenewStatus(const uint256& proTxHash, LeaseAutoRenewStatus& out);

/**
 * The height at which AUTOMATIC renewal of this lease begins — deterministically
 * staggered so that operators registered in the same window (the genesis case:
 * every initial lease expires at nearly the same height) do not all broadcast in
 * the same block.
 *
 *   renewalWindowStart  = expiry - L/2
 *   renewalWindowLength = L/4
 *   jitter = H("BATHRON_LEASE_RENEWAL_JITTER_V1" || genesisHash || proTxHash
 *              || nextSequence) mod renewalWindowLength
 *   start  = renewalWindowStart + jitter
 *
 * The start therefore falls in [expiry - L/2, expiry - L/4): even the latest
 * jitter leaves a safety margin of L/4 blocks (~1.75 days at the shipped 10080
 * blocks / 60 s) for the operator to see a failing renewal and fix it by hand.
 * Deterministic on purpose: no RNG in anything consensus-adjacent, and the
 * schedule is reproducible for tests and post-mortems. The MANUAL RPC is never
 * gated by this — it works at any height.
 */
int LeaseRenewalStartHeight(const uint256& genesisHash, const uint256& proTxHash,
                            uint32_t nextSequence, int expiryHeight, int horizonBlocks);

/**
 * Funding rate for a lease, in sat/kB — DERIVED from the consensus floor
 * (ComputeMinM1Fee) times a documented margin, never a restated constant.
 */
CAmount LeaseFundingFeeRatePerK();

#ifdef ENABLE_WALLET
/**
 * Build, fund, sign and broadcast a TX_OPERATOR_LEASE renewing `proTxHash`.
 *
 * The sequence is read from the chain tip and advanced by exactly one (consensus
 * rejects anything else with `bad-lease-sequence`); the payload is signed with
 * `operatorKey` over the domain-separated, chain-bound message; the fee is paid
 * by `pwallet` and must clear the shared settlement minimum.
 *
 * This is the ONE place a lease transaction is constructed — the RPC and the
 * auto-renewer both call it, so they can never diverge.
 *
 * On failure, `failReasonOut` (optional) receives a CLASSIFIED slug — the same
 * vocabulary LeaseAutoRenewStatus::strLastReason uses — so callers can expose
 * "why" without parsing the human message.
 */
OperationResult BuildAndSendLeaseRenewal(CWallet* pwallet, const uint256& proTxHash,
                                         const CKey& operatorKey, uint256& txidOut,
                                         std::string* failReasonOut = nullptr);
#endif // ENABLE_WALLET

/** Schedule the periodic lease monitor (and auto-renewal, if enabled). */
void InitOperatorLeaseMonitor(CScheduler& scheduler);

/** Stop the periodic lease monitor. */
void ShutdownOperatorLeaseMonitor();

#endif // BATHRON_MASTERNODE_LEASE_RENEWER_H
