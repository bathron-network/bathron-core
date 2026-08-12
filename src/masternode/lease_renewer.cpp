// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/lease_renewer.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "logging.h"
#include "masternode/activemasternode.h"
#include "masternode/deterministicmns.h"
#include "masternode/providertx.h"
#include "masternode/specialtx_validation.h"
#include "messagesigner.h"
#include "net/net.h"
#include "policy/feerate.h"
#include "primitives/transaction.h"
#include "scheduler.h"
#include "state/settlement_logic.h"
#include "txmempool.h"
#include "util/system.h"
#include "util/validation.h"
#include "utiltime.h"
#include "validation.h"
#include "version.h"

#ifdef ENABLE_WALLET
#include "script/sign.h"
#include "wallet/wallet.h"
#endif

#include <atomic>
#include <map>
#include <mutex>

static std::mutex g_leaseMutex;
static std::atomic<bool> g_leaseMonitorEnabled{false};
static std::atomic<bool> g_leaseAutoRenew{false};

//! Blocks between two warnings about the same identity — one per hour at the
//! 60 s spacing. Loud enough to be seen, quiet enough not to drown the log.
static const int LEASE_WARN_EVERY_BLOCKS = 60;

//! Margin multiplier over the consensus fee floor. The fee is estimated by the
//! wallet on the UNSIGNED payload, while the O-5 rule is applied to the SIGNED
//! transaction (~65 bytes larger) — 2× would already cover that; 4× also absorbs
//! rounding and a change in input count without ever mattering in absolute terms
//! (a few dozen sats per renewal, once per horizon). The signed-size recheck in
//! BuildAndSendLeaseRenewal stays authoritative regardless of this margin.
static const int LEASE_FEE_MARGIN_MULTIPLIER = 4;

CAmount LeaseFundingFeeRatePerK()
{
    // ComputeMinM1Fee(1000) IS the consensus floor expressed per kB (O-5,
    // 50 sat/kB today). Derive from the shared rule rather than restating the
    // number, so a change of the floor cannot silently strand this builder
    // below it.
    return ComputeMinM1Fee(1000) * LEASE_FEE_MARGIN_MULTIPLIER;
}

int LeaseRenewalStartHeight(const uint256& genesisHash, const uint256& proTxHash,
                            uint32_t nextSequence, int expiryHeight, int horizonBlocks)
{
    // Window = [expiry - L/2, expiry - L/4): the earliest start leaves half the
    // horizon, the LATEST still leaves L/4 blocks of safety margin before
    // expiry. See the header for the rationale.
    const int windowStart = expiryHeight - horizonBlocks / 2;
    const int windowLength = std::max(1, horizonBlocks / 4);
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << std::string("BATHRON_LEASE_RENEWAL_JITTER_V1");
    ss << genesisHash;
    ss << proTxHash;
    ss << nextSequence;
    const uint64_t jitter = ss.GetHash().GetUint64(0) % (uint64_t)windowLength;
    return windowStart + (int)jitter;
}

//! proTxHash -> chain height at which we last warned about it.
static std::map<uint256, int> g_lastWarnHeight;

//! proTxHash -> last auto-renewal attempt/skip. Guarded by g_leaseMutex.
static std::map<uint256, LeaseAutoRenewStatus> g_autoRenewStatus;

bool GetLeaseAutoRenewStatus(const uint256& proTxHash, LeaseAutoRenewStatus& out)
{
    std::lock_guard<std::mutex> lock(g_leaseMutex);
    auto it = g_autoRenewStatus.find(proTxHash);
    if (it == g_autoRenewStatus.end()) return false;
    out = it->second;
    return true;
}

//! Record an attempt/skip. Caller must hold g_leaseMutex (LeaseMonitorPass does).
static void RecordAutoRenewAttempt(const uint256& proTxHash, int height, bool success,
                                   const std::string& reason, const std::string& detail,
                                   const uint256& txid = uint256())
{
    LeaseAutoRenewStatus& st = g_autoRenewStatus[proTxHash];
    st.nLastAttemptHeight = height;
    st.nLastAttemptTime = GetTime();
    st.fLastSuccess = success;
    st.strLastReason = reason;
    st.strLastError = detail;
    if (success) st.lastTxid = txid;
}

#ifdef ENABLE_WALLET

OperationResult BuildAndSendLeaseRenewal(CWallet* pwallet, const uint256& proTxHash,
                                         const CKey& operatorKey, uint256& txidOut,
                                         std::string* failReasonOut)
{
    // Classified failure slug + human message, in one move. The slug vocabulary
    // is what LeaseAutoRenewStatus/getactivemnstatus surface.
    const auto fail = [&](const char* slug, const std::string& msg) {
        if (failReasonOut) *failReasonOut = slug;
        return errorOut(msg);
    };

    if (!pwallet) {
        return fail("no-wallet", "no wallet available to pay the lease fee");
    }
    if (pwallet->IsLocked()) {
        return fail("wallet-locked", "the fee wallet is locked; unlock it to renew");
    }
    if (!operatorKey.IsValid()) {
        return fail("invalid-operator-key", "invalid operator key");
    }
    if (!deterministicMNManager) {
        return fail("mn-manager-unavailable", "masternode manager not available");
    }

    // The identity and its CURRENT sequence are chain facts, read at the tip.
    auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(proTxHash);
    if (!dmn) {
        return fail("identity-not-found",
                    strprintf("masternode with hash %s not found", proTxHash.ToString()));
    }

    // Fail fast on a key that cannot possibly produce an accepted renewal, so the
    // operator gets a clear message instead of a consensus reject code.
    if (operatorKey.GetPubKey().GetID() != dmn->pdmnState->pubKeyOperator.GetID()) {
        return fail("wrong-operator-key",
                    strprintf("the supplied key is not the current operator key of %s",
                              proTxHash.ToString()));
    }

    OperatorLeasePL pl;
    pl.nVersion = OperatorLeasePL::CURRENT_VERSION;
    pl.proTxHash = proTxHash;
    // Strictly increasing, EXACTLY previous + 1 — consensus rejects anything else
    // (`bad-lease-sequence`), which is what makes replays structurally dead.
    pl.nLeaseSequence = dmn->pdmnState->nLeaseSequence + 1;

    CMutableTransaction tx;
    tx.nVersion = CTransaction::TxVersion::SAPLING;
    tx.nType = CTransaction::TxType::TX_OPERATOR_LEASE;

    // ── Fund ────────────────────────────────────────────────────────────────
    // NOTE: the generic FundSpecialTx helper in rpc/rpcevo.cpp cannot be reused
    // here. It ends with UpdateSpecialTxInputsHash(), which assigns
    // payload.inputsHash — and OperatorLeasePL deliberately has NO inputsHash
    // field (the payload carries only version/proTxHash/sequence, and replay is
    // killed by the sequence rule instead). Everything else mirrors it.
    SetTxPayload(tx, pl);

    static CTxOut dummyTxOut(0, CScript() << OP_RETURN);
    bool dummyTxOutAdded = false;
    if (tx.vout.empty()) {
        // CreateTransaction requires at least one recipient.
        tx.vout.emplace_back(dummyTxOut);
        dummyTxOutAdded = true;
    }

    // MEASURED: letting the wallet estimate the fee (what the other protx RPCs do)
    // produces `bad-lease-fee` on a fresh regtest chain — the estimator has no data
    // and legitimately returns zero, while the lease must clear the CONSENSUS
    // minimum of O-5 (ComputeMinM1Fee, 50 sat/kB). The other provider payloads
    // never noticed because no consensus rule prices them. So fund at an EXPLICIT
    // rate DERIVED from the consensus floor (LeaseFundingFeeRatePerK — floor ×
    // documented margin, see LEASE_FEE_MARGIN_MULTIPLIER), which dominates both
    // the relay minimum and the consensus rule even after the ~65-byte operator
    // signature is appended post-funding (the fee is estimated on the unsigned
    // payload, the rule is applied to the signed one — rechecked below).
    CAmount nFee;
    CFeeRate feeRate = CFeeRate(LeaseFundingFeeRatePerK());
    if (::minRelayTxFee.GetFeePerK() > feeRate.GetFeePerK()) {
        feeRate = ::minRelayTxFee;
    }
    int nChangePos = -1;
    std::string strFailReason;
    if (!pwallet->FundTransaction(tx, nFee, /*overrideEstimatedFeeRate=*/true, feeRate,
                                  nChangePos, strFailReason, false, false, {})) {
        const bool insufficient = strFailReason.find("Insufficient funds") != std::string::npos;
        return fail(insufficient ? "insufficient-funds" : "funding-failed", strFailReason);
    }

    if (dummyTxOutAdded && tx.vout.size() > 1) {
        // FundTransaction added a change output, so the dummy is no longer needed.
        auto it = std::find(tx.vout.begin(), tx.vout.end(), dummyTxOut);
        if (it != tx.vout.end()) {
            tx.vout.erase(it);
        }
    }

    // ── Sign the payload ────────────────────────────────────────────────────
    // NOT ::SerializeHash(payload) (what SignSpecialTxPayloadByHash does for the
    // other provider payloads): the lease message is domain-separated AND bound
    // to the chain identity, so a lease signed for another chain cannot be
    // replayed here.
    pl.vchSig.clear();
    const uint256 sigHash = pl.GetSignatureHash(Params().GetConsensus().hashGenesisBlock);
    if (!CHashSigner::SignHash(sigHash, operatorKey, pl.vchSig)) {
        return fail("payload-sign-failed", "failed to sign the operator lease payload");
    }
    SetTxPayload(tx, pl);

    // The consensus rule is applied to the SIGNED transaction, so RECOMPUTE the
    // minimum on the signed size here rather than trusting the funding estimate.
    // Refusing with the two numbers beats broadcasting something the mempool
    // answers with a bare `bad-lease-fee`.
    {
        const CAmount minFee = ComputeMinM1Fee(::GetSerializeSize(CTransaction(tx), PROTOCOL_VERSION));
        if (nFee < minFee) {
            return fail("fee-below-minimum",
                        strprintf("funded fee %d is below the consensus lease minimum %d "
                                  "(O-5); raise -paytxfee or fund from a wallet with more M0",
                                  nFee, minFee));
        }
    }

    // ── Pre-flight, sign inputs, submit ─────────────────────────────────────
    {
        LOCK(cs_main);
        CValidationState state;
        CCoinsViewCache view(pcoinsTip.get());
        if (!CheckSpecialTx(CTransaction(tx), chainActive.Tip(), &view, state)) {
            return fail("preflight-rejected", FormatStateMessage(state));
        }
    }

    // Resolve the funded inputs through a MEMPOOL-BACKED view, not pcoinsTip
    // alone: when this wallet renewed another of its identities moments ago,
    // that renewal's change is a legitimate funding source the wallet tracks —
    // but it lives in the mempool, not in the confirmed UTXO set, and a
    // confirmed-only lookup refuses the chained renewal as "spent" (measured on
    // a multi-identity daemon). Coins are copied out first so the signing pass
    // below takes cs_wallet without ever nesting it with mempool.cs.
    std::map<COutPoint, Coin> spentCoins;
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache view(pcoinsTip.get());
        CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);
        view.SetBackend(viewMempool);
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            const Coin& coin = view.AccessCoin(tx.vin[i].prevout);
            if (coin.IsSpent()) {
                return fail("input-spent", strprintf("input %d (%s) not found or already spent",
                                                     i, tx.vin[i].prevout.ToStringShort()));
            }
            spentCoins.emplace(tx.vin[i].prevout, coin);
        }
    }

    {
        LOCK2(cs_main, pwallet->cs_wallet);
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            CTxIn& txin = tx.vin[i];
            const Coin& coin = spentCoins.at(txin.prevout);
            SigVersion sv = tx.GetRequiredSigVersion();
            txin.scriptSig.clear();
            SignatureData sigdata;
            if (!ProduceSignature(MutableTransactionSignatureCreator(pwallet, &tx, i,
                                                                     coin.out.nValue, SIGHASH_ALL),
                                  coin.out.scriptPubKey, sigdata, sv)) {
                return fail("input-sign-failed", strprintf("input %d (%s) signature failed",
                                                           i, txin.prevout.ToStringShort()));
            }
            UpdateTransaction(tx, i, sigdata);
        }
    }

    CTransactionRef txRef = MakeTransactionRef(tx);
    // Hand the signed transaction to the WALLET, not to a bare ATMP+relay: the
    // wallet must learn about the pending spend and about its own change, or the
    // NEXT renewal built from the same wallet re-selects the same coins and
    // double-spends this one (MEASURED on a multi-identity daemon whose slots
    // coincided: txn-mempool-conflict, then input-spent, healing only at the
    // next block). CommitTransaction records the tx, submits it to the mempool
    // — with the O-5 fee rule enforced, no exemption — abandons the wallet
    // entry if the mempool refuses it, and relays it to peers.
    const CWallet::CommitResult& cres =
        pwallet->CommitTransaction(txRef, static_cast<CReserveKey*>(nullptr), g_connman.get());
    if (cres.status != CWallet::CommitStatus::OK) {
        return fail("tx-rejected", FormatStateMessage(cres.state));
    }

    txidOut = txRef->GetHash();
    return OperationResult(true);
}

#endif // ENABLE_WALLET

//! Warn about `proTxHash` at most once every LEASE_WARN_EVERY_BLOCKS blocks.
static bool ShouldWarn(const uint256& proTxHash, int height)
{
    auto it = g_lastWarnHeight.find(proTxHash);
    if (it != g_lastWarnHeight.end() && height - it->second < LEASE_WARN_EVERY_BLOCKS) {
        return false;
    }
    g_lastWarnHeight[proTxHash] = height;
    return true;
}

/**
 * One monitor pass: for every MN this node operates, compare the lease expiry to
 * the tip and act once half the horizon is consumed.
 */
static void LeaseMonitorPass()
{
    std::lock_guard<std::mutex> lock(g_leaseMutex);

    if (!fMasterNode || !activeMasternodeManager || !deterministicMNManager) {
        return;
    }
    const CActiveMasternodeInfo* info = activeMasternodeManager->GetInfo();
    if (!info) {
        return;
    }

    int height;
    {
        LOCK(cs_main);
        if (IsInitialBlockDownload() || !chainActive.Tip()) {
            return;   // expiries mean nothing until we know where the tip is
        }
        height = chainActive.Height();
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    const int horizon = consensus.nOperatorLeaseBlocks;
    // Warn once HALF the horizon is consumed: ~3.5 days at the shipped 10080
    // blocks / 60 s, which is the time an operator has to notice a renewal that
    // is failing (locked wallet, empty wallet) and fix it by hand.
    const int renewBelow = horizon / 2;

    const CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();

    for (const uint256& proTxHash : info->GetManagedProTxHashes()) {
        auto dmn = mnList.GetMN(proTxHash);
        if (!dmn) continue;

        const int expiry = dmn->pdmnState->nLeaseExpiryHeight;
        const int remaining = expiry - height;
        if (remaining > renewBelow) {
            continue;   // plenty of margin
        }

        // AUTOMATIC renewal is deterministically staggered: it begins at a
        // per-identity height inside [expiry - L/2, expiry - L/4), so operators
        // registered in the same window (the genesis case) do not all broadcast
        // in the same block. Warnings are NOT staggered — visibility first.
        const int autoRenewStart = LeaseRenewalStartHeight(
            consensus.hashGenesisBlock, proTxHash,
            dmn->pdmnState->nLeaseSequence + 1, expiry, horizon);

        const bool expired = (remaining <= 0);
        if (ShouldWarn(proTxHash, height)) {
            if (expired) {
                LogPrintf("OPERATOR-LEASE: WARNING: MN %s lease EXPIRED at height %d (tip %d). "
                          "This identity leaves the production AND finality sets at the next "
                          "epoch snapshot. Renew now: protx_renew_lease %s\n",
                          proTxHash.ToString(), expiry, height, proTxHash.ToString());
            } else {
                LogPrintf("OPERATOR-LEASE: WARNING: MN %s lease expires at height %d, in %d blocks "
                          "(~%d hours). Renew with: protx_renew_lease %s%s\n",
                          proTxHash.ToString(), expiry, remaining,
                          (int)((int64_t)remaining * consensus.nTargetSpacing / 3600),
                          proTxHash.ToString(),
                          g_leaseAutoRenew.load() ? "" : "  (or set leaseautorenew=1)");
            }
        }

        if (!g_leaseAutoRenew.load()) {
            continue;
        }
        if (height < autoRenewStart) {
            continue;   // this identity's jittered slot has not opened yet
        }

#ifdef ENABLE_WALLET
        // A renewal already waiting in the mempool would be rejected as a conflict
        // (only one can be block-valid, since the sequence must be prev+1).
        {
            CMutableTransaction probe;
            probe.nVersion = CTransaction::TxVersion::SAPLING;
            probe.nType = CTransaction::TxType::TX_OPERATOR_LEASE;
            OperatorLeasePL probePl;
            probePl.proTxHash = proTxHash;
            probePl.nLeaseSequence = dmn->pdmnState->nLeaseSequence + 1;
            SetTxPayload(probe, probePl);
            if (mempool.existsProviderTxConflict(CTransaction(probe))) {
                RecordAutoRenewAttempt(proTxHash, height, /*success=*/false,
                                       "pending-in-mempool",
                                       "a renewal is already waiting in the mempool");
                continue;   // renewal already pending
            }
        }

        CKey operatorKey;
        if (!info->GetOperatorKey(proTxHash, operatorKey)) {
            LogPrintf("OPERATOR-LEASE: cannot auto-renew %s: operator key not loaded\n",
                      proTxHash.ToString());
            RecordAutoRenewAttempt(proTxHash, height, false, "operator-key-not-loaded",
                                   "operator key not loaded on this node");
            continue;
        }

        CWallet* pwallet = vpwallets.empty() ? nullptr : vpwallets[0];
        if (!pwallet) {
            LogPrintf("OPERATOR-LEASE: cannot auto-renew %s: no wallet loaded on this node\n",
                      proTxHash.ToString());
            RecordAutoRenewAttempt(proTxHash, height, false, "no-wallet",
                                   "no wallet loaded on this node");
            continue;
        }
        if (pwallet->IsLocked()) {
            LogPrintf("OPERATOR-LEASE: cannot auto-renew %s: wallet is LOCKED. Unlock it or renew "
                      "by hand — otherwise this identity expires at height %d\n",
                      proTxHash.ToString(), expiry);
            RecordAutoRenewAttempt(proTxHash, height, false, "wallet-locked",
                                   strprintf("wallet is locked; identity expires at height %d", expiry));
            continue;
        }

        uint256 txid;
        std::string failReason;
        const OperationResult res =
            BuildAndSendLeaseRenewal(pwallet, proTxHash, operatorKey, txid, &failReason);
        if (!res) {
            LogPrintf("OPERATOR-LEASE: auto-renewal of %s FAILED (%s): %s\n",
                      proTxHash.ToString(), failReason, res.getError());
            RecordAutoRenewAttempt(proTxHash, height, false,
                                   failReason.empty() ? "failed" : failReason, res.getError());
            continue;
        }
        LogPrintf("OPERATOR-LEASE: auto-renewed %s (sequence %u, tx %s)\n",
                  proTxHash.ToString(), dmn->pdmnState->nLeaseSequence + 1, txid.ToString());
        RecordAutoRenewAttempt(proTxHash, height, true, "success", "", txid);
#else
        LogPrintf("OPERATOR-LEASE: cannot auto-renew %s: this binary is built without wallet "
                  "support; renew from a wallet-enabled node\n", proTxHash.ToString());
        RecordAutoRenewAttempt(proTxHash, height, false, "no-wallet-support",
                               "binary built without wallet support");
#endif // ENABLE_WALLET
    }
}

static void LeaseMonitorCallback()
{
    if (!g_leaseMonitorEnabled.load()) {
        return;
    }
    try {
        LeaseMonitorPass();
    } catch (const std::exception& e) {
        LogPrintf("OPERATOR-LEASE: exception in monitor: %s\n", e.what());
    }
}

void InitOperatorLeaseMonitor(CScheduler& scheduler)
{
    if (!fMasterNode) {
        return;   // nothing to monitor: this node operates no identity
    }

    const bool autoRenew = gArgs.GetBoolArg("-leaseautorenew", DEFAULT_LEASE_AUTORENEW);
    g_leaseAutoRenew.store(autoRenew);
    g_leaseMonitorEnabled.store(true);

    int interval = gArgs.GetArg("-leaserenewinterval", DEFAULT_LEASE_RENEW_INTERVAL);
    if (interval < 30) interval = 30;
    if (interval > 3600) interval = 3600;

    if (autoRenew) {
        LogPrintf("OPERATOR-LEASE: monitor enabled, auto-renewal ON, interval=%d seconds\n",
                  interval);
    } else {
        // Not an error — auto-renewal is opt-in by design — but an operator that
        // does not know renewal exists is exactly how the finality population
        // drains, so say it once, plainly, at every startup.
        LogPrintf("OPERATOR-LEASE: monitor enabled, auto-renewal OFF (leaseautorenew=0), "
                  "interval=%d seconds. Leases must be renewed by hand with protx_renew_lease "
                  "before they expire, or this node's identities leave the production and "
                  "finality sets.\n", interval);
    }

    scheduler.scheduleEvery([]() {
        LeaseMonitorCallback();
    }, interval * 1000);
}

void ShutdownOperatorLeaseMonitor()
{
    g_leaseMonitorEnabled.store(false);
    g_leaseAutoRenew.store(false);
    std::lock_guard<std::mutex> lock(g_leaseMutex);
    g_lastWarnHeight.clear();
    g_autoRenewStatus.clear();
}
