// Copyright (c) 2017 The Dash Core developers
// Copyright (c) 2020-2022 The PIVX Core developers
// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/specialtx_validation.h"

#include "btcheaders/btcheaders.h"  // BTCHEADERS_MAX_PAYLOAD_SIZE
#include "chain.h"
#include "coins.h"
#include "chainparams.h"
#include "clientversion.h"
#include "consensus/validation.h"
#include "masternode/deterministicmns.h"
#include "masternode/providertx.h"
#include "messagesigner.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"
#include "htlc/htlc.h"                // BP02: HTLC for M1 atomic swaps
#include "htlc/htlcdb.h"              // BP02: HTLC database
#include "burnclaim/burnclaim.h"      // BP10/BP11: BTC burn claims
#include "burnclaim/burnclaimdb.h"    // BP11: Burn claim database
#include "btcheaders/btcheadersdb.h"  // BP-SPVMNPUB: BTC headers database
// LOT 2 (AUD-003): util/system.h (gArgs) no longer included here — no node-local
// option may influence this translation unit's consensus verdicts.

#include <cstdlib>                    // getenv — LAB-only commit-failure seam (r15)

/* -- Helper static functions -- */

// LOT 1 round 15 — LAB-ONLY commit-failure seam, for the real-process proof (Phase I).
//
// COMPILE-TIME GATED (pre-GO review requirement): the seam exists ONLY in a binary
// configured with --enable-lab-failcommit (AC_DEFINE BATHRON_ENABLE_LAB_FAILCOMMIT,
// default OFF). Official release builds (--disable-tests) AND ordinary test builds do
// NOT contain it — no env-var string, no getenv, no fault-injection code path; the
// stub below compiles to a constant and the call sites fold away. A runtime
// IsRegTestNet() check alone was judged insufficient for a deployed binary.
//
// In a lab build it forces commit step N of the given direction to fail so a LIVE
// bathrond can exercise the fatal-abort path end to end (fatal log -> latch ->
// shutdown -> consistency gate -> -reindex). Still not an RPC/argument/config option —
// env var, read once, honoured on REGTEST ONLY even in the lab binary. The abort
// primitive itself has no trigger surface; this only makes a Commit() return false,
// exactly like a disk fault would.
#ifdef BATHRON_ENABLE_LAB_FAILCOMMIT
static bool LabForcedCommitFailure(bool fConnect, int step)
{
    static const int connectStep = []() {
        if (!Params().IsRegTestNet()) return 0;
        const char* e = std::getenv("BATHRON_LAB_FAILCOMMIT_CONNECT_STEP");
        return e ? std::atoi(e) : 0;
    }();
    static const int disconnectStep = []() {
        if (!Params().IsRegTestNet()) return 0;
        const char* e = std::getenv("BATHRON_LAB_FAILCOMMIT_DISCONNECT_STEP");
        return e ? std::atoi(e) : 0;
    }();
    const int forced = fConnect ? connectStep : disconnectStep;
    if (forced != 0 && forced == step) {
        LogPrintf("LAB SEAM: forcing %s commit step %d to FAIL "
                  "(BATHRON_LAB_FAILCOMMIT_*, regtest only)\n",
                  fConnect ? "connect" : "disconnect", step);
        return true;
    }
    return false;
}
#else
static inline bool LabForcedCommitFailure(bool, int) { return false; }
#endif

static bool CheckService(const CService& addr, CValidationState& state)
{
    if (!addr.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-ipaddr");
    }
    if (!Params().IsRegTestNet() && !addr.IsRoutable()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-ipaddr");
    }

    // IP port must be the default one on main-net, which cannot be used on other nets.
    static int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != mainnetDefaultPort) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-ipaddr-port");
        }
    } else if (addr.GetPort() == mainnetDefaultPort) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-ipaddr-port");
    }

    // !TODO: add support for IPv6 and Tor
    if (!addr.IsIPv4()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-ipaddr");
    }

    return true;
}

template <typename Payload>
static bool CheckHashSig(const Payload& pl, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(pl), keyID, pl.vchSig, strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig", false, strError);
    }
    return true;
}

template <typename Payload>
static bool CheckHashSig(const Payload& pl, const CPubKey& pubKey, CValidationState& state)
{
    // ECDSA signature verification. The payload is operator-signed with
    // CHashSigner::SignHash -> key.SignCompact() (65-byte RECOVERABLE signature; see
    // rpcevo.cpp SignSpecialTxPayloadByHash). It MUST therefore be verified the
    // compact way (recover the pubkey from the sig and compare by keyID), NOT with
    // CPubKey::Verify(), which expects a DER-encoded signature and so rejected EVERY
    // compact operator signature with bad-protx-sig. That silently broke 100% of the
    // operator-hash-signed provider txs (ProUpServTx service-update / PoSe revival,
    // and the ProUpRegTx operator path): a PoSe-banned MN could never be revived and
    // a MN could never change its advertised service. No valid such tx has ever been
    // accepted on-chain (they were all rejected here), so this is a pure correctness
    // fix: nothing that used to validate changes, and -reindex is unaffected (no
    // historical tx exists whose verdict could flip). The owner-signed paths already
    // used the CKeyID overload below (VerifyHash), which was always correct.
    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(pl), pubKey, pl.vchSig, strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig", false, strError);
    }
    return true;
}

template <typename Payload>
static bool CheckStringSig(const Payload& pl, const CKeyID& keyID, CValidationState& state)
{
    std::string strError;
    if (!CMessageSigner::VerifyMessage(keyID, pl.vchSig, pl.MakeSignString(), strError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig", false, strError);
    }
    return true;
}

template <typename Payload>
static bool CheckInputsHash(const CTransaction& tx, const Payload& pl, CValidationState& state)
{
    if (CalcTxInputsHash(tx) != pl.inputsHash) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-inputs-hash");
    }

    return true;
}

static bool CheckCollateralOut(const CTxOut& out, const ProRegPL& pl, CValidationState& state, CTxDestination& collateralDestRet)
{
    if (!ExtractDestination(out.scriptPubKey, collateralDestRet)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral-dest");
    }
    // don't allow reuse of collateral key for other keys (don't allow people to put the collateral key onto an online server)
    // this check applies to internal and external collateral, but internal collaterals are not necessarely a P2PKH
    if (collateralDestRet == CTxDestination(pl.keyIDOwner) ||
            collateralDestRet == CTxDestination(pl.keyIDVoting)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral-reuse");
    }
    // check collateral amount
    if (out.nValue != Params().GetConsensus().nMNCollateralAmt) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-collateral-amount");
    }
    return true;
}

// Provider Register Payload
static bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache* view, CValidationState& state)
{

    ProRegPL pl;
    if (!GetValidatedTxPayload(tx, pl, state)) {
        // pass the state returned by the function above
        return false;
    }

    // It's allowed to set addr to 0, which will put the MN into PoSe-banned state and require a ProUpServTx to be issues later
    // If any of both is set, it must be valid however
    if (pl.addr != CService() && !CheckService(pl.addr, state)) {
        // pass the state returned by the function above
        return false;
    }

    // A ProRegTx that references EXTERNAL collateral (collateralOutpoint set) must NOT
    // also spend that same outpoint as one of its own inputs. This check is tx-INTRINSIC
    // (needs no coins view), so it is enforced identically at mempool acceptance, at
    // ConnectBlock, and in the no-context path. It closes a view-ordering gap: at mempool
    // the collateral is still unspent when the check below runs (tx passes), but at
    // ConnectBlock the tx's own inputs are already spent into the view, so GetUTXOCoin sees
    // the collateral consumed → bad-protx-collateral → the block never connects → the tx is
    // never evicted from the mempool → the producer rebuilds the same invalid block every
    // DMM slot → chain production stalls (observed live 2026-07-01).
    if (!pl.collateralOutpoint.hash.IsNull()) {
        for (const CTxIn& in : tx.vin) {
            if (in.prevout == pl.collateralOutpoint) {
                return state.DoS(100, false, REJECT_INVALID, "bad-protx-collateral-spent-self");
            }
        }
    }

    if (pl.collateralOutpoint.hash.IsNull()) {
        // collateral included in the proReg tx
        if (pl.collateralOutpoint.n >= tx.vout.size()) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral-index");
        }
        CTxDestination collateralTxDest;
        if (!CheckCollateralOut(tx.vout[pl.collateralOutpoint.n], pl, state, collateralTxDest)) {
            // pass the state returned by the function above
            return false;
        }
        // collateral is part of this ProRegTx, so we know the collateral is owned by the issuer
        if (!pl.vchSig.empty()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig");
        }
    } else if (pindexPrev != nullptr) {
        assert(view != nullptr);

        // Referenced external collateral.
        // This is checked only when pindexPrev is not null (thus during ConnectBlock-->CheckSpecialTx),
        // because this is a contextual check: we need the updated utxo set, to verify that
        // the coin exists and it is unspent.
        Coin coin;
        if (!view->GetUTXOCoin(pl.collateralOutpoint, coin)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral");
        }
        CTxDestination collateralTxDest;
        if (!CheckCollateralOut(coin.out, pl, state, collateralTxDest)) {
            // pass the state returned by the function above
            return false;
        }
        // Extract key from collateral. This only works for P2PK and P2PKH collaterals and will fail for P2SH.
        // Issuer of this ProRegTx must prove ownership with this key by signing the ProRegTx
        const CKeyID* keyForPayloadSig = boost::get<CKeyID>(&collateralTxDest);
        if (!keyForPayloadSig) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral-pkh");
        }
        // collateral is not part of this ProRegTx, so we must verify ownership of the collateral
        if (!CheckStringSig(pl, *keyForPayloadSig, state)) {
            // pass the state returned by the function above
            return false;
        }
    }

    if (!CheckInputsHash(tx, pl, state)) {
        return false;
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        // MULTI-MN v4.0: IP uniqueness check REMOVED - multiple MNs can share same IP
        // MN identity is operatorPubKey, not IP:Port

        // ownerKey MUST be unique - prevents collateral theft
        if (mnList.HasUniqueProperty(pl.keyIDOwner)) {
            return state.DoS(10, false, REJECT_DUPLICATE, "bad-protx-dup-owner-key");
        }

        // MULTI-MN v4.0: operatorPubKey duplicates ALLOWED
        // ================================================
        // One operator can manage N masternodes with a SINGLE key.
        // This enforces the Operator-Centric model where:
        // - 1 operatorPubKey = 1 identity (score, badges, reputation)
        // - N MNs with same key = N votes (economic weight)
        //
        // Security: ownerKey remains unique, so collateral is protected.
        // The operator key is only for signing blocks/HU, not for funds.
        //
        // REMOVED:
        // if (mnList.HasUniqueProperty(pl.pubKeyOperator)) {
        //     return state.DoS(10, false, REJECT_DUPLICATE, "bad-protx-dup-operator-key");
        // }
    }

    return true;
}

// Provider Update Service Payload
static bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{

    ProUpServPL pl;
    if (!GetValidatedTxPayload(tx, pl, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (!CheckService(pl.addr, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (!CheckInputsHash(tx, pl, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto mn = mnList.GetMN(pl.proTxHash);
        if (!mn) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
        }

        // MULTI-MN: IP uniqueness check REMOVED - multiple MNs can share same IP
        // MN identity is operatorPubKey, not IP:Port

        // BATHRON: ECDSA - we can only check the signature if pindexPrev != nullptr and the MN is known
        if (!CheckHashSig(pl, mn->pdmnState->pubKeyOperator, state)) {
            // pass the state returned by the function above
            return false;
        }
    }

    return true;
}

// Provider Update Registrar Payload
static bool CheckProUpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache* view, CValidationState& state)
{

    ProUpRegPL pl;
    if (!GetValidatedTxPayload(tx, pl, state)) {
        // pass the state returned by the function above
        return false;
    }

    CTxDestination payoutDest;
    if (!ExtractDestination(pl.scriptPayout, payoutDest)) {
        // should not happen as we checked script types before
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee-dest");
    }

    // don't allow reuse of payee key for other keys
    if (payoutDest == CTxDestination(pl.keyIDVoting)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee-reuse");
    }

    if (!CheckInputsHash(tx, pl, state)) {
        return false;
    }

    if (pindexPrev) {
        assert(view != nullptr);

        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto dmn = mnList.GetMN(pl.proTxHash);
        if (!dmn) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
        }

        // don't allow reuse of payee key for owner key
        if (payoutDest == CTxDestination(dmn->pdmnState->keyIDOwner)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee-reuse");
        }

        Coin coin;
        if (!view->GetUTXOCoin(dmn->collateralOutpoint, coin)) {
            // this should never happen (there would be no dmn otherwise)
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-collateral");
        }

        // don't allow reuse of collateral key for other keys (don't allow people to put the payee key onto an online server)
        CTxDestination collateralTxDest;
        if (!ExtractDestination(coin.out.scriptPubKey, collateralTxDest)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-collateral-dest");
        }
        if (collateralTxDest == CTxDestination(dmn->pdmnState->keyIDOwner) ||
                collateralTxDest == CTxDestination(pl.keyIDVoting)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral-reuse");
        }

        // MULTI-MN v4.0: operatorPubKey duplicates ALLOWED
        // Same operator can manage multiple MNs
        // See: doc/blueprints/done/15-MULTI-MN-SINGLE-DAEMON.md section 5.2.1
        // if (mnList.HasUniqueProperty(pl.pubKeyOperator)) {
        //     auto otherDmn = mnList.GetUniquePropertyMN(pl.pubKeyOperator);
        //     if (pl.proTxHash != otherDmn->proTxHash) {
        //         return state.DoS(10, false, REJECT_DUPLICATE, "bad-protx-dup-key");
        //     }
        // }

        if (!CheckHashSig(pl, dmn->pdmnState->keyIDOwner, state)) {
            // pass the state returned by the function above
            return false;
        }

    }

    return true;
}

// Provider Update Revoke Payload
// ═════════════════════════════════════════════════════════════════════════════
// LOT 9 M3 — TX_OPERATOR_LEASE (spec §C / O-3 / O-5)
// ═════════════════════════════════════════════════════════════════════════════
//
// Renewal of an operator's lease. Everything here is a CHAIN fact resolvable
// from pindexPrev alone:
//   * the operator must EXIST and be confirmed (bootstrap-trust included) in the
//     list at pindexPrev;
//   * the sequence must be EXACTLY previousSequence + 1 (strictly increasing:
//     replays and stale re-broadcasts are structurally dead);
//   * the signature must verify against the CURRENT operator key over the
//     domain-separated, chain-bound message (OperatorLeasePL::GetSignatureHash);
//   * the fee (O-5) must meet the shared settlement minimum — no exemption, no
//     mint, no effect on A5/A6/A7 (the tx only spends M0 and pays fee). The
//     input payer MAY be anyone; only the OPERATOR signature authorizes the
//     renewal itself.
// The expiry is NEVER read from the payload: BuildNewListFromBlock derives it
// from the inclusion height. Renewing early is allowed (extends from inclusion);
// renewing an EXPIRED lease is allowed (recovery blocks exist for exactly that);
// the schedule effect happens only through a FUTURE epoch snapshot.
static bool CheckOperatorLeaseTx(const CTransaction& tx, const CBlockIndex* pindexPrev,
                                 const CCoinsViewCache* view, CValidationState& state)
{
    OperatorLeasePL pl;
    if (!GetValidatedTxPayload(tx, pl, state)) {
        return false;
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto mn = mnList.GetMN(pl.proTxHash);
        if (!mn) {
            return state.DoS(100, false, REJECT_INVALID, "bad-lease-protx-hash");
        }

        // Existing AND confirmed — the same bootstrap-trust predicate the schedule
        // and finality eligibility use.
        const bool isBootstrapMN =
            (mn->pdmnState->nRegisteredHeight <= Params().GetConsensus().nDMMBootstrapHeight);
        if (!isBootstrapMN && mn->pdmnState->confirmedHash.IsNull()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-lease-operator-unconfirmed");
        }

        // Strictly increasing sequence: EXACTLY previous + 1. This kills replays
        // (an old lease has sequence <= previous) and skips (sequence gaps).
        if (pl.nLeaseSequence != mn->pdmnState->nLeaseSequence + 1) {
            return state.DoS(100, false, REJECT_INVALID, "bad-lease-sequence", false,
                             strprintf("got %u, want %u", pl.nLeaseSequence,
                                       mn->pdmnState->nLeaseSequence + 1));
        }

        // Operator signature over the domain-separated, chain-bound message.
        const CPubKey& pubKey = mn->pdmnState->pubKeyOperator;
        if (!pubKey.IsValid()) {
            return state.DoS(100, false, REJECT_INVALID, "bad-lease-operator-key");
        }
        std::string strError;
        const uint256 sigHash = pl.GetSignatureHash(Params().GetConsensus().hashGenesisBlock);
        if (!CHashSigner::VerifyHash(sigHash, pubKey.GetID(), pl.vchSig, strError)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-lease-sig", false, strError);
        }
    }

    return true;
}

//! LOT 9 M3 — block-level lease dedup: at most ONE renewal per proTxHash per
//! block, rejected DETERMINISTICALLY by scanning the whole block — never
//! dependent on transaction order (both duplicates fail the block identically).
bool CheckNoDuplicateOperatorLeasesInBlock(const std::vector<std::shared_ptr<const CTransaction>>& vtx,
                                           CValidationState& state)
{
    std::set<uint256> seenProTx;
    for (const auto& tx : vtx) {
        if (!tx || tx->nType != CTransaction::TxType::TX_OPERATOR_LEASE) continue;
        OperatorLeasePL pl;
        if (!GetTxPayload(*tx, pl)) continue;   // rejected by CheckSpecialTx
        if (!seenProTx.insert(pl.proTxHash).second) {
            return state.DoS(100, error("%s: duplicate operator lease for %s in one block",
                                        __func__, pl.proTxHash.ToString()),
                             REJECT_INVALID, "bad-lease-duplicate-in-block");
        }
    }
    return true;
}

static bool CheckProUpRevTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{

    ProUpRevPL pl;
    if (!GetValidatedTxPayload(tx, pl, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (!CheckInputsHash(tx, pl, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto dmn = mnList.GetMN(pl.proTxHash);
        if (!dmn)
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");

        // BATHRON: ECDSA
        if (!CheckHashSig(pl, dmn->pdmnState->pubKeyOperator, state)) {
            // pass the state returned by the function above
            return false;
        }
    }

    return true;
}

// Basic non-contextual checks for all tx types
static bool CheckSpecialTxBasic(const CTransaction& tx, CValidationState& state)
{
    bool hasExtraPayload = tx.hasExtraPayload();

    if (tx.IsNormalType()) {
        // Type-0 txes don't have extra payload
        if (hasExtraPayload) {
            return state.DoS(100, error("%s: Type 0 doesn't support extra payload", __func__),
                             REJECT_INVALID, "bad-txns-type-payload");
        }
        // Normal transaction. Nothing to check
        return true;
    }

    // Special txes need at least version 2
    if (!tx.isSaplingVersion()) {
        return state.DoS(100, error("%s: Type %d not supported with version %d", __func__, tx.nType, tx.nVersion),
                         REJECT_INVALID, "bad-txns-type-version");
    }

    // Cannot be coinbase tx
    if (tx.IsCoinBase()) {
        return state.DoS(10, error("%s: Special tx is coinbase", __func__),
                         REJECT_INVALID, "bad-txns-special-coinbase");
    }

    // Special/settlement transactions must NOT carry Sapling shielded components.
    // M0 shielding happens exclusively through NORMAL (type-0) transactions
    // (shieldsendmany). A settlement tx (TX_LOCK/UNLOCK/TRANSFER_M1, HTLC_*) that
    // carried a non-zero valueBalance could push value into the Sapling pool that
    // the settlement conservation checks (which are blind to valueBalance) never
    // charged to its inputs — an M0-shield inflation vector (e.g. a TX_LOCK whose
    // receipt-excluding conservation dropped the shielded sink). There is no
    // legitimate use of shielded data inside a special tx, so reject it outright.
    // Note: special txes use the SAPLING tx *version* but must have EMPTY sapData;
    // hasSaplingData() only trips on actual shielded spends/outputs/valueBalance.
    if (tx.hasSaplingData()) {
        return state.DoS(100, error("%s: special tx (type=%d) carries Sapling shielded data", __func__, (int)tx.nType),
                         REJECT_INVALID, "bad-txns-special-has-sapling");
    }

    // BP30 settlement types and HTLC types do not use extraPayload
    // (HTLCs store parameters in P2SH scripts; claims/refunds have no payload)
    // Note: HTLC_CREATE_3S DOES use extraPayload (for 3 hashlocks)
    bool isBP30NoPayloadType = (tx.nType == CTransaction::TxType::TX_LOCK ||
                                tx.nType == CTransaction::TxType::TX_UNLOCK ||
                                tx.nType == CTransaction::TxType::TX_TRANSFER_M1 ||
                                tx.nType == CTransaction::TxType::HTLC_CREATE_M1 ||
                                tx.nType == CTransaction::TxType::HTLC_CLAIM ||
                                tx.nType == CTransaction::TxType::HTLC_REFUND ||
                                tx.nType == CTransaction::TxType::HTLC_CLAIM_3S ||
                                tx.nType == CTransaction::TxType::HTLC_REFUND_3S);

    // Special txes must have a non-empty payload (except types that don't need it)
    if (!hasExtraPayload && !isBP30NoPayloadType) {
        return state.DoS(100, error("%s: Special tx (type=%d) without extra payload", __func__, tx.nType),
                         REJECT_INVALID, "bad-txns-payload-empty");
    }

    // Size limits (only check if payload exists)
    // TX_BTC_HEADERS uses its own size limit (BTCHEADERS_MAX_PAYLOAD_SIZE = 100KB)
    // because genesis block 1 headers TX can be ~105KB
    size_t maxPayloadSize = MAX_SPECIALTX_EXTRAPAYLOAD;
    if (tx.nType == CTransaction::TxType::TX_BTC_HEADERS) {
        maxPayloadSize = BTCHEADERS_MAX_PAYLOAD_SIZE;
    }
    if (hasExtraPayload && tx.extraPayload->size() > maxPayloadSize) {
        return state.DoS(100, error("%s: Special tx payload oversize (%d > %d)", __func__,
                         tx.extraPayload->size(), maxPayloadSize),
                         REJECT_INVALID, "bad-txns-payload-oversize");
    }

    return true;
}

// contextual and non-contextual per-type checks
// - pindexPrev=null: CheckBlock-->CheckSpecialTxNoContext
// - pindexPrev=chainActive.Tip: AcceptToMemoryPoolWorker-->CheckSpecialTx
// - pindexPrev=pindex->pprev: ConnectBlock-->ProcessSpecialTxsInBlock-->CheckSpecialTx
// LOT 7 (L6-F16) — which DB(s) does this tx type's validity depend on? Over-declaring
// is safe (the extra DB's marker is == parent in normal operation too); under-declaring
// leaves a divergence surface, so the HTLC types require BOTH because their creates
// consume an M1 receipt (settlement) while their state lives in htlcdb.
static LocalStateDB RequiredLocalStateDBs(const CTransaction& tx)
{
    using T = CTransaction::TxType;
    switch (tx.nType) {
        case T::TX_LOCK:
        case T::TX_UNLOCK:
        case T::TX_TRANSFER_M1:
            return LocalStateDB::SETTLEMENT;
        case T::HTLC_CREATE_M1:
        case T::HTLC_CLAIM:
        case T::HTLC_REFUND:
        case T::HTLC_CREATE_3S:
        case T::HTLC_CLAIM_3S:
        case T::HTLC_REFUND_3S:
            return LocalStateDB::BOTH;
        default:
            // NORMAL still reaches the vault/receipt/HTLC protection block below, which
            // reads BOTH derived DBs — so a normal tx spending a protected output must
            // be judged against an in-sync DB too.
            return LocalStateDB::BOTH;
    }
}

bool CheckLocalStateConsistency(const CBlockIndex* pindexPrev, LocalStateDB need,
                                bool fBlockConnect, CValidationState& state)
{
    AssertLockHeld(cs_main);
    if (need == LocalStateDB::NONE || pindexPrev == nullptr || pindexPrev->phashBlock == nullptr) {
        // NONE: nothing to check. null parent: the non-contextual CheckBlock path,
        // where R1/R2/DB reads are deliberately skipped (skipMNChecks). null phashBlock:
        // no verifiable parent identity to compare a marker against — in production a
        // connected pindexPrev always has phashBlock, so this only spares synthetic
        // block indexes (unit fixtures), never a real validation path.
        return true;
    }
    // GENESIS BOUNDARY. The derived-DB best-block MARKER is written by a block's own
    // commit, so on a fresh (or -reindex-replayed) chain it is ABSENT until block 1
    // commits — both DBs document this as the normal fresh state and set it "on next
    // block connect" (CheckSettlementDBConsistency / CheckHtlcDBConsistency). Genesis
    // itself does not run ProcessSpecialTxsInBlock (InitSettlementAtGenesis writes only
    // the height-0 state record, not the marker). So when the parent IS genesis
    // (height 0) an absent marker is the legitimate first-block state, not a behind DB;
    // and no settlement/HTLC record can predate block 1, so there is nothing to protect
    // and nothing to be inconsistent with. Treat block-1 validation as consistent — the
    // same genesis exemption the A5/A7 base backstop makes (prevHeight==0). Without this,
    // gate B fatal-latches the first block of every fresh chain (caught by the regtest
    // process lab). Beyond genesis (parent height > 0) an absent marker means a
    // wiped/torn DB and MUST still be caught below.
    if (pindexPrev->nHeight == 0) {
        return true;
    }
    const uint256 expected = pindexPrev->GetBlockHash();

    auto behind = [&](const char* which, bool haveDB, bool readOk, const uint256& got) -> bool {
        // true == LOCAL INCONSISTENCY (DB behind / torn / absent).
        if (!haveDB || !readOk) return true;
        return got != expected;
    };

    const bool needS = (need == LocalStateDB::SETTLEMENT || need == LocalStateDB::BOTH);
    const bool needH = (need == LocalStateDB::HTLC       || need == LocalStateDB::BOTH);

    bool inconsistent = false;
    std::string whichDB;
    if (needS) {
        uint256 h; bool ok = (g_settlementdb && g_settlementdb->ReadBestBlock(h));
        if (behind("settlement", g_settlementdb != nullptr, ok, h)) { inconsistent = true; whichDB = "settlement"; }
    }
    if (!inconsistent && needH) {
        uint256 h; bool ok = (g_htlcdb && g_htlcdb->ReadBestBlock(h));
        if (behind("htlc", g_htlcdb != nullptr, ok, h)) { inconsistent = true; whichDB = "htlc"; }
    }
    if (!inconsistent) {
        return true;   // DB IS the parent state — present/absent records are authoritative.
    }

    // LOCAL inconsistency. NEVER block invalidity, NEVER a peer ban.
    if (fBlockConnect) {
        // Block-connect path: this node cannot validate the chain from a behind/torn
        // derived DB. Fire the LOT 1 fatal latch: it logs, messages, StartShutdown()s
        // once, sets `state` to a NON-invalid Error, and every subsequent
        // ConnectBlock/DisconnectBlock/ActivateBestChainStep is refused until -reindex.
        LogPrintf("LOT7: %s DB is not the parent's state (expected %s) during block connect — "
                  "firing the consensus-DB fatal latch, node must -reindex\n",
                  whichDB.c_str(), expected.ToString().substr(0, 16));
        AbortConsensusDBState(/*fConnect=*/true, /*nStep=*/0, whichDB, /*fPartial=*/false,
                              pindexPrev->nHeight + 1, expected, &state);
        return false;
    }
    // Mempool / RPC / template path: cannot judge this tx locally. Non-persisting
    // Error — the tx is not accepted, no DoS, no ban, and there is no silent retry
    // loop here (unlike ActivateBestChain). If the DB really is behind, the block path
    // will fire the fatal latch and the whole node stops.
    LogPrintf("LOT7: %s DB behind the tip (expected %s) — cannot judge special tx locally, "
              "rejecting without invalidity/ban\n", whichDB.c_str(), expected.ToString().substr(0, 16));
    return state.Error("local-state-behind-" + whichDB);
}

bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache* view, CValidationState& state, bool fBlockConnect)
{
    AssertLockHeld(cs_main);

    if (!CheckSpecialTxBasic(tx, state)) {
        // pass the state returned by the function above
        return false;
    }
    if (pindexPrev) {
        // reject special transactions before enforcement
        if (!tx.IsNormalType() && !Params().GetConsensus().NetworkUpgradeActive(pindexPrev->nHeight + 1, Consensus::UPGRADE_V6_0)) {
            return state.DoS(100, error("%s: Special tx when v6 upgrade not enforced yet", __func__),
                             REJECT_INVALID, "bad-txns-v6-not-active");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP30: Vault Consensus Protection (Bearer Asset Model)
    //
    // Vaults use OP_TRUE script (anyone-can-spend) but are PROTECTED by consensus.
    // Only TX_UNLOCK is allowed to spend vault UTXOs.
    // This prevents theft of locked M0 by anyone crafting a spending TX.
    // ═══════════════════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════════════════
    // BP30: M1 Receipt Consensus Protection (option B, UPGRADE_M1_RECEIPT_PROTECTED)
    //
    // Symmetric to the vault guard: a bearer M1 receipt (P2PKH, settlement-tracked)
    // may only be consumed by a settlement tx that RECONCILES it in
    // ProcessSpecialTxsInBlock — i.e. erases the receipt and/or adjusts M1_supply:
    //   - TX_UNLOCK       (redeem M1 -> M0,        ApplyUnlock::EraseReceipt)
    //   - TX_TRANSFER_M1  (move M1,                ApplyTransfer::EraseReceipt)
    //   - HTLC_CREATE_M1  (M1 -> covenant,         ApplyHTLCCreate::EraseReceipt)
    //   - HTLC_CREATE_3S  (M1 -> 3-secret covenant, ApplyHTLC3SCreate::EraseReceipt)
    // Any other spend (NORMAL, or any non-reconciling type) would leave M1_supply
    // above the live receipt set and orphan the backing vault M0 (no receipt left
    // to pair in a TX_UNLOCK) → deflationary leakage. Rejecting it makes M1 strictly
    // == locked/pooled M0 at the consensus level.
    //
    // HTLC outpoint protection (same gate): an HTLC / HTLC3S P2SH output is
    // settlement-tracked exactly like a receipt. Only the matching claim/refund
    // type reconciles it (ApplyHTLCClaim/ApplyHTLCRefund resolve the record and
    // recreate the M1 receipt), and every HTLC Check/Apply reconciles ONLY vin[0].
    // Any other spend — a NORMAL tx satisfying the redeem script (preimage or
    // timeout branch), a non-HTLC special type, a cross-family claim, or a
    // conforming type carrying the HTLC at vin[1..] — would consume the UTXO
    // while its record stays ACTIVE forever: M1_supply overstated, backing vault
    // M0 orphaned (deflationary leakage). The same vin[0]-only rule applies to
    // the receipt consumed by HTLC_CREATE_M1/HTLC_CREATE_3S (ApplyHTLC*Create
    // erases only vin[0]'s receipt); TX_UNLOCK/TX_TRANSFER_M1 reconcile every
    // receipt input (canonical order enforced in CheckUnlock/CheckTransfer).
    //
    // Gating: enforced only at/after activation. When pindexPrev is null
    // (non-contextual CheckBlock) the height is unknown, so we defer to the
    // contextual ConnectBlock/mempool call (pindexPrev set), which is authoritative
    // — same pattern as the v6 gate above. The vault guard stays ungated.
    // ═══════════════════════════════════════════════════════════════════════════
    if (view && g_settlementdb) {
        // LOT 7 (L6-F16, gate B): the vault/receipt/HTLC protection below and the
        // per-type checks read the derived DBs. Verify the DB IS the parent's state
        // FIRST; a behind/torn DB is a LOCAL fault (fatal+reindex on connect, plain
        // reject on mempool), never block invalidity or a peer ban.
        if (!CheckLocalStateConsistency(pindexPrev, RequiredLocalStateDBs(tx), fBlockConnect, state)) {
            return false;
        }
        const bool m1ReceiptProtected = pindexPrev &&
            Params().GetConsensus().IsM1ReceiptProtected(pindexPrev->nHeight + 1);
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const CTxIn& txin = tx.vin[i];
            // LOT 7 (A): "is this a vault" is answered from the CANONICAL coins view
            // (IsVaultScript == OP_TRUE), not the derived DB. The coins view is the
            // real UTXO set at the parent and is rebuilt by -reindex, so this removes
            // the vault half of L6-F16 entirely — no DB dependency, no divergence.
            //
            // A valid input is ALWAYS a live UTXO in the view (you cannot reference a
            // spent output — CheckTxInputs enforces that separately). So in production
            // the coin is present and the view decides. Only synthetic unit fixtures,
            // which do not populate the view, hit the absent-coin branch; there the DB
            // classification is used as a fallback so the business rule still runs.
            const Coin& coin = view->AccessCoin(txin.prevout);
            const bool coinPresent = !coin.IsSpent();
            const bool isVaultByScript = coinPresent && IsVaultScript(coin.out.scriptPubKey);
            const bool isVaultByDB = g_settlementdb->IsVault(txin.prevout);
            bool treatAsVault;
            if (coinPresent) {
                // The canonical coins view (rebuilt by -reindex, identical on every node)
                // is the vault AUTHORITY: a vault is exactly an OP_TRUE UTXO — CheckLock
                // enforces vout[0] == OP_TRUE, and the settlement model treats "every
                // OP_TRUE output = vault backing" (settlement_logic.cpp). Classify by
                // SCRIPT. This removes the DB dependency that was the vault half of
                // L6-F16: a real vault stays protected even against an empty/behind DB,
                // and every node computes the same verdict, so a non-UNLOCK spend of a
                // vault is a DETERMINISTIC DoS (below), never a local divergence.
                treatAsVault = isVaultByScript;

                // Only ONE view/DB contradiction is genuine DB corruption: the DB carries
                // a vault entry for an outpoint whose LIVE coin is NOT OP_TRUE. A real
                // vault entry always backs an OP_TRUE coin (ApplyLock/CheckLock), so with
                // the marker at the parent (gate B passed) this means the derived DB
                // disagrees with the canonical UTXO set -> corrupt DB, a LOCAL fault
                // (fatal+reindex on connect / non-persisting Error on mempool), NOT an
                // invalid tx. The OPPOSITE direction — an OP_TRUE coin with NO DB entry —
                // is NOT a fault and must NOT halt the node: it is exactly the empty/behind
                // DB case this LOT exists to survive. The script already classifies it as a
                // vault, so it is protected by the deterministic rule below; a bare OP_TRUE
                // output that was never a registered vault is likewise protected uniformly
                // (consistent with "every OP_TRUE = vault backing"), with no divergence.
                if (isVaultByDB && !isVaultByScript) {
                    if (fBlockConnect) {
                        LogPrintf("LOT7(A): settlementdb marks %s a vault but its live coin is "
                                  "not OP_TRUE — settlementdb corrupt, node must -reindex\n",
                                  txin.prevout.ToString().c_str());
                        AbortConsensusDBState(/*fConnect=*/true, /*nStep=*/0, "settlement-vault", /*fPartial=*/false,
                                              pindexPrev ? pindexPrev->nHeight + 1 : 0,
                                              (pindexPrev && pindexPrev->phashBlock) ? pindexPrev->GetBlockHash() : uint256(), &state);
                        return false;
                    }
                    return state.Error("local-vault-classification-disagreement");
                }
            } else {
                treatAsVault = isVaultByDB;   // unreachable in production; fixture fallback
            }
            if (treatAsVault) {
                // REAL consensus rule, unchanged: only TX_UNLOCK spends a vault.
                if (tx.nType != CTransaction::TxType::TX_UNLOCK) {
                    return state.DoS(100, error("%s: Vault %s can only be spent by TX_UNLOCK, got type %d",
                                                __func__, txin.prevout.ToString(), (int)tx.nType),
                                     REJECT_INVALID, "bad-txns-vault-protected");
                }
            } else if (m1ReceiptProtected && g_settlementdb->IsM1Receipt(txin.prevout)) {
                if (tx.nType != CTransaction::TxType::TX_UNLOCK &&
                    tx.nType != CTransaction::TxType::TX_TRANSFER_M1 &&
                    tx.nType != CTransaction::TxType::HTLC_CREATE_M1 &&
                    tx.nType != CTransaction::TxType::HTLC_CREATE_3S) {
                    return state.DoS(100, error("%s: M1 receipt %s can only be spent by TX_UNLOCK/TX_TRANSFER_M1/HTLC_CREATE_M1/HTLC_CREATE_3S, got type %d",
                                                __func__, txin.prevout.ToString(), (int)tx.nType),
                                     REJECT_INVALID, "bad-txns-receipt-protected");
                }
                if ((tx.nType == CTransaction::TxType::HTLC_CREATE_M1 ||
                     tx.nType == CTransaction::TxType::HTLC_CREATE_3S) && i != 0) {
                    return state.DoS(100, error("%s: M1 receipt %s at vin[%d] of an HTLC create (only vin[0] is reconciled)",
                                                __func__, txin.prevout.ToString(), (int)i),
                                     REJECT_INVALID, "bad-txns-receipt-not-vin0");
                }
            } else if (m1ReceiptProtected && g_htlcdb && g_htlcdb->IsHTLC(txin.prevout)) {
                if ((tx.nType != CTransaction::TxType::HTLC_CLAIM &&
                     tx.nType != CTransaction::TxType::HTLC_REFUND) || i != 0) {
                    return state.DoS(100, error("%s: HTLC %s can only be spent as vin[0] of HTLC_CLAIM/HTLC_REFUND, got type %d at vin[%d]",
                                                __func__, txin.prevout.ToString(), (int)tx.nType, (int)i),
                                     REJECT_INVALID, "bad-txns-htlc-protected");
                }
            } else if (m1ReceiptProtected && g_htlcdb && g_htlcdb->IsHTLC3S(txin.prevout)) {
                if ((tx.nType != CTransaction::TxType::HTLC_CLAIM_3S &&
                     tx.nType != CTransaction::TxType::HTLC_REFUND_3S) || i != 0) {
                    return state.DoS(100, error("%s: HTLC3S %s can only be spent as vin[0] of HTLC_CLAIM_3S/HTLC_REFUND_3S, got type %d at vin[%d]",
                                                __func__, txin.prevout.ToString(), (int)tx.nType, (int)i),
                                     REJECT_INVALID, "bad-txns-htlc3s-protected");
                }
            }
        }

        // B4.4 O2b: fee-receipt destination covenant (gated by UPGRADE_FEE_RECEIPT_PINNED).
        if (pindexPrev && Params().GetConsensus().IsFeeReceiptPinned(pindexPrev->nHeight + 1)) {
            if (!CheckFeeReceiptOwnerCovenant(tx, state)) {
                return false;  // state carries the reject reason
            }
        }
    }

    // per-type checks
    switch (tx.nType) {
        case CTransaction::TxType::NORMAL: {
            // nothing to check
            return true;
        }
        case CTransaction::TxType::PROREG: {
            // provider-register
            return CheckProRegTx(tx, pindexPrev, view, state);
        }
        case CTransaction::TxType::PROUPSERV: {
            // provider-update-service
            return CheckProUpServTx(tx, pindexPrev, state);
        }
        case CTransaction::TxType::PROUPREG: {
            // provider-update-registrar
            return CheckProUpRegTx(tx, pindexPrev, view, state);
        }
        case CTransaction::TxType::PROUPREV: {
            // provider-update-revoke
            return CheckProUpRevTx(tx, pindexPrev, state);
        }
        case CTransaction::TxType::TX_OPERATOR_LEASE: {
            // LOT 9 M3: operator lease renewal
            return CheckOperatorLeaseTx(tx, pindexPrev, view, state);
        }
        // BP30 settlement types - validate during mempool acceptance to prevent invalid TXes
        // FIX: Previously returned true without validation, allowing invalid TX_UNLOCK to enter mempool
        // and block production (block assembler includes them, but ConnectBlock rejects them)
        case CTransaction::TxType::TX_LOCK: {
            if (view) {
                if (!CheckLock(tx, *view, state)) {
                    return false;
                }
            }
            return true;
        }
        case CTransaction::TxType::TX_UNLOCK: {
            if (view) {
                if (!CheckUnlock(tx, *view, state)) {
                    return false;
                }
            }
            return true;
        }
        case CTransaction::TxType::TX_TRANSFER_M1: {
            // Validate during mempool acceptance like TX_LOCK/TX_UNLOCK so a
            // malformed/non-conserving transfer cannot enter the mempool and a
            // block template (block-production griefing). ConnectBlock remains
            // the authoritative check before ApplyTransfer.
            if (view) {
                if (!CheckTransfer(tx, *view, state)) {
                    return false;
                }
            }
            return true;
        }

        // BP02 HTLC types - validate during mempool acceptance to prevent invalid TXes
        case CTransaction::TxType::HTLC_CREATE_M1: {
            // Validate HTLC creation: check M1 receipt exists and amount matches
            // fCheckUTXO=false: view.HaveCoin() is unreliable here because:
            // - During mempool acceptance: mempool view shows conflicting TXs as spent
            // - During block validation: view state varies by call context
            // Settlement DB IsM1Receipt() is the authoritative check for M1 receipts
            if (view) {
                uint32_t nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
                if (!CheckHTLCCreate(tx, *view, state, false, nHeight)) {
                    return false;  // state already set by CheckHTLCCreate
                }
            }
            return true;
        }
        case CTransaction::TxType::HTLC_CLAIM: {
            // Validate HTLC claim: check HTLC exists and preimage is correct.
            // nHeight feeds the F-HTLC-2 R2 child-lifetime guard (covenant claims).
            if (view) {
                if (!CheckHTLCClaim(tx, *view, pindexPrev ? pindexPrev->nHeight + 1 : 0, state)) {
                    return false;
                }
            }
            return true;
        }
        case CTransaction::TxType::HTLC_REFUND: {
            // Validate HTLC refund: check HTLC exists and timelock expired
            if (view) {
                if (!CheckHTLCRefund(tx, *view, pindexPrev ? pindexPrev->nHeight + 1 : 0, state)) {
                    return false;
                }
            }
            return true;
        }
        // ═══════════════════════════════════════════════════════════════════════════
        // BP02-3S: 3-Secret HTLC for FlowSwap protocol
        // ═══════════════════════════════════════════════════════════════════════════
        case CTransaction::TxType::HTLC_CREATE_3S: {
            // Validate 3-secret HTLC creation: M1 receipt → HTLC3S P2SH
            if (view) {
                uint32_t nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
                if (!CheckHTLC3SCreate(tx, *view, state, false, nHeight)) {
                    return false;
                }
            }
            return true;
        }
        case CTransaction::TxType::HTLC_CLAIM_3S: {
            // Validate 3-secret HTLC claim: check HTLC3S exists and 3 preimages are correct
            if (view) {
                if (!CheckHTLC3SClaim(tx, *view, state)) {
                    return false;
                }
            }
            return true;
        }
        case CTransaction::TxType::HTLC_REFUND_3S: {
            // Validate 3-secret HTLC refund: check HTLC3S exists and timelock expired
            if (view) {
                if (!CheckHTLC3SRefund(tx, *view, pindexPrev ? pindexPrev->nHeight + 1 : 0, state)) {
                    return false;
                }
            }
            return true;
        }
        // ═══════════════════════════════════════════════════════════════════════════
        // BP10/BP11: BTC Burn Claims
        // TX_BURN_CLAIM: User submits burn proof → enters PENDING state
        // TX_MINT_M0BTC: Block producer creates after K_FINALITY → enters FINAL state
        // ═══════════════════════════════════════════════════════════════════════════
        case CTransaction::TxType::TX_BURN_CLAIM: {
            // Validate burn claim payload
            if (!tx.extraPayload) {
                return state.DoS(100, error("%s: TX_BURN_CLAIM missing payload", __func__),
                                 REJECT_INVALID, "bad-burnclaim-no-payload");
            }

            BurnClaimPayload payload;
            try {
                CDataStream ss(*tx.extraPayload, SER_NETWORK, PROTOCOL_VERSION);
                ss >> payload;
            } catch (...) {
                return state.DoS(100, error("%s: TX_BURN_CLAIM payload decode failed", __func__),
                                 REJECT_INVALID, "bad-burnclaim-decode");
            }

            std::string strError;
            if (!payload.IsTriviallyValid(strError)) {
                return state.DoS(100, error("%s: TX_BURN_CLAIM trivial validation failed: %s", __func__, strError),
                                 REJECT_INVALID, "bad-burnclaim-trivial");
            }

            // Full validation (SPV merkle proof against the consensus btcheadersdb +
            // duplicate check) is STATEFUL — it reads g_btcheadersdb, which only holds
            // the BTC headers published by blocks ALREADY connected. In the
            // context-free CheckBlock path (pindexPrev == nullptr) a block can arrive
            // OUT OF ORDER during IBD/headers-first sync: a far-ahead block's burn
            // references a BTC header that btcheadersdb only receives once the
            // intervening blocks connect. Running the stateful check here rejects that
            // valid block with burnclaim-btc-header-missing and STALLS the sync of any
            // node catching up (the live fleet grows ~in order, so it never saw this —
            // but a fresh/lagging node does; observed on a re-synced node stuck at a
            // far-ahead block). Defer to the contextual path, exactly like
            // TX_MINT_M0BTC above: ProcessSpecialTxsInBlock (ConnectBlock) re-invokes
            // CheckSpecialTx with pindexPrev = pindex->pprev in strict block order,
            // where btcheadersdb is always current. Mempool acceptance passes the tip
            // (non-null pindexPrev), so it keeps the full check.
            if (pindexPrev == nullptr) {
                return true;  // context-free CheckBlock: trivial validation only (done above)
            }
            uint32_t height = pindexPrev->nHeight + 1;
            return CheckBurnClaim(payload, state, height);
        }
        case CTransaction::TxType::TX_MINT_M0BTC: {
            // TX_MINT_M0BTC is only created by block producers during block creation
            // It should NEVER be submitted to mempool directly
            //
            // Call contexts:
            // - pindexPrev=null: CheckBlock→CheckSpecialTxNoContext (allow - basic validation)
            // - pindexPrev=chainActive.Tip: AcceptToMemoryPool (reject - handled in AcceptToMemoryPool)
            // - pindexPrev=pindex->pprev: ConnectBlock→ProcessSpecialTxsInBlock (allow - validated separately)
            //
            // NOTE: We cannot distinguish mempool vs block connection by pindexPrev alone
            // (both have pindexPrev == chainActive.Tip() at call time). The mempool rejection
            // is handled in AcceptToMemoryPool BEFORE calling CheckSpecialTx.
            // Here we just do basic payload validation for both contexts.

            // Basic payload validation (format check only)
            // Full validation (matching expected TX) is done in ProcessSpecialTxsInBlock
            if (!tx.extraPayload || tx.extraPayload->empty()) {
                return state.DoS(100, error("%s: TX_MINT_M0BTC missing payload", __func__),
                                 REJECT_INVALID, "bad-mint-payload");
            }
            MintPayload payload;
            try {
                CDataStream ss(*tx.extraPayload, SER_NETWORK, PROTOCOL_VERSION);
                ss >> payload;
            } catch (const std::exception& e) {
                return state.DoS(100, error("%s: TX_MINT_M0BTC payload decode failed: %s", __func__, e.what()),
                                 REJECT_INVALID, "bad-mint-payload-decode");
            }
            std::string strError;
            if (!payload.IsTriviallyValid(strError)) {
                return state.DoS(100, error("%s: TX_MINT_M0BTC trivial validation failed: %s", __func__, strError),
                                 REJECT_INVALID, "bad-mint-trivial");
            }
            return true;  // Basic validation passed
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // TX_BTC_HEADERS: On-chain BTC header publication (BP-SPVMNPUB)
        // ═══════════════════════════════════════════════════════════════════════════
        case CTransaction::TxType::TX_BTC_HEADERS: {
            // Consensus validation rules R1-R7
            // R7 (count/size) is checked FIRST inside CheckBtcHeadersTx
            return CheckBtcHeadersTx(tx, pindexPrev, state);
        }
    }

    return state.DoS(10, error("%s: special tx %s with invalid type %d", __func__, tx.GetHash().ToString(), tx.nType),
                     REJECT_INVALID, "bad-tx-type");
}

bool CheckSpecialTxNoContext(const CTransaction& tx, CValidationState& state)
{
    return CheckSpecialTx(tx, nullptr, nullptr, state);
}

// Registered set of HEIGHT-MONOTONIC-TIGHTENING special-tx reject reasons.
// These are the ONLY reasons for which validity strictly decreases as the
// chain height grows (the tx/record carries a fixed target height). Any future
// tightening rule MUST be registered here (and covered by a rollover test),
// otherwise the mempool sweep / assembler skip below will not catch it.
// Only two special-tx rules currently tighten with height: the pivot child
// under-life check (R2, HTLC_CLAIM) and the born-expired-parent check
// (HTLC_CREATE_M1); every other height-dependent special-tx rule loosens
// (e.g. refund "not-expired") and so never becomes invalid after admission.
static bool IsHeightTighteningRejectReason(const std::string& r)
{
    return r == "bad-htlcclaim-child-underlife" ||      // F-HTLC-2 R2 (claim births under-life child)
           r == "bad-htlccreate-expired-at-creation";   // F-HTLC-2 companion (parent born expired)
}

bool IsSpecialTxHeightPermanentlyInvalid(const CTransaction& tx, const CCoinsViewCache& view,
                                         uint32_t nHeight, std::string& strReason)
{
    AssertLockHeld(cs_main);
    strReason.clear();

    // Only the carriers of a tightening rule need to be probed. Everything
    // else is either height-independent or height-LOOSENING (premature), and a
    // premature special tx never enters the mempool (it is rejected at
    // admission and only admitted once already valid) — so it can never become
    // invalid here. Probing just these keeps this guard narrow and cheap.
    //
    // LOT 9 final — TX_OPERATOR_LEASE is a STATE-monotonic-tightening carrier:
    // the operator's on-chain sequence only ever GROWS along a chain (each mined
    // renewal increments it; nothing decrements it short of a reorg, which
    // re-evaluates the pool through its own path). A renewal carrying a sequence
    // <= the current one can therefore never become valid on this chain — the
    // competing wrapper of an already-mined renewal is exactly that case. It is
    // classified here by DECODING, never by probing CheckOperatorLeaseTx (no
    // signature verification on this per-mempool-tx-per-block path). A HIGHER
    // sequence is premature, which a reorg can revive — NOT permanent.
    CValidationState state;
    switch (tx.nType) {
    case CTransaction::TxType::TX_OPERATOR_LEASE: {
        OperatorLeasePL pl;
        if (!GetTxPayload(tx, pl)) return false;  // malformed never enters the pool
        auto mn = deterministicMNManager->GetListAtChainTip().GetMN(pl.proTxHash);
        if (!mn) return false;  // operator unknown here: reorg-dependent, not permanent
        if (pl.nLeaseSequence <= mn->pdmnState->nLeaseSequence) {
            strReason = "bad-lease-sequence-stale";
            return true;
        }
        return false;
    }
    case CTransaction::TxType::HTLC_CREATE_M1:
        // fCheckUTXO=false: we must not evict/skip on transient view state
        // (e.g. the M1 receipt shown spent by a competing mempool entry); only
        // the height-tightening companion reject is our concern here.
        if (CheckHTLCCreate(tx, view, state, /*fCheckUTXO=*/false, nHeight)) return false;
        break;
    case CTransaction::TxType::HTLC_CLAIM:
        if (CheckHTLCClaim(tx, view, nHeight, state)) return false;
        break;
    default:
        return false;  // no tightening rule on this type
    }

    // Rejected: it is our concern ONLY if the reason is a registered tightening
    // one. A same-block-pending parent ("bad-htlcclaim-not-htlc"), a bad amount,
    // etc. are NOT height-permanent — leave them to ConnectBlock / normal timing.
    const std::string& reason = state.GetRejectReason();
    if (IsHeightTighteningRejectReason(reason)) {
        strReason = reason;
        return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// B4.4 O2b helpers — fee-receipt owner registration (connect) / erasure (undo).
// Fee-receipt class = every exactly-OP_TRUE output of the settlement tx types
// that mint one: TX_TRANSFER_M1 (fee, last M1 vout) and covenant-mode
// HTLC_CLAIM / HTLC_CLAIM_3S (covenantFee, vout[1]). The per-type Check*
// guards guarantee at most ONE such output and no stray OP_TRUE, so the
// generic "every OP_TRUE vout" loop is exact. Owner = the including block's
// coinbase vout[0] script. Registration is gated (UPGRADE_FEE_RECEIPT_PINNED);
// erasure is ungated and idempotent (safe on pre-gate history replay).
// ═══════════════════════════════════════════════════════════════════════════
static void RegisterFeeReceiptOwners(const CTransaction& tx, const CBlock& block,
                                     const CBlockIndex* pindex, CSettlementDB::Batch& batch)
{
    if (!Params().GetConsensus().IsFeeReceiptPinned(pindex->nHeight)) return;
    if (block.vtx.empty() || block.vtx[0]->vout.empty()) return;
    const CScript& ownerScript = block.vtx[0]->vout[0].scriptPubKey;
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const CScript& spk = tx.vout[i].scriptPubKey;
        if (spk.size() == 1 && spk[0] == OP_TRUE) {
            batch.WriteFeeOwner(COutPoint(tx.GetHash(), i), ownerScript);
        }
    }
}

static void EraseFeeReceiptOwners(const CTransaction& tx, CSettlementDB::Batch& batch)
{
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const CScript& spk = tx.vout[i].scriptPubKey;
        if (spk.size() == 1 && spk[0] == OP_TRUE) {
            batch.EraseFeeOwner(COutPoint(tx.GetHash(), i));
        }
    }
}

// B4.4 O2b: fee-receipt destination covenant (the ENFORCEMENT half; caller gates
// it on UPGRADE_FEE_RECEIPT_PINNED). A fee-receipt registered at connect carries
// an owner (the including block's producer coinbase script). Spending it is valid
// only if the owned value flows to that owner OR to a fresh OP_TRUE fee output
// (owned by the next producer) — never to a third party, so a front-run becomes a
// donation to the producer line. All owned inputs in one tx must share a single
// owner. Extracted from CheckSpecialTx so the adversarial property test can hammer
// it in isolation (settlement_block_tests). Reads the committed settlement DB.
bool CheckFeeReceiptOwnerCovenant(const CTransaction& tx, CValidationState& state)
{
    if (!g_settlementdb) return true;
    CScript owner;
    bool haveOwner = false;
    CAmount ownedIn = 0;
    for (const CTxIn& txin : tx.vin) {
        CScript o;
        if (!g_settlementdb->ReadFeeOwner(txin.prevout, o)) continue;
        if (!haveOwner) { owner = o; haveOwner = true; }
        else if (o != owner) {
            return state.DoS(100, error("%s: tx spends fee-receipts with different owners", __func__),
                             REJECT_INVALID, "bad-txns-feereceipt-owner-mixed");
        }
        M1Receipt r;
        if (g_settlementdb->ReadReceipt(txin.prevout, r)) ownedIn += r.amount;
    }
    if (!haveOwner) return true;

    // Value may reach the owner directly OR a fresh OP_TRUE fee output (owned by
    // the NEXT block's producer) — never a third party. This lets the standard
    // settlement fee be carved without the sweeper adding its own M1, while a
    // front-runner paying THEMSELVES (a distinct script) can never satisfy it.
    CAmount toOwnerOrFee = 0;
    for (const CTxOut& out : tx.vout) {
        const CScript& spk = out.scriptPubKey;
        const bool isOpTrue = (spk.size() == 1 && spk[0] == OP_TRUE);
        if (spk == owner || isOpTrue) toOwnerOrFee += out.nValue;
    }
    // TX_UNLOCK's settlement fee is NOT an output (released from the vault into
    // the coinbase, BP30 v3.1) — a legitimate sweep-by-unlock pays the owner
    // ownedIn minus that fee. Allow only the MINIMUM fee as slack (floor 50, the
    // builder's dust floor), NOT the tx's actual fee: an attacker inflating the
    // fee to burn the owner's value into the coinbase (griefing, no thief profit)
    // is capped at this dust-sized slack per sweep.
    CAmount slack = 0;
    if (tx.nType == CTransaction::TxType::TX_UNLOCK) {
        slack = std::max(ComputeMinM1Fee(::GetSerializeSize(tx, PROTOCOL_VERSION)), (CAmount)50);
    }
    if (toOwnerOrFee + slack < ownedIn) {
        return state.DoS(100, error("%s: fee-receipt value %lld not paid to owner/fee (got %lld, slack %lld)",
                                    __func__, (long long)ownedIn, (long long)toOwnerOrFee, (long long)slack),
                         REJECT_INVALID, "bad-txns-feereceipt-owner");
    }
    return true;
}


bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, const CCoinsViewCache* view, CValidationState& state, bool fJustCheck, bool fSettlementOnly, ConsensusCommitStrategy* commitStrategy)
{
    AssertLockHeld(cs_main);
    LogPrintf("SPECIALTX: ProcessSpecialTxsInBlock ENTER height=%d fJustCheck=%d fSettlementOnly=%d\n",
              pindex->nHeight, fJustCheck, fSettlementOnly);

    // LOT 1 r15: fatal latch — a prior commit failure means the consensus DBs may be
    // torn. Refuse BEFORE any business read, validation or staging: no second
    // execution of the btcheaders apply (which would fail "bad-btcheaders-not-heavier"
    // against its own already-committed batch), no DoS, no BLOCK_FAILED_VALID.
    if (IsConsensusDBFatal()) {
        return state.Error("consensus-db-fatal: special-tx processing refused pending restart");
    }

    // Skip validation in settlement-only mode (used for rebuild from chain)
    if (!fSettlementOnly) {
        // check special txes
        for (const CTransactionRef& tx: block.vtx) {
            LogPrintf("SPECIALTX: CheckSpecialTx tx=%s nType=%d\n", tx->GetHash().ToString().substr(0, 16), (int)tx->nType);
            if (!CheckSpecialTx(*tx, pindex->pprev, view, state, /*fBlockConnect=*/true)) {
                // pass the state returned by the function above
                return false;
            }
        }
        LogPrintf("SPECIALTX: All CheckSpecialTx passed\n");

        // B4.6: block-level burn-claim checks (intra-block dedup + BP10 cap).
        // Per-tx CheckBurnClaim reads burnclaimdb, written only at connect —
        // same-block duplicates pass it; this closes that window.
        if (!CheckNoDuplicateBurnClaimsInBlock(block.vtx, state)) {
            return false;
        }

        // LOT 9 M3: one operator-lease renewal per proTxHash per block. Per-tx
        // CheckOperatorLeaseTx validates each against the PARENT list, so two
        // renewals carrying the same (previous+1) sequence would both pass it —
        // this whole-block scan closes that window, order-independently.
        if (!CheckNoDuplicateOperatorLeasesInBlock(block.vtx, state)) {
            return false;
        }

        // HU finality is handled via hu/finality.cpp

        LogPrintf("SPECIALTX: Calling deterministicMNManager->ProcessBlock...\n");
        if (!deterministicMNManager->ProcessBlock(block, pindex, state, fJustCheck)) {
            // pass the state returned by the function above
            LogPrintf("SPECIALTX: deterministicMNManager->ProcessBlock FAILED\n");
            return false;
        }
        LogPrintf("SPECIALTX: deterministicMNManager->ProcessBlock OK\n");
    } else {
        LogPrintf("SPECIALTX: Settlement-only mode - skipping CheckSpecialTx and MN processing\n");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ATOMICITY FIX: Declare batches at function scope so they survive until
    // the final commit phase. This prevents DB inconsistency if later processing fails.
    // ═══════════════════════════════════════════════════════════════════════════
    std::unique_ptr<CSettlementDB::Batch> settlementBatchPtr;
    std::unique_ptr<btcheadersdb::CBtcHeadersDB::Batch> btcHeadersBatchPtr;  // BP-SPVMNPUB
    // AUD-017: htlcdb and burnclaimdb used to write THROUGH to LevelDB mid-block, so a
    // block that failed a later check left durable consensus state behind (an orphan
    // PENDING claim, or an HTLC marked CLAIMED whose outpoint is still unspent) with no
    // rollback and no startup detection. They now share the same deferred-commit
    // boundary as settlement/btcheaders: staged here, committed only in the final phase.
    std::unique_ptr<CHtlcDB::Batch> htlcBatchPtr;
    std::unique_ptr<CBurnClaimDB::Batch> burnBatchPtr;
    SettlementState settlementStateForA6;  // Keep for A6 check
    // LOT 8 — A5 rules 2+3 operands, stashed in the settlement section and checked
    // AFTER the per-tx mint validation (precise LOT 2 reasons first), before commit.
    CAmount lot8PrevS = 0, lot8PrevL = 0, lot8DeltaS = 0, lot8DeltaL = 0;
    bool lot8A5Armed = false;
    bool hasSettlementBatch = false;
    bool hasBtcHeadersBatch = false;       // BP-SPVMNPUB
    CTransactionRef mintTxForCommit = nullptr;  // Keep for deferred ConnectMintM0BTC

    auto htlcBatch_ = [&]() -> CHtlcDB::Batch& {
        if (!htlcBatchPtr) htlcBatchPtr = std::make_unique<CHtlcDB::Batch>(g_htlcdb->CreateBatch());
        return *htlcBatchPtr;
    };
    auto burnBatch_ = [&]() -> CBurnClaimDB::Batch& {
        if (!burnBatchPtr) burnBatchPtr = std::make_unique<CBurnClaimDB::Batch>(g_burnclaimdb->CreateBatch());
        return *burnBatchPtr;
    };
    // L6-F12 — RECLASSIFIED WITH PROOF, not fixed by a guard (r4, independent review).
    //
    // r4 first added an `a6BaseVerified` gate here, downgrading A6 failures to
    // state.Error when the base state could not be verified against this block's
    // parent. The review showed that was wrong twice over, and it is REVERTED:
    //   (1) it fixed nothing. ApplyLock and ApplyUnlock move M0_vaulted and M1_supply
    //       by the SAME amount (settlement_logic.cpp), and the A6 parity check compares
    //       exactly those two counters — so A6 is preserved by construction under ANY
    //       base, including the zero base a failed ReadState leaves behind. These three
    //       sites cannot produce a verdict that depends on local settlement state.
    //   (2) it added a node-shutdown path. "settlement-base-unverifiable" is not in
    //       IsLocalFinalityRefusal's allowlist, so it fell into ActivateBestChainStep's
    //       "A system error occurred" branch -> return false -> node/init.cpp
    //       StartShutdown() — the exact hazard this work package removed elsewhere.
    //
    // The genuinely divergence-prone sites are a DIFFERENT family — CheckUnlock,
    // CheckTransfer, the CheckHTLC*Claim/Refund pair and CheckA7 all read
    // g_settlementdb / g_htlcdb and persist BLOCK_FAILED_VALID plus a peer ban from
    // that purely local state. That is a separate work package, recorded as a BLOCKING
    // follow-up rather than started here.

    // ═══════════════════════════════════════════════════════════════════════════
    // BP30 Settlement Layer: Apply state changes for TX_LOCK/UNLOCK/TRANSFER_M1
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck && g_settlementdb) {
        LogPrintf("SETTLEMENT: ProcessSpecialTxsInBlock START height=%d\n", pindex->nHeight);

        // Create batch for atomic updates (stored in function-scope ptr for deferred commit)
        settlementBatchPtr = std::make_unique<CSettlementDB::Batch>(g_settlementdb->CreateBatch());
        CSettlementDB::Batch& batch = *settlementBatchPtr;

        // Load current settlement state
        SettlementState settlementState;
        uint32_t prevHeight = pindex->pprev ? pindex->pprev->nHeight : 0;
        bool readOk = g_settlementdb->ReadState(prevHeight, settlementState);
        LogPrintf("SETTLEMENT: ReadState(h=%d) = %d, M0_vaulted=%lld M1_supply=%lld\n",
                  prevHeight, readOk,
                  (long long)settlementState.M0_vaulted,
                  (long long)settlementState.M1_supply);

        // LOT 7 (L6-F16) — the A5/A7 invariants below are computed FROM this base state.
        // The AUTHORITATIVE discriminator "is the settlement DB at the parent?" is the DB
        // best-block MARKER, and gate B (CheckSpecialTx) already checks it for every
        // special-tx type BEFORE we reach here: RequiredLocalStateDBs maps every type to
        // SETTLEMENT or BOTH, so a block whose settlement marker != parent is refused as a
        // LOCAL fault in phase 1 (fatal+reindex on connect / plain error on mempool) and
        // phase 2 never runs on a behind or empty DB. That is why a stale base cannot
        // produce a divergent A5/A7 verdict: the block does not get this far.
        //
        // This is the residual TORN-DB backstop for the one window gate B cannot see: the
        // marker says "at the parent" (so gate B passed) but the per-height base record is
        // missing or belongs to another block — i.e. the marker advanced without its state,
        // a crash mid-commit. SettlementState carries hashBlock, so we detect it. `readOk`
        // is REDUNDANT under the current serialization — hashBlock is the LAST field
        // (settlement.h) and CDataStream reads are all-or-nothing (streams.h: a short read
        // throws BEFORE the memcpy), so any failed/truncated ReadState leaves the freshly
        // default-constructed hashBlock null, which already fails `== expectedParent`. It is
        // kept DEFENSIVELY and would only become load-bearing if the field order changed.
        // A torn DB is a LOCAL fault -> fatal + reindex on this
        // (always the connect) path, NEVER an invalid block or a ban. Keying on the marker
        // (not the record alone) means synthetic fixtures with no parent marker — and every
        // healthy node — are unaffected; only a marker/record contradiction fires. Genesis
        // (prevHeight==0) has no predecessor record and is exempt.
        const uint256 expectedParent = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        uint256 dbMarker;
        const bool markerIsParent = pindex->pprev &&
            g_settlementdb->ReadBestBlock(dbMarker) && dbMarker == expectedParent;
        const bool baseTorn = markerIsParent &&
            !(readOk && settlementState.hashBlock == expectedParent);
        if (baseTorn) {
            LogPrintf("LOT7: settlement marker IS the parent but the base record at h=%d is "
                      "missing/mismatched (readOk=%d) — torn settlement DB, firing the "
                      "consensus-DB fatal latch, node must -reindex\n", prevHeight, readOk);
            AbortConsensusDBState(/*fConnect=*/true, /*nStep=*/0, "settlement-base", /*fPartial=*/false,
                                  pindex->nHeight, expectedParent, &state);
            return false;
        }


        // ═══════════════════════════════════════════════════════════════════════
        // SECURITY FIX: Track receipts created in this block to prevent
        // TX_LOCK from spending M1 receipts created earlier in the same block.
        // This closes the attack vector where:
        //   TX_A: LOCK creates Receipt_A (not yet in settlement DB)
        //   TX_B: LOCK spends Receipt_A (IsM0Standard returns true incorrectly)
        // ═══════════════════════════════════════════════════════════════════════
        std::set<COutPoint> pendingReceipts;  // Receipts created in this block
        std::set<COutPoint> pendingVaults;    // Vaults created in this block

        // Process settlement transactions
        for (const CTransactionRef& tx: block.vtx) {
            switch (tx->nType) {
                case CTransaction::TxType::TX_LOCK:
                    LogPrintf("SETTLEMENT: Processing TX_LOCK %s\n", tx->GetHash().ToString().substr(0, 16));

                    // SECURITY: Check that no input is a pending receipt from this block
                    for (const CTxIn& txin : tx->vin) {
                        if (pendingReceipts.count(txin.prevout)) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: TX_LOCK spends receipt from same block"),
                                           REJECT_INVALID, "bad-lock-spends-pending-receipt");
                        }
                    }

                    if (!CheckLock(*tx, *view, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: TX_LOCK validation failed");
                    }
                    LogPrintf("SETTLEMENT: CheckLock PASSED\n");
                    if (!ApplyLock(*tx, *view, settlementState, pindex->nHeight, batch)) {
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyLock failed"),
                                               REJECT_INVALID, "bad-lock-apply");
                    }

                    // Track the receipt created by this lock (vout[1] by convention)
                    pendingReceipts.insert(COutPoint(tx->GetHash(), 1));
                    pendingVaults.insert(COutPoint(tx->GetHash(), 0));

                    LogPrintf("SETTLEMENT: ApplyLock DONE, M0_vaulted=%lld M1_supply=%lld\n",
                              (long long)settlementState.M0_vaulted,
                              (long long)settlementState.M1_supply);
                    break;
                case CTransaction::TxType::TX_UNLOCK:
                    LogPrintf("SETTLEMENT: Processing TX_UNLOCK %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckUnlock(*tx, *view, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: TX_UNLOCK validation failed");
                    }
                    LogPrintf("SETTLEMENT: CheckUnlock PASSED\n");
                    {
                        UnlockUndoData undoData;
                        if (!ApplyUnlock(*tx, *view, settlementState, batch, undoData)) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyUnlock failed"),
                                               REJECT_INVALID, "bad-unlock-apply");
                        }
                        // Store undo data for reorg support (keyed by txid)
                        batch.WriteUnlockUndo(tx->GetHash(), undoData);
                        // Schedule GC of this undo data (SETTLEMENT_UNDO_PRUNE_DEPTH blocks later).
                        batch.WriteUndoPruneSchedule(static_cast<uint32_t>(pindex->nHeight), tx->GetHash(), /*undoType=*/0);
                    }
                    LogPrintf("SETTLEMENT: ApplyUnlock DONE, M0_vaulted=%lld M1_supply=%lld\n",
                              (long long)settlementState.M0_vaulted,
                              (long long)settlementState.M1_supply);
                    break;
                case CTransaction::TxType::TX_TRANSFER_M1:
                    LogPrintf("SETTLEMENT: Processing TX_TRANSFER_M1 %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckTransfer(*tx, *view, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: TX_TRANSFER_M1 validation failed");
                    }
                    LogPrintf("SETTLEMENT: CheckTransfer PASSED\n");
                    {
                        // BP30 v2.2: Store undo data for reorg support
                        TransferUndoData undoData;
                        if (!ApplyTransfer(*tx, *view, batch, undoData)) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyTransfer failed"),
                                         REJECT_INVALID, "bad-transfer-apply");
                        }
                        batch.WriteTransferUndo(tx->GetHash(), undoData);
                        // Schedule GC of this undo data (SETTLEMENT_UNDO_PRUNE_DEPTH blocks later).
                        batch.WriteUndoPruneSchedule(static_cast<uint32_t>(pindex->nHeight), tx->GetHash(), /*undoType=*/1);

                        // B4.4 O2b: pin the TRANSFER fee-receipt to this block's producer.
                        RegisterFeeReceiptOwners(*tx, block, pindex, batch);
                    }
                    LogPrintf("SETTLEMENT: ApplyTransfer DONE (M1 supply unchanged)\n");
                    break;
                // BP02 HTLC types
                case CTransaction::TxType::HTLC_CREATE_M1:
                    LogPrintf("HTLC: Processing HTLC_CREATE_M1 %s\n", tx->GetHash().ToString().substr(0, 16));
                    // Pass fCheckUTXO=false: by this point, UpdateCoins() has already spent the inputs
                    // from the view, so view.HaveCoin() would return false for in-block TXs
                    if (!CheckHTLCCreate(*tx, *view, state, false, pindex->nHeight)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: HTLC_CREATE_M1 validation failed");
                    }
                    {
                        if (!ApplyHTLCCreate(*tx, *view, pindex->nHeight, batch, htlcBatch_())) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyHTLCCreate failed"),
                                         REJECT_INVALID, "bad-htlc-create-apply");
                        }
                    }
                    LogPrintf("HTLC: ApplyHTLCCreate DONE\n");
                    break;
                case CTransaction::TxType::HTLC_CLAIM:
                    LogPrintf("HTLC: Processing HTLC_CLAIM %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLCClaim(*tx, *view, pindex->nHeight, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: HTLC_CLAIM validation failed");
                    }
                    {
                        if (!ApplyHTLCClaim(*tx, *view, pindex->nHeight, batch, htlcBatch_())) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyHTLCClaim failed"),
                                         REJECT_INVALID, "bad-htlc-claim-apply");
                        }
                        // B4.4 O2b: pin the covenant-mode claim fee (OP_TRUE vout[1]).
                        RegisterFeeReceiptOwners(*tx, block, pindex, batch);
                    }
                    LogPrintf("HTLC: ApplyHTLCClaim DONE\n");
                    break;
                case CTransaction::TxType::HTLC_REFUND:
                    LogPrintf("HTLC: Processing HTLC_REFUND %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLCRefund(*tx, *view, pindex->nHeight, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: HTLC_REFUND validation failed");
                    }
                    {
                        if (!ApplyHTLCRefund(*tx, *view, pindex->nHeight, batch, htlcBatch_())) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyHTLCRefund failed"),
                                         REJECT_INVALID, "bad-htlc-refund-apply");
                        }
                    }
                    LogPrintf("HTLC: ApplyHTLCRefund DONE\n");
                    break;
                // BP02-3S: 3-Secret HTLC for FlowSwap protocol
                case CTransaction::TxType::HTLC_CREATE_3S:
                    LogPrintf("HTLC3S: Processing HTLC_CREATE_3S %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLC3SCreate(*tx, *view, state, false, pindex->nHeight)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: HTLC_CREATE_3S validation failed");
                    }
                    {
                        if (!ApplyHTLC3SCreate(*tx, *view, pindex->nHeight, batch, htlcBatch_())) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyHTLC3SCreate failed"),
                                         REJECT_INVALID, "bad-htlc3s-create-apply");
                        }
                    }
                    LogPrintf("HTLC3S: ApplyHTLC3SCreate DONE\n");
                    break;
                case CTransaction::TxType::HTLC_CLAIM_3S:
                    LogPrintf("HTLC3S: Processing HTLC_CLAIM_3S %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLC3SClaim(*tx, *view, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: HTLC_CLAIM_3S validation failed");
                    }
                    {
                        if (!ApplyHTLC3SClaim(*tx, *view, pindex->nHeight, batch, htlcBatch_())) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyHTLC3SClaim failed"),
                                         REJECT_INVALID, "bad-htlc3s-claim-apply");
                        }
                        // B4.4 O2b: pin the covenant-mode claim fee (OP_TRUE vout[1]).
                        RegisterFeeReceiptOwners(*tx, block, pindex, batch);
                    }
                    LogPrintf("HTLC3S: ApplyHTLC3SClaim DONE\n");
                    break;
                case CTransaction::TxType::HTLC_REFUND_3S:
                    LogPrintf("HTLC3S: Processing HTLC_REFUND_3S %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLC3SRefund(*tx, *view, pindex->nHeight, state)) {
                        // L6-F13: the inner Check* already set MODE_INVALID with a PRECISE reject
                        // reason; wrapping it in a second DoS() overwrote that reason with a
                        // generic slug and doubled nDoS to 200. Return with the state the
                        // check produced — the verdict is identical, the diagnostic is not.
                        return error("ProcessSpecialTxsInBlock: HTLC_REFUND_3S validation failed");
                    }
                    {
                        if (!ApplyHTLC3SRefund(*tx, *view, pindex->nHeight, batch, htlcBatch_())) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: ApplyHTLC3SRefund failed"),
                                         REJECT_INVALID, "bad-htlc3s-refund-apply");
                        }
                    }
                    LogPrintf("HTLC3S: ApplyHTLC3SRefund DONE\n");
                    break;
                default:
                    break;
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // HTLC GC: erase RESOLVED HTLC records whose resolution is now deeper than
        // any possible reorg (HTLC_PRUNE_DEPTH). Their P2SH outpoints are spent
        // UTXOs — the UTXO layer, not htlcdb, guards against re-spend — so the
        // records are dead weight past reorg depth. Deterministic across nodes and
        // consensus-neutral (never changes a block-validity decision). Bounds
        // htlcdb to a ~PRUNE_DEPTH window instead of unbounded growth.
        // ═══════════════════════════════════════════════════════════════════════
        if (g_htlcdb && pindex->nHeight > static_cast<int>(HTLC_PRUNE_DEPTH)) {
            g_htlcdb->PruneResolvedAtHeight(
                static_cast<uint32_t>(pindex->nHeight) - HTLC_PRUNE_DEPTH, htlcBatch_());
        }

        // Same GC for TX_UNLOCK/TX_TRANSFER_M1 undo data (audit #6): keyed by txid,
        // written every unlock/transfer, read only by UndoSpecialTxsInBlock.
        //
        // Round-3 POINT 5: this used to commit its OWN batch immediately, i.e. a
        // DURABLE ERASURE performed before the block was validated and NOT undone if
        // the block then failed. I had called it "idempotent, consensus-neutral GC";
        // that is true of the erasure itself but it does not make a pre-validation
        // durable write acceptable, and the margin is zero: SETTLEMENT_UNDO_PRUNE_DEPTH
        // (100, settlement.h:53) EQUALS DEFAULT_MAX_REORG_DEPTH (100, consensus.h:30),
        // while nHuMaxReorgDepth is 0 on mainnet/testnet ("no artificial limit — reorg
        // blocked by actual HU finality only"). So a reorg that finality has not yet
        // bounded can reach exactly the depth whose undo data this just erased.
        // It now goes into the DEFERRED settlement batch: erased only if the block
        // commits, atomically with the state that made it dead weight.
        if (pindex->nHeight > static_cast<int>(SETTLEMENT_UNDO_PRUNE_DEPTH)) {
            g_settlementdb->PruneUndoAtHeight(
                static_cast<uint32_t>(pindex->nHeight) - SETTLEMENT_UNDO_PRUNE_DEPTH, batch);
        }

        // ═══════════════════════════════════════════════════════════════════════
        // A5 MONETARY CONSERVATION — INDEPENDENT (LOT 8).
        // (block reward = 0; coinbase only recycles fees — it never mints M0)
        //
        // The historical check compared two copies of the same local sum (tautology;
        // doc/LOT8-PHASE0-A5-INVENTORY.md). The replacement runs on STAGED values,
        // BEFORE any commit (a partial commit failure leaves a durable S != L on
        // disk — measured, doc/LOT8-M1B-FAILAT-MATRIX.md — so post-commit
        // accumulators must never be the gate's operands):
        //   Rule 1  parent coherence: prevS (settlement) == prevL (burn ledger),
        //           both read under markers certified at the parent. A mismatch is a
        //           LOCAL fault (corrupt DB) -> LOT 1 fatal latch, NEVER DoS/ban.
        //   Rule 2  independent deltas: Σ(mint outputs) == Σ(burnedSats of the
        //           parent's PENDING claims this block finalizes). A mismatch under a
        //           coherent parent is a DETERMINISTIC consensus invalidity.
        //   Rule 3  staged totals: nextS == nextL (overflow-checked) before commit.
        // ═══════════════════════════════════════════════════════════════════════

        // Save previous state for A5 verification
        SettlementState prevState;
        if (pindex->pprev) {
            g_settlementdb->ReadState(prevHeight, prevState);
        } else {
            // Genesis block: prevState is all zeros
            prevState.SetNull();
        }

        // ── Rule 1 — parent coherence (S vs L at the parent). Keyed EXACTLY like the
        // LOT 7 checks: it only speaks when BOTH DB best-block markers are the parent's
        // hash (then the committed DBs ARE the parent state — LOT 1 invariant), and the
        // genesis parent is exempt (markers are legitimately absent there; LOT 7). This
        // catches the corruption class where markers are correct but a TOTAL diverged:
        // a purely LOCAL fault -> fatal + reindex, never block invalidity, never a ban.
        const CAmount prevS = prevState.M0_total_supply;
        CAmount prevL = 0;
        bool fParentCoherent = false;   // true only when rule 1 actually verified S==L
        // F1: true only when the burn ledger's marker IS the parent, i.e. its total may
        // legitimately decide a consensus verdict. Beyond genesis this is now MANDATORY —
        // an uncertified ledger is a LOCAL FAULT, never a silent disarm (see below).
        bool fLedgerCertified = false;
        if (g_burnclaimdb && pindex->pprev && pindex->pprev->nHeight > 0) {
            const uint256 parentHash = pindex->pprev->GetBlockHash();
            uint256 sMk, lMk;
            const bool sAtParent = g_settlementdb->ReadBestBlock(sMk) && sMk == parentHash;
            const bool lAtParent = g_burnclaimdb->ReadBestBlock(lMk) && lMk == parentHash;

            // ── F1 — LEDGER CERTIFICATION (three cases, kept strictly separate).
            //
            // deltaL is read from the burn ledger, so the ledger's parent identity must be
            // CERTIFIED before any verdict depends on it. LOT 7's gate B certifies the
            // settlement/HTLC markers but NEVER the burnclaim one (RequiredLocalStateDBs
            // maps to SETTLEMENT/HTLC only), so an uncertified ledger reaches this point.
            //
            //   A. parent == genesis, marker legitimately absent (it is written by a
            //      block's own commit, so block 1 has none) -> exempt, A5 WITHHELD, no
            //      fatal, no DoS. Handled by the `pprev->nHeight > 0` guard above; this
            //      branch is not even entered. Same exemption as LOT 7's gate B.
            //   B. height > 0 and the marker is ABSENT or != pindexPrev -> the ledger
            //      cannot certify anything: LOCAL FAULT. Fire the LOT 1 fatal latch
            //      (non-invalid state.Error + REINDEX_REQUIRED). NEVER state.DoS, never a
            //      ban, never BLOCK_FAILED_*. A5 is NEVER silently disarmed here: an
            //      earlier revision withheld the verdict instead, which left the money
            //      belt off with no operator signal at all (measured: an inflated mint
            //      connected under mutation). Withholding was the wrong trade — the
            //      correct answer to "I cannot certify" is to STOP, not to judge blind.
            //   C. marker certified at the parent -> rules parent/delta/totals ARMED.
            //
            // Fixtures must model a real node (markers at the parent) rather than the rule
            // being relaxed to accommodate synthetic indexes.
            // NOTE (independent review, LOW): unlike the deferred rules 2/3 below, this
            // fatal is NOT excluded under fSettlementOnly. That path — RebuildSettlement
            // replaying with the other DBs untouched — is DEAD (no caller;
            // -rebuildsettlement is refused at init) and LOT 1 neutralised it precisely
            // because it repairs one DB and leaves the rest on a possibly non-canonical
            // block. Were it ever revived, its ledger marker would sit at the TIP, not at
            // the parent, and this fatal would fire on the first replayed block. Anyone
            // reviving it must add the exclusion here first.
            if (!lAtParent) {
                LogPrintf("LOT8(A5/F1): burn ledger is NOT certified at the parent (%s) — "
                          "its total cannot decide a monetary verdict; LOCAL fault, node "
                          "must -reindex\n", parentHash.ToString().substr(0, 16).c_str());
                AbortConsensusDBState(/*fConnect=*/true, /*nStep=*/0, "a5-ledger-uncertified",
                                      /*fPartial=*/false, pindex->nHeight,
                                      parentHash, &state);
                return false;
            }
            fLedgerCertified = true;
            if (sAtParent) {
                prevL = (CAmount)g_burnclaimdb->GetM0BTCSupply();
                if (prevS != prevL) {
                    LogPrintf("LOT8(A5): parent totals diverge under matching markers "
                              "(prevS=%lld prevL=%lld at parent %s) — local DB corruption, "
                              "node must -reindex\n", (long long)prevS, (long long)prevL,
                              parentHash.ToString().substr(0, 16).c_str());
                    AbortConsensusDBState(/*fConnect=*/true, /*nStep=*/0, "a5-parent",
                                          /*fPartial=*/false, pindex->nHeight,
                                          parentHash, &state);
                    return false;
                }
                fParentCoherent = true;
            }
        }

        // ── deltaS: Σ M0 created by this block's TX_MINT_M0BTC outputs (the
        // settlement-side delta). NEVER derived from the burn ledger.
        CAmount burnclaimsAmount = 0;
        for (const CTransactionRef& tx : block.vtx) {
            if (tx->nType == CTransaction::TxType::TX_MINT_M0BTC) {
                for (const CTxOut& out : tx->vout) {
                    burnclaimsAmount += out.nValue;
                }
            }
        }
        const CAmount deltaS = burnclaimsAmount;

        // ── deltaL: Σ record.burnedSats of the parent's PENDING claims this block
        // finalizes — read from the burn ledger COMMITTED AT THE PARENT (which claims a
        // mint finalizes = its payload's btcTxids; ConnectMintM0BTC flips exactly those
        // to FINAL). NEVER derived from the mint oracle or from the mint outputs.
        // A referenced claim that is missing or not PENDING contributes 0 — the delta
        // check below then rejects deterministically (and the per-tx CheckMintM0BTC /
        // expected-mint equality reject those blocks independently).
        CAmount deltaL = 0;
        std::set<uint256> countedBurns;   // REVIEW MEDIUM-2: one burn counted once per block
        if (g_burnclaimdb) {
            for (const CTransactionRef& tx : block.vtx) {
                if (tx->nType != CTransaction::TxType::TX_MINT_M0BTC) continue;
                MintPayload mp;
                if (!GetTxPayload(*tx, mp)) {
                    return state.DoS(100, error("ProcessSpecialTxsInBlock: undecodable mint payload"),
                                     REJECT_INVALID, "bad-mint-payload");
                }
                for (const uint256& btcTxid : mp.btcTxids) {
                    // REVIEW MEDIUM-2. Count each burn AT MOST ONCE across the whole block.
                    // Without this, a payload naming the same txid twice (with two matching
                    // outputs) inflated BOTH sides equally — deltaS = deltaL = 2b for a
                    // single real burn of b — so rule 2 PASSED while ConnectMintM0BTC
                    // incremented the ledger twice, and A5 kept reporting VERIFIED. The
                    // duplicate is caught elsewhere today (MintPayload::IsTriviallyValid ->
                    // bad-mint-trivial), but the independence belt must not be blind to a
                    // REFERENCE mutation while claiming to cover VALUE mutations. A repeat
                    // now adds 0 to deltaL, so deltaS != deltaL rejects the block.
                    if (!countedBurns.insert(btcTxid).second) continue;
                    BurnClaimRecord rec;
                    if (g_burnclaimdb->GetBurnClaim(btcTxid, rec) &&
                        rec.status == BurnClaimStatus::PENDING) {
                        if ((CAmount)rec.burnedSats >
                            std::numeric_limits<CAmount>::max() - deltaL) {
                            return state.DoS(100, error("ProcessSpecialTxsInBlock: deltaL overflow"),
                                             REJECT_INVALID, "settlement-a5-overflow");
                        }
                        deltaL += (CAmount)rec.burnedSats;
                    }
                }
            }
            // ── Rules 2 + 3 are DEFERRED (stashed here, checked below AFTER the
            // per-tx mint checks and the expected-mint equality), so the PRECISE
            // LOT 2 reject reasons (mint-unknown-claim / mint-amount-mismatch /
            // mint-not-pending / bad-mint-*) keep firing first on malformed mints,
            // and A5 stays the independent belt over the accumulators. Still runs
            // BEFORE the A6 check and before ANY commit (staged values only).
            // F1 case C: the ledger IS certified at the parent (case B already returned
            // fatal, case A never enters this block), so the verdict is ARMED. Beyond
            // genesis `fLedgerCertified` is necessarily true here, which is precisely why
            // A5 can no longer be silently disarmed at height > 0.
            lot8PrevS = prevS;
            lot8PrevL = fParentCoherent ? prevL : prevS;
            lot8DeltaS = deltaS;
            lot8DeltaL = deltaL;
            // Case A (genesis parent): the block above was never entered, so this stays
            // false -> A5 WITHHELD, no fatal, no DoS. Case B already returned fatal.
            // Case C: true -> ARMED. There is no fourth outcome at height > 0.
            lot8A5Armed = fLedgerCertified;
            // When rule 1 could not run (markerless fixtures / burnclaimdb-free setups /
            // genesis parent), prevL is substituted with prevS so rules 2-3 still bind
            // the DELTAS — the parent-coherence arm is then covered by the startup gate
            // and by rule 1 on the next marker-certified connect.
        }
        // NOTE: g_burnclaimdb == nullptr happens only in reduced unit fixtures; in
        // production init always creates it, so the delta check always arms.

        // Update A5 fields (burn-only: M0 only from BTC burns)
        settlementState.burnclaims_block = burnclaimsAmount;  // BP11
        settlementState.M0_total_supply = prevState.M0_total_supply + burnclaimsAmount;

        // A4 / A7 (circuit breaker): M0 is backed 1:1 by burned BTC, whose supply is
        // capped at 21M. M0_total_supply (sats) must therefore never exceed the 21M cap
        // (nMaxMoneyOut sats). A violation means inflation beyond the BTC supply — reject
        // the block. Catches both overflow and a runaway burn-claim accounting bug.
        if (!CheckA7(settlementState, Params().GetConsensus().nMaxMoneyOut, state)) {
            // L6-F13: CheckA7 already set a precise reason (settlement-a7-cap); keep it.
            return error("ProcessSpecialTxsInBlock: A4/A7 SUPPLY CAP VIOLATED at height=%d "
                         "(M0_total=%lld > cap=%lld)", pindex->nHeight,
                         (long long)settlementState.M0_total_supply,
                         (long long)Params().GetConsensus().nMaxMoneyOut);
        }

        // Update settlement state height/hash and write snapshot
        settlementState.nHeight = pindex->nHeight;
        settlementState.hashBlock = block.GetHash();

        LogPrintf("SETTLEMENT: A5 OK - M0_total=%lld (prev=%lld + delta=%lld, "
                  "independent deltaL=%lld, parentCoherent=%d)\n",
                  (long long)settlementState.M0_total_supply,
                  (long long)prevState.M0_total_supply,
                  (long long)deltaS, (long long)deltaL, (int)fParentCoherent);

        batch.WriteState(settlementState);

        // BP30 v2.2: Write best block hash atomically with batch
        batch.WriteBestBlock(block.GetHash());
        LogPrintf("SETTLEMENT: WriteState prepared for h=%d\n", pindex->nHeight);

        // ATOMICITY FIX: Store state for A6 check and defer commit to end of function
        settlementStateForA6 = settlementState;
        hasSettlementBatch = true;
        // NOTE: Commit moved to end of function (after A6 check passes)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP10/BP11: BTC Burn Claims and M0BTC Minting
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck && g_burnclaimdb) {
        LogPrintf("BURNCLAIM: ProcessSpecialTxsInBlock START height=%d\n", pindex->nHeight);

        int mintTxCount = 0;
        CTransactionRef actualMintTx = nullptr;

        for (const CTransactionRef& tx : block.vtx) {
            switch (tx->nType) {
                case CTransaction::TxType::TX_BURN_CLAIM: {
                    LogPrintf("BURNCLAIM: Processing TX_BURN_CLAIM %s\n",
                              tx->GetHash().ToString().substr(0, 16));

                    // Extract and validate payload
                    BurnClaimPayload payload;
                    if (!tx->extraPayload) {
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: TX_BURN_CLAIM missing payload"),
                                         REJECT_INVALID, "bad-burnclaim-payload-missing");
                    }
                    try {
                        CDataStream ss(*tx->extraPayload, SER_NETWORK, PROTOCOL_VERSION);
                        ss >> payload;
                    } catch (...) {
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: TX_BURN_CLAIM payload decode failed"),
                                         REJECT_INVALID, "bad-burnclaim-payload-decode");
                    }

                    // Enter PENDING state
                    if (!EnterPendingState(payload, pindex->nHeight, burnBatch_())) {
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: EnterPendingState failed"),
                                         REJECT_INVALID, "bad-burnclaim-pending");
                    }
                    LogPrintf("BURNCLAIM: TX_BURN_CLAIM entered PENDING state\n");
                    break;
                }
                case CTransaction::TxType::TX_MINT_M0BTC: {
                    LogPrintf("BURNCLAIM: Processing TX_MINT_M0BTC %s\n",
                              tx->GetHash().ToString().substr(0, 16));

                    mintTxCount++;
                    // Only 1 TX_MINT_M0BTC allowed per block (BP11 finalization)
                    // Block 1 has TX_BTC_HEADERS only, mints start at Block 2+
                    if (mintTxCount > 1) {
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: Multiple TX_MINT_M0BTC in block"),
                                         REJECT_INVALID, "bad-mint-multiple");
                    }
                    actualMintTx = tx;

                    // Validate mint TX (DO NOT apply yet - defer to after expectedMint validation)
                    //
                    // LOT 2 (AUD-003): mint validity is CONSENSUS-DETERMINISTIC on EVERY
                    // network. The old testnet/regtest `-enablemint=0` branch skipped
                    // CheckMintM0BTC entirely — a node-local option deciding block
                    // validity (and the door to the round-11 double-mint class). Local
                    // options are production/mempool policy only; they never change the
                    // acceptance of a received block. The bypass is REMOVED, not gated.
                    // CheckMintM0BTC fills `state` with a deterministic reject reason
                    // (mint-unknown-claim, mint-not-pending, mint-claim-too-early, ...);
                    // DoS(100) marks the block invalid instead of the old bare error()
                    // (which read as a SYSTEM error and caused endless retries).
                    if (!CheckMintM0BTC(*tx, state, pindex->nHeight)) {
                        const std::string reason = state.GetRejectReason();
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: CheckMintM0BTC failed: %s", reason),
                                         REJECT_INVALID, reason.empty() ? "bad-mint" : reason);
                    }
                    // NOTE: ConnectMintM0BTC moved to AFTER expectedMint validation
                    // to avoid atomicity bug where DB commits before validation passes
                    break;
                }
                case CTransaction::TxType::TX_BTC_HEADERS: {
                    // BP-SPVMNPUB: Process on-chain BTC headers
                    LogPrintf("BTCHEADERS: Processing TX_BTC_HEADERS %s\n",
                              tx->GetHash().ToString().substr(0, 16));

                    if (!g_btcheadersdb) {
                        return state.Error("btcheadersdb-unavailable");   // local: DB unavailable, block not judged
                    }

                    // Create batch if not already created
                    if (!btcHeadersBatchPtr) {
                        btcHeadersBatchPtr = std::make_unique<btcheadersdb::CBtcHeadersDB::Batch>(
                            g_btcheadersdb->CreateBatch());
                    }

                    // Process the TX_BTC_HEADERS (pass BATHRON height for publisher tracking)
                    if (!ProcessBtcHeadersTxInBlock(*tx, *btcHeadersBatchPtr, pindex->nHeight)) {
                        // LOT 1 round 5: was a bare error() with no reject reason, so the
                        // cause was invisible to callers and to tests. Setting a reason
                        // does NOT change the consensus rule — the block is rejected
                        // either way — it only makes the failure diagnosable.
                        return state.DoS(100, error("ProcessSpecialTxsInBlock: ProcessBtcHeadersTxInBlock failed"),
                                         REJECT_INVALID, "bad-btcheaders-apply");
                    }
                    hasBtcHeadersBatch = true;
                    LogPrintf("BTCHEADERS: TX_BTC_HEADERS processed OK\n");
                    break;
                }
                default:
                    break;
            }
        }

        // Validate that the expected TX_MINT_M0BTC is present (strict equality).
        // Block 1 has TX_BTC_HEADERS only. Mints start at Block 2+.
        //
        // LOT 2 (AUD-003): the oracle is CreateExpectedMintM0BTC — a pure function of
        // consensus state (burnclaimdb + btcheadersdb). It NEVER reads the burn kill
        // switch or -enablemint, so every honest node computes the same expectation
        // for the same block: two nodes with opposite local settings accept and
        // reject exactly the same blocks. (The old oracle read AreBtcBurnsEnabled();
        // a flipped node then rejected the canonical mint as "Unexpected".) The old
        // testnet/regtest `-enablemint=0` skip of this whole section is REMOVED.
        // The verdicts are deterministic consensus rules → DoS(100) + reject reason,
        // not the old bare error() that read as a retryable system error.
        if (pindex->nHeight >= 2) {
            CTransaction expectedMint = CreateExpectedMintM0BTC(pindex->nHeight);
            if (!expectedMint.IsNull()) {
                if (mintTxCount == 0) {
                    return state.DoS(100, error("ProcessSpecialTxsInBlock: Missing required TX_MINT_M0BTC"),
                                     REJECT_INVALID, "bad-mint-missing");
                }
                if (actualMintTx && actualMintTx->GetHash() != expectedMint.GetHash()) {
                    return state.DoS(100, error("ProcessSpecialTxsInBlock: TX_MINT_M0BTC mismatch "
                                                "(expected %s, got %s)",
                                                expectedMint.GetHash().ToString().substr(0, 16),
                                                actualMintTx->GetHash().ToString().substr(0, 16)),
                                     REJECT_INVALID, "bad-mint-mismatch");
                }
            } else {
                if (mintTxCount > 0) {
                    return state.DoS(100, error("ProcessSpecialTxsInBlock: Unexpected TX_MINT_M0BTC"),
                                     REJECT_INVALID, "bad-mint-unexpected");
                }
            }
        }

        // ATOMICITY FIX: Store mintTx for deferred ConnectMintM0BTC (after A6 check)
        if (actualMintTx) {
            mintTxForCommit = actualMintTx;
            LogPrintf("BURNCLAIM: TX_MINT_M0BTC validated, deferred for commit phase\n");
        }

        // NOTE: ConnectMintM0BTC + WriteBestBlock moved to final commit section below
        LogPrintf("BURNCLAIM: ProcessSpecialTxsInBlock validations OK\n");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LOT 8 — A5 rules 2+3 (deferred): the INDEPENDENT delta equality and the staged
    // totals, on the operands stashed in the settlement section. Runs AFTER the
    // per-tx mint checks and the expected-mint equality (their precise reject
    // reasons fire first on malformed mints) and BEFORE the A6 check and any commit.
    // fSettlementOnly (the neutralised rebuild path) is excluded: there the claims
    // are already FINAL in a non-wiped burnclaimdb, so deltaL would be structurally
    // 0 against a real deltaS — the path is disabled by LOT 1 and must not acquire
    // a new false invalidity.
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck && !fSettlementOnly && lot8A5Armed) {
        CAmount lot8NextS = 0;
        if (!CheckA5Independent(lot8PrevS, lot8PrevL, lot8DeltaS, lot8DeltaL,
                                Params().GetConsensus().nMaxMoneyOut, state, lot8NextS)) {
            // CheckA5Independent set a precise reason (settlement-a5-delta-mismatch /
            // -overflow / -negative / -total-mismatch); keep it (L6-F13 discipline).
            return error("ProcessSpecialTxsInBlock: A5 INDEPENDENT CHECK FAILED at height=%d "
                         "(deltaS=%lld deltaL=%lld)", pindex->nHeight,
                         (long long)lot8DeltaS, (long long)lot8DeltaL);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // A6 Invariant: M0_vaulted == M1_supply
    // ATOMICITY FIX: Use IN-MEMORY values (not DB reads) since batches not yet committed
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck && hasSettlementBatch) {
        if (settlementStateForA6.M0_vaulted != settlementStateForA6.M1_supply) {
            // L6-F12: same reasoning as the ApplyLock/ApplyUnlock sites — this compares
            // quantities derived from the base state read out of the LOCAL settlement DB.
            // Only mark the block invalid when that base was verified against this
            // block's parent; otherwise the node cannot judge and says so locally.
            return state.DoS(100, error("ProcessSpecialTxsInBlock: A6 invariant FAILED at height=%d: M0_vaulted=%lld != M1_supply=%lld",
                             pindex->nHeight, (long long)settlementStateForA6.M0_vaulted, (long long)settlementStateForA6.M1_supply),
                                 REJECT_INVALID, "bad-a6-parity");
        }
        LogPrintf("SETTLEMENT: A6 invariant OK at height=%d\n", pindex->nHeight);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ATOMICITY FIX: FINAL COMMIT PHASE
    // Only commit all DB batches AFTER all validations (A5, A6) have passed.
    // This prevents DB inconsistency if any validation fails.
    // ═══════════════════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE B (STAGE) — last fallible step before any durable write.
    //
    // ROUND 11, BLOCKING FIX. ConnectMintM0BTC used to sit INSIDE the commit phase,
    // after the settlement and btcheaders batches had already been committed. It only
    // STAGES (it writes into burnBatch_(), never to LevelDB), but its `return false`
    // was the first — and only — reachable failure positioned after a durable commit.
    // Under -enablemint=0 (testnet/regtest) a block carrying a valid TX_BTC_HEADERS
    // plus a mint naming an unknown claim was rejected here, AFTER btcheadersdb had
    // been committed; and CheckBtcHeadersDBConsistency then silently rewrote its own
    // marker, so the orphaned headers were never reported. That is exactly the
    // failure class this lot exists to remove, so the call moves BEFORE the boundary.
    //
    // Invariant this establishes: after the first Commit() nothing fallible runs
    // except the Commit()s themselves, whose only failure mode is I/O.
    if (!fJustCheck && mintTxForCommit) {
        // LOT 2: the injected strategy can force THIS step to fail, so a test can
        // assert that a staging failure happens with ZERO commit steps reached.
        // Since LOT 2 removed the -enablemint bypass, no real input can make
        // ConnectMintM0BTC fail any more, and without this hook the round-11
        // ordering guard is unfalsifiable (proven by mutation). Production passes
        // no strategy, so this is inert outside tests.
        const bool fForcedStagingFailure = commitStrategy && commitStrategy->ForceStagingFailure();
        if (fForcedStagingFailure ||
            !ConnectMintM0BTC(*mintTxForCommit, pindex->nHeight, burnBatch_())) {
            return state.DoS(100, error("ProcessSpecialTxsInBlock: ConnectMintM0BTC failed "
                                        "(mint names a claim absent from burnclaimdb) at height=%d",
                                        pindex->nHeight),
                             REJECT_INVALID, "bad-mint-unknown-claim-apply");
        }
        LogPrintf("BURNCLAIM: TX_MINT_M0BTC staged, %zu claims at height %d\n",
                  mintTxForCommit->vout.size(), pindex->nHeight);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE C (COMMIT) — batches only. NO business lookups, NO validation, NO
    // fallible Connect*/Apply* below this line. Anything added here that can fail
    // for a non-I/O reason reintroduces the round-11 defect.
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck) {
        // LOT 1 round 7: every commit below goes through this dispatcher. With no
        // strategy (production) it is a direct call; a test strategy can make step N
        // return false so we can assert no silent partial success.
        // ROUND 14 — a commit failure is a LOCAL STORAGE failure, never block
        // invalidity. ROUND 15 — round 14's StartShutdown() alone was NOT enough: it is
        // asynchronous, so ActivateBestChain could still RETRY the block on top of the
        // committed prefix before the shutdown landed, and the second pass could
        // convert the local failure into a bogus consensus rejection. Every failure now
        // goes through THE fatal primitive (validation.cpp AbortConsensusDBState):
        // latch first, first-context preserved, real AbortNode, shutdown requested,
        // state carries a non-invalid Error(). The injected strategy's Abort() is
        // OBSERVATION ONLY — it records, it cannot veto or replace the primitive.
        int commitsDone = 0;
        auto failCommit = [&](int step, const char* what) -> bool {
            const bool partial = (commitsDone > 0);
            AbortConsensusDBState(/*fConnect=*/true, step, what, partial,
                                  pindex->nHeight, block.GetHash(), &state);
            if (commitStrategy) commitStrategy->Abort(step, partial, state.GetRejectReason());
            return false;
        };
        auto doCommit = [&](int step, const std::function<bool()>& realCommit) -> bool {
            const bool ok = commitStrategy ? commitStrategy->Commit(step, realCommit)
                                           : (LabForcedCommitFailure(true, step) ? false : realCommit());
            if (ok) ++commitsDone;
            return ok;
        };

        // 1) Commit Settlement batch
        if (hasSettlementBatch && settlementBatchPtr) {
            if (!doCommit(1, [&]{ return settlementBatchPtr->Commit(); })) {
                return failCommit(1, "settlement batch");
            }
            LogPrintf("SETTLEMENT: Batch committed OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        // 2) Commit BTC headers batch (BP-SPVMNPUB)
        if (hasBtcHeadersBatch && btcHeadersBatchPtr) {
            btcHeadersBatchPtr->WriteBestBlock(block.GetHash());
            if (!doCommit(2, [&]{ return btcHeadersBatchPtr->Commit(); })) {
                return failCommit(2, "btcheaders batch");
            }
            LogPrintf("BTCHEADERS: Batch committed OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        // 2b) Commit the HTLC batch (AUD-017: staged since the first HTLC tx).
        if (htlcBatchPtr) {
            // LOT 1 round 4: the marker is written INSIDE the same WriteBatch as the
            // mutations, so it can never be ahead of or behind the records it vouches
            // for. It now HAS a reader — CheckHtlcDBConsistency, wired into the startup
            // gate — which is what was missing when round 2 removed the first attempt.
            htlcBatchPtr->WriteBestBlock(block.GetHash());
            if (!doCommit(3, [&]{ return htlcBatchPtr->Commit(); })) {
                return failCommit(3, "htlc batch");
            }
            LogPrintf("HTLC: Batch committed OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        } else if (g_htlcdb) {
            // No HTLC tx in this block — the marker must STILL advance, otherwise it
            // lags the tip and the startup gate would report a false divergence on the
            // very next restart. Same batch discipline, just nothing else in it.
            // Routed through doCommit as step 3 too: the ordering audit flagged this as
            // the one commit the injectable strategy could not reach, which would have
            // left a real commit outside the failure matrix.
            CHtlcDB::Batch markerOnly = g_htlcdb->CreateBatch();
            markerOnly.WriteBestBlock(block.GetHash());
            if (!doCommit(3, [&]{ return markerOnly.Commit(); })) {
                return failCommit(3, "htlc marker");
            }
        }

        // 4) Commit the BURNCLAIM batch — claims staged this block, the mint
        //    finalization above, and the best-block marker, in ONE atomic write.
        //    AUD-017: the marker can no longer be reached without the records that
        //    justify it, and a failed block commits neither.
        if (g_burnclaimdb) {
            burnBatch_().WriteBestBlock(block.GetHash());
            if (!doCommit(4, [&]{ return burnBatchPtr->Commit(); })) {
                return failCommit(4, "burnclaim batch");
            }
            LogPrintf("BURNCLAIM: Batch committed OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        // 5) ATOMICITY FIX: Write "all committed" marker LAST
        // At startup, if this differs from chain tip → need reindex
        if (g_settlementdb) {
            // Round 7: this result used to be DISCARDED, so the one marker the startup
            // gate depends on could fail while the block still reported success.
            if (!doCommit(5, [&]{ return g_settlementdb->WriteAllCommitted(block.GetHash()); })) {
                return failCommit(5, "all-committed marker");
            }
            LogPrintf("ATOMICITY: All DBs committed marker written for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        LogPrintf("SPECIALTX: All DB batches committed successfully\n");
    }

    return true;
}

bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck, ConsensusCommitStrategy* commitStrategy)
{
    // LOT 1 r15: fatal latch — same rule as the connect side. Refuse BEFORE any read
    // or staging; a disconnect over torn storage rewinds DBs that may not all be at
    // the same block.
    if (IsConsensusDBFatal()) {
        return error("UndoSpecialTxsInBlock: refused — consensus DB fatal latch is set; restart the node");
    }

    if (!deterministicMNManager->UndoBlock(block, pindex)) {
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP30 Settlement Layer: Undo state changes for TX_LOCK/TX_UNLOCK
    // ═══════════════════════════════════════════════════════════════════════════
    if (!g_settlementdb) {
        return true;  // No settlement DB, nothing to undo
    }

    // BP30 v2.3: Skip actual DB modifications during verification checks
    // During -checkblocks verification at startup, we only want to verify undo
    // data exists, not actually apply it to the settlement DB
    if (fJustCheck) {
        return true;  // Skip settlement undo during verification
    }

    CSettlementDB::Batch batch = g_settlementdb->CreateBatch();

    // AUD-017 (disconnect side): htlcdb and burnclaimdb are staged the same way as on
    // the connect side, so a disconnect that fails partway leaves them untouched
    // instead of half-reverted.
    std::unique_ptr<CHtlcDB::Batch> htlcBatchPtr;
    std::unique_ptr<CBurnClaimDB::Batch> burnBatchPtr;
    std::unique_ptr<btcheadersdb::CBtcHeadersDB::Batch> hdrBatchPtr;
    auto htlcBatch_ = [&]() -> CHtlcDB::Batch& {
        if (!htlcBatchPtr) htlcBatchPtr = std::make_unique<CHtlcDB::Batch>(g_htlcdb->CreateBatch());
        return *htlcBatchPtr;
    };
    auto burnBatch_ = [&]() -> CBurnClaimDB::Batch& {
        if (!burnBatchPtr) burnBatchPtr = std::make_unique<CBurnClaimDB::Batch>(g_burnclaimdb->CreateBatch());
        return *burnBatchPtr;
    };

    // Load current settlement state (must exist — written during ProcessSpecialTxsInBlock)
    SettlementState settlementState;
    if (!g_settlementdb->ReadState(pindex->nHeight, settlementState)) {
        return error("UndoSpecialTxsInBlock: Failed to read settlement state at height %d", pindex->nHeight);
    }

    // Undo settlement transactions (in reverse order)
    for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
        const CTransactionRef& tx = *it;
        switch (tx->nType) {
            case CTransaction::TxType::TX_LOCK:
                if (!UndoLock(*tx, settlementState, batch)) {
                    return error("UndoSpecialTxsInBlock: UndoLock failed");
                }
                break;
            case CTransaction::TxType::TX_UNLOCK:
                // BP30 v2.1: Load undo data from settlement DB
                {
                    UnlockUndoData undoData;
                    if (!g_settlementdb->ReadUnlockUndo(tx->GetHash(), undoData)) {
                        return error("UndoSpecialTxsInBlock: Failed to read UnlockUndoData for tx %s",
                                     tx->GetHash().ToString().substr(0, 16));
                    }

                    if (!UndoUnlock(*tx, undoData, settlementState, batch)) {
                        return error("UndoSpecialTxsInBlock: UndoUnlock failed");
                    }

                    // Erase undo data after successful undo
                    batch.EraseUnlockUndo(tx->GetHash());

                    LogPrintf("SETTLEMENT: UndoUnlock OK, M0_vaulted=%lld M1_supply=%lld\n",
                              (long long)settlementState.M0_vaulted,
                              (long long)settlementState.M1_supply);
                }
                break;
            case CTransaction::TxType::TX_TRANSFER_M1:
                {
                    // BP30 v2.2: Read undo data from settlement DB
                    TransferUndoData undoData;
                    if (!g_settlementdb->ReadTransferUndo(tx->GetHash(), undoData)) {
                        return error("UndoSpecialTxsInBlock: Failed to read TransferUndoData for tx %s",
                                     tx->GetHash().ToString().substr(0, 16));
                    }

                    if (!UndoTransfer(*tx, undoData, batch)) {
                        return error("UndoSpecialTxsInBlock: UndoTransfer failed");
                    }

                    // Erase undo data after successful undo
                    batch.EraseTransferUndo(tx->GetHash());

                    // B4.4 O2b: erase any fee-owner entries this transfer registered.
                    EraseFeeReceiptOwners(*tx, batch);

                    LogPrintf("SETTLEMENT: UndoTransfer OK, restored receipt amount=%lld\n",
                              (long long)undoData.originalReceipt.amount);
                }
                break;
            // BP02 HTLC undo
            case CTransaction::TxType::HTLC_CREATE_M1:
                {
                    if (!UndoHTLCCreate(*tx, batch, htlcBatch_())) {
                        return error("UndoSpecialTxsInBlock: UndoHTLCCreate failed");
                    }
                    LogPrintf("HTLC: UndoHTLCCreate OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_CLAIM:
                {
                    if (!UndoHTLCClaim(*tx, batch, htlcBatch_())) {
                        return error("UndoSpecialTxsInBlock: UndoHTLCClaim failed");
                    }
                    // B4.4 O2b: erase the claim fee's owner entry (idempotent).
                    EraseFeeReceiptOwners(*tx, batch);
                    LogPrintf("HTLC: UndoHTLCClaim OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_REFUND:
                {
                    if (!UndoHTLCRefund(*tx, batch, htlcBatch_())) {
                        return error("UndoSpecialTxsInBlock: UndoHTLCRefund failed");
                    }
                    LogPrintf("HTLC: UndoHTLCRefund OK\n");
                }
                break;
            // BP02-3S: 3-Secret HTLC undo
            case CTransaction::TxType::HTLC_CREATE_3S:
                {
                    if (!UndoHTLC3SCreate(*tx, batch, htlcBatch_())) {
                        return error("UndoSpecialTxsInBlock: UndoHTLC3SCreate failed");
                    }
                    LogPrintf("HTLC3S: UndoHTLC3SCreate OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_CLAIM_3S:
                {
                    if (!UndoHTLC3SClaim(*tx, batch, htlcBatch_())) {
                        return error("UndoSpecialTxsInBlock: UndoHTLC3SClaim failed");
                    }
                    // B4.4 O2b: erase the claim fee's owner entry (idempotent).
                    EraseFeeReceiptOwners(*tx, batch);
                    LogPrintf("HTLC3S: UndoHTLC3SClaim OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_REFUND_3S:
                {
                    if (!UndoHTLC3SRefund(*tx, batch, htlcBatch_())) {
                        return error("UndoSpecialTxsInBlock: UndoHTLC3SRefund failed");
                    }
                    LogPrintf("HTLC3S: UndoHTLC3SRefund OK\n");
                }
                break;
            default:
                break;
        }
    }

    // Restore previous settlement state
    uint32_t prevHeight = pindex->pprev ? pindex->pprev->nHeight : 0;
    uint256 prevBlockHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();

    // A5 FIX: Restore M0_total_supply from previous block's state.
    // The undo loop above correctly reverts M0_vaulted/M1_supply via
    // UndoLock/UndoUnlock, but M0_total_supply must be restored from
    // the previous block to undo any TX_MINT_M0BTC in this block.
    if (pindex->pprev) {
        SettlementState prevSettlementState;
        if (g_settlementdb->ReadState(prevHeight, prevSettlementState)) {
            settlementState.M0_total_supply = prevSettlementState.M0_total_supply;
            settlementState.burnclaims_block = prevSettlementState.burnclaims_block;
        } else {
            // Fallback: subtract burn amounts from this block
            CAmount burnclaimsAmount = 0;
            for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
                const CTransactionRef& tx = *it;
                if (tx->nType == CTransaction::TxType::TX_MINT_M0BTC) {
                    for (const CTxOut& out : tx->vout) {
                        burnclaimsAmount += out.nValue;
                    }
                }
            }
            if (burnclaimsAmount > settlementState.M0_total_supply) {
                return error("UndoSpecialTxsInBlock: M0_total_supply underflow "
                             "(supply=%lld, burnclaims=%lld)",
                             (long long)settlementState.M0_total_supply,
                             (long long)burnclaimsAmount);
            }
            settlementState.M0_total_supply -= burnclaimsAmount;
            settlementState.burnclaims_block = 0;
        }
    } else {
        settlementState.M0_total_supply = 0;
        settlementState.burnclaims_block = 0;
    }

    settlementState.nHeight = prevHeight;
    settlementState.hashBlock = prevBlockHash;
    batch.WriteState(settlementState);

    // BP30 v2.2: Write previous block hash atomically with batch
    batch.WriteBestBlock(prevBlockHash);

    // ═══════════════════════════════════════════════════════════════════════════
    // BP10/BP11: Undo BTC Burn Claims and M0BTC Minting
    // ═══════════════════════════════════════════════════════════════════════════
    if (g_burnclaimdb) {
        LogPrintf("BURNCLAIM: UndoSpecialTxsInBlock START height=%d\n", pindex->nHeight);

        // Undo burn claim transactions (in reverse order)
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            const CTransactionRef& tx = *it;
            switch (tx->nType) {
                case CTransaction::TxType::TX_MINT_M0BTC: {
                    LogPrintf("BURNCLAIM: Undoing TX_MINT_M0BTC %s\n",
                              tx->GetHash().ToString().substr(0, 16));

                    // Revert finalization
                    if (!DisconnectMintM0BTC(*tx, pindex->nHeight, burnBatch_())) {
                        return error("UndoSpecialTxsInBlock: DisconnectMintM0BTC failed for %s",
                                     tx->GetHash().ToString().substr(0, 16));
                    }
                    LogPrintf("BURNCLAIM: TX_MINT_M0BTC undo OK\n");
                    break;
                }
                case CTransaction::TxType::TX_BURN_CLAIM: {
                    LogPrintf("BURNCLAIM: Undoing TX_BURN_CLAIM %s\n",
                              tx->GetHash().ToString().substr(0, 16));

                    // Extract payload
                    BurnClaimPayload payload;
                    if (tx->extraPayload) {
                        try {
                            CDataStream ss(*tx->extraPayload, SER_NETWORK, PROTOCOL_VERSION);
                            ss >> payload;
                        } catch (...) {
                            return error("UndoSpecialTxsInBlock: TX_BURN_CLAIM payload decode failed");
                        }

                        // Undo pending state
                        if (!UndoBurnClaim(payload, pindex->nHeight, burnBatch_())) {
                            return error("UndoSpecialTxsInBlock: UndoBurnClaim failed");
                        }
                    }
                    LogPrintf("BURNCLAIM: TX_BURN_CLAIM undo OK\n");
                    break;
                }
                default:
                    break;
            }
        }

        // Update best block hash — inside the SAME batch as the undos above.
        uint256 prevBlockHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        burnBatch_().WriteBestBlock(prevBlockHash);   // staged; committed in PHASE C
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP-SPVMNPUB: Undo BTC Headers
    // ═══════════════════════════════════════════════════════════════════════════
    if (g_btcheadersdb) {
        LogPrintf("BTCHEADERS: UndoSpecialTxsInBlock START height=%d\n", pindex->nHeight);

        hdrBatchPtr = std::make_unique<btcheadersdb::CBtcHeadersDB::Batch>(g_btcheadersdb->CreateBatch());
        // Named hdrBatch, not `batch`: it used to shadow the settlement CSettlementDB::Batch
        // declared above, and BOTH types expose WriteBestBlock(const uint256&) — so any
        // future line added here meaning the settlement batch would have compiled silently
        // against the wrong database.
        btcheadersdb::CBtcHeadersDB::Batch& hdrBatch = *hdrBatchPtr;

        // Undo BTC header transactions (in reverse order)
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            const CTransactionRef& tx = *it;
            if (tx->nType == CTransaction::TxType::TX_BTC_HEADERS) {
                LogPrintf("BTCHEADERS: Undoing TX_BTC_HEADERS %s\n",
                          tx->GetHash().ToString().substr(0, 16));

                if (!DisconnectBtcHeadersTx(*tx, hdrBatch, pindex->nHeight)) {
                    return error("UndoSpecialTxsInBlock: DisconnectBtcHeadersTx failed");
                }
                LogPrintf("BTCHEADERS: TX_BTC_HEADERS undo OK\n");
            }
        }

        // Update best block hash
        uint256 prevBlockHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        hdrBatch.WriteBestBlock(prevBlockHash);   // staged; committed in PHASE C
    }

    // ATOMICITY: move the all_committed marker back to the previous block, exactly
    // like the connect path does after its final commit. Without this, a node whose
    // last action is a disconnect (InvalidateBlock, rollback without reconnect)
    // restarts with best_block == chain tip but all_committed still pointing at the
    // disconnected block -> the startup consistency check reads it as a mid-commit
    // crash and demands a full settlement rebuild for nothing.
    // ═══════════════════════════════════════════════════════════════════════════
    // PHASE C (COMMIT) — disconnect side. ROUND 12.
    //
    // Previously the settlement batch committed ~130 lines earlier, then the
    // burn-claim and btcheaders undo ran — both fallible — and could `return error`
    // with settlement (and htlc) already durable: a half-rewound disconnect. Every
    // undo is now STAGED first and nothing commits until here. Same rule as connect:
    // batches only, no business calls, every result checked, marker last.
    // ═══════════════════════════════════════════════════════════════════════════
    {
        const uint256 undoPrevHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        // ROUND 14 — same fail-closed discipline as connect. DisconnectTip returned a
        // bare error(), leaving chainActive still on the block whose settlement DB had
        // already been rewound: a retry then failed on the erased undo data and the node
        // could never reorg away from it.
        // ROUND 15 — same fatal primitive as the connect side (see the comment there):
        // latch first, real AbortNode once, strategy Abort() is observation only.
        int commitsDone = 0;
        auto failCommit = [&](int step, const char* what) -> bool {
            const bool partial = (commitsDone > 0);
            CValidationState fatalState;    // UndoSpecialTxsInBlock has no caller state
            AbortConsensusDBState(/*fConnect=*/false, step, what, partial,
                                  pindex->nHeight, pindex->GetBlockHash(), &fatalState);
            if (commitStrategy) commitStrategy->Abort(step, partial, fatalState.GetRejectReason());
            return false;
        };
        auto doCommit = [&](int step, const std::function<bool()>& realCommit) -> bool {
            const bool ok = commitStrategy ? commitStrategy->Commit(step, realCommit)
                                           : (LabForcedCommitFailure(false, step) ? false : realCommit());
            if (ok) ++commitsDone;
            return ok;
        };

        if (!doCommit(1, [&]{ return batch.Commit(); })) {
            return failCommit(1, "settlement batch");
        }
        if (htlcBatchPtr) {
            htlcBatchPtr->WriteBestBlock(undoPrevHash);
            if (!doCommit(3, [&]{ return htlcBatchPtr->Commit(); })) {
                return failCommit(3, "htlc undo batch");
            }
        } else if (g_htlcdb) {
            CHtlcDB::Batch markerOnly = g_htlcdb->CreateBatch();
            markerOnly.WriteBestBlock(undoPrevHash);
            if (!doCommit(3, [&]{ return markerOnly.Commit(); })) {
                return failCommit(3, "htlc marker");
            }
        }
        if (burnBatchPtr && !doCommit(4, [&]{ return burnBatchPtr->Commit(); })) {
            return failCommit(4, "burnclaim undo batch");
        }
        if (hdrBatchPtr && !doCommit(2, [&]{ return hdrBatchPtr->Commit(); })) {
            return failCommit(2, "btcheaders undo batch");
        }
        // ATOMICITY marker LAST, and its result is now CHECKED (it was discarded).
        if (g_settlementdb) {
            if (!doCommit(5, [&]{ return g_settlementdb->WriteAllCommitted(undoPrevHash); })) {
                return failCommit(5, "all-committed marker");
            }
        }
        LogPrintf("SPECIALTX: disconnect batches committed for prev=%s\n",
                  undoPrevHash.ToString().substr(0, 8));
    }

    return true;
}

uint256 CalcTxInputsHash(const CTransaction& tx)
{
    CHashWriter hw(CLIENT_VERSION, SER_GETHASH);
    // transparent inputs
    for (const CTxIn& in: tx.vin) {
        hw << in.prevout;
    }
    // shield inputs
    if (tx.hasSaplingData()) {
        for (const SpendDescription& sd: tx.sapData->vShieldedSpend) {
            hw << sd.nullifier;
        }
    }
    return hw.GetHash();
}

template <typename T>
bool GetValidatedTxPayload(const CTransaction& tx, T& obj, CValidationState& state)
{
    if (tx.nType != T::SPECIALTX_TYPE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-type");
    }
    if (!GetTxPayload(tx, obj)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
    }
    return obj.IsTriviallyValid(state);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 8 — architecture C: full-chain A5 audit (explicit command, never automatic).
// Recomputes both monetary totals from the canonical blocks alone; trusts NOTHING
// it audits. See the header for scope and honesty constraints.
// ═══════════════════════════════════════════════════════════════════════════════
bool AuditA5Supply(A5AuditResult& out)
{
    AssertLockHeld(cs_main);
    out = A5AuditResult();

    if (chainActive.Tip() == nullptr) {
        out.strError = "no chain";
        return false;
    }

    // burn txid -> parsed burnedSats, discovered from TX_BURN_CLAIM payloads on the
    // canonical chain (never read from burnclaimdb). Erased when a mint finalizes it,
    // so a double-mint of the same burn shows up as an unknown reference.
    std::map<uint256, CAmount> pendingBurns;

    for (int h = 0; h <= chainActive.Height(); ++h) {
        const CBlockIndex* pindex = chainActive[h];
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            out.strError = strprintf("block %d unreadable from disk (pruned/corrupt)", h);
            return false;   // caller must report UNAVAILABLE, never VERIFIED
        }
        ++out.nBlocksScanned;

        for (const CTransactionRef& tx : block.vtx) {
            if (tx->nType == CTransaction::TxType::TX_BURN_CLAIM) {
                BurnClaimPayload bp;
                if (!GetTxPayload(*tx, bp)) {
                    out.strError = strprintf("undecodable burn-claim payload at height %d", h);
                    return false;
                }
                BtcParsedTx parsed;
                BurnInfo info;
                if (!ParseBtcTransaction(bp.btcTxBytes, parsed) ||
                    !ParseBurnOutputs(parsed, info)) {
                    out.strError = strprintf("unparseable burn tx in claim at height %d", h);
                    return false;
                }
                pendingBurns[ComputeBtcTxid(parsed)] = (CAmount)info.burnedSats;
                ++out.nClaimsSeen;
            } else if (tx->nType == CTransaction::TxType::TX_MINT_M0BTC) {
                // S side: the mint's own outputs (settlement creation).
                for (const CTxOut& o : tx->vout) {
                    if (o.nValue < 0 ||
                        o.nValue > std::numeric_limits<CAmount>::max() - out.auditS) {
                        out.strError = strprintf("mint output overflow at height %d", h);
                        return false;
                    }
                    out.auditS += o.nValue;
                }
                // L side: the burns this mint finalizes, from the RECOMPUTED registry.
                MintPayload mp;
                if (!GetTxPayload(*tx, mp)) {
                    out.strError = strprintf("undecodable mint payload at height %d", h);
                    return false;
                }
                for (const uint256& btcTxid : mp.btcTxids) {
                    auto it = pendingBurns.find(btcTxid);
                    if (it == pendingBurns.end()) {
                        ++out.nUnknownMintRefs;   // double-mint or unknown ref -> mismatch
                        continue;
                    }
                    if (it->second > std::numeric_limits<CAmount>::max() - out.auditL) {
                        out.strError = strprintf("burn total overflow at height %d", h);
                        return false;
                    }
                    out.auditL += it->second;
                    pendingBurns.erase(it);       // one burn, one mint
                }
                ++out.nMintsSeen;
            }
            // NOTE: genesis/premine outputs are NORMAL/coinbase outputs, not
            // TX_MINT_M0BTC — they are structurally excluded from auditS, exactly as
            // they are excluded from M0_total_supply and m0btcSupply.
        }
    }

    // The live accumulators, for the caller's comparison (read, never trusted).
    if (g_settlementdb) {
        SettlementState st;
        if (g_settlementdb->ReadLatestState(st)) { out.dbS = st.M0_total_supply; out.haveDbS = true; }
        // REVIEW LOW-1 (mirror): an unreadable state stays UNREADABLE — the caller
        // reports UNAVAILABLE rather than auditing against a synthesized 0.
    }
    if (g_burnclaimdb) {
        out.dbL = (CAmount)g_burnclaimdb->GetM0BTCSupply();
        out.haveDbL = true;
    }

    out.fComplete = true;
    return true;
}
