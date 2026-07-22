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
#include "util/system.h"              // gArgs for enablemint flag

/* -- Helper static functions -- */

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
bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache* view, CValidationState& state)
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
        const bool m1ReceiptProtected = pindexPrev &&
            Params().GetConsensus().IsM1ReceiptProtected(pindexPrev->nHeight + 1);
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const CTxIn& txin = tx.vin[i];
            if (g_settlementdb->IsVault(txin.prevout)) {
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

    // Only the two carriers of a tightening rule need to be probed. Everything
    // else is either height-independent or height-LOOSENING (premature), and a
    // premature special tx never enters the mempool (it is rejected at
    // admission and only admitted once already valid) — so it can never become
    // invalid here. Probing just these two keeps this guard narrow and cheap.
    CValidationState state;
    switch (tx.nType) {
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


bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, const CCoinsViewCache* view, CValidationState& state, bool fJustCheck, bool fSettlementOnly)
{
    AssertLockHeld(cs_main);
    LogPrintf("SPECIALTX: ProcessSpecialTxsInBlock ENTER height=%d fJustCheck=%d fSettlementOnly=%d\n",
              pindex->nHeight, fJustCheck, fSettlementOnly);

    // Skip validation in settlement-only mode (used for rebuild from chain)
    if (!fSettlementOnly) {
        // check special txes
        for (const CTransactionRef& tx: block.vtx) {
            LogPrintf("SPECIALTX: CheckSpecialTx tx=%s nType=%d\n", tx->GetHash().ToString().substr(0, 16), (int)tx->nType);
            if (!CheckSpecialTx(*tx, pindex->pprev, view, state)) {
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
    SettlementState settlementStateForA6;  // Keep for A6 check
    bool hasSettlementBatch = false;
    bool hasBtcHeadersBatch = false;       // BP-SPVMNPUB
    CTransactionRef mintTxForCommit = nullptr;  // Keep for deferred ConnectMintM0BTC

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
                        return error("ProcessSpecialTxsInBlock: TX_LOCK validation failed");
                    }
                    LogPrintf("SETTLEMENT: CheckLock PASSED\n");
                    if (!ApplyLock(*tx, *view, settlementState, pindex->nHeight, batch)) {
                        return error("ProcessSpecialTxsInBlock: ApplyLock failed");
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
                        return error("ProcessSpecialTxsInBlock: TX_UNLOCK validation failed");
                    }
                    LogPrintf("SETTLEMENT: CheckUnlock PASSED\n");
                    {
                        UnlockUndoData undoData;
                        if (!ApplyUnlock(*tx, *view, settlementState, batch, undoData)) {
                            return error("ProcessSpecialTxsInBlock: ApplyUnlock failed");
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
                        return error("ProcessSpecialTxsInBlock: TX_TRANSFER_M1 validation failed");
                    }
                    LogPrintf("SETTLEMENT: CheckTransfer PASSED\n");
                    {
                        // BP30 v2.2: Store undo data for reorg support
                        TransferUndoData undoData;
                        if (!ApplyTransfer(*tx, *view, batch, undoData)) {
                            return error("ProcessSpecialTxsInBlock: ApplyTransfer failed");
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
                        return error("ProcessSpecialTxsInBlock: HTLC_CREATE_M1 validation failed");
                    }
                    {
                        CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                        if (!ApplyHTLCCreate(*tx, *view, pindex->nHeight, batch, htlcBatch)) {
                            return error("ProcessSpecialTxsInBlock: ApplyHTLCCreate failed");
                        }
                        htlcBatch.Commit();
                    }
                    LogPrintf("HTLC: ApplyHTLCCreate DONE\n");
                    break;
                case CTransaction::TxType::HTLC_CLAIM:
                    LogPrintf("HTLC: Processing HTLC_CLAIM %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLCClaim(*tx, *view, pindex->nHeight, state)) {
                        return error("ProcessSpecialTxsInBlock: HTLC_CLAIM validation failed");
                    }
                    {
                        CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                        if (!ApplyHTLCClaim(*tx, *view, pindex->nHeight, batch, htlcBatch)) {
                            return error("ProcessSpecialTxsInBlock: ApplyHTLCClaim failed");
                        }
                        htlcBatch.Commit();
                        // B4.4 O2b: pin the covenant-mode claim fee (OP_TRUE vout[1]).
                        RegisterFeeReceiptOwners(*tx, block, pindex, batch);
                    }
                    LogPrintf("HTLC: ApplyHTLCClaim DONE\n");
                    break;
                case CTransaction::TxType::HTLC_REFUND:
                    LogPrintf("HTLC: Processing HTLC_REFUND %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLCRefund(*tx, *view, pindex->nHeight, state)) {
                        return error("ProcessSpecialTxsInBlock: HTLC_REFUND validation failed");
                    }
                    {
                        CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                        if (!ApplyHTLCRefund(*tx, *view, pindex->nHeight, batch, htlcBatch)) {
                            return error("ProcessSpecialTxsInBlock: ApplyHTLCRefund failed");
                        }
                        htlcBatch.Commit();
                    }
                    LogPrintf("HTLC: ApplyHTLCRefund DONE\n");
                    break;
                // BP02-3S: 3-Secret HTLC for FlowSwap protocol
                case CTransaction::TxType::HTLC_CREATE_3S:
                    LogPrintf("HTLC3S: Processing HTLC_CREATE_3S %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLC3SCreate(*tx, *view, state, false, pindex->nHeight)) {
                        return error("ProcessSpecialTxsInBlock: HTLC_CREATE_3S validation failed");
                    }
                    {
                        CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                        if (!ApplyHTLC3SCreate(*tx, *view, pindex->nHeight, batch, htlcBatch)) {
                            return error("ProcessSpecialTxsInBlock: ApplyHTLC3SCreate failed");
                        }
                        htlcBatch.Commit();
                    }
                    LogPrintf("HTLC3S: ApplyHTLC3SCreate DONE\n");
                    break;
                case CTransaction::TxType::HTLC_CLAIM_3S:
                    LogPrintf("HTLC3S: Processing HTLC_CLAIM_3S %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLC3SClaim(*tx, *view, state)) {
                        return error("ProcessSpecialTxsInBlock: HTLC_CLAIM_3S validation failed");
                    }
                    {
                        CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                        if (!ApplyHTLC3SClaim(*tx, *view, pindex->nHeight, batch, htlcBatch)) {
                            return error("ProcessSpecialTxsInBlock: ApplyHTLC3SClaim failed");
                        }
                        htlcBatch.Commit();
                        // B4.4 O2b: pin the covenant-mode claim fee (OP_TRUE vout[1]).
                        RegisterFeeReceiptOwners(*tx, block, pindex, batch);
                    }
                    LogPrintf("HTLC3S: ApplyHTLC3SClaim DONE\n");
                    break;
                case CTransaction::TxType::HTLC_REFUND_3S:
                    LogPrintf("HTLC3S: Processing HTLC_REFUND_3S %s\n", tx->GetHash().ToString().substr(0, 16));
                    if (!CheckHTLC3SRefund(*tx, *view, pindex->nHeight, state)) {
                        return error("ProcessSpecialTxsInBlock: HTLC_REFUND_3S validation failed");
                    }
                    {
                        CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                        if (!ApplyHTLC3SRefund(*tx, *view, pindex->nHeight, batch, htlcBatch)) {
                            return error("ProcessSpecialTxsInBlock: ApplyHTLC3SRefund failed");
                        }
                        htlcBatch.Commit();
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
            CHtlcDB::Batch pruneBatch = g_htlcdb->CreateBatch();
            g_htlcdb->PruneResolvedAtHeight(
                static_cast<uint32_t>(pindex->nHeight) - HTLC_PRUNE_DEPTH, pruneBatch);
            pruneBatch.Commit();
        }

        // Same GC for TX_UNLOCK/TX_TRANSFER_M1 undo data (audit #6): keyed by txid,
        // written every unlock/transfer, read only by UndoSpecialTxsInBlock → dead
        // weight once deeper than any reorg. Deterministic + consensus-neutral.
        if (pindex->nHeight > static_cast<int>(SETTLEMENT_UNDO_PRUNE_DEPTH)) {
            CSettlementDB::Batch undoPruneBatch = g_settlementdb->CreateBatch();
            g_settlementdb->PruneUndoAtHeight(
                static_cast<uint32_t>(pindex->nHeight) - SETTLEMENT_UNDO_PRUNE_DEPTH, undoPruneBatch);
            undoPruneBatch.Commit();
        }

        // ═══════════════════════════════════════════════════════════════════════
        // A5 MONETARY CONSERVATION: M0_supply(N) = M0_supply(N-1) + BurnClaims
        // (block reward = 0; coinbase only recycles fees — it never mints M0)
        // This prevents inflation even if 90% of MNs are compromised
        // ═══════════════════════════════════════════════════════════════════════

        // Save previous state for A5 verification
        SettlementState prevState;
        if (pindex->pprev) {
            g_settlementdb->ReadState(prevHeight, prevState);
        } else {
            // Genesis block: prevState is all zeros
            prevState.SetNull();
        }

        // BP11: Calculate burnclaims amount (sum of TX_MINT_M0BTC outputs)
        // This must be calculated BEFORE A5 check
        CAmount burnclaimsAmount = 0;
        for (const CTransactionRef& tx : block.vtx) {
            if (tx->nType == CTransaction::TxType::TX_MINT_M0BTC) {
                for (const CTxOut& out : tx->vout) {
                    burnclaimsAmount += out.nValue;
                }
            }
        }

        // Update A5 fields (burn-only: M0 only from BTC burns)
        settlementState.burnclaims_block = burnclaimsAmount;  // BP11
        settlementState.M0_total_supply = prevState.M0_total_supply + burnclaimsAmount;

        // A4 / A7 (circuit breaker): M0 is backed 1:1 by burned BTC, whose supply is
        // capped at 21M. M0_total_supply (sats) must therefore never exceed the 21M cap
        // (nMaxMoneyOut sats). A violation means inflation beyond the BTC supply — reject
        // the block. Catches both overflow and a runaway burn-claim accounting bug.
        if (!CheckA7(settlementState, Params().GetConsensus().nMaxMoneyOut, state)) {
            return error("ProcessSpecialTxsInBlock: A4/A7 SUPPLY CAP VIOLATED at height=%d "
                         "(M0_total=%lld > cap=%lld)", pindex->nHeight,
                         (long long)settlementState.M0_total_supply,
                         (long long)Params().GetConsensus().nMaxMoneyOut);
        }

        // Update settlement state height/hash and write snapshot
        settlementState.nHeight = pindex->nHeight;
        settlementState.hashBlock = block.GetHash();

        // Verify A5 invariant before committing
        if (!CheckA5(settlementState, prevState, state)) {
            return error("ProcessSpecialTxsInBlock: A5 MONETARY CONSERVATION VIOLATED at height=%d", pindex->nHeight);
        }
        LogPrintf("SETTLEMENT: A5 OK - M0_total=%lld (prev=%lld + burns=%lld)\n",
                  (long long)settlementState.M0_total_supply,
                  (long long)prevState.M0_total_supply,
                  (long long)burnclaimsAmount);

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
                        return error("ProcessSpecialTxsInBlock: TX_BURN_CLAIM missing payload");
                    }
                    try {
                        CDataStream ss(*tx->extraPayload, SER_NETWORK, PROTOCOL_VERSION);
                        ss >> payload;
                    } catch (...) {
                        return error("ProcessSpecialTxsInBlock: TX_BURN_CLAIM payload decode failed");
                    }

                    // Enter PENDING state
                    if (!EnterPendingState(payload, pindex->nHeight)) {
                        return error("ProcessSpecialTxsInBlock: EnterPendingState failed");
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
                        return error("ProcessSpecialTxsInBlock: Multiple TX_MINT_M0BTC in block");
                    }
                    actualMintTx = tx;

                    // Validate mint TX (DO NOT apply yet - defer to after expectedMint validation)
                    // BP11: -enablemint=0 skips mint validation (testnet recovery/dev ONLY).
                    // HARD-GATED to testnet/regtest — on mainnet the bypass is NEVER honored,
                    // so a real value-bearing chain can never accept an unbacked TX_MINT_M0BTC.
                    const bool fAllowMintBypass = Params().IsTestnet() || Params().IsRegTestNet();
                    const bool fEnableMintValidation = fAllowMintBypass ? gArgs.GetBoolArg("-enablemint", true) : true;
                    if (fEnableMintValidation) {
                        CValidationState mintState;
                        if (!CheckMintM0BTC(*tx, mintState, pindex->nHeight)) {
                            return error("ProcessSpecialTxsInBlock: CheckMintM0BTC failed: %s",
                                         mintState.GetRejectReason());
                        }
                    } else {
                        LogPrintf("BURNCLAIM: TX_MINT_M0BTC validation skipped (-enablemint=0)\n");
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
                        return error("ProcessSpecialTxsInBlock: btcheadersdb not initialized");
                    }

                    // Create batch if not already created
                    if (!btcHeadersBatchPtr) {
                        btcHeadersBatchPtr = std::make_unique<btcheadersdb::CBtcHeadersDB::Batch>(
                            g_btcheadersdb->CreateBatch());
                    }

                    // Process the TX_BTC_HEADERS (pass BATHRON height for publisher tracking)
                    if (!ProcessBtcHeadersTxInBlock(*tx, *btcHeadersBatchPtr, pindex->nHeight)) {
                        return error("ProcessSpecialTxsInBlock: ProcessBtcHeadersTxInBlock failed");
                    }
                    hasBtcHeadersBatch = true;
                    LogPrintf("BTCHEADERS: TX_BTC_HEADERS processed OK\n");
                    break;
                }
                default:
                    break;
            }
        }

        // Validate that expected TX_MINT_M0BTC is present (strict equality)
        // BP11: -enablemint=0 skips mint validation (testnet recovery/dev ONLY) — HARD-GATED
        // to testnet/regtest; on mainnet the bypass is never honored.
        // Block 1 has TX_BTC_HEADERS only. Mints start at Block 2+.
        const bool fAllowMintBypass2 = Params().IsTestnet() || Params().IsRegTestNet();
        const bool fEnableMint = fAllowMintBypass2 ? gArgs.GetBoolArg("-enablemint", true) : true;
        if (fEnableMint && pindex->nHeight >= 2) {
            CTransaction expectedMint = CreateMintM0BTC(pindex->nHeight);
            if (!expectedMint.IsNull()) {
                if (mintTxCount == 0) {
                    return error("ProcessSpecialTxsInBlock: Missing required TX_MINT_M0BTC");
                }
                if (actualMintTx && actualMintTx->GetHash() != expectedMint.GetHash()) {
                    return error("ProcessSpecialTxsInBlock: TX_MINT_M0BTC mismatch "
                                 "(expected %s, got %s)",
                                 expectedMint.GetHash().ToString().substr(0, 16),
                                 actualMintTx->GetHash().ToString().substr(0, 16));
                }
            } else {
                if (mintTxCount > 0) {
                    return error("ProcessSpecialTxsInBlock: Unexpected TX_MINT_M0BTC");
                }
            }
        } else if (!fEnableMint) {
            LogPrintf("BURNCLAIM: TX_MINT_M0BTC validation skipped (-enablemint=0)\n");
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
    // A6 Invariant: M0_vaulted == M1_supply
    // ATOMICITY FIX: Use IN-MEMORY values (not DB reads) since batches not yet committed
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck && hasSettlementBatch) {
        if (settlementStateForA6.M0_vaulted != settlementStateForA6.M1_supply) {
            return error("ProcessSpecialTxsInBlock: A6 invariant FAILED at height=%d: M0_vaulted=%lld != M1_supply=%lld",
                         pindex->nHeight, (long long)settlementStateForA6.M0_vaulted, (long long)settlementStateForA6.M1_supply);
        }
        LogPrintf("SETTLEMENT: A6 invariant OK at height=%d\n", pindex->nHeight);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ATOMICITY FIX: FINAL COMMIT PHASE
    // Only commit all DB batches AFTER all validations (A5, A6) have passed.
    // This prevents DB inconsistency if any validation fails.
    // ═══════════════════════════════════════════════════════════════════════════
    if (!fJustCheck) {
        // 1) Commit Settlement batch
        if (hasSettlementBatch && settlementBatchPtr) {
            if (!settlementBatchPtr->Commit()) {
                return error("ProcessSpecialTxsInBlock: Failed to commit settlement batch");
            }
            LogPrintf("SETTLEMENT: Batch committed OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        // 2) Commit BTC headers batch (BP-SPVMNPUB)
        if (hasBtcHeadersBatch && btcHeadersBatchPtr) {
            btcHeadersBatchPtr->WriteBestBlock(block.GetHash());
            if (!btcHeadersBatchPtr->Commit()) {
                return error("ProcessSpecialTxsInBlock: Failed to commit btcheaders batch");
            }
            LogPrintf("BTCHEADERS: Batch committed OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        // 3) Apply BURNCLAIM finalization
        // ═══════════════════════════════════════════════════════════════════════════
        // DAEMON-ONLY BURN FLOW: TX_BURN_CLAIM → TX_MINT_M0BTC
        // Burns detected by burn_claim_daemon after network starts.
        // Same K_FINALITY for ALL burns (20 testnet, 100 mainnet).
        // ═══════════════════════════════════════════════════════════════════════════
        if (mintTxForCommit) {
            ConnectMintM0BTC(*mintTxForCommit, pindex->nHeight);
            LogPrintf("BURNCLAIM: TX_MINT_M0BTC finalized %zu claims at height %d\n",
                mintTxForCommit->vout.size(), pindex->nHeight);
        }

        // 4) Write BURNCLAIM best block
        if (g_burnclaimdb) {
            g_burnclaimdb->WriteBestBlock(block.GetHash());
            LogPrintf("BURNCLAIM: WriteBestBlock OK for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        // 5) ATOMICITY FIX: Write "all committed" marker LAST
        // At startup, if this differs from chain tip → need reindex
        if (g_settlementdb) {
            g_settlementdb->WriteAllCommitted(block.GetHash());
            LogPrintf("ATOMICITY: All DBs committed marker written for block=%s\n", block.GetHash().ToString().substr(0, 8));
        }

        LogPrintf("SPECIALTX: All DB batches committed successfully\n");
    }

    return true;
}

bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, bool fJustCheck)
{
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
                    CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                    if (!UndoHTLCCreate(*tx, batch, htlcBatch)) {
                        return error("UndoSpecialTxsInBlock: UndoHTLCCreate failed");
                    }
                    htlcBatch.Commit();
                    LogPrintf("HTLC: UndoHTLCCreate OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_CLAIM:
                {
                    CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                    if (!UndoHTLCClaim(*tx, batch, htlcBatch)) {
                        return error("UndoSpecialTxsInBlock: UndoHTLCClaim failed");
                    }
                    htlcBatch.Commit();
                    // B4.4 O2b: erase the claim fee's owner entry (idempotent).
                    EraseFeeReceiptOwners(*tx, batch);
                    LogPrintf("HTLC: UndoHTLCClaim OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_REFUND:
                {
                    CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                    if (!UndoHTLCRefund(*tx, batch, htlcBatch)) {
                        return error("UndoSpecialTxsInBlock: UndoHTLCRefund failed");
                    }
                    htlcBatch.Commit();
                    LogPrintf("HTLC: UndoHTLCRefund OK\n");
                }
                break;
            // BP02-3S: 3-Secret HTLC undo
            case CTransaction::TxType::HTLC_CREATE_3S:
                {
                    CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                    if (!UndoHTLC3SCreate(*tx, batch, htlcBatch)) {
                        return error("UndoSpecialTxsInBlock: UndoHTLC3SCreate failed");
                    }
                    htlcBatch.Commit();
                    LogPrintf("HTLC3S: UndoHTLC3SCreate OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_CLAIM_3S:
                {
                    CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                    if (!UndoHTLC3SClaim(*tx, batch, htlcBatch)) {
                        return error("UndoSpecialTxsInBlock: UndoHTLC3SClaim failed");
                    }
                    htlcBatch.Commit();
                    // B4.4 O2b: erase the claim fee's owner entry (idempotent).
                    EraseFeeReceiptOwners(*tx, batch);
                    LogPrintf("HTLC3S: UndoHTLC3SClaim OK\n");
                }
                break;
            case CTransaction::TxType::HTLC_REFUND_3S:
                {
                    CHtlcDB::Batch htlcBatch = g_htlcdb->CreateBatch();
                    if (!UndoHTLC3SRefund(*tx, batch, htlcBatch)) {
                        return error("UndoSpecialTxsInBlock: UndoHTLC3SRefund failed");
                    }
                    htlcBatch.Commit();
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

    // Commit batch atomically
    if (!batch.Commit()) {
        return error("UndoSpecialTxsInBlock: Failed to write settlement batch");
    }

    LogPrintf("SETTLEMENT: Undo committed OK, reverted to block=%s (h=%d)\n",
              prevBlockHash.ToString().substr(0, 8), prevHeight);

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
                    DisconnectMintM0BTC(*tx, pindex->nHeight);
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
                        if (!UndoBurnClaim(payload, pindex->nHeight)) {
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

        // Update best block hash
        uint256 prevBlockHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        g_burnclaimdb->WriteBestBlock(prevBlockHash);
        LogPrintf("BURNCLAIM: Undo committed OK\n");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP-SPVMNPUB: Undo BTC Headers
    // ═══════════════════════════════════════════════════════════════════════════
    if (g_btcheadersdb) {
        LogPrintf("BTCHEADERS: UndoSpecialTxsInBlock START height=%d\n", pindex->nHeight);

        btcheadersdb::CBtcHeadersDB::Batch batch = g_btcheadersdb->CreateBatch();

        // Undo BTC header transactions (in reverse order)
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            const CTransactionRef& tx = *it;
            if (tx->nType == CTransaction::TxType::TX_BTC_HEADERS) {
                LogPrintf("BTCHEADERS: Undoing TX_BTC_HEADERS %s\n",
                          tx->GetHash().ToString().substr(0, 16));

                if (!DisconnectBtcHeadersTx(*tx, batch, pindex->nHeight)) {
                    return error("UndoSpecialTxsInBlock: DisconnectBtcHeadersTx failed");
                }
                LogPrintf("BTCHEADERS: TX_BTC_HEADERS undo OK\n");
            }
        }

        // Update best block hash
        uint256 prevBlockHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        batch.WriteBestBlock(prevBlockHash);
        if (!batch.Commit()) {
            return error("UndoSpecialTxsInBlock: Failed to commit btcheaders undo batch");
        }
        LogPrintf("BTCHEADERS: Undo committed OK\n");
    }

    // ATOMICITY: move the all_committed marker back to the previous block, exactly
    // like the connect path does after its final commit. Without this, a node whose
    // last action is a disconnect (InvalidateBlock, rollback without reconnect)
    // restarts with best_block == chain tip but all_committed still pointing at the
    // disconnected block -> the startup consistency check reads it as a mid-commit
    // crash and demands a full settlement rebuild for nothing.
    if (g_settlementdb) {
        uint256 prevBlockHash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
        g_settlementdb->WriteAllCommitted(prevBlockHash);
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
