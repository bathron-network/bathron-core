// Copyright (c) 2018-2021 The Dash Core developers
// Copyright (c) 2021-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/providertx.h"

#include "key_io.h"
#include "utilstrencodings.h"

std::string ProRegPL::MakeSignString() const
{
    std::ostringstream ss;

    ss << HexStr(scriptPayout) << "|";
    ss << EncodeDestination(keyIDOwner) << "|";
    ss << EncodeDestination(keyIDVoting) << "|";

    // ... and also the full hash of the payload as a protection against malleability and replays
    ss << ::SerializeHash(*this).ToString();

    return ss.str();
}

std::string ProRegPL::ToString() const
{
    CTxDestination dest;
    std::string payee = ExtractDestination(scriptPayout, dest) ?
                        EncodeDestination(dest) : "unknown";
    return strprintf("ProRegPL(nVersion=%d, collateralOutpoint=%s, addr=%s, ownerAddress=%s, operatorPubKey=%s, votingAddress=%s, scriptPayout=%s)",
        nVersion, collateralOutpoint.ToStringShort(), addr.ToString(), EncodeDestination(keyIDOwner), HexStr(pubKeyOperator), EncodeDestination(keyIDVoting), payee);
}

void ProRegPL::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.pushKV("version", nVersion);
    obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
    obj.pushKV("collateralIndex", (int)collateralOutpoint.n);
    obj.pushKV("service", addr.ToString());
    obj.pushKV("ownerAddress", EncodeDestination(keyIDOwner));
    // BATHRON: ECDSA pubkey
    obj.pushKV("operatorPubKey", HexStr(pubKeyOperator));
    obj.pushKV("vrfPubKey", HexStr(pubKeyVRF));
    obj.pushKV("votingAddress", EncodeDestination(keyIDVoting));

    CTxDestination dest1;
    if (ExtractDestination(scriptPayout, dest1)) {
        obj.pushKV("payoutAddress", EncodeDestination(dest1));
    }
    obj.pushKV("inputsHash", inputsHash.ToString());
}

bool ProRegPL::IsTriviallyValid(CValidationState& state) const
{
    // v3 is the ONLY supported version. Legacy v2 (ECDSA operator key without a dedicated
    // ECVRF sortition key) is fully removed: under VRF-only finality a v2 operator can never
    // produce a valid sortition proof, so it would be counted toward N (raising the finality
    // threshold ceil(2/3·N)) while casting 0 votes, degrading fault tolerance for the WHOLE
    // network (audit F5 "silently dead operator"). No live v2 MN exists (the 8 testnet MNs
    // registered v3 via genesis; mainnet unlaunched) so pinning to v3 orphans nothing. This
    // must land before mainnet genesis is pinned (post-launch it would be a hard fork).
    if (nVersion != ProRegPL::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }
    if (nType != 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-type");
    }
    if (nMode != 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-mode");
    }

    if (keyIDOwner.IsNull() || keyIDVoting.IsNull()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-key-null");
    }
    if (!pubKeyOperator.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-operator-key-invalid");
    }
    if (!pubKeyVRF.IsFullyValid()) {
        // audit F5: IsFullyValid() (not IsValid(), which is size-only) — the VRF key MUST
        // be a real on-curve point, else ECVRF_verify can never accept its proofs and the
        // operator would be silently finality-dead.
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-vrf-key-invalid");
    }
    // we may support other kinds of scripts later, but restrict it for now
    if (!scriptPayout.IsPayToPublicKeyHash()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee");
    }
    CTxDestination payoutDest;
    if (!ExtractDestination(scriptPayout, payoutDest)) {
        // should not happen as we checked script types before
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee-dest");
    }
    // don't allow reuse of payout key for other keys (don't allow people to put the payee key onto an online server)
    if (payoutDest == CTxDestination(keyIDOwner) ||
        payoutDest == CTxDestination(keyIDVoting)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee-reuse");
    }

    return true;
}

std::string ProUpServPL::ToString() const
{
    return strprintf("ProUpServPL(nVersion=%d, proTxHash=%s, addr=%s)",
        nVersion, proTxHash.ToString(), addr.ToString());
}

void ProUpServPL::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.pushKV("version", nVersion);
    obj.pushKV("proTxHash", proTxHash.ToString());
    obj.pushKV("service", addr.ToString());
    obj.pushKV("inputsHash", inputsHash.ToString());
}

bool ProUpServPL::IsTriviallyValid(CValidationState& state) const
{
    if (nVersion == 0 || nVersion > ProUpServPL::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }
    return true;
}

std::string ProUpRegPL::ToString() const
{
    CTxDestination dest;
    std::string payee = ExtractDestination(scriptPayout, dest) ?
                        EncodeDestination(dest) : "unknown";
    // BATHRON: ECDSA pubkey
    return strprintf("ProUpRegPL(nVersion=%d, proTxHash=%s, operatorPubKey=%s, votingAddress=%s, payoutAddress=%s)",
        nVersion, proTxHash.ToString(), HexStr(pubKeyOperator), EncodeDestination(keyIDVoting), payee);
}

void ProUpRegPL::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.pushKV("version", nVersion);
    obj.pushKV("proTxHash", proTxHash.ToString());
    obj.pushKV("votingAddress", EncodeDestination(keyIDVoting));
    CTxDestination dest;
    if (ExtractDestination(scriptPayout, dest)) {
        obj.pushKV("payoutAddress", EncodeDestination(dest));
    }
    // BATHRON: ECDSA pubkey
    obj.pushKV("operatorPubKey", HexStr(pubKeyOperator));
    obj.pushKV("vrfPubKey", HexStr(pubKeyVRF));
    obj.pushKV("inputsHash", inputsHash.ToString());
}

bool ProUpRegPL::IsTriviallyValid(CValidationState& state) const
{
    // v3 is the ONLY supported version (legacy v2 removed). A v2 ProUpRegTx would strip the
    // operator's pubKeyVRF, turning a live operator into a silently finality-dead one. See
    // ProRegPL::IsTriviallyValid for the full rationale.
    if (nVersion != ProUpRegPL::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }
    if (nMode != 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-mode");
    }

    if (!pubKeyOperator.IsValid()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-operator-key-invalid");
    }
    if (!pubKeyVRF.IsFullyValid()) {
        // audit F5: IsFullyValid() (not IsValid(), which is size-only) — the VRF key MUST
        // be a real on-curve point, else ECVRF_verify can never accept its proofs and the
        // operator would be silently finality-dead.
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-vrf-key-invalid");
    }
    if (keyIDVoting.IsNull()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-voting-key-null");
    }
    // !TODO: enable other scripts
    if (!scriptPayout.IsPayToPublicKeyHash()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee");
    }

    return true;
}

std::string ProUpRevPL::ToString() const
{
    return strprintf("ProUpRevPL(nVersion=%d, proTxHash=%s, nReason=%d)",
                      nVersion, proTxHash.ToString(), nReason);
}

void ProUpRevPL::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.pushKV("version", nVersion);
    obj.pushKV("proTxHash", proTxHash.ToString());
    obj.pushKV("reason", (int)nReason);
    obj.pushKV("inputsHash", inputsHash.ToString());
}

bool ProUpRevPL::IsTriviallyValid(CValidationState& state) const
{
    if (nVersion == 0 || nVersion > ProUpRevPL::CURRENT_VERSION) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");
    }

    // pl.nReason < ProUpRevPL::REASON_NOT_SPECIFIED is always `false` since
    // pl.nReason is unsigned and ProUpRevPL::REASON_NOT_SPECIFIED == 0
    if (nReason > ProUpRevPL::REASON_LAST) {
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-reason");
    }
    return true;
}

bool GetProRegCollateral(const CTransactionRef& tx, COutPoint& outRet)
{
    if (tx == nullptr) {
        return false;
    }
    if (!tx->IsSpecialTx() || tx->nType != CTransaction::TxType::PROREG) {
        return false;
    }
    ProRegPL pl;
    if (!GetTxPayload(*tx, pl)) {
        return false;
    }
    outRet = pl.collateralOutpoint.hash.IsNull() ? COutPoint(tx->GetHash(), pl.collateralOutpoint.n)
                                                 : pl.collateralOutpoint;
    return true;
}


