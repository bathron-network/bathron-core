// Copyright (c) 2018-2021 The Dash Core developers
// Copyright (c) 2021-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/deterministicmns.h"

#include "chain.h"
#include "coins.h"
#include "chainparams.h"
#include "consensus/params.h"
#include "hash.h"              // For CHashWriter
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "key_io.h"
#include "guiinterface.h"
#include "masternode/blockproducer.h"  // For GetProducerSlot, CalculateBlockProducerScores
#include "net/netbase.h"       // For Lookup()
#include "script/standard.h"
#include "sync.h"
#include "utilstrencodings.h"  // For ParseHex
#include "validation.h"          // For IsInitialBlockDownload()
#include "validationinterface.h" // For GetMainSignals()

#include <univalue.h>

static const std::string DB_LIST_SNAPSHOT = "dmn_S";
static const std::string DB_LIST_DIFF = "dmn_D";

std::unique_ptr<CDeterministicMNManager> deterministicMNManager;

std::string CDeterministicMNState::ToString() const
{
    CTxDestination dest;
    std::string payoutAddress = "unknown";
    if (ExtractDestination(scriptPayout, dest)) {
        payoutAddress = EncodeDestination(dest);
    }

    return strprintf("CDeterministicMNState(nRegisteredHeight=%d, nPoSePenalty=%d, nPoSeRevivedHeight=%d, nPoSeBanHeight=%d, nRevocationReason=%d, ownerAddress=%s, operatorPubKey=%s, votingAddress=%s, addr=%s, payoutAddress=%s)",
        nRegisteredHeight, nPoSePenalty, nPoSeRevivedHeight, nPoSeBanHeight, nRevocationReason,
        EncodeDestination(keyIDOwner), HexStr(pubKeyOperator), EncodeDestination(keyIDVoting), addr.ToStringIPPort(), payoutAddress);
}

void CDeterministicMNState::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.pushKV("service", addr.ToStringIPPort());
    obj.pushKV("registeredHeight", nRegisteredHeight);
    obj.pushKV("PoSePenalty", nPoSePenalty);
    obj.pushKV("PoSeRevivedHeight", nPoSeRevivedHeight);
    obj.pushKV("PoSeBanHeight", nPoSeBanHeight);
    obj.pushKV("revocationReason", nRevocationReason);
    obj.pushKV("ownerAddress", EncodeDestination(keyIDOwner));
    obj.pushKV("operatorPubKey", HexStr(pubKeyOperator));
    if (pubKeyVRF.IsValid()) {
        obj.pushKV("vrfPubKey", HexStr(pubKeyVRF));
    }
    obj.pushKV("votingAddress", EncodeDestination(keyIDVoting));

    CTxDestination dest1;
    if (ExtractDestination(scriptPayout, dest1)) {
        obj.pushKV("payoutAddress", EncodeDestination(dest1));
    }
}

uint64_t CDeterministicMN::GetInternalId() const
{
    // can't get it if it wasn't set yet
    assert(internalId != std::numeric_limits<uint64_t>::max());
    return internalId;
}

std::string CDeterministicMN::ToString() const
{
    return strprintf("CDeterministicMN(proTxHash=%s, collateralOutpoint=%s, state=%s", proTxHash.ToString(), collateralOutpoint.ToStringShort(), pdmnState->ToString());
}

void CDeterministicMN::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();

    UniValue stateObj;
    pdmnState->ToJson(stateObj);

    obj.pushKV("proTxHash", proTxHash.ToString());
    obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
    obj.pushKV("collateralIndex", (int)collateralOutpoint.n);
    obj.pushKV("dmnstate", stateObj);
}

CDeterministicMNCPtr CDeterministicMNList::GetMN(const uint256& proTxHash) const
{
    auto p = mnMap.find(proTxHash);
    if (p == nullptr) {
        return nullptr;
    }
    return *p;
}

CDeterministicMNCPtr CDeterministicMNList::GetValidMN(const uint256& proTxHash) const
{
    auto dmn = GetMN(proTxHash);
    if (dmn && dmn->IsPoSeBanned()) {
        return nullptr;
    }
    return dmn;
}

// MULTI-MN v4.0: Get ALL masternodes with the same operator key
// This enables one operator to manage N MNs with a single key
std::vector<CDeterministicMNCPtr> CDeterministicMNList::GetMNsByOperatorKey(const CPubKey& pubKey) const
{
    std::vector<CDeterministicMNCPtr> result;
    for (const auto& p : mnMap) {
        if (p.second->pdmnState->pubKeyOperator == pubKey && !p.second->IsPoSeBanned()) {
            result.push_back(p.second);
        }
    }
    return result;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByCollateral(const COutPoint& collateralOutpoint) const
{
    return GetUniquePropertyMN(collateralOutpoint);
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByInternalId(uint64_t internalId) const
{
    auto proTxHash = mnInternalIdMap.find(internalId);
    if (!proTxHash) {
        return nullptr;
    }
    return GetMN(*proTxHash);
}

void CDeterministicMNList::PoSeDecrease(const uint256& proTxHash)
{
    auto dmn = GetMN(proTxHash);
    if (!dmn) {
        throw(std::runtime_error(strprintf("%s: Can't find a masternode with proTxHash=%s", __func__, proTxHash.ToString())));
    }
    assert(dmn->pdmnState->nPoSePenalty > 0 && dmn->pdmnState->nPoSeBanHeight == -1);

    auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
    newState->nPoSePenalty--;
    UpdateMN(proTxHash, newState);
}

CDeterministicMNListDiff CDeterministicMNList::BuildDiff(const CDeterministicMNList& to) const
{
    CDeterministicMNListDiff diffRet;

    to.ForEachMN(false, [&](const CDeterministicMNCPtr& toPtr) {
        auto fromPtr = GetMN(toPtr->proTxHash);
        if (fromPtr == nullptr) {
            diffRet.addedMNs.emplace_back(toPtr);
        } else if (fromPtr != toPtr || fromPtr->pdmnState != toPtr->pdmnState) {
            CDeterministicMNStateDiff stateDiff(*fromPtr->pdmnState, *toPtr->pdmnState);
            if (stateDiff.fields) {
                diffRet.updatedMNs.emplace(toPtr->GetInternalId(), std::move(stateDiff));
            }
        }
    });
    ForEachMN(false, [&](const CDeterministicMNCPtr& fromPtr) {
        auto toPtr = to.GetMN(fromPtr->proTxHash);
        if (toPtr == nullptr) {
            diffRet.removedMns.emplace(fromPtr->GetInternalId());
        }
    });

    // added MNs need to be sorted by internalId so that these are added in correct order when the diff is applied later
    // otherwise internalIds will not match with the original list
    std::sort(diffRet.addedMNs.begin(), diffRet.addedMNs.end(), [](const CDeterministicMNCPtr& a, const CDeterministicMNCPtr& b) {
        return a->GetInternalId() < b->GetInternalId();
    });

    return diffRet;
}

CDeterministicMNList CDeterministicMNList::ApplyDiff(const CBlockIndex* pindex, const CDeterministicMNListDiff& diff) const
{
    CDeterministicMNList result = *this;
    result.blockHash = pindex->GetBlockHash();
    result.nHeight = pindex->nHeight;

    for (const auto& id : diff.removedMns) {
        auto dmn = result.GetMNByInternalId(id);
        if (!dmn) {
            throw(std::runtime_error(strprintf("%s: can't find a removed masternode, id=%d", __func__, id)));
        }
        result.RemoveMN(dmn->proTxHash);
    }
    for (const auto& dmn : diff.addedMNs) {
        result.AddMN(dmn);
    }
    for (const auto& p : diff.updatedMNs) {
        auto dmn = result.GetMNByInternalId(p.first);
        result.UpdateMN(dmn, p.second);
    }

    return result;
}

void CDeterministicMNList::AddMN(const CDeterministicMNCPtr& dmn, bool fBumpTotalCount)
{
    assert(dmn != nullptr);

    if (mnMap.find(dmn->proTxHash)) {
        throw(std::runtime_error(strprintf("%s: can't add a duplicate masternode with the same proTxHash=%s", __func__, dmn->proTxHash.ToString())));
    }
    if (mnInternalIdMap.find(dmn->GetInternalId())) {
        throw(std::runtime_error(strprintf("%s: can't add a duplicate masternode with the same internalId=%d", __func__, dmn->GetInternalId())));
    }
    // MULTI-MN v4.0: Only ownerKey must remain unique (collateral protection)
    // operatorPubKey duplicates ALLOWED - 1 operator can manage N MNs with same key
    // See: doc/blueprints/done/15-MULTI-MN-SINGLE-DAEMON.md section 5.2.1
    if (HasUniqueProperty(dmn->pdmnState->keyIDOwner)) {
        throw(std::runtime_error(strprintf("%s: can't add a masternode with a duplicate owner key (%s)", __func__, EncodeDestination(dmn->pdmnState->keyIDOwner))));
    }

    mnMap = mnMap.set(dmn->proTxHash, dmn);
    mnInternalIdMap = mnInternalIdMap.set(dmn->GetInternalId(), dmn->proTxHash);
    AddUniqueProperty(dmn, dmn->collateralOutpoint);
    // MULTI-MN v4.0: Only ownerKey tracked as unique property
    // operatorPubKey NOT tracked - same operator can manage multiple MNs
    AddUniqueProperty(dmn, dmn->pdmnState->keyIDOwner);
    // REMOVED: AddUniqueProperty(dmn, dmn->pdmnState->pubKeyOperator);

    if (fBumpTotalCount) {
        // nTotalRegisteredCount acts more like a checkpoint, not as a limit,
        nTotalRegisteredCount = std::max(dmn->GetInternalId() + 1, (uint64_t)nTotalRegisteredCount);
    }
}

void CDeterministicMNList::UpdateMN(const CDeterministicMNCPtr& oldDmn, const CDeterministicMNStateCPtr& pdmnState)
{
    assert(oldDmn != nullptr);

    // MULTI-MN: IP uniqueness check REMOVED - multiple MNs can share same IP

    auto dmn = std::make_shared<CDeterministicMN>(*oldDmn);
    auto oldState = dmn->pdmnState;
    dmn->pdmnState = pdmnState;
    mnMap = mnMap.set(oldDmn->proTxHash, dmn);

    // MULTI-MN: IP no longer tracked as unique property
    UpdateUniqueProperty(dmn, oldState->keyIDOwner, pdmnState->keyIDOwner);
    // MULTI-MN v4.0: pubKeyOperator is NOT tracked as a unique property (AddMN
    // intentionally does not insert it — duplicate operator keys are allowed,
    // see line 511). Updating it here would call DeleteUniqueProperty on a key
    // absent from mnUniquePropertyMap and trip assert(p && ...) at
    // deterministicmns.h:485 -> abort() on every node (e.g. on an operator-key
    // ProUpReg). Must stay symmetric with AddMN.
}

void CDeterministicMNList::UpdateMN(const uint256& proTxHash, const CDeterministicMNStateCPtr& pdmnState)
{
    auto oldDmn = mnMap.find(proTxHash);
    if (!oldDmn) {
        throw(std::runtime_error(strprintf("%s: Can't find a masternode with proTxHash=%s", __func__, proTxHash.ToString())));
    }
    UpdateMN(*oldDmn, pdmnState);
}

void CDeterministicMNList::UpdateMN(const CDeterministicMNCPtr& oldDmn, const CDeterministicMNStateDiff& stateDiff)
{
    assert(oldDmn != nullptr);
    auto oldState = oldDmn->pdmnState;
    auto newState = std::make_shared<CDeterministicMNState>(*oldState);
    stateDiff.ApplyToState(*newState);
    UpdateMN(oldDmn, newState);
}

void CDeterministicMNList::RemoveMN(const uint256& proTxHash)
{
    auto dmn = GetMN(proTxHash);
    if (!dmn) {
        throw(std::runtime_error(strprintf("%s: Can't find a masternode with proTxHash=%s", __func__, proTxHash.ToString())));
    }
    DeleteUniqueProperty(dmn, dmn->collateralOutpoint);
    // MULTI-MN: IP no longer tracked as unique property
    DeleteUniqueProperty(dmn, dmn->pdmnState->keyIDOwner);
    // MULTI-MN v4.0: pubKeyOperator is NOT tracked as a unique property (AddMN
    // never inserts it, see line 511). Deleting it here calls
    // DeleteUniqueProperty on a key absent from the map -> assert(p && ...) at
    // deterministicmns.h:485 -> abort() on EVERY validating node. This is the
    // fix for the network-wide halt triggered by spending any MN collateral
    // (BuildNewListFromBlock -> RemoveMN) or a ProReg-replacement. Stay
    // symmetric with AddMN.

    mnMap = mnMap.erase(proTxHash);
    mnInternalIdMap = mnInternalIdMap.erase(dmn->GetInternalId());
}

CDeterministicMNManager::CDeterministicMNManager(CEvoDB& _evoDb) :
    evoDb(_evoDb)
{
}

bool CDeterministicMNManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& _state, bool fJustCheck)
{
    int nHeight = pindex->nHeight;
    if (!IsDIP3Enforced(nHeight)) {
        // nothing to do
        return true;
    }

    CDeterministicMNList oldList, newList;
    CDeterministicMNListDiff diff;

    try {
        LOCK(cs);

        if (!BuildNewListFromBlock(block, pindex->pprev, _state, newList, true)) {
            // pass the state returned by the function above
            return false;
        }

        if (fJustCheck) {
            return true;
        }

        if (newList.GetHeight() == -1) {
            newList.SetHeight(nHeight);
        }

        newList.SetBlockHash(block.GetHash());

        oldList = GetListForBlock(pindex->pprev);
        diff = oldList.BuildDiff(newList);

        evoDb.Write(std::make_pair(DB_LIST_DIFF, newList.GetBlockHash()), diff);
        if ((nHeight % DISK_SNAPSHOT_PERIOD) == 0 || oldList.GetHeight() == -1) {
            evoDb.Write(std::make_pair(DB_LIST_SNAPSHOT, newList.GetBlockHash()), newList);
            mnListsCache.emplace(newList.GetBlockHash(), newList);
            LogPrintf("CDeterministicMNManager::%s -- Wrote snapshot. nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                __func__, nHeight, newList.GetAllMNsCount());
        }

        diff.nHeight = pindex->nHeight;
        mnListDiffsCache.emplace(pindex->GetBlockHash(), diff);
    } catch (const std::exception& e) {
        LogPrintf("CDeterministicMNManager::%s -- internal error: %s\n", __func__, e.what());
        return _state.DoS(100, false, REJECT_INVALID, "failed-dmn-block");
    }

    // Don't hold cs while calling signals
    if (diff.HasChanges()) {
        GetMainSignals().NotifyMasternodeListChanged(false, oldList, diff);
        uiInterface.NotifyMasternodeListChanged(newList);
    }

    LOCK(cs);
    CleanupCache(nHeight);

    return true;
}

bool CDeterministicMNManager::UndoBlock(const CBlock& block, const CBlockIndex* pindex)
{
    if (!IsDIP3Enforced(pindex->nHeight)) {
        // nothing to do
        return true;
    }

    const uint256& blockHash = block.GetHash();

    CDeterministicMNList curList;
    CDeterministicMNList prevList;
    CDeterministicMNListDiff diff;
    {
        LOCK(cs);
        evoDb.Read(std::make_pair(DB_LIST_DIFF, blockHash), diff);

        if (diff.HasChanges()) {
            // need to call this before erasing
            curList = GetListForBlock(pindex);
            prevList = GetListForBlock(pindex->pprev);
        }

        mnListsCache.erase(blockHash);
        mnListDiffsCache.erase(blockHash);
    }

    if (diff.HasChanges()) {
        auto inversedDiff = curList.BuildDiff(prevList);
        GetMainSignals().NotifyMasternodeListChanged(true, curList, inversedDiff);
        uiInterface.NotifyMasternodeListChanged(prevList);
    }

    return true;
}

void CDeterministicMNManager::SetTipIndex(const CBlockIndex* pindex)
{
    LOCK(cs);
    tipIndex = pindex;
}

bool CDeterministicMNManager::BuildNewListFromBlock(const CBlock& block, const CBlockIndex* pindexPrev, CValidationState& _state, CDeterministicMNList& mnListRet, bool debugLogs)
{
    AssertLockHeld(cs);
    const auto& consensus = Params().GetConsensus();
    int nHeight = pindexPrev->nHeight + 1;

    CDeterministicMNList oldList = GetListForBlock(pindexPrev);
    CDeterministicMNList newList = oldList;
    newList.SetBlockHash(UINT256_ZERO); // we can't know the final block hash, so better not return a (invalid) block hash
    newList.SetHeight(nHeight);

    // we iterate the oldList here and update the newList
    // this is only valid as long these have not diverged at this point, which is the case as long as we don't add
    // code above this loop that modifies newList
    oldList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        if (!dmn->pdmnState->confirmedHash.IsNull()) {
            // already confirmed
            return;
        }

        // this works on the previous block, so confirmation will happen one block after nMasternodeMinimumConfirmations
        // has been reached, but the block hash will then point to the block at nMasternodeMinimumConfirmations
        int nConfirmations = pindexPrev->nHeight - dmn->pdmnState->nRegisteredHeight;

        // ═══════════════════════════════════════════════════════════════════════════
        // BATHRON Bootstrap Exception: MNs registered during bootstrap are confirmed immediately
        // ═══════════════════════════════════════════════════════════════════════════
        // Block 0 = Genesis (no MNs)
        // Bootstrap window = height <= nDMMBootstrapHeight
        // (burn claims → mint → collateral funding → ProRegTx)
        // Blocks 3-5 = ProRegTx (MNs registered) - need immediate confirmation
        // Block 6+ = DMM active (MNs must be confirmed to produce blocks)
        // Without this exception, MNs would wait nMasternodeCollateralMinConf blocks
        // ═══════════════════════════════════════════════════════════════════════════
        // Bootstrap window MUST match the eligibility gates (block-producer + HU finality
        // GetUniqueOperators both use consensus.nDMMBootstrapHeight). Previously hardcoded to
        // 5, which diverged from nDMMBootstrapHeight (mainnet 10 / testnet 250 / regtest 2):
        // an MN registered in the 6..nDMMBootstrapHeight window was bootstrap-eligible for
        // production/finality yet forced by this loop to wait nMasternodeCollateralMinConf for
        // its confirmedHash. Harmless (eligibility doesn't require confirmedHash for bootstrap
        // MNs) but a real inconsistency trap. Align to the same constant.
        bool bBootstrapMN = (dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight);

        if (bBootstrapMN || nConfirmations >= consensus.MasternodeCollateralMinConf()) {
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            newState->UpdateConfirmedHash(pindexPrev->GetBlockHash());
            newList.UpdateMN(dmn->proTxHash, newState);
            if (bBootstrapMN && nConfirmations < consensus.MasternodeCollateralMinConf()) {
                LogPrintf("DMN: Bootstrap MN %s confirmed immediately at block %d (registered at %d)\n",
                          dmn->proTxHash.ToString().substr(0, 16), pindexPrev->nHeight + 1, dmn->pdmnState->nRegisteredHeight);
            }
        }
    });

    // PoSe decay — two rules, height-gated (UPGRADE_POSE_PRODUCER_DECAY):
    //  - LEGACY (pre-activation): every penalized MN decays 1 EVERY block. Because
    //    the decay ran before the +1-per-missed-slot below, a penalty could never
    //    exceed 1 → the 3-strike ban was mathematically unreachable (dead code).
    //  - NEW: decay only for the MN that successfully PRODUCED this block (applied
    //    in the PoSe section below, where the producer is resolved) — the original
    //    design: "penalty decreases by 1 per block when MN produces successfully".
    //    A down MN now accrues +1 per missed slot with no decay → ban at strike 3.
    const bool fPoSeProducerDecay = consensus.IsPoSeProducerDecay(nHeight);
    if (!fPoSeProducerDecay) {
        DecreasePoSePenalties(newList);
    }

    // we skip the coinbase
    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        if (tx.nType == CTransaction::TxType::PROREG) {
            ProRegPL pl;
            if (!GetTxPayload(tx, pl)) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
            }

            auto dmn = std::make_shared<CDeterministicMN>(newList.GetTotalRegisteredCount());
            dmn->proTxHash = tx.GetHash();

            // collateralOutpoint is either pointing to an external collateral or to the ProRegTx itself
            dmn->collateralOutpoint = pl.collateralOutpoint.hash.IsNull() ? COutPoint(tx.GetHash(), pl.collateralOutpoint.n)
                                                                          : pl.collateralOutpoint;

            // BATHRON: Legacy MN system removed - DMN only

            auto replacedDmn = newList.GetMNByCollateral(dmn->collateralOutpoint);
            if (replacedDmn != nullptr) {
                // This might only happen with a ProRegTx that refers an external collateral
                // In that case the new ProRegTx will replace the old one. This means the old one is removed
                // and the new one is added like a completely fresh one (new internalId)
                newList.RemoveMN(replacedDmn->proTxHash);
                if (debugLogs) {
                    LogPrintf("CDeterministicMNManager::%s -- MN %s removed from list because collateral was used for a new ProRegTx. collateralOutpoint=%s, nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                              __func__, replacedDmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort(), nHeight, newList.GetAllMNsCount());
                }
            }

            // MULTI-MN: IP uniqueness check REMOVED - multiple MNs can share same IP
            if (newList.HasUniqueProperty(pl.keyIDOwner)) {
                return _state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-owner-key");
            }
            // MULTI-MN v4.0: Operator key uniqueness check REMOVED
            // One operator can manage N masternodes with a SINGLE key
            // if (newList.HasUniqueProperty(pl.pubKeyOperator)) {
            //     return _state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-operator-key");
            // }

            auto dmnState = std::make_shared<CDeterministicMNState>(pl);
            dmnState->nRegisteredHeight = nHeight;
            if (pl.addr == CService()) {
                // start in banned pdmnState as we need to wait for a ProUpServTx
                dmnState->nPoSeBanHeight = nHeight;
            }
            dmn->pdmnState = dmnState;

            newList.AddMN(dmn);

            if (debugLogs) {
                LogPrintf("CDeterministicMNManager::%s -- MN %s added at height %d: %s\n",
                    __func__, tx.GetHash().ToString(), nHeight, pl.ToString());
            }

        } else if (tx.nType == CTransaction::TxType::PROUPSERV) {
            ProUpServPL pl;
            if (!GetTxPayload(tx, pl)) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
            }

            // MULTI-MN: IP uniqueness check REMOVED - multiple MNs can share same IP

            CDeterministicMNCPtr dmn = newList.GetMN(pl.proTxHash);
            if (!dmn) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
            }
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            newState->addr = pl.addr;

            if (newState->nPoSeBanHeight != -1) {
                // BATHRON: only revive when all keys are set (ECDSA)
                if (newState->pubKeyOperator.IsValid() && !newState->keyIDVoting.IsNull() && !newState->keyIDOwner.IsNull()) {
                    newState->nPoSePenalty = 0;
                    newState->nPoSeBanHeight = -1;
                    newState->nPoSeRevivedHeight = nHeight;

                    if (debugLogs) {
                        LogPrintf("CDeterministicMNManager::%s -- MN %s revived at height %d\n",
                            __func__, pl.proTxHash.ToString(), nHeight);
                    }
                }
            }

            newList.UpdateMN(pl.proTxHash, newState);
            if (debugLogs) {
                LogPrintf("CDeterministicMNManager::%s -- MN %s updated at height %d: %s\n",
                    __func__, pl.proTxHash.ToString(), nHeight, pl.ToString());
            }

        } else if (tx.nType == CTransaction::TxType::PROUPREG) {
            ProUpRegPL pl;
            if (!GetTxPayload(tx, pl)) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
            }

            CDeterministicMNCPtr dmn = newList.GetMN(pl.proTxHash);
            if (!dmn) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
            }
            // MULTI-MN v4.0: Operator key uniqueness check REMOVED
            // One operator can manage N masternodes with a SINGLE key
            // if (newList.HasUniqueProperty(pl.pubKeyOperator) && newList.GetUniquePropertyMN(pl.pubKeyOperator)->proTxHash != pl.proTxHash) {
            //     return _state.DoS(100, false, REJECT_DUPLICATE, "bad-protx-dup-operator-key");
            // }
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            // BATHRON: ECDSA pubkey comparison (direct, no .Get())
            if (newState->pubKeyOperator != pl.pubKeyOperator) {
                // reset all operator related fields and put MN into PoSe-banned state in case the operator key changes
                newState->ResetOperatorFields();
                newState->BanIfNotBanned(nHeight);
            }
            // BATHRON: Direct assignment for CPubKey (no .Set())
            newState->pubKeyOperator = pl.pubKeyOperator;
            newState->pubKeyVRF = pl.pubKeyVRF;
            newState->keyIDVoting = pl.keyIDVoting;
            newState->scriptPayout = pl.scriptPayout;

            newList.UpdateMN(pl.proTxHash, newState);

            if (debugLogs) {
                LogPrintf("CDeterministicMNManager::%s -- MN %s updated at height %d: %s\n",
                    __func__, pl.proTxHash.ToString(), nHeight, pl.ToString());
            }

        } else if (tx.nType == CTransaction::TxType::PROUPREV) {
            ProUpRevPL pl;
            if (!GetTxPayload(tx, pl)) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-payload");
            }

            CDeterministicMNCPtr dmn = newList.GetMN(pl.proTxHash);
            if (!dmn) {
                return _state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
            }
            auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            newState->ResetOperatorFields();
            newState->BanIfNotBanned(nHeight);
            newState->nRevocationReason = pl.nReason;

            newList.UpdateMN(pl.proTxHash, newState);

            if (debugLogs) {
                LogPrintf("CDeterministicMNManager::%s -- MN %s updated at height %d: %s\n",
                    __func__, pl.proTxHash.ToString(), nHeight, pl.ToString());
            }
        }
    }

    // check if any existing MN collateral is spent by this transaction
    // we skip the coinbase
    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];
        for (const auto& in : tx.vin) {
            auto dmn = newList.GetMNByCollateral(in.prevout);
            if (dmn && dmn->collateralOutpoint == in.prevout) {
                newList.RemoveMN(dmn->proTxHash);
                if (debugLogs) {
                    LogPrintf("CDeterministicMNManager::%s -- MN %s removed from list because collateral was spent. collateralOutpoint=%s, nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                              __func__, dmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort(), nHeight, newList.GetAllMNsCount());
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON PoSe: 3-STRIKE RULE - 2 misses tolerated, BAN on 3rd miss
    // ═══════════════════════════════════════════════════════════════════════════
    // If a fallback producer signed this block (slot > 0), the primary producer
    // missed their slot. Penalty progression:
    //   - 1st miss: nPoSePenalty = 1 (warning)
    //   - 2nd miss: nPoSePenalty = 2 (final warning)
    //   - 3rd miss: nPoSePenalty = 3 → BAN (nPoSeBanHeight set)
    //
    // Fair but strict:
    // - MNs get 2 chances for network issues, maintenance, etc.
    // - 3rd miss = MN is unreliable → banned
    // - Banned MNs can be revived via protx_update_service
    // - Penalty decreases by 1 per block when MN produces successfully
    constexpr int POSE_BAN_THRESHOLD = 3;  // Ban on 3rd miss

    if (nHeight > consensus.nDMMBootstrapHeight && pindexPrev != nullptr) {
        // Calculate producer slot from block timestamp
        int producerSlot = mn_consensus::GetProducerSlot(pindexPrev, block.nTime);

        // NEW decay rule (post-UPGRADE_POSE_PRODUCER_DECAY): the MN that produced
        // this block did its job — decay ITS penalty by 1. Same modulo producer
        // resolution as the validation-side check (scores over the PREVIOUS list).
        if (fPoSeProducerDecay) {
            auto scoresDecay = mn_consensus::CalculateBlockProducerScores(pindexPrev, oldList);
            if (!scoresDecay.empty()) {
                const auto& producedMn = scoresDecay[producerSlot % (int)scoresDecay.size()].second;
                if (newList.HasMN(producedMn->proTxHash)) {
                    auto dmnProd = newList.GetMN(producedMn->proTxHash);
                    if (dmnProd->pdmnState->nPoSePenalty > 0 && dmnProd->pdmnState->nPoSeBanHeight == -1) {
                        newList.PoSeDecrease(producedMn->proTxHash);
                    }
                }
            }
        }

        if (producerSlot > 0) {
            // A fallback produced this block - penalize the primary producer(s) who missed
            auto scores = mn_consensus::CalculateBlockProducerScores(pindexPrev, oldList);
            const auto missedIdx = mn_consensus::ComputeMissedProducerIndices(producerSlot, (int)scores.size());

            // Anti-cascade guard (NEW rule only — the legacy path stays byte-identical
            // for -reindex): skip this block's punishments when the evidence points to
            // a NETWORK event (chain-wide-outage recovery, > 1/3 of producers "missed")
            // rather than individual faults. Without it, 3 rocky recovery blocks would
            // mass-ban honest MNs below the finality quorum floor while the ProUpServ
            // revival txs need the chain to advance. See ShouldSkipPoSePunishment.
            const int64_t dtSincePrev = (int64_t)block.GetBlockTime() - pindexPrev->GetBlockTime();
            const bool fSkipPunish = fPoSeProducerDecay &&
                mn_consensus::ShouldSkipPoSePunishment(dtSincePrev, consensus.nStaleChainTimeout,
                                                       missedIdx.size(), scores.size());
            if (fSkipPunish) {
                LogPrintf("CDeterministicMNManager::%s -- PoSe: network-event guard at height %d — skipping %d missed-slot penalt%s (dt=%ds, missed=%d/%d producers)\n",
                          __func__, nHeight, (int)missedIdx.size(), missedIdx.size() == 1 ? "y" : "ies",
                          (int)dtSincePrev, (int)missedIdx.size(), (int)scores.size());
            }

            // Penalize the MNs that missed their slot, consistent with the modulo
            // producer selection: excludes the actual producer (slot % n) and
            // penalizes each missed MN at most once even when the slot wrapped
            // past n (dmm-production-4 — the old raw-index loop over-penalized).
            for (int i : fSkipPunish ? std::vector<int>{} : missedIdx) {
                const auto& missedMn = scores[i].second;

                if (!missedMn->IsPoSeBanned() && newList.HasMN(missedMn->proTxHash)) {
                    auto dmn = newList.GetMN(missedMn->proTxHash);
                    auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);

                    // Increment penalty
                    newState->nPoSePenalty++;

                    if (newState->nPoSePenalty >= POSE_BAN_THRESHOLD) {
                        // 3rd strike = BAN
                        newState->nPoSeBanHeight = nHeight;
                        LogPrintf("CDeterministicMNManager::%s -- PoSe BAN: MN %s BANNED at height %d (3rd miss, slot #%d)\n",
                                  __func__, missedMn->proTxHash.ToString().substr(0, 16), nHeight, i);
                    } else {
                        // Warning (1st or 2nd miss)
                        LogPrintf("CDeterministicMNManager::%s -- PoSe WARNING: MN %s penalty %d/3 at height %d (missed slot #%d)\n",
                                  __func__, missedMn->proTxHash.ToString().substr(0, 16), newState->nPoSePenalty, nHeight, i);
                    }

                    newList.UpdateMN(missedMn->proTxHash, newState);
                }
            }
        }
    }

    mnListRet = std::move(newList);

    return true;
}

void CDeterministicMNManager::DecreasePoSePenalties(CDeterministicMNList& mnList)
{
    std::vector<uint256> toDecrease;
    toDecrease.reserve(mnList.GetValidMNsCount() / 10);
    // only iterate and decrease for valid ones (not PoSe banned yet)
    // if a MN ever reaches the maximum, it stays in PoSe banned state until revived
    mnList.ForEachMN(true, [&](const CDeterministicMNCPtr& dmn) {
        if (dmn->pdmnState->nPoSePenalty > 0 && dmn->pdmnState->nPoSeBanHeight == -1) {
            toDecrease.emplace_back(dmn->proTxHash);
        }
    });

    for (const auto& proTxHash : toDecrease) {
        mnList.PoSeDecrease(proTxHash);
    }
}

CDeterministicMNList CDeterministicMNManager::GetListForBlock(const CBlockIndex* pindex)
{
    LOCK(cs);

    // Return early before enforcement
    if (!IsDIP3Enforced(pindex->nHeight)) {
        return {};
    }

    CDeterministicMNList snapshot;
    std::list<const CBlockIndex*> listDiffIndexes;

    while (true) {
        // try using cache before reading from disk
        auto itLists = mnListsCache.find(pindex->GetBlockHash());
        if (itLists != mnListsCache.end()) {
            snapshot = itLists->second;
            break;
        }

        if (evoDb.Read(std::make_pair(DB_LIST_SNAPSHOT, pindex->GetBlockHash()), snapshot)) {
            mnListsCache.emplace(pindex->GetBlockHash(), snapshot);
            break;
        }

        // no snapshot found yet, check diffs
        auto itDiffs = mnListDiffsCache.find(pindex->GetBlockHash());
        if (itDiffs != mnListDiffsCache.end()) {
            listDiffIndexes.emplace_front(pindex);
            pindex = pindex->pprev;
            continue;
        }

        CDeterministicMNListDiff diff;
        if (!evoDb.Read(std::make_pair(DB_LIST_DIFF, pindex->GetBlockHash()), diff)) {
            // no snapshot and no diff on disk means that it's initial snapshot (empty list)
            const auto& consensusParams = Params().GetConsensus();
            bool isV6AlwaysActive = consensusParams.vUpgrades[Consensus::UPGRADE_V6_0].nActivationHeight == Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
            bool isValidEmptyList = IsActivationHeight(pindex->nHeight + 1, consensusParams, Consensus::UPGRADE_V6_0) ||
                                    (isV6AlwaysActive && pindex->nHeight == 0);
            if (!isValidEmptyList) {
                // The MN-list diff for this block is not on disk. Two very different
                // cases, told apart by whether the block is CONNECTED on our active
                // chain — NOT by IsInitialBlockDownload(), which is unreliable on a
                // young chain: every block is recent, so a node hundreds of blocks
                // behind still reports "not in IBD", and the old throw fired on any
                // peer message referencing a block ahead of our tip (finality gossip,
                // inv, headers-first delivery) — an uncaught exception aborts
                // ProcessMessages and STALLS the sync. Observed live: a re-syncing node
                // wedged at its tip while peers gossiped signatures for far-ahead blocks.
                //   (a) pindex NOT on our active chain -> a peer referenced a block we
                //       have not connected yet. Benign: return an empty list; callers
                //       skip MN-dependent handling for a block we have not processed.
                //   (b) pindex IS on our active chain but data is missing -> real
                //       corruption of our own chain state. Throw.
                if (chainActive.Contains(pindex)) {
                    std::string err = strprintf("No masternode list data found for connected block %s at height %d. "
                                                "Possible corrupt database.", pindex->GetBlockHash().ToString(), pindex->nHeight);
                    throw std::runtime_error(err);
                }
                // Unconnected block (peer referenced it ahead of our tip) — return empty.
                LogPrint(BCLog::MASTERNODE, "GetListForBlock: evodb data not available for unconnected block %s at height %d (ahead of tip)\n",
                         pindex->GetBlockHash().ToString(), pindex->nHeight);
                return CDeterministicMNList(pindex->GetBlockHash(), pindex->nHeight, 0);
            }
            snapshot = CDeterministicMNList(pindex->GetBlockHash(), -1, 0);
            mnListsCache.emplace(pindex->GetBlockHash(), snapshot);
            break;
        }

        diff.nHeight = pindex->nHeight;
        mnListDiffsCache.emplace(pindex->GetBlockHash(), std::move(diff));
        listDiffIndexes.emplace_front(pindex);
        pindex = pindex->pprev;
    }

    for (const auto& diffIndex : listDiffIndexes) {
        const auto& diff = mnListDiffsCache.at(diffIndex->GetBlockHash());
        if (diff.HasChanges()) {
            snapshot = snapshot.ApplyDiff(diffIndex, diff);
        } else {
            snapshot.SetBlockHash(diffIndex->GetBlockHash());
            snapshot.SetHeight(diffIndex->nHeight);
        }
    }

    if (tipIndex) {
        // always keep a snapshot for the tip
        if (snapshot.GetBlockHash() == tipIndex->GetBlockHash()) {
            mnListsCache.emplace(snapshot.GetBlockHash(), snapshot);
        } else {
        }
    }

    return snapshot;
}

CDeterministicMNList CDeterministicMNManager::GetListAtChainTip()
{
    LOCK(cs);
    if (!tipIndex) {
        return {};
    }
    return GetListForBlock(tipIndex);
}

void CDeterministicMNManager::SetListForTesting(const CBlockIndex* pindex, const CDeterministicMNList& mnList, bool asTip)
{
    // TEST-ONLY: seed the per-block cache directly so GetListForBlock/
    // GetListAtChainTip resolve to a prebuilt list without a real block being
    // processed. NB: GetListForBlock still gates on IsDIP3Enforced(height), so
    // callers must use a pindex whose nHeight has UPGRADE_V6_0 active.
    LOCK(cs);
    mnListsCache[pindex->GetBlockHash()] = mnList;
    if (asTip) {
        tipIndex = pindex;
    }
}

bool CDeterministicMNManager::IsDIP3Enforced(int nHeight) const
{
    return Params().GetConsensus().NetworkUpgradeActive(nHeight, Consensus::UPGRADE_V6_0);
}

bool CDeterministicMNManager::IsDIP3Enforced() const
{
    int tipHeight = WITH_LOCK(cs, return tipIndex ? tipIndex->nHeight : -1;);
    return IsDIP3Enforced(tipHeight);
}

void CDeterministicMNManager::CleanupCache(int nHeight)
{
    AssertLockHeld(cs);

    std::vector<uint256> toDeleteLists;
    std::vector<uint256> toDeleteDiffs;
    for (const auto& p : mnListsCache) {
        if (p.second.GetHeight() + LIST_DIFFS_CACHE_SIZE < nHeight) {
            toDeleteLists.emplace_back(p.first);
            continue;
        }
    }
    for (const auto& h : toDeleteLists) {
        mnListsCache.erase(h);
    }
    for (const auto& p : mnListDiffsCache) {
        if (p.second.nHeight + LIST_DIFFS_CACHE_SIZE < nHeight) {
            toDeleteDiffs.emplace_back(p.first);
        }
    }
    for (const auto& h : toDeleteDiffs) {
        mnListDiffsCache.erase(h);
    }
}


