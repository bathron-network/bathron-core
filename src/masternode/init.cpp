// Copyright (c) 2021-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "masternode/init.h"

#include "activemasternode.h"
#include "masternode/deterministicmns.h"
#include "masternode/evodb.h"
#include "masternode/evonotificationinterface.h"
#include "net/net.h"
#include "flatdb.h"
#include "guiinterface.h"
#include "guiinterfaceutil.h"
#include "state/finality.h"
#include "scheduler.h"
#include "masternode/masternode_meta_manager.h"
#include "validation.h"
#include "wallet/wallet.h"

#include <boost/thread.hpp>

static std::unique_ptr<EvoNotificationInterface> pEvoNotificationInterface{nullptr};

std::string GetTierTwoHelpString(bool showDebug)
{
    std::string strUsage = HelpMessageGroup("Masternode options:");
    strUsage += HelpMessageOpt("-masternode=<n>", strprintf("Enable the client to act as a masternode (0-1, default: %u)", DEFAULT_MASTERNODE));
    // BATHRON: Legacy masternode.conf removed - DMN only
    strUsage += HelpMessageOpt("-mnconflock=<n>", strprintf("Lock masternodes collateral utxo (default: %u)", DEFAULT_MNCONFLOCK));
    strUsage += HelpMessageOpt("-mnoperatorprivatekey=<bech32>", "Set the masternode operator private key. Can be specified multiple times for Multi-MN mode. Only valid with -masternode=1.");
    strUsage += HelpMessageOpt("-mn_produce_delay=<seconds>", "Delay in seconds before producing blocks. Used for HA failover: primary=0, secondary=5, tertiary=10. ECDSA deterministic signatures ensure identical blocks. (default: 0)");
    if (showDebug) {
        strUsage += HelpMessageOpt("-pushversion", strprintf("Modifies the mnauth serialization if the version is lower than %d."
                                                             "testnet/regtest only; ", MNAUTH_NODE_VER_VERSION));
    }
    return strUsage;
}

void InitTierTwoInterfaces()
{
    pEvoNotificationInterface = std::make_unique<EvoNotificationInterface>();
    RegisterValidationInterface(pEvoNotificationInterface.get());
}

void ResetTierTwoInterfaces()
{
    if (pEvoNotificationInterface) {
        UnregisterValidationInterface(pEvoNotificationInterface.get());
        pEvoNotificationInterface.reset();
    }

    if (activeMasternodeManager) {
        UnregisterValidationInterface(activeMasternodeManager);
        delete activeMasternodeManager;
        activeMasternodeManager = nullptr;
    }
}

void InitTierTwoPreChainLoad(bool fReindex)
{
    int64_t nEvoDbCache = 1024 * 1024 * 64; // Max cache is 64MB
    deterministicMNManager.reset();
    evoDb.reset();
    evoDb.reset(new CEvoDB(nEvoDbCache, false, fReindex));
    deterministicMNManager.reset(new CDeterministicMNManager(*evoDb));

}

void InitTierTwoPostCoinsCacheLoad(CScheduler* scheduler)
{
}

void InitTierTwoChainTip()
{
    // Force the evo notification interface to cache the current block tip
    // (without calling UpdatedBlockTip directly, to avoid triggering other
    // listeners like zmq etc.)
    pEvoNotificationInterface->InitializeCurrentBlockTip();
}

bool LoadTierTwo(int chain_active_height, bool load_cache_files)
{
    // BATHRON: Legacy masternode cache loading removed - DMN only

    // ############################## //
    // ## Net MNs Metadata Manager ## //
    // ############################## //
    uiInterface.InitMessage(_("Loading masternode metadata cache..."));
    CFlatDB<CMasternodeMetaMan> metadb(MN_META_CACHE_FILENAME, MN_META_CACHE_FILE_ID);
    if (load_cache_files) {
        if (!metadb.Load(g_mmetaman)) {
            return UIError(strprintf(_("Failed to load masternode metadata cache from: %s"), metadb.GetDbPath().string()));
        }
    } else {
        CMasternodeMetaMan mmetamanTmp;
        if (!metadb.Dump(mmetamanTmp)) {
            return UIError(strprintf(_("Failed to clear masternode metadata cache at: %s"), metadb.GetDbPath().string()));
        }
    }

    return true;
}

void RegisterTierTwoValidationInterface()
{
    // BATHRON: Legacy masternodePayments validation interface removed - no MN payments in BATHRON (coinbase = recycled fees only)
    if (activeMasternodeManager) RegisterValidationInterface(activeMasternodeManager);
}

void DumpTierTwo()
{
    // BATHRON: Legacy DumpMasternodes/DumpMasternodePayments removed - DMN only
    CFlatDB<CMasternodeMetaMan>(MN_META_CACHE_FILENAME, MN_META_CACHE_FILE_ID).Dump(g_mmetaman);
}


bool InitActiveMN()
{
    fMasterNode = gArgs.GetBoolArg("-masternode", DEFAULT_MASTERNODE);
    if (fMasterNode && fTxIndex == false) {
        return UIError(strprintf(_("Enabling Masternode support requires turning on transaction indexing."
                                   "Please add %s to your configuration and start with %s"), "txindex=1", "-reindex"));
    }

    if (fMasterNode) {

        if (gArgs.IsArgSet("-connect") && gArgs.GetArgs("-connect").size() > 0) {
            return UIError(_("Cannot be a masternode and only connect to specific nodes"));
        }

        if (gArgs.GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS) < DEFAULT_MAX_PEER_CONNECTIONS) {
            return UIError(strprintf(_("Masternode must be able to handle at least %d connections, set %s=%d"),
                                     DEFAULT_MAX_PEER_CONNECTIONS, "-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS));
        }

        // OPERATOR-CENTRIC v4.0: Only ONE operator key allowed per daemon
        // Blueprint 15: "Une seule mnoperatorprivatekey = N MNs gérés"
        // One key = one operator identity. The daemon auto-discovers all MNs with this key.
        const std::vector<std::string>& mnoperatorkeys = gArgs.GetArgs("-mnoperatorprivatekey");
        if (mnoperatorkeys.empty()) {
            return UIError(_("Masternode requires exactly one -mnoperatorprivatekey"));
        }
        if (mnoperatorkeys.size() > 1) {
            return UIError(_("Only ONE operator key allowed per daemon (Operator-Centric model). "
                           "One key can manage multiple MNs."));
        }
        LogPrintf("OPERATOR-CENTRIC: Loading operator key (1 key = N MNs)\n");

        if (!deterministicMNManager->IsDIP3Enforced()) {
            return UIError(_("Cannot start deterministic masternode before DIP3 enforcement"));
        }

        activeMasternodeManager = new CActiveDeterministicMasternodeManager();

        // Load the single operator key
        auto res = activeMasternodeManager->SetOperatorKey(mnoperatorkeys[0]);
        if (!res) { return UIError(res.getError()); }
        LogPrintf("OPERATOR-CENTRIC: Operator key loaded, will auto-discover MNs on-chain\n");

        // HA Failover: Set production delay
        int nProduceDelay = gArgs.GetArg("-mn_produce_delay", 0);
        if (nProduceDelay > 0) {
            activeMasternodeManager->SetProduceDelay(nProduceDelay);
            LogPrintf("HA FAILOVER: Production delay set to %d seconds (secondary/tertiary mode)\n", nProduceDelay);
        }
        RegisterValidationInterface(activeMasternodeManager);
        const CBlockIndex* pindexTip = WITH_LOCK(cs_main, return chainActive.Tip(););
        activeMasternodeManager->Init(pindexTip);
        if (activeMasternodeManager->GetState() == CActiveDeterministicMasternodeManager::MASTERNODE_ERROR) {
            return UIError(activeMasternodeManager->GetStatus());
        }
    }

#ifdef ENABLE_WALLET
    // BATHRON: Lock DMN collateral utxo automatically
    if (gArgs.GetBoolArg("-mnconflock", DEFAULT_MNCONFLOCK) && !vpwallets.empty()) {
        LogPrintf("Locking masternode collaterals...\n");
        const auto& mnList = deterministicMNManager->GetListAtChainTip();
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
            for (CWallet* pwallet : vpwallets) {
                pwallet->LockOutpointIfMineWithMutex(nullptr, dmn->collateralOutpoint);
            }
        });
    }
#endif
    // All good
    return true;
}

void StartTierTwoThreadsAndScheduleJobs(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    // BATHRON: Legacy ThreadCheckMasternodes removed - DMN system handles MN lifecycle
}

void StopTierTwoThreads()
{
}

void DeleteTierTwo()
{
    deterministicMNManager.reset();
    evoDb.reset();
}

void InterruptTierTwo()
{
}
