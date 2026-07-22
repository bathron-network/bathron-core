// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/evonotificationinterface.h"

#include "masternode/deterministicmns.h"
#include "masternode/mnauth.h"
#include "validation.h"

void EvoNotificationInterface::InitializeCurrentBlockTip()
{
    LOCK(cs_main);
    deterministicMNManager->SetTipIndex(chainActive.Tip());
}

void EvoNotificationInterface::NotifyMasternodeListChanged(bool undo, const CDeterministicMNList& oldMNList, const CDeterministicMNListDiff& diff)
{
    CMNAuth::NotifyMasternodeListChanged(undo, oldMNList, diff);
}
