// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_EVO_EVONOTIFICATIONINTERFACE_H
#define BATHRON_EVO_EVONOTIFICATIONINTERFACE_H

#include "validationinterface.h"

class EvoNotificationInterface : public CValidationInterface
{
public:
    virtual ~EvoNotificationInterface() = default;

    // Initialize current block height in sub-modules on startup
    void InitializeCurrentBlockTip();

protected:
    // CValidationInterface
    void NotifyMasternodeListChanged(bool undo, const CDeterministicMNList& oldMNList, const CDeterministicMNListDiff& diff) override;
};

#endif // BATHRON_EVO_EVONOTIFICATIONINTERFACE_H
