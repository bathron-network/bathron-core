// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/btcstate.h"

static BtcStateProviderFn g_btcStateProvider = nullptr;

void SetBtcStateProvider(BtcStateProviderFn fn)
{
    g_btcStateProvider = fn;
}

bool EvalBtcStateQuery(const BtcStateQuery& query)
{
    if (!g_btcStateProvider) return false;  // fail closed
    return g_btcStateProvider(query);
}
