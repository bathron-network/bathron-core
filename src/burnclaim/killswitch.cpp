// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "burnclaim/killswitch.h"
#include "logging.h"
#include "util/system.h"

#include <chrono>

// Global atomic flag - default to enabled
std::atomic<bool> g_btc_burns_enabled{true};

// Track last change timestamp
static std::atomic<int64_t> g_last_change_timestamp{0};

// Store config default for status reporting
static bool g_config_default = true;

void InitKillSwitch()
{
    // Read from config, default to enabled (true)
    g_config_default = gArgs.GetBoolArg("-btcburnsenabled", true);
    g_btc_burns_enabled.store(g_config_default);

    if (!g_config_default) {
        LogPrintf("KILLSWITCH: BTC burns DISABLED by config (-btcburnsenabled=0)\n");
    } else {
        LogPrintf("KILLSWITCH: BTC burns enabled (default)\n");
    }
}

bool AreBtcBurnsEnabled()
{
    return g_btc_burns_enabled.load();
}

bool SetBtcBurnsEnabled(bool enabled)
{
    bool expected = !enabled;
    if (g_btc_burns_enabled.compare_exchange_strong(expected, enabled)) {
        // State changed
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        g_last_change_timestamp.store(now);

        if (enabled) {
            LogPrintf("KILLSWITCH: BTC burns ENABLED (kill switch deactivated)\n");
        } else {
            LogPrintf("KILLSWITCH: BTC burns DISABLED (kill switch activated)\n");
        }
        return true;
    }
    // Already in requested state
    return false;
}

KillSwitchStatus GetKillSwitchStatus()
{
    KillSwitchStatus status;
    status.enabled = g_btc_burns_enabled.load();
    status.lastChanged = g_last_change_timestamp.load();
    status.configDefault = g_config_default;
    return status;
}
