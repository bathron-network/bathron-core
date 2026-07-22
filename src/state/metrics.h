// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_METRICS_H
#define BATHRON_METRICS_H

#include <atomic>

namespace hu {

/**
 * HU Metrics - finality-delay telemetry surfaced by getfinalitystatus.
 * All counters are atomic for thread-safe updates.
 */
struct HuMetrics {
    std::atomic<int64_t> lastFinalityDelayMs{0};    // Delay of last finalized block (ms)
    std::atomic<int64_t> totalFinalityDelayMs{0};   // Sum of all finality delays (for avg)
    std::atomic<uint64_t> finalityDelayCount{0};    // Number of finality delay samples
    std::atomic<int64_t> lastBlockReceivedTime{0};  // Timestamp when last block was received
};

// Global metrics instance
extern HuMetrics g_hu_metrics;

} // namespace hu

#endif // BATHRON_METRICS_H
