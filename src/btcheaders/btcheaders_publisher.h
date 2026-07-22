// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCHEADERS_PUBLISHER_H
#define BATHRON_BTCHEADERS_PUBLISHER_H

#include <cstdint>
#include <string>

/**
 * BTC Headers Automatic Publisher (BP-SPVMNPUB)
 *
 * Automatically publishes TX_BTC_HEADERS when:
 * - btcheaderspublish=1 is configured
 * - Node is an active masternode with operator key
 * - btcspv has headers ahead of btcheadersdb
 *
 * The publisher checks periodically and submits headers to mempool.
 * Other masternodes can also publish - first valid TX wins.
 *
 * Configuration:
 *   btcheaderspublish=1   Enable automatic publishing (default: 0)
 *   btcpublishinterval=60 Interval in seconds between checks (default: 60)
 */

class CScheduler;

/**
 * Initialize the BTC headers publisher.
 * Called during node startup if btcheaderspublish=1.
 *
 * @param scheduler The node's scheduler for periodic tasks
 */
void InitBtcHeadersPublisher(CScheduler& scheduler);

/**
 * Shutdown the BTC headers publisher.
 */
void ShutdownBtcHeadersPublisher();


#endif // BATHRON_BTCHEADERS_PUBLISHER_H
