// Copyright (c) 2012-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_VERSION_H
#define BATHRON_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 70929;

/**
 * Testnet epoch - increment this when creating a new testnet genesis
 * This changes the network magic to prevent old testnet nodes from connecting
 * Now with auto-wipe: incrementing this will automatically wipe stale DBs on all nodes
 *
 * History:
 *   1 = Initial BATHRON testnet (2024-12)
 *   2 = Genesis clean reset (2025-01-03)
 *   3 = SPV-hardening genesis (2026-06-28): R6 bootstrap anchor, reindex-wipe,
 *       killswitch policy, dup/replay guards, corrected genesis checkpoint header
 */
static const int TESTNET_EPOCH = 3;

//! initial proto version, to be increased after version/verack negotiation
static const int INIT_PROTO_VERSION = 209;

//! disconnect from peers older than this proto version
//! Updated to 70929 to reject old testnet nodes with stale headers
static const int MIN_PEER_PROTO_VERSION_AFTER_ENFORCEMENT = 70929;

//! Version where MNAUTH was introduced
static const int MNAUTH_NODE_VER_VERSION = 70925;

// Make sure that none of the values above collide with
// `ADDRV2_FORMAT`.

#endif // BATHRON_VERSION_H
