// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCSOURCENET_H
#define BATHRON_BTCSOURCENET_H

#include <cstdint>
#include <string>

// The Bitcoin network BATHRON reads as its monetary source.
// COMMITTED in BATHRON consensus params (chainparams) — engaged at BATHRON
// genesis, NEVER selectable at runtime. There is deliberately no Signet value:
// Signet header PoW is forgeable in CPU-seconds (BIP-325 authentication lives
// in the coinbase witness, which TX_BTC_HEADERS does not carry), so it can
// never be a monetary source.
enum class BtcSourceNet : uint8_t {
    BITCOIN_MAINNET = 0,   // future public BATHRON network
    BITCOIN_TESTNET4 = 1,  // BATHRON measurement network (BIP-94)
};

std::string BtcSourceNetToString(BtcSourceNet net);

#endif // BATHRON_BTCSOURCENET_H
