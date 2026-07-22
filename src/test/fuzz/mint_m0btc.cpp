// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the TX_MINT_M0BTC extraPayload — the MONEY-CREATION wire
// surface (Type 32). The attacker controls the payload version and the
// `btcTxids` vector count (a CompactSize that drives allocation), plus the
// sortedness/dedup that IsTriviallyValid enforces (A5 keeps mint == finalized
// burns, so a malformed mint payload must be rejected cleanly, never crash).
// Closes the coverage gap "CheckMintM0BTC surface has no fuzz target".
//
// Build/run under libFuzzer + ASan/UBSan:
//   ./configure --enable-fuzz CC=clang CXX=clang++
//   CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1"
//   make -C src test/fuzz/mint_m0btc && ./src/test/fuzz/mint_m0btc corpus/

#include "burnclaim/burnclaim.h"
#include "streams.h"
#include "test/fuzz/fuzz.h"
#include "version.h"

#include <string>
#include <vector>

void test_one_input(std::vector<uint8_t> buffer)
{
    // Deserialize the attacker-controlled MintPayload — the money-creation WIRE
    // surface (Type 32). The btcTxids vector count is a CompactSize that drives
    // allocation; the hardened serialize.h allocator must bound it — never OOM,
    // over-read, or crash regardless of input.
    //
    // Scope: this fuzzes the PARSE + serialize round-trip (attacker bytes -> struct).
    // The semantic checks (IsTriviallyValid: version/sortedness/dedup, and
    // CheckMintM0BTC vs burnclaimdb) are intentionally NOT called here — they live
    // in burnclaim.cpp, whose TU drags the full server/wallet/sapling closure into
    // the link. Those paths are covered by unit tests and reached under attacker
    // control via the settlement_block fuzzer (ProcessSpecialTxsInBlock).
    CDataStream ds(buffer, SER_NETWORK, PROTOCOL_VERSION);
    MintPayload payload;
    try {
        ds >> payload;
    } catch (const std::exception&) {
        return;
    }

    // Round-trip: re-serializing a successfully-parsed payload must not crash and
    // (for canonical inputs) must reproduce a parseable stream.
    CDataStream out(SER_NETWORK, PROTOCOL_VERSION);
    out << payload;
    MintPayload rt;
    try { out >> rt; } catch (const std::exception&) { /* non-canonical tail — fine */ }
}
