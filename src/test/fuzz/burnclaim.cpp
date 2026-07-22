// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the BATHRON-custom burnclaim parsing surface — the
// hand-rolled Bitcoin-transaction parser that bypasses the hardened serialize.h
// allocator. This is where the unbounded `scriptWitness.resize(witnessCount)`
// OOM DoS lived. Build/run under libFuzzer + AddressSanitizer:
//   ./configure --enable-fuzz CC=clang CXX=clang++  (then set
//   CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1")
//   make -C src test/fuzz/burnclaim && ./src/test/fuzz/burnclaim corpus/

#include "burnclaim/burnclaim.h"
#include "streams.h"
#include "test/fuzz/fuzz.h"
#include "version.h"

#include <string>
#include <vector>

void test_one_input(std::vector<uint8_t> buffer)
{
    // 1) Hammer the hand-rolled BTC-tx parser directly. It reads attacker-
    //    controlled CompactSize counts (vin/vout/witness/script lengths) and
    //    must never OOM, over-read, or crash regardless of input.
    {
        BtcParsedTx tx;
        (void)ParseBtcTransaction(buffer, tx);
        (void)ComputeBtcWtxid(buffer);
        std::vector<uint8_t> opReturn;
        (void)ExtractOpReturnData(buffer, opReturn);
    }

    // 2) Full BurnClaimPayload deserialize + trivial validation. Reaches the
    //    same parser via IsTriviallyValid, plus the OP_RETURN / P2WSH / merkle
    //    parsing paths.
    {
        CDataStream ds(buffer, SER_NETWORK, PROTOCOL_VERSION);
        BurnClaimPayload payload;
        try {
            ds >> payload;
        } catch (const std::exception&) {
            return;
        }
        std::string strError;
        (void)payload.IsTriviallyValid(strError);
    }
}
