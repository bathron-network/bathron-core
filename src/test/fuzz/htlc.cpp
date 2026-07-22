// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the HTLC extraPayload wire surface (HTLC_CREATE_M1 and the
// 3-secret HTLC_CREATE_3S). Interesting because deserialize is VERSION-GATED:
// a v2 payload reads extra covenant fields (templateCommitment, htlc3* keys),
// so an attacker-chosen version byte steers how many bytes are consumed. Parse
// + IsTriviallyValid must be crash-free (no over-read / OOB) on any input.
// Closes the coverage gap "HTLC types have no dedicated fuzz target".
//
// Build/run under libFuzzer + ASan/UBSan:
//   ./configure --enable-fuzz CC=clang CXX=clang++
//   CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1"
//   make -C src test/fuzz/htlc && ./src/test/fuzz/htlc corpus/

#include "htlc/htlc.h"
#include "streams.h"
#include "test/fuzz/fuzz.h"
#include "version.h"

#include <string>
#include <vector>

void test_one_input(std::vector<uint8_t> buffer)
{
    // HTLC_CREATE_M1 payload (v1 no-covenant / v2 covenant, version-gated fields).
    {
        CDataStream ds(buffer, SER_NETWORK, PROTOCOL_VERSION);
        HTLCCreatePayload p;
        try {
            ds >> p;
            std::string err;
            (void)p.IsTriviallyValid(err);
        } catch (const std::exception&) { /* malformed bytes rejected — fine */ }
    }

    // HTLC_CREATE_3S payload (3 hashlocks, same version-gated covenant shape).
    {
        CDataStream ds(buffer, SER_NETWORK, PROTOCOL_VERSION);
        HTLC3SCreatePayload p;
        try {
            ds >> p;
            std::string err;
            (void)p.IsTriviallyValid(err);
        } catch (const std::exception&) { /* malformed bytes rejected — fine */ }
    }
}
