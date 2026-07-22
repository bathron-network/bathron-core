// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the BATHRON-custom BTC SPV header payload (TX_BTC_HEADERS).
// Exercises BtcHeadersPayload deserialization + trivial validation (the R7
// count/size bounds before any headers[] access). Build/run under libFuzzer +
// AddressSanitizer the same way as the burnclaim target.

#include "btcheaders/btcheaders.h"
#include "streams.h"
#include "test/fuzz/fuzz.h"
#include "version.h"

#include <string>
#include <vector>

void test_one_input(std::vector<uint8_t> buffer)
{
    CDataStream ds(buffer, SER_NETWORK, PROTOCOL_VERSION);
    BtcHeadersPayload payload;
    try {
        ds >> payload;
    } catch (const std::exception&) {
        return;
    }
    std::string strError;
    (void)payload.IsTriviallyValid(strError);
}
