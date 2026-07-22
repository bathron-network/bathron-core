// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the Sapling shielded-pool WIRE + context-free money checks —
// the only MONETARY surface (M0 shield/unshield) that had no fuzz coverage
// (redteam-plan R11). The attacker controls the whole sapData tail: valueBalance
// + vShieldedSpend/vShieldedOutput vectors (SpendDescription/OutputDescription
// with attacker CompactSize counts driving allocation) + bindingSig. This target
// deserializes an arbitrary tx and runs SaplingValidation::CheckTransaction ->
// CheckTransactionWithoutProofVerification, exercising:
//   - the sapData deserialize (unbounded-count allocation must be caught),
//   - valueBalance range / no-sources-no-sinks (inflation guard),
//   - intra-tx duplicate-nullifier detection.
//
// Scope (honest): this does NOT reach librustzcash proof / binding-sig
// verification nor the persistent cross-tx/cross-block nullifier set — those
// need proving params + full chain context and enter via ConnectBlock. This
// fuzzes the parse + context-free consensus checks; must never crash/OOM/UB.
//
// Build/run under libFuzzer + ASan/UBSan:
//   make -C src CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1 -fno-strict-aliasing" test/fuzz/sapling_tx

#include "primitives/transaction.h"
#include "sapling/sapling_validation.h"
#include "consensus/validation.h"
#include "amount.h"
#include "streams.h"
#include "test/fuzz/fuzz.h"
#include "version.h"

#include <vector>

void test_one_input(std::vector<uint8_t> buffer)
{
    CMutableTransaction mtx;
    try {
        CDataStream ds(buffer, SER_NETWORK, PROTOCOL_VERSION);
        ds >> mtx;
    } catch (const std::exception&) {
        return;  // malformed wire — rejected by the deserializer, fine
    }

    const CTransaction tx(mtx);
    CValidationState state;
    CAmount nValueOut = 0;
    // Total on any attacker input; return value is a pure verdict, not asserted.
    (void)SaplingValidation::CheckTransaction(tx, state, nValueOut);
}
