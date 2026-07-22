// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_SCRIPT_TEMPLATE_HASH_H
#define BATHRON_SCRIPT_TEMPLATE_HASH_H

#include "hash.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

/** Maximum outputs allowed in a CTV template (DoS bound on the checker-side
 *  re-hash). Raised 4 -> 64 (2026-07-06, M1 bar "generalize CTV"): 4 was
 *  enough for 2-3-output settlements but starved batching/vault fan-outs;
 *  64 outputs hash in ~a few µs (one SHA256d over <~2.5 KB), negligible next
 *  to a signature check. Prevout/witness commit modes remain deliberately
 *  absent: DLC tree chaining RELIES on templates not committing prevouts
 *  (dlc_script_tests: template_hash_ignores_prevout).
 *
 *  ⚠️ CONSENSUS / FREEZE NOTE (pre-freeze review). This cap is a compile-time
 *  constant, NOT an independent network-upgrade — so the 4->64 raise is a
 *  validity LOOSENING that does not flip at an activation height of its own.
 *  It is SOUND for mainnet because it ships as part of the OP_TEMPLATEVERIFY
 *  semantics gated by UPGRADE_V7_0: on mainnet V7_0 is NO_ACTIVATION until the
 *  freeze, CTV does not run before then, and the frozen binary that flips V7_0
 *  carries cap=64 — so every node agrees. The mixed-binary fork risk exists
 *  ONLY on a chain where V7_0 is already ALWAYS_ACTIVE (testnet) during a
 *  ROLLING deploy; the project's deploy model (fresh disposable genesis for
 *  consensus changes) avoids it. If the cap ever changes again on a live
 *  V7_0-active chain, gate it on a new UpgradeIndex. Freeze checklist: cap=64
 *  is FROZEN together with the V7_0 flip. */
static const size_t CTV_MAX_OUTPUTS = 64;

/** Compute the template hash for OP_TEMPLATEVERIFY (CTV-lite).
 *  Hash = SHA256d(nVersion || nType || locktime || input_count || sequences ||
 *                 output_count || outputs[])
 *  Commits nType to prevent cross-type template collisions (normal vs special TX).
 *  Does NOT commit prevouts or witnesses.
 */
inline uint256 ComputeTemplateHash(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << tx.nVersion;
    ss << tx.nType;
    ss << tx.nLockTime;

    WriteCompactSize(ss, tx.vin.size());
    for (const auto& in : tx.vin)
        ss << in.nSequence;

    WriteCompactSize(ss, tx.vout.size());
    for (const auto& out : tx.vout) {
        ss << out.nValue;
        ss << out.scriptPubKey;
    }

    return ss.GetHash();
}

#endif // BATHRON_SCRIPT_TEMPLATE_HASH_H
