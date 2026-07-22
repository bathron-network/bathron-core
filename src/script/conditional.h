// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_SCRIPT_CONDITIONAL_H
#define BATHRON_SCRIPT_CONDITIONAL_H

#include "script/script.h"
#include "pubkey.h"
#include "uint256.h"

#include <vector>

/**
 * Conditional Script (hash + timelock)
 * BIP-199 compatible P2SH standard
 * Compatible: BTC, LTC, DASH, ZEC, BCH, DOGE
 */

/**
 * Create conditional script (P2SH redeemScript)
 *
 * @param hashlock   SHA256(secret), 32 bytes
 * @param timelock   Block height (absolute)
 * @param destA      Destination if secret revealed
 * @param destB      Destination if timeout
 * @return           redeemScript for P2SH
 */
CScript CreateConditionalScript(
    const uint256& hashlock,
    uint32_t timelock,
    const CKeyID& destA,
    const CKeyID& destB
);

/**
 * Decode conditional script parameters
 *
 * @param script     redeemScript to decode
 * @param hashlock   Output: extracted hashlock
 * @param timelock   Output: extracted timelock
 * @param destA      Output: destination A
 * @param destB      Output: destination B
 * @return           true if valid conditional script
 */
bool DecodeConditionalScript(
    const CScript& script,
    uint256& hashlock,
    uint32_t& timelock,
    CKeyID& destA,
    CKeyID& destB
);

/**
 * Check if script is a conditional script
 */
bool IsConditionalScript(const CScript& script);

/**
 * Create scriptSig for spending via branch A (with secret)
 */
CScript CreateConditionalSpendA(
    const std::vector<unsigned char>& sig,
    const CPubKey& pubkey,
    const std::vector<unsigned char>& secret,
    const CScript& redeemScript
);

/**
 * Create scriptSig for spending via branch B (timeout)
 */
CScript CreateConditionalSpendB(
    const std::vector<unsigned char>& sig,
    const CPubKey& pubkey,
    const CScript& redeemScript
);

// =============================================================================
// Covenant Conditional Script (OP_TEMPLATEVERIFY)
// =============================================================================

/**
 * Create conditional script with covenant (P2SH redeemScript)
 *
 * Branch A forces the spending TX to match a template commitment C3,
 * ensuring the claim atomically creates HTLC3 (Settlement Pivot).
 *
 * Script structure:
 *   OP_IF
 *     OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
 *     <C3> OP_TEMPLATEVERIFY OP_DROP
 *     OP_DUP OP_HASH160 <destA>
 *   OP_ELSE
 *     <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *     OP_DUP OP_HASH160 <destB>
 *   OP_ENDIF
 *   OP_EQUALVERIFY OP_CHECKSIG
 *
 * @param hashlock             SHA256(secret), 32 bytes
 * @param timelock             Block height (absolute)
 * @param destA                Destination if secret revealed
 * @param destB                Destination if timeout
 * @param templateCommitment   C3 = ComputeTemplateHash(PivotTx)
 * @return                     redeemScript for P2SH
 */
CScript CreateConditionalWithCovenantScript(
    const uint256& hashlock,
    uint32_t timelock,
    const CKeyID& destA,
    const CKeyID& destB,
    const uint256& templateCommitment
);

/**
 * Decode conditional script with covenant
 *
 * @param script               redeemScript to decode
 * @param hashlock             Output: extracted hashlock
 * @param timelock             Output: extracted timelock
 * @param destA                Output: destination A
 * @param destB                Output: destination B
 * @param templateCommitment   Output: extracted C3 commitment
 * @return                     true if valid covenant conditional script
 */
bool DecodeConditionalWithCovenantScript(
    const CScript& script,
    uint256& hashlock,
    uint32_t& timelock,
    CKeyID& destA,
    CKeyID& destB,
    uint256& templateCommitment
);

/**
 * Check if script is a conditional script with covenant
 */
bool IsConditionalWithCovenantScript(const CScript& script);

// =============================================================================
// 3-Secret Conditional Script (FlowSwap)
// =============================================================================

/**
 * Create 3-secret conditional script (P2SH redeemScript) for FlowSwap
 *
 * Script structure (canonical order: S_user, S_lp1, S_lp2):
 *
 * OP_IF
 *   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H_user> OP_EQUALVERIFY
 *   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H_lp1> OP_EQUALVERIFY
 *   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H_lp2> OP_EQUALVERIFY
 *   OP_DUP OP_HASH160 <claimKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 * OP_ELSE
 *   <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *   OP_DUP OP_HASH160 <refundKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 * OP_ENDIF
 *
 * @param hashlock_user  SHA256(S_user)
 * @param hashlock_lp1   SHA256(S_lp1)
 * @param hashlock_lp2   SHA256(S_lp2)
 * @param timelock       Block height (absolute)
 * @param claimDest      Destination if all 3 secrets revealed
 * @param refundDest     Destination if timeout
 * @return               redeemScript for P2SH
 */
CScript CreateConditional3SScript(
    const uint256& hashlock_user,
    const uint256& hashlock_lp1,
    const uint256& hashlock_lp2,
    uint32_t timelock,
    const CKeyID& claimDest,
    const CKeyID& refundDest
);

/**
 * Create scriptSig for spending 3S HTLC via branch A (with 3 secrets)
 *
 * Stack (LIFO, pushed in reverse order for execution):
 * <sig> <pubkey> <S_lp2> <S_lp1> <S_user> OP_TRUE <redeemScript>
 *
 * Canonical order for preimage verification: S_user first, then S_lp1, then S_lp2
 */
CScript CreateConditional3SSpendA(
    const std::vector<unsigned char>& sig,
    const CPubKey& pubkey,
    const std::vector<unsigned char>& preimage_user,
    const std::vector<unsigned char>& preimage_lp1,
    const std::vector<unsigned char>& preimage_lp2,
    const CScript& redeemScript
);

/**
 * Create scriptSig for spending 3S HTLC via branch B (timeout)
 */
CScript CreateConditional3SSpendB(
    const std::vector<unsigned char>& sig,
    const CPubKey& pubkey,
    const CScript& redeemScript
);

// =============================================================================
// 3-Secret Conditional Script WITH Covenant (Per-Leg FlowSwap)
// =============================================================================

/**
 * Create 3-secret conditional script with covenant (P2SH redeemScript)
 *
 * Extends CreateConditional3SScript with OP_TEMPLATEVERIFY to enforce
 * that the claiming TX output goes to a specific destination (LP_OUT).
 * Used in per-leg mode where M1 flows LP_IN → LP_OUT.
 *
 * Script structure:
 *
 * OP_IF
 *   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H_user> OP_EQUALVERIFY
 *   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H_lp1> OP_EQUALVERIFY
 *   OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H_lp2> OP_EQUALVERIFY
 *   <C3> OP_TEMPLATEVERIFY OP_DROP
 *   OP_DUP OP_HASH160 <claimKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 * OP_ELSE
 *   <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *   OP_DUP OP_HASH160 <refundKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 * OP_ENDIF
 *
 * @param hashlock_user        SHA256(S_user)
 * @param hashlock_lp1         SHA256(S_lp1)
 * @param hashlock_lp2         SHA256(S_lp2)
 * @param timelock             Block height (absolute)
 * @param claimDest            Destination if all 3 secrets revealed
 * @param refundDest           Destination if timeout
 * @param templateCommitment   C3 = ComputeTemplateHash(PivotTx to LP_OUT)
 * @return                     redeemScript for P2SH
 */
CScript CreateConditional3SWithCovenantScript(
    const uint256& hashlock_user,
    const uint256& hashlock_lp1,
    const uint256& hashlock_lp2,
    uint32_t timelock,
    const CKeyID& claimDest,
    const CKeyID& refundDest,
    const uint256& templateCommitment
);

#endif // BATHRON_SCRIPT_CONDITIONAL_H
