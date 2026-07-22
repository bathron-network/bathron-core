// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "htlc/htlc.h"
#include "hash.h"
#include "script/conditional.h"
#include "script/script.h"
#include "utilstrencodings.h"

bool ExtractPreimageFromScriptSig(
    const CScript& scriptSig,
    const CScript& redeemScript,
    std::vector<unsigned char>& preimage)
{
    // Branch A scriptSig format (from CreateConditionalSpendA):
    // <sig> <pubkey> <preimage> OP_TRUE <redeemScript>
    //
    // We need to extract the preimage (32 bytes) which is the 3rd element.

    std::vector<std::vector<unsigned char>> stack;
    opcodetype opcode;
    std::vector<unsigned char> data;
    CScript::const_iterator it = scriptSig.begin();

    // Parse all push elements into stack
    while (it < scriptSig.end()) {
        if (!scriptSig.GetOp(it, opcode, data))
            return false;

        if (opcode <= OP_PUSHDATA4) {
            // Data push
            stack.push_back(data);
        } else if (opcode == OP_TRUE || opcode == OP_1) {
            // OP_TRUE is encoded as OP_1 in some cases
            stack.push_back({1});
        } else if (opcode == OP_FALSE || opcode == OP_0) {
            stack.push_back({});
        } else {
            // Unexpected opcode
            return false;
        }
    }

    // Minimum elements for branch A: sig, pubkey, preimage, OP_TRUE, redeemScript
    if (stack.size() < 5)
        return false;

    // Last element should be redeemScript
    const std::vector<unsigned char>& lastElem = stack.back();
    CScript extractedRedeem(lastElem.begin(), lastElem.end());
    if (extractedRedeem != redeemScript)
        return false;

    // Second to last should be OP_TRUE (branch selector)
    // For branch A, this is {1} (OP_TRUE pushes 1)
    const std::vector<unsigned char>& branchSelector = stack[stack.size() - 2];
    if (branchSelector.empty() || branchSelector[0] != 1)
        return false;  // Not branch A (claim path)

    // Third to last is the preimage
    const std::vector<unsigned char>& extractedPreimage = stack[stack.size() - 3];
    if (extractedPreimage.size() != HTLC_PREIMAGE_SIZE)
        return false;

    preimage = extractedPreimage;
    return true;
}

bool VerifyPreimage(
    const std::vector<unsigned char>& preimage,
    const uint256& hashlock)
{
    if (preimage.size() != HTLC_PREIMAGE_SIZE)
        return false;

    uint256 computed;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(computed.begin());

    return computed == hashlock;
}

// =============================================================================
// 3-Secret HTLC Helper Functions (FlowSwap)
// =============================================================================

bool ExtractPreimagesFromScriptSig3S(
    const CScript& scriptSig,
    const CScript& redeemScript,
    std::vector<unsigned char>& preimage_user,
    std::vector<unsigned char>& preimage_lp1,
    std::vector<unsigned char>& preimage_lp2)
{
    // Branch A scriptSig format (from CreateConditional3SSpendA):
    // <sig> <pubkey> <S_lp2> <S_lp1> <S_user> OP_TRUE <redeemScript>
    //
    // Stack is LIFO, verification order: S_user, S_lp1, S_lp2
    // So pushed order is: S_lp2, S_lp1, S_user (reverse of verification)

    std::vector<std::vector<unsigned char>> stack;
    opcodetype opcode;
    std::vector<unsigned char> data;
    CScript::const_iterator it = scriptSig.begin();

    // Parse all push elements into stack
    while (it < scriptSig.end()) {
        if (!scriptSig.GetOp(it, opcode, data))
            return false;

        if (opcode <= OP_PUSHDATA4) {
            stack.push_back(data);
        } else if (opcode == OP_TRUE || opcode == OP_1) {
            stack.push_back({1});
        } else if (opcode == OP_FALSE || opcode == OP_0) {
            stack.push_back({});
        } else {
            return false;
        }
    }

    // Minimum elements: sig, pubkey, S_lp2, S_lp1, S_user, OP_TRUE, redeemScript = 7
    if (stack.size() < 7)
        return false;

    // Last element should be redeemScript
    const std::vector<unsigned char>& lastElem = stack.back();
    CScript extractedRedeem(lastElem.begin(), lastElem.end());
    if (extractedRedeem != redeemScript)
        return false;

    // Second to last should be OP_TRUE (branch selector)
    const std::vector<unsigned char>& branchSelector = stack[stack.size() - 2];
    if (branchSelector.empty() || branchSelector[0] != 1)
        return false;  // Not branch A (claim path)

    // Extract preimages in canonical order (user, lp1, lp2)
    // Stack order from end: redeemScript, OP_TRUE, S_user, S_lp1, S_lp2, pubkey, sig
    // Indices from end: -1=redeem, -2=OP_TRUE, -3=S_user, -4=S_lp1, -5=S_lp2

    const std::vector<unsigned char>& extracted_user = stack[stack.size() - 3];
    const std::vector<unsigned char>& extracted_lp1 = stack[stack.size() - 4];
    const std::vector<unsigned char>& extracted_lp2 = stack[stack.size() - 5];

    // Verify all are 32 bytes
    if (extracted_user.size() != HTLC_PREIMAGE_SIZE ||
        extracted_lp1.size() != HTLC_PREIMAGE_SIZE ||
        extracted_lp2.size() != HTLC_PREIMAGE_SIZE) {
        return false;
    }

    preimage_user = extracted_user;
    preimage_lp1 = extracted_lp1;
    preimage_lp2 = extracted_lp2;
    return true;
}

bool VerifyPreimages3S(
    const std::vector<unsigned char>& preimage_user,
    const std::vector<unsigned char>& preimage_lp1,
    const std::vector<unsigned char>& preimage_lp2,
    const uint256& hashlock_user,
    const uint256& hashlock_lp1,
    const uint256& hashlock_lp2)
{
    // Verify each preimage independently
    if (!VerifyPreimage(preimage_user, hashlock_user))
        return false;
    if (!VerifyPreimage(preimage_lp1, hashlock_lp1))
        return false;
    if (!VerifyPreimage(preimage_lp2, hashlock_lp2))
        return false;

    return true;
}
