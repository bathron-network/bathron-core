// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btcspv/btcspv.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "hash.h"
#include "key_io.h"
#include "logging.h"
#include "rpc/server.h"
#include "streams.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <functional>
#include <univalue.h>

UniValue getbtctip(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "getbtctip\n"
            "\nReturns current best BTC chain tip info.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\": n,          (numeric) Block height\n"
            "  \"hash\": \"hash\",     (string) Block hash\n"
            "  \"synced\": true|false  (boolean) Whether synced to recent time\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getbtctip", "")
            + HelpExampleRpc("getbtctip", "")
        );
    }

    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("height", (int)g_btc_spv->GetTipHeight());
    result.pushKV("hash", g_btc_spv->GetTipHash().GetHex());
    result.pushKV("chainwork", ArithToUint256(g_btc_spv->GetTipChainWork()).GetHex());
    result.pushKV("synced", g_btc_spv->IsSynced());
    result.pushKV("headers_count", (int)g_btc_spv->GetHeaderCount());

    return result;
}

UniValue getbtcheader(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "getbtcheader \"hash_or_height\"\n"
            "\nReturns BTC block header info by hash or height.\n"
            "\nArguments:\n"
            "1. hash_or_height    (string/numeric, required) Block hash or height\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\": \"hash\",           (string) Block hash\n"
            "  \"height\": n,                (numeric) Block height\n"
            "  \"confirmations\": n,         (numeric) Number of confirmations\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getbtcheader", "800000")
        );
    }

    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    BtcHeaderIndex index;

    // Handle both string and numeric parameters
    const UniValue& paramVal = request.params[0];

    if (paramVal.isNum()) {
        // Direct numeric height
        uint32_t height = paramVal.get_int();
        if (!g_btc_spv->GetHeaderAtHeight(height, index)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Block not found at height %d", height));
        }
    } else {
        // String parameter - could be hash or height as string
        std::string param = paramVal.get_str();

        // Determine if this is a hash (64 hex chars) or height
        bool isHash = (param.length() == 64 &&
                       param.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos);

        LogPrint(BCLog::NET, "BTC-SPV: getbtcheader param='%s' len=%d isHash=%d\n",
                 param.substr(0, 16), param.length(), isHash);

        if (isHash) {
            // Parse as hash
            uint256 hash = uint256S(param);
            if (!g_btc_spv->GetHeader(hash, index)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Block not found: " + param);
            }
        } else {
            // Parse as height
            try {
                uint32_t height = std::stoul(param);
                if (!g_btc_spv->GetHeaderAtHeight(height, index)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Block not found at height %d", height));
                }
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid height or hash: " + param);
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", index.hash.GetHex());
    result.pushKV("height", (int)index.height);
    result.pushKV("version", index.header.nVersion);
    result.pushKV("previousblockhash", index.hashPrevBlock.GetHex());
    result.pushKV("merkleroot", index.header.hashMerkleRoot.GetHex());
    result.pushKV("time", (int64_t)index.header.nTime);
    result.pushKV("bits", strprintf("%08x", index.header.nBits));
    result.pushKV("nonce", (uint64_t)index.header.nNonce);
    result.pushKV("chainwork", index.chainWorkSer.GetHex());
    result.pushKV("confirmations", (int)g_btc_spv->GetConfirmations(index.hash));
    result.pushKV("in_best_chain", g_btc_spv->IsInBestChain(index.hash));

    return result;
}

UniValue submitbtcheaders(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "submitbtcheaders \"headers_hex\"\n"
            "\nSubmit raw BTC headers directly (for testing without P2P).\n"
            "\nArguments:\n"
            "1. headers_hex    (string, required) Concatenated 80-byte headers in hex\n"
            "\nResult:\n"
            "{\n"
            "  \"accepted\": n,           (numeric) Number of headers accepted\n"
            "  \"rejected\": n,           (numeric) Number of headers rejected\n"
            "  \"tip_height\": n,         (numeric) Current tip height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("submitbtcheaders", "\"0100000000000000...\"")
        );
    }

    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    std::string hexHeaders = request.params[0].get_str();
    std::vector<unsigned char> headerData = ParseHex(hexHeaders);

    if (headerData.size() % 80 != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Headers data must be multiple of 80 bytes, got %d", headerData.size()));
    }

    // Parse headers
    std::vector<BtcBlockHeader> headers;
    size_t numHeaders = headerData.size() / 80;

    for (size_t i = 0; i < numHeaders; i++) {
        BtcBlockHeader header;
        CDataStream ss(std::vector<char>(headerData.begin() + i * 80, headerData.begin() + (i + 1) * 80),
                       SER_NETWORK, PROTOCOL_VERSION);
        ss >> header;
        headers.push_back(header);
    }

    // Submit headers
    CBtcSPV::BatchResult result = g_btc_spv->AddHeaders(headers);

    UniValue response(UniValue::VOBJ);
    response.pushKV("accepted", (int)result.accepted);
    response.pushKV("rejected", (int)result.rejected);
    response.pushKV("tip_height", (int)result.tipHeight);

    if (!result.firstRejectReason.empty()) {
        UniValue reject(UniValue::VOBJ);
        reject.pushKV("hash", result.firstRejectHash.GetHex());
        reject.pushKV("reason", result.firstRejectReason);
        response.pushKV("first_reject", reject);
    }

    return response;
}

UniValue getbtcsyncstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "getbtcsyncstatus\n"
            "\nReturns BTC SPV sync status.\n"
            "\nResult:\n"
            "{\n"
            "  \"synced\": true|false,         (boolean) Whether synced to recent time\n"
            "  \"headers_count\": n,           (numeric) Number of headers in DB\n"
            "  \"tip_height\": n,              (numeric) Current tip height\n"
            "  \"tip_hash\": \"hash\",         (string) Current tip hash\n"
            "  \"network\": \"signet|mainnet\",(string) BTC network\n"
            "  \"spv_ready\": true|false,      (boolean) Whether SPV is ready for burn claims\n"
            "  \"min_supported_height\": n|null (numeric/null) Lowest BTC height for trustless burns\n"
            "}\n"
            "\nNote: min_supported_height only bounds the local burn-scan paths (scanburns/daemon);\n"
            "consensus validation requires the header in the consensus btcheadersdb.\n"
            "If spv_ready=false, the local scan paths cannot discover burns.\n"
            "\nExamples:\n"
            + HelpExampleCli("getbtcsyncstatus", "")
        );
    }

    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("synced", g_btc_spv->IsSynced());
    result.pushKV("headers_count", (int)g_btc_spv->GetHeaderCount());
    result.pushKV("tip_height", (int)g_btc_spv->GetTipHeight());
    result.pushKV("tip_hash", g_btc_spv->GetTipHash().GetHex());
    result.pushKV("network", Params().IsTestnet() ? "signet" : "mainnet");

    // BP09: Expose minimum supported height for burn claim validation
    // Burns below this height cannot be verified trustlessly (checkpoint limitation)
    //
    // UINT32_MAX is a sentinel meaning "SPV not ready" - don't expose as valid height
    uint32_t minHeight = g_btc_spv->GetMinSupportedHeight();
    bool spvReady = (minHeight != UINT32_MAX);
    result.pushKV("spv_ready", spvReady);
    if (spvReady) {
        result.pushKV("min_supported_height", (int64_t)minHeight);
    } else {
        result.pushKV("min_supported_height", UniValue());  // null
    }

    return result;
}

UniValue verifymerkleproof(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4) {
        throw std::runtime_error(
            "verifymerkleproof \"txid\" \"merkleroot\" [\"proof\",...] txindex\n"
            "\nVerify a merkle proof for a transaction.\n"
            "\nArguments:\n"
            "1. txid        (string, required) Transaction ID\n"
            "2. merkleroot  (string, required) Block merkle root\n"
            "3. proof       (array, required) Array of proof hashes\n"
            "4. txindex     (numeric, required) Transaction index in block\n"
            "\nResult:\n"
            "true|false    (boolean) Whether the proof is valid\n"
        );
    }

    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    uint256 txid = uint256S(request.params[0].get_str());
    uint256 merkleRoot = uint256S(request.params[1].get_str());

    std::vector<uint256> proof;
    UniValue proofArr = request.params[2].get_array();
    for (size_t i = 0; i < proofArr.size(); i++) {
        proof.push_back(uint256S(proofArr[i].get_str()));
    }

    uint32_t txIndex = request.params[3].get_int();

    return g_btc_spv->VerifyMerkleProof(txid, merkleRoot, proof, txIndex);
}

// Helper to parse Bitcoin CMerkleBlock format and extract sibling hashes
// The CMerkleBlock format is: header(80) + nTx(4) + vHash(varint+hashes) + vBits(varint+bytes)
UniValue parsemerkleblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "parsemerkleblock \"merkleblock_hex\" \"txid\"\n"
            "\nParse a Bitcoin CMerkleBlock and extract the sibling proof for a specific txid.\n"
            "\nArguments:\n"
            "1. merkleblock_hex  (string, required) Output from gettxoutproof\n"
            "2. txid             (string, required) Transaction ID to extract proof for\n"
            "\nResult:\n"
            "{\n"
            "  \"merkleroot\": \"...\",   (string) Block merkle root\n"
            "  \"txindex\": n,            (numeric) Transaction index in block\n"
            "  \"siblings\": [\"...\"],   (array) Sibling hashes for proof\n"
            "}\n"
        );
    }

    std::string mbHex = request.params[0].get_str();
    uint256 targetTxid = uint256S(request.params[1].get_str());

    std::vector<unsigned char> mbData = ParseHex(mbHex);
    if (mbData.size() < 84) {  // 80 header + 4 nTx minimum
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Merkle block too short");
    }

    // Parse header (80 bytes)
    BtcBlockHeader header;
    CDataStream ssHeader(std::vector<char>(mbData.begin(), mbData.begin() + 80), SER_NETWORK, PROTOCOL_VERSION);
    ssHeader >> header;

    // Parse nTransactions (4 bytes, little-endian)
    uint32_t nTx = mbData[80] | (mbData[81] << 8) | (mbData[82] << 16) | (mbData[83] << 24);

    // Parse vHash (varint count + hashes)
    size_t pos = 84;
    uint64_t nHashes = 0;
    if (mbData[pos] < 0xFD) {
        nHashes = mbData[pos];
        pos += 1;
    } else if (mbData[pos] == 0xFD) {
        nHashes = mbData[pos+1] | (mbData[pos+2] << 8);
        pos += 3;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many hashes in proof");
    }

    std::vector<uint256> vHash;
    for (uint64_t i = 0; i < nHashes; i++) {
        if (pos + 32 > mbData.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unexpected end of merkle block");
        }
        uint256 hash;
        memcpy(hash.begin(), &mbData[pos], 32);
        vHash.push_back(hash);
        pos += 32;
    }

    // Parse vBits (varint count + bytes)
    uint64_t nBits = 0;
    if (mbData[pos] < 0xFD) {
        nBits = mbData[pos];
        pos += 1;
    } else if (mbData[pos] == 0xFD) {
        nBits = mbData[pos+1] | (mbData[pos+2] << 8);
        pos += 3;
    }

    std::vector<bool> vBits;
    for (uint64_t i = 0; i < nBits * 8; i++) {
        uint64_t byteIdx = i / 8;
        uint64_t bitIdx = i % 8;
        if (pos + byteIdx >= mbData.size()) break;
        vBits.push_back((mbData[pos + byteIdx] >> bitIdx) & 1);
    }

    // Calculate tree height
    uint32_t height = 0;
    while ((1u << height) < nTx) height++;

    // Traverse tree to find txid and extract siblings
    std::vector<uint256> siblings;
    uint32_t txIndex = 0;
    size_t hashIdx = 0;
    size_t bitIdx = 0;

    std::function<uint256(uint32_t, uint32_t, uint32_t)> traverse;
    traverse = [&](uint32_t h, uint32_t pos, uint32_t width) -> uint256 {
        if (bitIdx >= vBits.size()) {
            return uint256();
        }
        bool flag = vBits[bitIdx++];

        if (h == 0 || !flag) {
            // Leaf or pruned subtree - use hash from vHash
            if (hashIdx >= vHash.size()) return uint256();
            return vHash[hashIdx++];
        }

        // Internal node - descend
        uint32_t leftWidth = 1u << (h - 1);
        if (leftWidth > width) leftWidth = width;
        uint32_t rightWidth = (width > leftWidth) ? (width - leftWidth) : 0;

        uint256 left = traverse(h - 1, pos, leftWidth);
        uint256 right = (rightWidth > 0) ? traverse(h - 1, pos + leftWidth, rightWidth) : left;

        return Hash(left.begin(), left.end(), right.begin(), right.end());
    };

    // First pass: find if target txid is in the proof and get its path
    // We need to do a more careful extraction

    // Simpler approach: decode the path from vBits and extract siblings
    // For a single-tx proof, the path follows the 1-bits down to the tx

    hashIdx = 0;
    bitIdx = 0;
    siblings.clear();

    int32_t foundIdx = -1;

    std::function<uint256(uint32_t, uint32_t, uint32_t, std::vector<uint256>&)> findAndExtract;
    findAndExtract = [&](uint32_t h, uint32_t startIdx, uint32_t width, std::vector<uint256>& path) -> uint256 {
        if (bitIdx >= vBits.size()) return uint256();
        bool flag = vBits[bitIdx++];

        if (h == 0) {
            // Leaf level
            if (hashIdx >= vHash.size()) return uint256();
            uint256 leafHash = vHash[hashIdx++];
            if (leafHash == targetTxid) {
                foundIdx = startIdx;
                siblings = path;  // Copy current path as siblings
            }
            return leafHash;
        }

        if (!flag) {
            // Pruned subtree - use hash
            if (hashIdx >= vHash.size()) return uint256();
            return vHash[hashIdx++];
        }

        // Internal node - descend both sides
        uint32_t leftWidth = 1u << (h - 1);
        if (leftWidth > width) leftWidth = width;
        uint32_t rightWidth = (width > leftWidth) ? (width - leftWidth) : 0;

        // Save right subtree hash for path, then traverse left
        size_t savedHashIdx = hashIdx;
        size_t savedBitIdx = bitIdx;

        // Traverse left first
        auto pathLeft = path;
        uint256 left = findAndExtract(h - 1, startIdx, leftWidth, pathLeft);

        // Now traverse right
        uint256 right;
        if (rightWidth > 0) {
            auto pathRight = path;
            right = findAndExtract(h - 1, startIdx + leftWidth, rightWidth, pathRight);
        } else {
            right = left;
        }

        // If target was in left subtree, add right as sibling
        if (foundIdx >= 0 && foundIdx < (int32_t)(startIdx + leftWidth) && siblings.size() < h) {
            siblings.push_back(right);
        }
        // If target was in right subtree, add left as sibling
        if (foundIdx >= (int32_t)(startIdx + leftWidth) && siblings.size() < h) {
            siblings.push_back(left);
        }

        return Hash(left.begin(), left.end(), right.begin(), right.end());
    };

    std::vector<uint256> emptyPath;
    uint256 computedRoot = findAndExtract(height, 0, nTx, emptyPath);

    if (foundIdx < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Target txid not found in merkle block");
    }

    // Reverse siblings (we collected from leaf to root, but proof is root to leaf... actually bottom-up is correct)
    // The siblings array should be in order from leaf's direct sibling up to root's child

    UniValue result(UniValue::VOBJ);
    result.pushKV("merkleroot", header.hashMerkleRoot.GetHex());
    result.pushKV("computed_root", computedRoot.GetHex());
    result.pushKV("root_matches", computedRoot == header.hashMerkleRoot);
    result.pushKV("txindex", foundIdx);
    result.pushKV("num_transactions", (int)nTx);
    result.pushKV("tree_height", (int)height);

    UniValue siblingsArr(UniValue::VARR);
    for (const auto& s : siblings) {
        siblingsArr.push_back(s.GetHex());
    }
    result.pushKV("siblings", siblingsArr);

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// buildblock1 - Compute canonical genesis burns merkle root (BP-SPV-BLOCK1 Step E)
// ═══════════════════════════════════════════════════════════════════════════
// This RPC is used by the bootstrap process to:
// 1. Validate a list of BTC burn claims against SPV headers
// 2. Compute the deterministic merkle root that will be hardcoded in chainparams
// 3. Generate the TX_MINT_M0BTC structure for Block 1
//
// The root commits to: H(btc_txid || btc_height || btc_blockhash || amount || recipient)
// Claims are sorted lexicographically by this hash before computing the root.
// ═══════════════════════════════════════════════════════════════════════════

// Canonical claim entry - deterministic hash of data available in TX_MINT_M0BTC
// This commits to: btc_txid (from payload), amount (from vout), recipient_script (from vout)
// NOTE: btc_height/btc_blockhash are NOT included because they're not in the transaction.
// The SPV validation happens separately (and can still use that data for validation).
static uint256 ComputeClaimEntryHash(const uint256& btcTxid, CAmount amount,
                                      const CScript& recipientScript) {
    CHashWriter ss(SER_GETHASH, 0);
    ss << btcTxid;
    ss << amount;
    ss << recipientScript;
    return ss.GetHash();
}

UniValue buildblock1(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "buildblock1 burns [validate_spv]\n"
            "\nCompute canonical genesis burns merkle root for Block 1.\n"
            "\nThis is used during bootstrap to generate the GENESIS_BURNS_ROOT\n"
            "that will be hardcoded in chainparams.cpp.\n"
            "\nArguments:\n"
            "1. burns           (array, required) Array of burn claim objects:\n"
            "   [\n"
            "     {\n"
            "       \"btc_txid\": \"hex\",      (string) BTC transaction ID\n"
            "       \"btc_height\": n,          (numeric) BTC block height\n"
            "       \"btc_blockhash\": \"hex\", (string) BTC block hash\n"
            "       \"amount\": n,              (numeric) Amount in sats\n"
            "       \"recipient\": \"addr\"     (string) BATHRON recipient address\n"
            "     }, ...\n"
            "   ]\n"
            "2. validate_spv    (boolean, optional, default=true) Validate against SPV\n"
            "\nResult:\n"
            "{\n"
            "  \"genesis_burns_root\": \"hex\", (string) Merkle root to hardcode\n"
            "  \"claim_count\": n,              (numeric) Number of claims\n"
            "  \"total_sats\": n,               (numeric) Total amount in sats\n"
            "  \"claims\": [                    (array) Canonical claim list\n"
            "    {\n"
            "      \"entry_hash\": \"hex\",     (string) H(txid||height||blockhash||amount||recipient)\n"
            "      \"btc_txid\": \"hex\",       (string) BTC txid\n"
            "      \"btc_height\": n,           (numeric) BTC block height\n"
            "      \"amount\": n,               (numeric) Amount in sats\n"
            "      \"recipient\": \"addr\"      (string) BATHRON address\n"
            "    }, ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("buildblock1", "'[{\"btc_txid\":\"abc...\",\"btc_height\":280000,\"btc_blockhash\":\"def...\",\"amount\":1000000,\"recipient\":\"yXXX...\"}]'")
        );
    }

    // Parse burns array
    const UniValue& burnsArr = request.params[0].get_array();
    bool validateSpv = request.params.size() > 1 ? request.params[1].get_bool() : true;

    if (burnsArr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Burns array cannot be empty");
    }

    // Get consensus params for validation
    const Consensus::Params& consensus = Params().GetConsensus();
    std::pair<uint32_t, uint32_t> btcHeightRange = consensus.GetBurnScanBtcHeightRange();
    uint32_t heightStart = btcHeightRange.first;
    uint32_t heightEnd = btcHeightRange.second;

    // Validate SPV is available if requested
    if (validateSpv && !g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized (use validate_spv=false to skip)");
    }

    // Parse and validate each claim
    struct ClaimEntry {
        uint256 entryHash;       // H(btc_txid || amount || recipient_script)
        uint256 btcTxid;
        uint32_t btcHeight;      // For SPV validation only, not in hash
        uint256 btcBlockhash;    // For SPV validation only, not in hash
        CAmount amount;
        std::string recipient;
        CScript recipientScript;
    };
    std::vector<ClaimEntry> claims;
    CAmount totalSats = 0;

    for (size_t i = 0; i < burnsArr.size(); i++) {
        const UniValue& burnObj = burnsArr[i];
        if (!burnObj.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Burn %zu is not an object", i));
        }

        // Extract required fields (copy to avoid dangling references)
        UniValue txidVal = find_value(burnObj, "btc_txid");
        UniValue heightVal = find_value(burnObj, "btc_height");
        UniValue blockhashVal = find_value(burnObj, "btc_blockhash");
        UniValue amountVal = find_value(burnObj, "amount");
        UniValue recipientVal = find_value(burnObj, "recipient");

        if (txidVal.isNull() || heightVal.isNull() || blockhashVal.isNull() ||
            amountVal.isNull() || recipientVal.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Burn %zu missing required field (btc_txid, btc_height, btc_blockhash, amount, recipient)", i));
        }

        ClaimEntry entry;
        entry.btcTxid = uint256S(txidVal.get_str());
        entry.btcHeight = heightVal.get_int();
        entry.btcBlockhash = uint256S(blockhashVal.get_str());
        entry.amount = amountVal.get_int64();
        entry.recipient = recipientVal.get_str();

        // Validate height in range
        if (entry.btcHeight < heightStart || entry.btcHeight > heightEnd) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Burn %zu: height %d outside scan range [%d, %d]",
                          i, entry.btcHeight, heightStart, heightEnd));
        }

        // Validate amount is positive
        if (entry.amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Burn %zu: amount must be positive", i));
        }

        // Validate recipient address and compute script
        CTxDestination dest = DecodeDestination(entry.recipient);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Burn %zu: invalid recipient address '%s'", i, entry.recipient));
        }
        entry.recipientScript = GetScriptForDestination(dest);

        // Validate against SPV if requested
        if (validateSpv) {
            BtcHeaderIndex headerIndex;
            if (!g_btc_spv->GetHeaderAtHeight(entry.btcHeight, headerIndex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Burn %zu: SPV has no header at height %d", i, entry.btcHeight));
            }

            if (headerIndex.hash != entry.btcBlockhash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Burn %zu: blockhash mismatch at height %d (SPV: %s, claim: %s)",
                              i, entry.btcHeight,
                              headerIndex.hash.ToString().substr(0, 16),
                              entry.btcBlockhash.ToString().substr(0, 16)));
            }

            // Verify block is in best chain
            if (!g_btc_spv->IsInBestChain(entry.btcBlockhash)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Burn %zu: block %s not in best chain",
                              i, entry.btcBlockhash.ToString().substr(0, 16)));
            }
        }

        // Compute canonical entry hash: H(btc_txid || amount || recipient_script)
        // NOTE: btc_height and btc_blockhash are NOT in the hash - they're for SPV validation only
        entry.entryHash = ComputeClaimEntryHash(entry.btcTxid, entry.amount, entry.recipientScript);

        claims.push_back(entry);
        totalSats += entry.amount;
    }

    // Sort claims lexicographically by entry hash (deterministic ordering)
    std::sort(claims.begin(), claims.end(), [](const ClaimEntry& a, const ClaimEntry& b) {
        return a.entryHash < b.entryHash;
    });

    // Build merkle tree from sorted entry hashes
    std::vector<uint256> leaves;
    for (const auto& claim : claims) {
        leaves.push_back(claim.entryHash);
    }

    // Compute merkle root (using BATHRON's standard merkle tree)
    uint256 merkleRoot;
    if (leaves.size() == 1) {
        merkleRoot = leaves[0];
    } else {
        // Build merkle tree level by level
        std::vector<uint256> level = leaves;
        while (level.size() > 1) {
            std::vector<uint256> nextLevel;
            for (size_t i = 0; i < level.size(); i += 2) {
                if (i + 1 < level.size()) {
                    // Hash pair
                    CHashWriter ss(SER_GETHASH, 0);
                    ss << level[i] << level[i + 1];
                    nextLevel.push_back(ss.GetHash());
                } else {
                    // Odd element - hash with itself
                    CHashWriter ss(SER_GETHASH, 0);
                    ss << level[i] << level[i];
                    nextLevel.push_back(ss.GetHash());
                }
            }
            level = nextLevel;
        }
        merkleRoot = level[0];
    }

    // Build result
    UniValue result(UniValue::VOBJ);
    result.pushKV("genesis_burns_root", merkleRoot.GetHex());
    result.pushKV("claim_count", (int)claims.size());
    result.pushKV("total_sats", totalSats);

    // Add canonical claim list for audit
    UniValue claimsArr(UniValue::VARR);
    for (const auto& claim : claims) {
        UniValue claimObj(UniValue::VOBJ);
        claimObj.pushKV("entry_hash", claim.entryHash.GetHex());
        claimObj.pushKV("btc_txid", claim.btcTxid.GetHex());
        claimObj.pushKV("btc_height", (int)claim.btcHeight);
        claimObj.pushKV("btc_blockhash", claim.btcBlockhash.GetHex());
        claimObj.pushKV("amount", claim.amount);
        claimObj.pushKV("recipient", claim.recipient);
        claimsArr.push_back(claimObj);
    }
    result.pushKV("claims", claimsArr);

    // Log for audit trail
    LogPrintf("buildblock1: Computed GENESIS_BURNS_ROOT=%s (N=%d, total=%s sats)\n",
              merkleRoot.GetHex(), claims.size(), FormatMoney(totalSats));

    return result;
}

// COMMIT 5: Hot reload RPC
UniValue reloadbtcspv(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "reloadbtcspv\n"
            "\nHot reload BTC SPV store without restarting the daemon.\n"
            "\nUse this after manually updating the btcspv/ directory (e.g., copying\n"
            "headers from a synced node). The SPV store will be closed and reopened,\n"
            "picking up any new headers that were added to the database files.\n"
            "\nResult:\n"
            "{\n"
            "  \"success\": true|false,       (boolean) Whether reload succeeded\n"
            "  \"old_height\": n,             (numeric) Height before reload\n"
            "  \"new_height\": n,             (numeric) Height after reload\n"
            "  \"synced\": true|false,        (boolean) Whether SPV is now synced\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("reloadbtcspv", "")
        );
    }

    if (!g_btc_spv) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "BTC SPV not initialized");
    }

    uint32_t oldHeight = g_btc_spv->GetTipHeight();

    bool success = g_btc_spv->Reload();

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", success);
    result.pushKV("old_height", (int)oldHeight);

    if (success && g_btc_spv) {
        result.pushKV("new_height", (int)g_btc_spv->GetTipHeight());
        result.pushKV("synced", g_btc_spv->IsSynced());
    } else {
        result.pushKV("new_height", 0);
        result.pushKV("synced", false);
    }

    return result;
}

// Register commands
static const CRPCCommand commands[] = {
    //  category       name                   actor              okSafeMode  argNames
    { "btcspv",       "getbtctip",           &getbtctip,         true,       {} },
    { "btcspv",       "getbtcheader",        &getbtcheader,      true,       {"hash_or_height"} },
    { "btcspv",       "submitbtcheaders",    &submitbtcheaders,  true,       {"headers_hex"} },
    { "btcspv",       "getbtcsyncstatus",    &getbtcsyncstatus,  true,       {} },
    { "btcspv",       "verifymerkleproof",   &verifymerkleproof, true,       {"txid", "merkleroot", "proof", "txindex"} },
    { "btcspv",       "parsemerkleblock",    &parsemerkleblock,  true,       {"merkleblock_hex", "txid"} },
    { "btcspv",       "reloadbtcspv",        &reloadbtcspv,      true,       {} },
    { "btcspv",       "buildblock1",         &buildblock1,       true,       {"burns", "validate_spv"} },
};

void RegisterBtcSpvRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
