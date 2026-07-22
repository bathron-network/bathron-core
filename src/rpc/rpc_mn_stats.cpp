// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/deterministicmns.h"
#include "rpc/server.h"
#include "validation.h"
#include "txdb.h"
#include "core_io.h"
#include "key_io.h"
#include "util/system.h"
#include "fs.h"
#include "sync.h"

#include <map>
#include <vector>
#include <numeric>
#include <cmath>
#include <fstream>
#include <regex>
#include <chrono>

// ============================================================================
// Cache System for listoperators (Performance Optimization)
// ============================================================================

struct ListOperatorsCache {
    UniValue cachedResult;
    int cacheHeight = -1;
    std::chrono::steady_clock::time_point cacheTime;
    static constexpr int CACHE_DURATION_SECONDS = 30;  // Cache for 30 seconds
    static constexpr int CACHE_MAX_BLOCK_AGE = 3;      // Invalidate if more than 3 blocks behind

    bool IsValid(int currentHeight) const {
        if (cacheHeight < 0) return false;

        // Invalidate if chain moved significantly
        if (currentHeight - cacheHeight > CACHE_MAX_BLOCK_AGE) return false;

        // Invalidate if cache is too old
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - cacheTime).count();
        if (elapsed > CACHE_DURATION_SECONDS) return false;

        return true;
    }

    void Update(const UniValue& result, int height) {
        cachedResult = result;
        cacheHeight = height;
        cacheTime = std::chrono::steady_clock::now();
    }
};

static ListOperatorsCache g_listOperatorsCache;
static RecursiveMutex cs_listOperatorsCache;

// ============================================================================
// Operator Alias System (Blueprint 16)
// ============================================================================

struct OperatorAlias {
    std::string alias;
    std::string operatorPubKey;
    int registeredHeight;
    int lastUpdateHeight;
};

// Global alias storage (in-memory, persisted to file)
static std::map<std::string, OperatorAlias> g_operatorAliases;        // pubkey -> alias
static std::map<std::string, std::string> g_aliasToOperator;          // alias -> pubkey
static RecursiveMutex cs_aliases;

static fs::path GetAliasFilePath()
{
    return GetDataDir() / "operator_aliases.json";
}

static void LoadOperatorAliases()
{
    LOCK(cs_aliases);
    g_operatorAliases.clear();
    g_aliasToOperator.clear();

    fs::path aliasFile = GetAliasFilePath();
    if (!fs::exists(aliasFile)) {
        return;
    }

    std::ifstream file(aliasFile.string());
    if (!file.is_open()) {
        return;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();

    // Simple JSON parsing (no external lib)
    // Format: {"aliases":[{"pubkey":"...","alias":"...","regHeight":N,"updateHeight":N},...]}
    size_t pos = content.find("\"aliases\"");
    if (pos == std::string::npos) return;

    size_t arrStart = content.find('[', pos);
    size_t arrEnd = content.rfind(']');
    if (arrStart == std::string::npos || arrEnd == std::string::npos) return;

    std::string arrContent = content.substr(arrStart + 1, arrEnd - arrStart - 1);

    // Parse each object
    size_t objStart = 0;
    while ((objStart = arrContent.find('{', objStart)) != std::string::npos) {
        size_t objEnd = arrContent.find('}', objStart);
        if (objEnd == std::string::npos) break;

        std::string obj = arrContent.substr(objStart, objEnd - objStart + 1);

        OperatorAlias entry;

        // Extract pubkey
        size_t pkPos = obj.find("\"pubkey\"");
        if (pkPos != std::string::npos) {
            size_t valStart = obj.find('\"', pkPos + 9);
            size_t valEnd = obj.find('\"', valStart + 1);
            if (valStart != std::string::npos && valEnd != std::string::npos) {
                entry.operatorPubKey = obj.substr(valStart + 1, valEnd - valStart - 1);
            }
        }

        // Extract alias
        size_t aliasPos = obj.find("\"alias\"");
        if (aliasPos != std::string::npos) {
            size_t valStart = obj.find('\"', aliasPos + 8);
            size_t valEnd = obj.find('\"', valStart + 1);
            if (valStart != std::string::npos && valEnd != std::string::npos) {
                entry.alias = obj.substr(valStart + 1, valEnd - valStart - 1);
            }
        }

        // Extract regHeight
        size_t regPos = obj.find("\"regHeight\"");
        if (regPos != std::string::npos) {
            size_t valStart = obj.find(':', regPos);
            if (valStart != std::string::npos) {
                entry.registeredHeight = std::atoi(obj.c_str() + valStart + 1);
            }
        }

        // Extract updateHeight
        size_t updPos = obj.find("\"updateHeight\"");
        if (updPos != std::string::npos) {
            size_t valStart = obj.find(':', updPos);
            if (valStart != std::string::npos) {
                entry.lastUpdateHeight = std::atoi(obj.c_str() + valStart + 1);
            }
        }

        if (!entry.operatorPubKey.empty() && !entry.alias.empty()) {
            g_operatorAliases[entry.operatorPubKey] = entry;
            g_aliasToOperator[entry.alias] = entry.operatorPubKey;
        }

        objStart = objEnd + 1;
    }
}

static void SaveOperatorAliases()
{
    LOCK(cs_aliases);

    std::ofstream file(GetAliasFilePath().string());
    if (!file.is_open()) {
        return;
    }

    file << "{\"aliases\":[";
    bool first = true;
    for (auto it = g_operatorAliases.begin(); it != g_operatorAliases.end(); ++it) {
        const OperatorAlias& entry = it->second;
        if (!first) file << ",";
        file << "{\"pubkey\":\"" << entry.operatorPubKey << "\","
             << "\"alias\":\"" << entry.alias << "\","
             << "\"regHeight\":" << entry.registeredHeight << ","
             << "\"updateHeight\":" << entry.lastUpdateHeight << "}";
        first = false;
    }
    file << "]}";
    file.close();
}

static std::string GetAliasForOperator(const std::string& operatorPubKey)
{
    LOCK(cs_aliases);
    if (g_operatorAliases.empty()) {
        LoadOperatorAliases();
    }
    auto it = g_operatorAliases.find(operatorPubKey);
    if (it != g_operatorAliases.end()) {
        return it->second.alias;
    }
    return "";
}

static std::string GetOperatorForAlias(const std::string& alias)
{
    LOCK(cs_aliases);
    if (g_aliasToOperator.empty()) {
        LoadOperatorAliases();
    }
    auto it = g_aliasToOperator.find(alias);
    if (it != g_aliasToOperator.end()) {
        return it->second;
    }
    return "";
}

static bool IsValidAlias(const std::string& alias)
{
    // 3-32 chars, alphanumeric + underscore + hyphen
    if (alias.length() < 3 || alias.length() > 32) return false;
    std::regex aliasRegex("^[a-zA-Z0-9_-]{3,32}$");
    return std::regex_match(alias, aliasRegex);
}

// ============================================================================
// MN Stats Structures
// ============================================================================

struct MNProductionStats {
    int blocksProduced = 0;
    int firstBlockProduced = 0;
    int lastBlockProduced = 0;
    std::vector<int> blockHeights;
    double productionRate = 0.0;
    double expectedRate = 0.0;
};

struct MNRotationStats {
    int expectedInterval = 0;
    double actualAvgInterval = 0.0;
    double deviation = 0.0;
    std::string health = "unknown";
    int longestGap = 0;
    int shortestGap = 0;
};

// ============================================================================
// Helper Functions
// ============================================================================

// Get payout address from MN
static std::string GetMNPayoutAddress(const CDeterministicMNCPtr& dmn)
{
    CTxDestination dest;
    if (ExtractDestination(dmn->pdmnState->scriptPayout, dest)) {
        return EncodeDestination(dest);
    }
    return "";
}

// Count blocks produced by each payout address
static std::map<std::string, MNProductionStats> GetBlockProductionByPayout(int startHeight, int endHeight)
{
    std::map<std::string, MNProductionStats> stats;

    LOCK(cs_main);
    for (int h = startHeight; h <= endHeight; h++) {
        if (h > chainActive.Height()) break;

        CBlockIndex* pindex = chainActive[h];
        if (!pindex) continue;

        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) continue;

        // Get coinbase transaction
        if (block.vtx.empty()) continue;
        const CTransaction& coinbase = *block.vtx[0];

        // Get payout address from vout[0]
        if (coinbase.vout.empty()) continue;
        CTxDestination dest;
        if (!ExtractDestination(coinbase.vout[0].scriptPubKey, dest)) continue;

        std::string payoutAddr = EncodeDestination(dest);
        stats[payoutAddr].blocksProduced++;
        stats[payoutAddr].blockHeights.push_back(h);

        if (stats[payoutAddr].firstBlockProduced == 0) {
            stats[payoutAddr].firstBlockProduced = h;
        }
        stats[payoutAddr].lastBlockProduced = h;
    }

    return stats;
}

// Calculate rotation stats from block heights
static MNRotationStats CalculateRotationStats(const std::vector<int>& blockHeights, int totalMNs)
{
    MNRotationStats stats;
    stats.expectedInterval = totalMNs;

    if (blockHeights.size() < 2) {
        stats.health = "insufficient_data";
        return stats;
    }

    std::vector<int> gaps;
    stats.longestGap = 0;
    stats.shortestGap = INT_MAX;

    for (size_t i = 1; i < blockHeights.size(); i++) {
        int gap = blockHeights[i] - blockHeights[i-1];
        gaps.push_back(gap);
        if (gap > stats.longestGap) stats.longestGap = gap;
        if (gap < stats.shortestGap) stats.shortestGap = gap;
    }

    // Calculate average
    double sum = std::accumulate(gaps.begin(), gaps.end(), 0.0);
    stats.actualAvgInterval = sum / gaps.size();

    // Calculate standard deviation
    double variance = 0.0;
    for (int gap : gaps) {
        variance += std::pow(gap - stats.actualAvgInterval, 2);
    }
    stats.deviation = std::sqrt(variance / gaps.size());

    // Determine health
    double deviationPercent = (stats.deviation / stats.expectedInterval) * 100.0;
    if (deviationPercent < 50) {
        stats.health = "healthy";
    } else if (deviationPercent < 100) {
        stats.health = "warning";
    } else {
        stats.health = "unhealthy";
    }

    return stats;
}

// Calculate fairness score
static double CalculateFairnessScore(const std::vector<int>& blocksPerMN)
{
    if (blocksPerMN.empty()) return 0.0;

    double mean = std::accumulate(blocksPerMN.begin(), blocksPerMN.end(), 0.0) / blocksPerMN.size();
    if (mean == 0) return 100.0;

    double variance = 0.0;
    for (int b : blocksPerMN) {
        variance += std::pow(b - mean, 2);
    }
    double stddev = std::sqrt(variance / blocksPerMN.size());
    double cv = (stddev / mean) * 100.0;

    return std::max(0.0, 100.0 - cv);
}

// ============================================================================
// RPC: getmnstats
// ============================================================================

UniValue getmnstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "getmnstats \"identifier\" (detailed)\n"
            "\nReturns comprehensive statistics for a masternode.\n"
            "\nArguments:\n"
            "1. \"identifier\"    (string, required) Collateral address, proTxHash, or operator pubkey\n"
            "2. detailed          (bool, optional, default=false) Include per-block details\n"
            "\nResult:\n"
            "{\n"
            "  \"proTxHash\": \"...\",\n"
            "  \"collateralAddress\": \"...\",\n"
            "  \"operatorPubKey\": \"...\",\n"
            "  \"service\": \"ip:port\",\n"
            "  \"production\": { blocksProduced, lastProducedHeight, productionRate, expectedRate },\n"
            "  \"presence\": { registeredHeight, activeBlocks, firstBlockProduced, lastBlockProduced, avgBlocksBetweenProduction },\n"
            "  \"rotation\": { expectedProductionInterval, actualAvgInterval, rotationDeviation, rotationHealth, longestGap, shortestGap }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmnstats", "\"y4mCkcQs2nP4BdqfJyktMzHP8zwoQxenZd\"")
            + HelpExampleCli("getmnstats", "\"d93e75fdd2b92f19a1fa1acf309276fa4a07e8fe0aebd3134b429c12c796237b\"")
        );
    }

    std::string identifier = request.params[0].get_str();
    bool detailed = false;
    if (request.params.size() > 1) {
        if (request.params[1].isBool()) {
            detailed = request.params[1].get_bool();
        } else if (request.params[1].isStr()) {
            std::string val = request.params[1].get_str();
            detailed = (val == "true" || val == "1");
        } else if (request.params[1].isNum()) {
            detailed = request.params[1].get_int() != 0;
        }
    }

    // Find MN by identifier
    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    CDeterministicMNCPtr dmn = nullptr;

    // Try as proTxHash
    if (identifier.size() == 64) {
        uint256 proTxHash = uint256S(identifier);
        dmn = mnList.GetMN(proTxHash);
    }

    // Try as collateral address
    if (!dmn) {
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& mn) {
            // Get collateral address
            Coin coin;
            if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(mn->collateralOutpoint, coin);)) {
                CTxDestination dest;
                if (ExtractDestination(coin.out.scriptPubKey, dest)) {
                    if (EncodeDestination(dest) == identifier) {
                        dmn = mn;
                    }
                }
            }
        });
    }

    // Try as operator pubkey
    if (!dmn) {
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& mn) {
            std::string opPubKey = HexStr(mn->pdmnState->pubKeyOperator);
            if (opPubKey == identifier || opPubKey.substr(0, identifier.size()) == identifier) {
                dmn = mn;
            }
        });
    }

    if (!dmn) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Masternode not found");
    }

    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););
    int totalMNs = mnList.GetValidMNsCount();
    int registeredHeight = dmn->pdmnState->nRegisteredHeight;

    // Get payout address and block production stats
    std::string payoutAddr = GetMNPayoutAddress(dmn);
    auto allStats = GetBlockProductionByPayout(registeredHeight, currentHeight);

    MNProductionStats prodStats;
    if (allStats.count(payoutAddr)) {
        prodStats = allStats[payoutAddr];
    }

    // Calculate rates
    int activeBlocks = currentHeight - registeredHeight;
    prodStats.productionRate = activeBlocks > 0 ? (prodStats.blocksProduced * 100.0 / activeBlocks) : 0;
    prodStats.expectedRate = totalMNs > 0 ? (100.0 / totalMNs) : 0;

    // Calculate rotation stats
    MNRotationStats rotStats = CalculateRotationStats(prodStats.blockHeights, totalMNs);

    // Build result
    UniValue result(UniValue::VOBJ);

    // Basic info
    result.pushKV("proTxHash", dmn->proTxHash.GetHex());

    // Get collateral address
    Coin coin;
    if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(dmn->collateralOutpoint, coin);)) {
        CTxDestination dest;
        if (ExtractDestination(coin.out.scriptPubKey, dest)) {
            result.pushKV("collateralAddress", EncodeDestination(dest));
        }
    }

    result.pushKV("operatorPubKey", HexStr(dmn->pdmnState->pubKeyOperator));
    result.pushKV("service", dmn->pdmnState->addr.ToString());
    result.pushKV("registeredHeight", registeredHeight);

    // Production stats
    UniValue production(UniValue::VOBJ);
    production.pushKV("blocksProduced", prodStats.blocksProduced);
    production.pushKV("lastProducedHeight", prodStats.lastBlockProduced);
    production.pushKV("productionRate", prodStats.productionRate);
    production.pushKV("expectedRate", prodStats.expectedRate);
    result.pushKV("production", production);

    // Presence stats
    UniValue presence(UniValue::VOBJ);
    presence.pushKV("registeredHeight", registeredHeight);
    presence.pushKV("activeBlocks", activeBlocks);
    presence.pushKV("firstBlockProduced", prodStats.firstBlockProduced);
    presence.pushKV("lastBlockProduced", prodStats.lastBlockProduced);
    presence.pushKV("blocksSinceLastProduction", currentHeight - prodStats.lastBlockProduced);

    double avgInterval = 0;
    if (prodStats.blockHeights.size() > 1) {
        avgInterval = (double)(prodStats.lastBlockProduced - prodStats.firstBlockProduced) / (prodStats.blockHeights.size() - 1);
    }
    presence.pushKV("avgBlocksBetweenProduction", avgInterval);
    result.pushKV("presence", presence);

    // Rotation stats
    UniValue rotation(UniValue::VOBJ);
    rotation.pushKV("expectedProductionInterval", rotStats.expectedInterval);
    rotation.pushKV("actualAvgInterval", rotStats.actualAvgInterval);
    rotation.pushKV("rotationDeviation", rotStats.deviation);
    rotation.pushKV("rotationHealth", rotStats.health);
    rotation.pushKV("longestGap", rotStats.longestGap);
    rotation.pushKV("shortestGap", rotStats.shortestGap);
    result.pushKV("rotation", rotation);

    // Detailed block list (optional)
    if (detailed) {
        UniValue blocks(UniValue::VARR);
        for (int h : prodStats.blockHeights) {
            blocks.push_back(h);
        }
        result.pushKV("producedBlocks", blocks);
    }

    return result;
}

// ============================================================================
// RPC: listmnstats
// ============================================================================

UniValue listmnstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "listmnstats (sort_by)\n"
            "\nReturns statistics for all masternodes.\n"
            "\nArguments:\n"
            "1. \"sort_by\"    (string, optional, default=\"blocks\") Sort by: blocks, rate, collateral\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"rank\": n,\n"
            "    \"proTxHash\": \"...\",\n"
            "    \"collateralAddress\": \"...\",\n"
            "    \"operatorPubKey\": \"...\",\n"
            "    \"blocksProduced\": n,\n"
            "    \"productionRate\": n.n,\n"
            "    \"expectedRate\": n.n\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listmnstats", "")
            + HelpExampleCli("listmnstats", "\"blocks\"")
        );
    }

    std::string sortBy = request.params.size() > 0 ? request.params[0].get_str() : "blocks";

    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););
    int totalMNs = mnList.GetValidMNsCount();

    // Get all block production stats
    auto allStats = GetBlockProductionByPayout(3, currentHeight);  // Start from block 3

    // Build MN stats list
    struct MNStatEntry {
        CDeterministicMNCPtr dmn;
        std::string collateralAddr;
        int blocksProduced;
        double rate;
    };
    std::vector<MNStatEntry> entries;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        MNStatEntry entry;
        entry.dmn = dmn;
        entry.blocksProduced = 0;

        // Get collateral address
        Coin coin;
        if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(dmn->collateralOutpoint, coin);)) {
            CTxDestination dest;
            if (ExtractDestination(coin.out.scriptPubKey, dest)) {
                entry.collateralAddr = EncodeDestination(dest);
            }
        }

        // Get block count from payout address
        std::string payoutAddr = GetMNPayoutAddress(dmn);
        if (allStats.count(payoutAddr)) {
            entry.blocksProduced = allStats[payoutAddr].blocksProduced;
        }

        int activeBlocks = currentHeight - dmn->pdmnState->nRegisteredHeight;
        entry.rate = activeBlocks > 0 ? (entry.blocksProduced * 100.0 / activeBlocks) : 0;

        entries.push_back(entry);
    });

    // Sort
    if (sortBy == "blocks") {
        std::sort(entries.begin(), entries.end(), [](const MNStatEntry& a, const MNStatEntry& b) {
            return a.blocksProduced > b.blocksProduced;
        });
    } else if (sortBy == "rate") {
        std::sort(entries.begin(), entries.end(), [](const MNStatEntry& a, const MNStatEntry& b) {
            return a.rate > b.rate;
        });
    }

    double expectedRate = totalMNs > 0 ? (100.0 / totalMNs) : 0;

    // Build result
    UniValue result(UniValue::VARR);
    int rank = 1;
    for (const auto& entry : entries) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("rank", rank++);
        obj.pushKV("proTxHash", entry.dmn->proTxHash.GetHex());
        obj.pushKV("collateralAddress", entry.collateralAddr);
        obj.pushKV("operatorPubKey", HexStr(entry.dmn->pdmnState->pubKeyOperator).substr(0, 16) + "...");
        obj.pushKV("service", entry.dmn->pdmnState->addr.ToString());
        obj.pushKV("blocksProduced", entry.blocksProduced);
        obj.pushKV("productionRate", entry.rate);
        obj.pushKV("expectedRate", expectedRate);
        result.push_back(obj);
    }

    return result;
}

// ============================================================================
// RPC: listoperators
// ============================================================================

UniValue listoperators(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "listoperators (sort_by)\n"
            "\nReturns aggregated statistics per operator.\n"
            "\nArguments:\n"
            "1. \"sort_by\"    (string, optional, default=\"blocks\") Sort by: blocks, mncount, share\n"
            "\nResult:\n"
            "{\n"
            "  \"totalBlocks\": n,\n"
            "  \"totalMNs\": n,\n"
            "  \"totalOperators\": n,\n"
            "  \"operators\": [\n"
            "    {\n"
            "      \"rank\": n,\n"
            "      \"operatorPubKey\": \"...\",\n"
            "      \"service\": \"ip:port\",\n"
            "      \"mnCount\": n,\n"
            "      \"blocksProduced\": n,\n"
            "      \"sharePercent\": n.n,\n"
            "      \"expectedShare\": n.n,\n"
            "      \"deviation\": \"+/-n.n%\"\n"
            "    }\n"
            "  ],\n"
            "  \"fairnessScore\": n.n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listoperators", "")
        );
    }

    std::string sortBy = request.params.size() > 0 ? request.params[0].get_str() : "blocks";

    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););

    // Check cache first (only for default sort)
    if (sortBy == "blocks") {
        LOCK(cs_listOperatorsCache);
        if (g_listOperatorsCache.IsValid(currentHeight)) {
            UniValue cachedResult = g_listOperatorsCache.cachedResult;
            cachedResult.pushKV("cached", true);
            cachedResult.pushKV("cacheHeight", g_listOperatorsCache.cacheHeight);
            return cachedResult;
        }
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    int totalMNs = mnList.GetValidMNsCount();

    // Get all block production stats
    auto allStats = GetBlockProductionByPayout(3, currentHeight);

    // Aggregate by operator
    struct OperatorStats {
        std::string operatorPubKey;
        std::string service;
        int mnCount = 0;
        int blocksProduced = 0;
        std::vector<std::string> collaterals;
    };
    std::map<std::string, OperatorStats> operatorMap;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        std::string opKey = HexStr(dmn->pdmnState->pubKeyOperator);

        if (operatorMap.find(opKey) == operatorMap.end()) {
            operatorMap[opKey].operatorPubKey = opKey;
            operatorMap[opKey].service = dmn->pdmnState->addr.ToString();
        }

        operatorMap[opKey].mnCount++;

        // Get collateral
        Coin coin;
        if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(dmn->collateralOutpoint, coin);)) {
            CTxDestination dest;
            if (ExtractDestination(coin.out.scriptPubKey, dest)) {
                operatorMap[opKey].collaterals.push_back(EncodeDestination(dest));
            }
        }

        // Get block count
        std::string payoutAddr = GetMNPayoutAddress(dmn);
        if (allStats.count(payoutAddr)) {
            operatorMap[opKey].blocksProduced += allStats[payoutAddr].blocksProduced;
        }
    });

    // Calculate total blocks
    int totalBlocks = 0;
    std::vector<int> blocksPerOperator;
    for (auto it = operatorMap.begin(); it != operatorMap.end(); ++it) {
        totalBlocks += it->second.blocksProduced;
        blocksPerOperator.push_back(it->second.blocksProduced);
    }

    // Convert to vector and sort
    std::vector<std::pair<std::string, OperatorStats>> operators(operatorMap.begin(), operatorMap.end());

    if (sortBy == "blocks") {
        std::sort(operators.begin(), operators.end(), [](const std::pair<std::string, OperatorStats>& a, const std::pair<std::string, OperatorStats>& b) {
            return a.second.blocksProduced > b.second.blocksProduced;
        });
    } else if (sortBy == "mncount") {
        std::sort(operators.begin(), operators.end(), [](const std::pair<std::string, OperatorStats>& a, const std::pair<std::string, OperatorStats>& b) {
            return a.second.mnCount > b.second.mnCount;
        });
    }

    // Build result
    UniValue result(UniValue::VOBJ);
    result.pushKV("totalBlocks", totalBlocks);
    result.pushKV("totalMNs", totalMNs);
    result.pushKV("totalOperators", (int)operators.size());

    UniValue opArray(UniValue::VARR);
    int rank = 1;
    for (size_t i = 0; i < operators.size(); ++i) {
        const OperatorStats& stats = operators[i].second;

        UniValue obj(UniValue::VOBJ);
        obj.pushKV("rank", rank++);

        // Add alias if registered
        std::string opAlias = GetAliasForOperator(stats.operatorPubKey);
        if (!opAlias.empty()) {
            obj.pushKV("alias", opAlias);
        }

        obj.pushKV("operatorPubKey", stats.operatorPubKey);
        obj.pushKV("operatorShort", stats.operatorPubKey.substr(0, 10) + "...");
        obj.pushKV("service", stats.service);
        obj.pushKV("mnCount", stats.mnCount);
        obj.pushKV("blocksProduced", stats.blocksProduced);

        double sharePercent = totalBlocks > 0 ? (stats.blocksProduced * 100.0 / totalBlocks) : 0;
        double expectedShare = totalMNs > 0 ? (stats.mnCount * 100.0 / totalMNs) : 0;
        double deviation = sharePercent - expectedShare;

        obj.pushKV("sharePercent", sharePercent);
        obj.pushKV("expectedShare", expectedShare);
        obj.pushKV("deviation", strprintf("%+.1f%%", deviation));

        // List of masternodes under this operator
        UniValue mnArray(UniValue::VARR);
        for (const auto& col : stats.collaterals) {
            mnArray.push_back(col.substr(0, 12) + "...");
        }
        obj.pushKV("masternodes", mnArray);

        opArray.push_back(obj);
    }
    result.pushKV("operators", opArray);

    // Fairness score
    double fairness = CalculateFairnessScore(blocksPerOperator);
    result.pushKV("fairnessScore", fairness);

    // Warnings
    UniValue warnings(UniValue::VARR);
    for (size_t i = 0; i < operators.size(); ++i) {
        const OperatorStats& stats = operators[i].second;

        double sharePercent = totalBlocks > 0 ? (stats.blocksProduced * 100.0 / totalBlocks) : 0;
        double expectedShare = totalMNs > 0 ? (stats.mnCount * 100.0 / totalMNs) : 0;
        double deviation = sharePercent - expectedShare;

        if (std::abs(deviation) > 5.0) {
            std::string opName = GetAliasForOperator(stats.operatorPubKey);
            if (opName.empty()) {
                opName = stats.operatorPubKey.substr(0, 10) + "...";
            }
            std::string warning = strprintf("%s is %s: %.1f%% vs expected %.1f%%",
                opName,
                deviation < 0 ? "under-producing" : "over-producing",
                sharePercent, expectedShare);
            warnings.push_back(warning);
        }
    }
    result.pushKV("warnings", warnings);

    // Update cache (only for default sort)
    if (sortBy == "blocks") {
        LOCK(cs_listOperatorsCache);
        g_listOperatorsCache.Update(result, currentHeight);
    }

    return result;
}

// ============================================================================
// RPC: getoperatorstats
// ============================================================================

UniValue getoperatorstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "getoperatorstats \"operator_pubkey\" (detailed)\n"
            "\nReturns comprehensive statistics for an operator.\n"
            "\nArguments:\n"
            "1. \"operator_pubkey\"  (string, required) Operator public key (full or prefix)\n"
            "2. detailed             (bool, optional, default=false) Include per-MN details\n"
            "\nResult:\n"
            "{\n"
            "  \"operatorPubKey\": \"...\",\n"
            "  \"service\": \"ip:port\",\n"
            "  \"mnCount\": n,\n"
            "  \"production\": { blocksProduced, sharePercent, expectedShare, deviation },\n"
            "  \"rotation\": { avgBlocksBetweenProduction, rotationHealth },\n"
            "  \"masternodes\": [...]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getoperatorstats", "\"03368dea7adae8e200709219ba3c4225f4a78b21078a0d747bc16aea0f88180389\"")
            + HelpExampleCli("getoperatorstats", "\"03368dea7a\" true")
        );
    }

    std::string operatorKey = request.params[0].get_str();
    bool detailed = false;
    if (request.params.size() > 1) {
        if (request.params[1].isBool()) {
            detailed = request.params[1].get_bool();
        } else if (request.params[1].isStr()) {
            std::string val = request.params[1].get_str();
            detailed = (val == "true" || val == "1");
        } else if (request.params[1].isNum()) {
            detailed = request.params[1].get_int() != 0;
        }
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););
    int totalMNs = mnList.GetValidMNsCount();

    // Get all block production stats
    auto allStats = GetBlockProductionByPayout(3, currentHeight);

    // Find all MNs for this operator
    std::string fullOperatorKey;
    std::string service;
    int mnCount = 0;
    int totalBlocksProduced = 0;
    std::vector<int> allBlockHeights;

    struct MNInfo {
        std::string proTxHash;
        std::string collateralAddr;
        int blocksProduced;
        double productionRate;
    };
    std::vector<MNInfo> masternodes;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        std::string opKey = HexStr(dmn->pdmnState->pubKeyOperator);

        // Match by full key or prefix
        if (opKey == operatorKey || opKey.substr(0, operatorKey.size()) == operatorKey) {
            if (fullOperatorKey.empty()) {
                fullOperatorKey = opKey;
                service = dmn->pdmnState->addr.ToString();
            }

            mnCount++;

            MNInfo info;
            info.proTxHash = dmn->proTxHash.GetHex();
            info.blocksProduced = 0;

            // Get collateral address
            Coin coin;
            if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(dmn->collateralOutpoint, coin);)) {
                CTxDestination dest;
                if (ExtractDestination(coin.out.scriptPubKey, dest)) {
                    info.collateralAddr = EncodeDestination(dest);
                }
            }

            // Get block count
            std::string payoutAddr = GetMNPayoutAddress(dmn);
            if (allStats.count(payoutAddr)) {
                info.blocksProduced = allStats[payoutAddr].blocksProduced;
                totalBlocksProduced += info.blocksProduced;

                // Collect block heights for rotation analysis
                for (int h : allStats[payoutAddr].blockHeights) {
                    allBlockHeights.push_back(h);
                }
            }

            int activeBlocks = currentHeight - dmn->pdmnState->nRegisteredHeight;
            info.productionRate = activeBlocks > 0 ? (info.blocksProduced * 100.0 / activeBlocks) : 0;

            masternodes.push_back(info);
        }
    });

    if (fullOperatorKey.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Operator not found");
    }

    // Sort block heights for rotation analysis
    std::sort(allBlockHeights.begin(), allBlockHeights.end());

    // Calculate total blocks across network
    int totalNetworkBlocks = 0;
    for (auto it = allStats.begin(); it != allStats.end(); ++it) {
        totalNetworkBlocks += it->second.blocksProduced;
    }

    // Build result
    UniValue result(UniValue::VOBJ);

    // Add alias if registered
    std::string opAlias = GetAliasForOperator(fullOperatorKey);
    if (!opAlias.empty()) {
        result.pushKV("alias", opAlias);
    }

    result.pushKV("operatorPubKey", fullOperatorKey);
    result.pushKV("operatorShort", fullOperatorKey.substr(0, 10) + "...");
    result.pushKV("service", service);
    result.pushKV("mnCount", mnCount);

    // Production stats
    UniValue production(UniValue::VOBJ);
    production.pushKV("blocksProduced", totalBlocksProduced);

    double sharePercent = totalNetworkBlocks > 0 ? (totalBlocksProduced * 100.0 / totalNetworkBlocks) : 0;
    double expectedShare = totalMNs > 0 ? (mnCount * 100.0 / totalMNs) : 0;
    double deviation = sharePercent - expectedShare;

    production.pushKV("sharePercent", sharePercent);
    production.pushKV("expectedShare", expectedShare);
    production.pushKV("deviation", strprintf("%+.1f%%", deviation));
    production.pushKV("deviationStatus", std::abs(deviation) < 5.0 ? "healthy" : (std::abs(deviation) < 10.0 ? "warning" : "unhealthy"));
    result.pushKV("production", production);

    // Rotation stats (for all MNs combined)
    UniValue rotation(UniValue::VOBJ);
    if (allBlockHeights.size() > 1) {
        double totalGap = 0;
        int longestGap = 0;
        int shortestGap = INT_MAX;

        for (size_t i = 1; i < allBlockHeights.size(); i++) {
            int gap = allBlockHeights[i] - allBlockHeights[i-1];
            totalGap += gap;
            if (gap > longestGap) longestGap = gap;
            if (gap < shortestGap) shortestGap = gap;
        }

        double avgGap = totalGap / (allBlockHeights.size() - 1);
        int expectedGap = totalMNs > 0 ? totalMNs / mnCount : 1;

        rotation.pushKV("avgBlocksBetweenProduction", avgGap);
        rotation.pushKV("expectedInterval", expectedGap);
        rotation.pushKV("longestGap", longestGap);
        rotation.pushKV("shortestGap", shortestGap);

        double gapDeviation = expectedGap > 0 ? std::abs(avgGap - expectedGap) / expectedGap * 100.0 : 0;
        rotation.pushKV("rotationHealth", gapDeviation < 50 ? "healthy" : (gapDeviation < 100 ? "warning" : "unhealthy"));
    } else {
        rotation.pushKV("avgBlocksBetweenProduction", 0);
        rotation.pushKV("rotationHealth", "insufficient_data");
    }
    result.pushKV("rotation", rotation);

    // Masternodes list
    if (detailed) {
        UniValue mnArray(UniValue::VARR);
        for (const auto& mn : masternodes) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("proTxHash", mn.proTxHash);
            obj.pushKV("collateralAddress", mn.collateralAddr);
            obj.pushKV("blocksProduced", mn.blocksProduced);
            obj.pushKV("productionRate", mn.productionRate);
            mnArray.push_back(obj);
        }
        result.pushKV("masternodes", mnArray);
    } else {
        UniValue mnArray(UniValue::VARR);
        for (const auto& mn : masternodes) {
            mnArray.push_back(mn.collateralAddr.substr(0, 12) + "...");
        }
        result.pushKV("masternodes", mnArray);
    }

    // Summary status
    std::string overallStatus = "healthy";
    if (std::abs(deviation) > 10.0) {
        overallStatus = "unhealthy";
    } else if (std::abs(deviation) > 5.0) {
        overallStatus = "warning";
    }
    result.pushKV("status", overallStatus);

    return result;
}

// ============================================================================
// RPC: checkrotation
// ============================================================================

UniValue checkrotation(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "checkrotation (since_height)\n"
            "\nVerifies fair rotation across all masternodes.\n"
            "\nArguments:\n"
            "1. since_height    (numeric, optional) Start height for analysis (default: registration height)\n"
            "\nResult:\n"
            "{\n"
            "  \"heightRange\": { \"from\": n, \"to\": n },\n"
            "  \"totalBlocks\": n,\n"
            "  \"totalMNs\": n,\n"
            "  \"expectedBlocksPerMN\": n.n,\n"
            "  \"distribution\": [...],\n"
            "  \"fairnessScore\": n.n,\n"
            "  \"maxDeviation\": n.n,\n"
            "  \"status\": \"healthy/warning/unhealthy\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("checkrotation", "")
            + HelpExampleCli("checkrotation", "100")
        );
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););
    int totalMNs = mnList.GetValidMNsCount();

    // Find earliest registration height if not specified
    int startHeight = 3;
    if (request.params.size() > 0) {
        startHeight = request.params[0].get_int();
    } else {
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
            if (dmn->pdmnState->nRegisteredHeight < startHeight || startHeight == 3) {
                startHeight = dmn->pdmnState->nRegisteredHeight;
            }
        });
        if (startHeight < 3) startHeight = 3;
    }

    // Get all block production stats
    auto allStats = GetBlockProductionByPayout(startHeight, currentHeight);

    // Map payout address to MN info
    struct MNDistEntry {
        std::string proTxHash;
        std::string collateral;
        std::string operatorKey;
        int blocks;
    };
    std::vector<MNDistEntry> distribution;
    std::vector<int> blocksPerMN;
    int totalBlocks = 0;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        MNDistEntry entry;
        entry.proTxHash = dmn->proTxHash.GetHex().substr(0, 12) + "...";
        entry.operatorKey = HexStr(dmn->pdmnState->pubKeyOperator).substr(0, 10) + "...";
        entry.blocks = 0;

        // Get collateral
        Coin coin;
        if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(dmn->collateralOutpoint, coin);)) {
            CTxDestination dest;
            if (ExtractDestination(coin.out.scriptPubKey, dest)) {
                entry.collateral = EncodeDestination(dest).substr(0, 12) + "...";
            }
        }

        // Get block count
        std::string payoutAddr = GetMNPayoutAddress(dmn);
        if (allStats.count(payoutAddr)) {
            entry.blocks = allStats[payoutAddr].blocksProduced;
        }

        totalBlocks += entry.blocks;
        blocksPerMN.push_back(entry.blocks);
        distribution.push_back(entry);
    });

    // Sort by blocks descending
    std::sort(distribution.begin(), distribution.end(), [](const MNDistEntry& a, const MNDistEntry& b) {
        return a.blocks > b.blocks;
    });

    double expectedPerMN = totalMNs > 0 ? (double)totalBlocks / totalMNs : 0;

    // Build result
    UniValue result(UniValue::VOBJ);

    UniValue heightRange(UniValue::VOBJ);
    heightRange.pushKV("from", startHeight);
    heightRange.pushKV("to", currentHeight);
    result.pushKV("heightRange", heightRange);

    result.pushKV("totalBlocks", totalBlocks);
    result.pushKV("totalMNs", totalMNs);
    result.pushKV("expectedBlocksPerMN", expectedPerMN);

    // Distribution
    UniValue distArray(UniValue::VARR);
    double maxDeviation = 0;
    for (const auto& entry : distribution) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("proTxHash", entry.proTxHash);
        obj.pushKV("collateral", entry.collateral);
        obj.pushKV("operatorKey", entry.operatorKey);
        obj.pushKV("blocks", entry.blocks);

        double deviation = expectedPerMN > 0 ? ((entry.blocks - expectedPerMN) / expectedPerMN) * 100.0 : 0;
        obj.pushKV("deviation", strprintf("%+.1f%%", deviation));

        if (std::abs(deviation) > maxDeviation) {
            maxDeviation = std::abs(deviation);
        }

        distArray.push_back(obj);
    }
    result.pushKV("distribution", distArray);

    // Fairness score
    double fairness = CalculateFairnessScore(blocksPerMN);
    result.pushKV("fairnessScore", fairness);
    result.pushKV("maxDeviation", maxDeviation);

    // Status
    std::string status = "healthy";
    if (fairness < 70 || maxDeviation > 50) {
        status = "unhealthy";
    } else if (fairness < 85 || maxDeviation > 25) {
        status = "warning";
    }
    result.pushKV("status", status);

    return result;
}

// ============================================================================
// RPC: getoperatorinfo (Blueprint 16)
// ============================================================================

// Badge definitions
enum class Badge {
    GENESIS_OPERATOR,    // Registered in block <= 100
    MULTI_MN,            // Manages 2+ MNs
    MULTI_MN_5,          // Manages 5+ MNs
    MULTI_MN_10,         // Manages 10+ MNs
    PERFECT_UPTIME,      // 100% production rate
    HIGH_PRODUCER,       // Above expected production rate
    VETERAN,             // Active 1000+ blocks
    WHALE_OPERATOR       // Total collateral >= 50,000 BATHRON
};

static std::string BadgeToString(Badge badge) {
    switch (badge) {
        case Badge::GENESIS_OPERATOR: return "genesis_operator";
        case Badge::MULTI_MN: return "multi_mn";
        case Badge::MULTI_MN_5: return "multi_mn_x5";
        case Badge::MULTI_MN_10: return "multi_mn_x10";
        case Badge::PERFECT_UPTIME: return "perfect_uptime";
        case Badge::HIGH_PRODUCER: return "high_producer";
        case Badge::VETERAN: return "veteran";
        case Badge::WHALE_OPERATOR: return "whale_operator";
        default: return "unknown";
    }
}

static std::string BadgeToIcon(Badge badge) {
    switch (badge) {
        case Badge::GENESIS_OPERATOR: return "🏆";
        case Badge::MULTI_MN: return "⚡";
        case Badge::MULTI_MN_5: return "⚡⚡";
        case Badge::MULTI_MN_10: return "⚡⚡⚡";
        case Badge::PERFECT_UPTIME: return "✓";
        case Badge::HIGH_PRODUCER: return "📈";
        case Badge::VETERAN: return "🎖️";
        case Badge::WHALE_OPERATOR: return "🐋";
        default: return "?";
    }
}

UniValue getoperatorinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1) {
        throw std::runtime_error(
            "getoperatorinfo \"identifier\"\n"
            "\nReturns comprehensive info for an operator including badges and reputation.\n"
            "\nArguments:\n"
            "1. \"identifier\"    (string, required) Operator public key (full or prefix)\n"
            "\nResult:\n"
            "{\n"
            "  \"operatorPubKey\": \"...\",\n"
            "  \"service\": \"ip:port\",\n"
            "  \"mnCount\": n,\n"
            "  \"blocksProduced\": n,\n"
            "  \"badges\": [...],\n"
            "  \"reputationScore\": n,\n"
            "  \"masternodes\": [...]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getoperatorinfo", "\"03368dea7adae8e200709219ba3c4225f4a78b21078a0d747bc16aea0f88180389\"")
            + HelpExampleCli("getoperatorinfo", "\"03368dea7a\"")
        );
    }

    std::string operatorKey = request.params[0].get_str();

    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););
    int totalMNs = mnList.GetValidMNsCount();

    // Get all block production stats
    auto allStats = GetBlockProductionByPayout(3, currentHeight);

    // Find all MNs for this operator
    std::string fullOperatorKey;
    std::string service;
    int mnCount = 0;
    int totalBlocksProduced = 0;
    int earliestRegistration = INT_MAX;
    CAmount totalCollateral = 0;

    struct MNInfo {
        std::string proTxHash;
        std::string collateralAddr;
        int blocksProduced;
        int registeredHeight;
        CAmount collateralAmount;
    };
    std::vector<MNInfo> masternodes;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        std::string opKey = HexStr(dmn->pdmnState->pubKeyOperator);

        // Match by full key or prefix
        if (opKey == operatorKey || opKey.substr(0, operatorKey.size()) == operatorKey) {
            if (fullOperatorKey.empty()) {
                fullOperatorKey = opKey;
                service = dmn->pdmnState->addr.ToString();
            }

            mnCount++;

            MNInfo info;
            info.proTxHash = dmn->proTxHash.GetHex();
            info.blocksProduced = 0;
            info.registeredHeight = dmn->pdmnState->nRegisteredHeight;
            info.collateralAmount = 0;

            if (info.registeredHeight < earliestRegistration) {
                earliestRegistration = info.registeredHeight;
            }

            // Get collateral address and amount
            Coin coin;
            if (WITH_LOCK(cs_main, return pcoinsTip->GetUTXOCoin(dmn->collateralOutpoint, coin);)) {
                CTxDestination dest;
                if (ExtractDestination(coin.out.scriptPubKey, dest)) {
                    info.collateralAddr = EncodeDestination(dest);
                }
                info.collateralAmount = coin.out.nValue;
                totalCollateral += coin.out.nValue;
            }

            // Get block count
            std::string payoutAddr = GetMNPayoutAddress(dmn);
            if (allStats.count(payoutAddr)) {
                info.blocksProduced = allStats[payoutAddr].blocksProduced;
                totalBlocksProduced += info.blocksProduced;
            }

            masternodes.push_back(info);
        }
    });

    if (fullOperatorKey.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Operator not found");
    }

    // Calculate total network blocks
    int totalNetworkBlocks = 0;
    for (auto it = allStats.begin(); it != allStats.end(); ++it) {
        totalNetworkBlocks += it->second.blocksProduced;
    }

    // Compute badges
    std::vector<Badge> badges;

    // Genesis Operator: registered <= block 100
    if (earliestRegistration <= 100) {
        badges.push_back(Badge::GENESIS_OPERATOR);
    }

    // Multi-MN badges
    if (mnCount >= 10) {
        badges.push_back(Badge::MULTI_MN_10);
    } else if (mnCount >= 5) {
        badges.push_back(Badge::MULTI_MN_5);
    } else if (mnCount >= 2) {
        badges.push_back(Badge::MULTI_MN);
    }

    // Production rate badges
    double expectedShare = totalMNs > 0 ? (mnCount * 100.0 / totalMNs) : 0;
    double actualShare = totalNetworkBlocks > 0 ? (totalBlocksProduced * 100.0 / totalNetworkBlocks) : 0;
    if (totalBlocksProduced > 0 && actualShare >= expectedShare * 0.99) {
        badges.push_back(Badge::PERFECT_UPTIME);
    }
    if (actualShare > expectedShare * 1.05) {
        badges.push_back(Badge::HIGH_PRODUCER);
    }

    // Veteran: active 1000+ blocks
    int activeBlocks = currentHeight - earliestRegistration;
    if (activeBlocks >= 1000) {
        badges.push_back(Badge::VETERAN);
    }

    // Whale: >= 50,000 BATHRON collateral
    if (totalCollateral >= 50000 * COIN) {
        badges.push_back(Badge::WHALE_OPERATOR);
    }

    // Calculate reputation score
    double reputationScore = 0;

    // Uptime component (40%)
    double uptimeScore = std::min(100.0, (actualShare / std::max(expectedShare, 0.01)) * 100.0);
    reputationScore += uptimeScore * 0.40;

    // MN count bonus (20%)
    double mnBonus = std::min(100.0, mnCount * 20.0);  // Max at 5 MNs
    reputationScore += mnBonus * 0.20;

    // Time active bonus (20%)
    double timeBonus = std::min(100.0, activeBlocks / 10.0);  // Max at 1000 blocks
    reputationScore += timeBonus * 0.20;

    // Badge bonus (20%)
    double badgeBonus = std::min(100.0, badges.size() * 25.0);  // Max at 4 badges
    reputationScore += badgeBonus * 0.20;

    // Build result
    UniValue result(UniValue::VOBJ);

    // Add alias if registered
    std::string alias = GetAliasForOperator(fullOperatorKey);
    if (!alias.empty()) {
        result.pushKV("alias", alias);
    }

    result.pushKV("operatorPubKey", fullOperatorKey);
    result.pushKV("operatorShort", fullOperatorKey.substr(0, 10) + "...");
    result.pushKV("service", service);
    result.pushKV("mnCount", mnCount);
    result.pushKV("registeredHeight", earliestRegistration);
    result.pushKV("activeBlocks", activeBlocks);
    result.pushKV("blocksProduced", totalBlocksProduced);

    // Shares
    result.pushKV("sharePercent", actualShare);
    result.pushKV("expectedShare", expectedShare);

    // Collateral
    result.pushKV("totalCollateral", ValueFromAmount(totalCollateral));
    result.pushKV("totalCollateralBATHRON", totalCollateral / COIN);

    // Badges
    UniValue badgeArray(UniValue::VARR);
    UniValue badgeIcons(UniValue::VARR);
    for (const auto& badge : badges) {
        badgeArray.push_back(BadgeToString(badge));
        badgeIcons.push_back(BadgeToIcon(badge));
    }
    result.pushKV("badges", badgeArray);
    result.pushKV("badgeIcons", badgeIcons);

    // Reputation
    result.pushKV("reputationScore", (int)std::round(reputationScore));

    // Masternodes list
    UniValue mnArray(UniValue::VARR);
    for (const auto& mn : masternodes) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("proTxHash", mn.proTxHash);
        obj.pushKV("collateralAddress", mn.collateralAddr);
        obj.pushKV("blocksProduced", mn.blocksProduced);
        obj.pushKV("registeredHeight", mn.registeredHeight);
        obj.pushKV("collateral", ValueFromAmount(mn.collateralAmount));
        mnArray.push_back(obj);
    }
    result.pushKV("masternodes", mnArray);

    return result;
}

// ============================================================================
// RPC: registeroperatoralias (Blueprint 16)
// ============================================================================

UniValue registeroperatoralias(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 2) {
        throw std::runtime_error(
            "registeroperatoralias \"operator_pubkey\" \"alias\"\n"
            "\nRegisters an alias for an operator. The alias must be unique.\n"
            "\nArguments:\n"
            "1. \"operator_pubkey\"  (string, required) Operator public key (full or prefix)\n"
            "2. \"alias\"            (string, required) Human-readable alias (3-32 chars, alphanumeric + _-)\n"
            "\nResult:\n"
            "{\n"
            "  \"success\": true,\n"
            "  \"alias\": \"...\",\n"
            "  \"operatorPubKey\": \"...\",\n"
            "  \"registeredHeight\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("registeroperatoralias", "\"03368dea7a\" \"Delta-Mining\"")
        );
    }

    std::string operatorKeyInput = request.params[0].get_str();
    std::string alias = request.params[1].get_str();

    // Validate alias format
    if (!IsValidAlias(alias)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Invalid alias format. Must be 3-32 characters, alphanumeric with _ and - only.");
    }

    // Find the operator in MN list
    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    std::string fullOperatorKey;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        std::string opKey = HexStr(dmn->pdmnState->pubKeyOperator);
        if (opKey == operatorKeyInput || opKey.substr(0, operatorKeyInput.size()) == operatorKeyInput) {
            fullOperatorKey = opKey;
        }
    });

    if (fullOperatorKey.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Operator not found in masternode list");
    }

    // Load existing aliases
    {
        LOCK(cs_aliases);
        if (g_operatorAliases.empty()) {
            LoadOperatorAliases();
        }
    }

    // Check if alias is already taken
    std::string existingOperator = GetOperatorForAlias(alias);
    if (!existingOperator.empty() && existingOperator != fullOperatorKey) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Alias '%s' is already taken by operator %s", alias, existingOperator.substr(0, 10) + "..."));
    }

    // Check if operator already has an alias
    std::string existingAlias = GetAliasForOperator(fullOperatorKey);
    if (!existingAlias.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Operator already has alias '%s'. Use updateoperatoralias to change it.", existingAlias));
    }

    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););

    // Register the alias
    {
        LOCK(cs_aliases);
        OperatorAlias entry;
        entry.alias = alias;
        entry.operatorPubKey = fullOperatorKey;
        entry.registeredHeight = currentHeight;
        entry.lastUpdateHeight = currentHeight;

        g_operatorAliases[fullOperatorKey] = entry;
        g_aliasToOperator[alias] = fullOperatorKey;

        SaveOperatorAliases();
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    result.pushKV("alias", alias);
    result.pushKV("operatorPubKey", fullOperatorKey);
    result.pushKV("operatorShort", fullOperatorKey.substr(0, 10) + "...");
    result.pushKV("registeredHeight", currentHeight);

    return result;
}

// ============================================================================
// RPC: updateoperatoralias (Blueprint 16)
// ============================================================================

UniValue updateoperatoralias(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 2) {
        throw std::runtime_error(
            "updateoperatoralias \"operator_pubkey\" \"new_alias\"\n"
            "\nUpdates the alias for an operator.\n"
            "\nArguments:\n"
            "1. \"operator_pubkey\"  (string, required) Operator public key (full or prefix)\n"
            "2. \"new_alias\"        (string, required) New alias (3-32 chars)\n"
            "\nResult:\n"
            "{\n"
            "  \"success\": true,\n"
            "  \"oldAlias\": \"...\",\n"
            "  \"newAlias\": \"...\",\n"
            "  \"operatorPubKey\": \"...\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("updateoperatoralias", "\"03368dea7a\" \"NewDeltaName\"")
        );
    }

    std::string operatorKeyInput = request.params[0].get_str();
    std::string newAlias = request.params[1].get_str();

    // Validate alias format
    if (!IsValidAlias(newAlias)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Invalid alias format. Must be 3-32 characters, alphanumeric with _ and - only.");
    }

    // Find the operator
    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
    std::string fullOperatorKey;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        std::string opKey = HexStr(dmn->pdmnState->pubKeyOperator);
        if (opKey == operatorKeyInput || opKey.substr(0, operatorKeyInput.size()) == operatorKeyInput) {
            fullOperatorKey = opKey;
        }
    });

    if (fullOperatorKey.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Operator not found");
    }

    // Load aliases
    {
        LOCK(cs_aliases);
        if (g_operatorAliases.empty()) {
            LoadOperatorAliases();
        }
    }

    // Check operator has existing alias
    std::string oldAlias = GetAliasForOperator(fullOperatorKey);
    if (oldAlias.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Operator has no alias. Use registeroperatoralias first.");
    }

    // Check new alias is not taken
    std::string existingOperator = GetOperatorForAlias(newAlias);
    if (!existingOperator.empty() && existingOperator != fullOperatorKey) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("Alias '%s' is already taken", newAlias));
    }

    int currentHeight = WITH_LOCK(cs_main, return chainActive.Height(););

    // Update the alias
    {
        LOCK(cs_aliases);

        // Remove old alias mapping
        g_aliasToOperator.erase(oldAlias);

        // Update entry
        g_operatorAliases[fullOperatorKey].alias = newAlias;
        g_operatorAliases[fullOperatorKey].lastUpdateHeight = currentHeight;

        // Add new alias mapping
        g_aliasToOperator[newAlias] = fullOperatorKey;

        SaveOperatorAliases();
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    result.pushKV("oldAlias", oldAlias);
    result.pushKV("newAlias", newAlias);
    result.pushKV("operatorPubKey", fullOperatorKey);
    result.pushKV("updatedHeight", currentHeight);

    return result;
}

// ============================================================================
// RPC: listaliases (Blueprint 16)
// ============================================================================

UniValue listaliases(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "listaliases\n"
            "\nLists all registered operator aliases.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"alias\": \"...\",\n"
            "    \"operatorPubKey\": \"...\",\n"
            "    \"registeredHeight\": n\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaliases", "")
        );
    }

    UniValue result(UniValue::VARR);

    {
        LOCK(cs_aliases);
        if (g_operatorAliases.empty()) {
            LoadOperatorAliases();
        }

        for (auto it = g_operatorAliases.begin(); it != g_operatorAliases.end(); ++it) {
            const OperatorAlias& entry = it->second;
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("alias", entry.alias);
            obj.pushKV("operatorPubKey", entry.operatorPubKey);
            obj.pushKV("operatorShort", entry.operatorPubKey.substr(0, 10) + "...");
            obj.pushKV("registeredHeight", entry.registeredHeight);
            obj.pushKV("lastUpdateHeight", entry.lastUpdateHeight);
            result.push_back(obj);
        }
    }

    return result;
}

// ============================================================================
// Register RPC Commands
// ============================================================================

// clang-format off
static const CRPCCommand commands[] =
{ //  category       name                 actor (function)    okSafe argNames
  //  -------------- -------------------- ------------------- ------ --------
    { "masternode",  "getmnstats",        &getmnstats,        true,  {"identifier", "detailed"} },
    { "masternode",  "listmnstats",       &listmnstats,       true,  {"sort_by"} },
    { "masternode",  "listoperators",     &listoperators,     true,  {"sort_by"} },
    { "masternode",  "getoperatorstats",  &getoperatorstats,  true,  {"operator_pubkey", "detailed"} },
    { "masternode",  "checkrotation",     &checkrotation,     true,  {"since_height"} },
    { "masternode",  "getoperatorinfo",   &getoperatorinfo,   true,  {"identifier"} },
    { "masternode",  "registeroperatoralias", &registeroperatoralias, true, {"operator_pubkey", "alias"} },
    { "masternode",  "updateoperatoralias",   &updateoperatoralias,   true, {"operator_pubkey", "new_alias"} },
    { "masternode",  "listaliases",       &listaliases,       true,  {} },
};
// clang-format on

void RegisterMNStatsRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
