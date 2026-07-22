// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_CONSENSUS_PARAMS_H
#define BATHRON_CONSENSUS_PARAMS_H

#include "amount.h"
#include "optional.h"
#include "uint256.h"
#include <map>
#include <string>
#include <vector>

namespace Consensus {

/**
* Index into Params.vUpgrades and NetworkUpgradeInfo
*
* Being array indices, these MUST be numbered consecutively.
*
* The order of these indices MUST match the order of the upgrades on-chain, as
* several functions depend on the enum being sorted.
*/
enum UpgradeIndex : uint32_t {
    BASE_NETWORK,
    UPGRADE_BIP65,
    UPGRADE_V3_4,
    UPGRADE_V4_0,
    UPGRADE_V5_0,
    UPGRADE_V6_0,
    UPGRADE_V7_0,        // OP_TEMPLATEVERIFY (CTV-lite covenants)
    UPGRADE_BTCHEADERS_REORG, // Work-based BTC reorg in consensus header chain (BP-BTCHEADERS-REORG)
    UPGRADE_M1_RECEIPT_PROTECTED, // M1 receipt consensus protection: bearer receipt only spendable by reconciling settlement tx (option B)
    UPGRADE_POSE_PRODUCER_DECAY, // PoSe decay only for the successful block producer (legacy every-block decay made the 3-strike ban unreachable)
    UPGRADE_BTCSTATE,    // OP_BTCSTATEVERIFY (A1 - BTC header facts in script) + btcheaders max-reorg-depth (R7)
    UPGRADE_CSFS,        // OP_CHECKSIGFROMSTACK (verify sig over arbitrary message - oracles/delegation)
    UPGRADE_CSV,         // OP_CHECKSEQUENCEVERIFY (BIP112) + BIP68 relative lock-times
    UPGRADE_OPCAT,       // re-enable OP_CAT (BIP347 semantics, 520-byte result cap)
    UPGRADE_OUTPUTVALUE, // OP_CHECKOUTPUTVALUE (A - amount introspection, verify form)
    UPGRADE_OUTPUTSCRIPT, // OP_CHECKOUTPUTSCRIPT (CCV/MATT - recursive covenants, verify form)
    UPGRADE_FEE_RECEIPT_PINNED, // B4.4 O2b: M1 fee-receipts pinned to the including block's producer (coinbase script owner)
    UPGRADE_TESTDUMMY,
    // NOTE: Also add new upgrades to NetworkUpgradeInfo in upgrades.cpp
    MAX_NETWORK_UPGRADES
};

struct NetworkUpgrade {
    /**
     * Height of the first block for which the new consensus rules will be active.
     * Default = NO_ACTIVATION_HEIGHT (fail-safe): an UpgradeIndex added to the enum but
     * forgotten in a per-network chainparams block then reads as "never active" instead
     * of an indeterminate value. Every real gate is still assigned explicitly.
     */
    int nActivationHeight{NO_ACTIVATION_HEIGHT};

    /**
     * Special value for nActivationHeight indicating that the upgrade is always active.
     * This is useful for testing, as it means tests don't need to deal with the activation
     * process (namely, faking a chain of somewhat-arbitrary length).
     *
     * New blockchains that want to enable upgrade rules from the beginning can also use
     * this value. However, additional care must be taken to ensure the genesis block
     * satisfies the enabled rules.
     */
    static constexpr int ALWAYS_ACTIVE = 0;

    /**
     * Special value for nActivationHeight indicating that the upgrade will never activate.
     * This is useful when adding upgrade code that has a testnet activation height, but
     * should remain disabled on mainnet.
     */
    static constexpr int NO_ACTIVATION_HEIGHT = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    // HU: Genesis coinbase maturity (minimal, since block reward = 0)
    // Only affects genesis outputs, no new coinbase after genesis
    static constexpr int HU_COINBASE_MATURITY = 10;
    CAmount nMaxMoneyOut;
    // HU: Masternode collateral amount (network-specific)
    CAmount nMNCollateralAmt;
    int64_t nTargetSpacing;
    int nTimeSlotLength;

    // ═══════════════════════════════════════════════════════════════════════
    // HU DMM + Finality Parameters (network-specific)
    // ═══════════════════════════════════════════════════════════════════════

    // Quorum configuration
    int nHuQuorumSize;              // Sybil FLOOR: min distinct operators to finalize (mainnet 4 = testnet 4 = 3f+1, regtest 1)
    int nHuFinalityLagWarning;      // Diagnostic-only: finality-lag (blocks) above which status degrades to
                                    // "lagging" (2x = "critical"/warning log). NOT consensus — display/log unit.
    int nHuFinalitySeedOffset;      // Fixed backward offset k for the finality-committee
                                    // seed (mainnet 6 / testnet 3 / regtest 1). Seed of
                                    // block H = hash(H-k) instead of hash(H-1): breaks the
                                    // production/finality double-lever (see quorum.h).
    int nHuExpectedCommitteeSize;   // E: VRF finality-committee CAP (1-op-1-vote, p=E/N). VRF-only,
                                    // wired. Threshold = ceil(2/3*min(E,N)). mainnet=testnet 128 / regtest 1.

    // DMM leader timeout
    int nHuLeaderTimeoutSeconds;    // Timeout before fallback to next MN (45s mainnet)
    int nHuFallbackRecoverySeconds; // Recovery window for fallback MNs (15s testnet/mainnet)

    // DMM Bootstrap phase - special rules for cold start
    // During bootstrap (height <= nDMMBootstrapHeight):
    // - Producer = always primary (scores[0]), no fallback slot calculation
    // - nTime = max(prevTime + 1, nNow) instead of slot-aligned time
    // This prevents timestamp issues when syncing a fresh chain from genesis
    int nDMMBootstrapHeight;        // Bootstrap phase height (5 testnet, 10 mainnet)

    // Reorg protection
    int nHuMaxReorgDepth;           // Max reorg depth before finality (12 mainnet)

    // ═══════════════════════════════════════════════════════════════════════
    // Cold Start / Stale Chain Recovery
    // ═══════════════════════════════════════════════════════════════════════
    // SECURITY: If the chain tip is older than this, allow DMM to bypass
    // normal sync requirements and produce blocks (cold start recovery).
    // Mainnet: 3600s (1h) - high security, attacker needs 1h+ network outage
    // Testnet: 600s (10min) - balanced for testing
    // Regtest: 60s - fast for automated tests
    int64_t nStaleChainTimeout;

    // BATHRON: spork system removed - see 03-SPORKS-MODERNIZATION blueprint
    // All features (Sapling, HU finality) are permanently active

    // Map with network updates
    NetworkUpgrade vUpgrades[MAX_NETWORK_UPGRADES];

    // ═══════════════════════════════════════════════════════════════════════
    // BTC SPV & Burn Parameters
    // ═══════════════════════════════════════════════════════════════════════
    // All burns (including pre-launch) detected by burn_claim_daemon.
    // No special genesis files - same flow for all burns.
    //
    // BURN_PREFIX: OP_RETURN prefix identifying BATHRON burns (e.g., "BATHRON1")
    // ═══════════════════════════════════════════════════════════════════════
    uint32_t burnScanBtcHeightStart{0};  // First BTC block height to scan for genesis burns
    uint32_t burnScanBtcHeightEnd{0};    // Last BTC block height to scan for genesis burns (inclusive)

    // Accessor for the genesis burn-scan BTC height window (consumed by buildblock1)
    std::pair<uint32_t, uint32_t> GetBurnScanBtcHeightRange() const { return {burnScanBtcHeightStart, burnScanBtcHeightEnd}; }

    bool MoneyRange(const CAmount& nValue) const { return (nValue >= 0 && nValue <= nMaxMoneyOut); }
    bool IsTimeProtocolV2(const int nHeight) const { return NetworkUpgradeActive(nHeight, UPGRADE_V4_0); }
    // BTC header chain reorg support (BP-BTCHEADERS-REORG). Before activation:
    // extend-tip-only (V1). At/after: work-based reorg of the consensus BTC header chain.
    bool IsBtcHeadersReorg(const int nHeight) const { return NetworkUpgradeActive(nHeight, UPGRADE_BTCHEADERS_REORG); }
    bool IsBtcState(const int nHeight) const { return NetworkUpgradeActive(nHeight, UPGRADE_BTCSTATE); }
    // (CSFS / CSV / OP_CAT / OUTPUTVALUE / OUTPUTSCRIPT are gated directly via
    //  NetworkUpgradeActive() at the opcode sites in validation.cpp — no wrapper.)
    // M1 receipt consensus protection (option B). At/after activation: a bearer M1
    // receipt UTXO can only be spent by a settlement tx that reconciles it
    // (TX_UNLOCK / TX_TRANSFER_M1 / HTLC_CREATE_M1); a NORMAL spend is rejected.
    bool IsM1ReceiptProtected(const int nHeight) const { return NetworkUpgradeActive(nHeight, UPGRADE_M1_RECEIPT_PROTECTED); }
    // B4.4 O2b. At/after activation: the OP_TRUE fee-receipt of a TX_TRANSFER_M1
    // (and the OP_TRUE covenant-fee of an HTLC claim) is registered at connect
    // with owner = the including block's coinbase vout[0] script; spending it is
    // valid only if its value flows to that owner (destination covenant). Kills
    // the ownerless bearer-fee front-run without touching the tx format.
    bool IsFeeReceiptPinned(const int nHeight) const { return NetworkUpgradeActive(nHeight, UPGRADE_FEE_RECEIPT_PINNED); }
    bool IsPoSeProducerDecay(const int nHeight) const { return NetworkUpgradeActive(nHeight, UPGRADE_POSE_PRODUCER_DECAY); }
    // NOTE: the UPGRADE_HU_VRF_SORTITION gate was removed — HU finality is VRF-only
    // (ECVRF sortition is the unconditional committee mechanism, no legacy top-N path
    // and no activation flag). The VRF-module audit is a pre-mainnet PROCESS gate.

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON Masternode Collateral Maturity
    // ═══════════════════════════════════════════════════════════════════════════
    // Prevents rapid MN registration/deregistration attacks on quorum
    // Values are set per-network in chainparams.cpp
    // ═══════════════════════════════════════════════════════════════════════════
    int nMasternodeCollateralMinConf{1};  // Default, overridden per network

    int MasternodeCollateralMinConf() const { return nMasternodeCollateralMinConf; }

    int FutureBlockTimeDrift(const int /*nHeight*/) const
    {
        // HU: Time Protocol v2 is always active — drift is one slot (14 s)
        return nTimeSlotLength - 1;
    }

    bool IsValidBlockTimeStamp(const int64_t nTime, const int /*nHeight*/) const
    {
        // Time Protocol v2 (always active) requires block time on a slot boundary
        return (nTime % nTimeSlotLength) == 0;
    }

    /**
     * Returns true if the given network upgrade is active as of the given block
     * height. Caller must check that the height is >= 0 (and handle unknown
     * heights).
     */
    bool NetworkUpgradeActive(int nHeight, Consensus::UpgradeIndex idx) const;
};
} // namespace Consensus

#endif // BATHRON_CONSENSUS_PARAMS_H
