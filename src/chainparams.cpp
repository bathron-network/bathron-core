// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "arith_uint256.h"
#include "consensus/merkle.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "version.h"  // For TESTNET_EPOCH

#include <assert.h>

void CChainParams::UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    assert(IsRegTestNet()); // -nuparams overrides are regtest-only (a testnet operator must not self-fork via config)
    assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
    consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
}

/**
 * BATHRON Genesis Block - Burn-only model (zero premine)
 *
 * ALL M0 originates from verified BTC burns via SPV (invariant A5).
 * Genesis coinbase is 0 BATHRON - symbolic only, not spendable.
 * Block reward = 0 (always). No premine, no allocation, no exception.
 *
 * Supply flow:
 *   BTC Burn on Bitcoin → TX_BURN_CLAIM → K confirmations → TX_MINT_M0BTC
 *   This is the ONLY path to create M0. Period.
 */
static CBlock CreateBathronGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    const char* pszTimestamp = "BATHRON Genesis 2026 - a settlement kernel for Bitcoin - M0 from BTC burns only";

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    // Coinbase must have at least 1 output (Bitcoin protocol requirement).
    // Value = 0: no M0 created at genesis. All M0 comes from BTC burns.
    txNew.vout.resize(1);
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("0000000000000000000000000000000000000000") << OP_EQUALVERIFY << OP_CHECKSIG;

    CBlock genesis;
    genesis.vtx.push_back(std::make_shared<const CTransaction>(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * BATHRON Testnet Genesis Block - Burn-only model (zero premine)
 *
 * Block 0: Coinbase = 0 BATHRON (symbolic, not spendable)
 * Block 1+: TX_BTC_HEADERS, then TX_BURN_CLAIM, then TX_MINT_M0BTC
 *
 * ALL M0 originates from verified BTC Signet burns.
 * No premine, no snapshot, no hardcoded allocation.
 * No virtual/genesis MN injection — MNs are registered by ProRegTx at block 2+.
 */
static CBlock CreateBathronTestnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    // NOTE: pszTimestamp is consensus-critical (changes genesis hash). DO NOT MODIFY.
    const char* pszTimestamp = "BATHRON Testnet Dec 2025 - Snapshot Genesis v4 - DMM from Block 1";

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    // Coinbase must have at least 1 output (Bitcoin protocol requirement).
    // Value = 0: no M0 created at genesis. All M0 comes from BTC burns.
    txNew.vout.resize(1);
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("0000000000000000000000000000000000000000") << OP_EQUALVERIFY << OP_CHECKSIG;

    CBlock genesis;
    genesis.vtx.push_back(std::make_shared<const CTransaction>(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * BATHRON Regtest Genesis Block - TEST-ONLY convenience premine
 *
 * WARNING: Regtest uses hardcoded outputs for automated test convenience.
 * This is an INTENTIONAL deviation from the burn-only model (A5).
 * Production networks (mainnet/testnet) have ZERO premine.
 *
 * These outputs are NOT tracked in settlement M0_total_supply.
 * They exist only to facilitate regtest without requiring a BTC node.
 */
static CBlock CreateBathronRegtestGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    const char* pszTimestamp = "BATHRON Regtest 2026 - Test Genesis v3";

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON Regtest Distribution - P2PKH outputs with KNOWN private keys
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Generated from regtest wallet - NEVER use on mainnet!
    //
    // Output 0: Test Wallet (50M HU)
    //   Address: y65ffDxjd8WVQn4J4ByKhSDWwVMs2r4k7d
    //   WIF:     cMpec6ZShrJvVMfehkdqVbkK9sHQCsqeBpyd7q5c682KxpbNT2aR
    //
    // Output 1: MN1 Collateral (100 HU)
    //   Address: y48kso2j49HW3mZtNasQxumSVpWzN6H16H
    //   WIF:     cRtHEkQ53gfYg3NWbpb8nCLPxebyRVEEfRpcWJVyLMhhp1wLmhdB
    //
    // Output 2: MN2 Collateral (100 HU)
    //   Address: y9Drs8V4updrVkuEAP3HyZfJukrZh3LBNm
    //   WIF:     cS3s7E4zVgtvn5BBz1ZcDgdfbs2t1qcNB8tQjffq64xo2aHc7XSq
    //
    // Output 3: MN3 Collateral (100 HU)
    //   Address: yEvakh8hWeVvfHY4kXBxowQ1gus2Q1imTP
    //   WIF:     cQX5FKoWNny66nYJEwwCwXVvhzn7Mm6C6u2zcPrhDFZ6tgPMiPni
    //
    // Output 4: MN Ops Fund (119,700 HU)
    //   Address: y6wgMBkg9BXfdMAH7Cf1quRZjJz98qaPAq
    //   WIF:     cPP8PfQgEaStUECCpKFzpZt9hFis8tj6E2vtqr3gweLyZkuwuvvY
    //
    // Output 5: Swap Reserve (48.5M HU)
    //   Address: y4wrFnnsRTkDhxBp61gDnjZ9Fg8yt7x34D
    //   WIF:     cNYJdV6Muuu1oVRP2fsCHYeTx3pkaq7itEV45mK36gTziSLQ4Qox
    //
    // Output 6: Reserve (500K M0)
    //   Address: yBNsxgEURuLLSYTjgT5fmUwBPK77s8a5fZ
    //   WIF:     cUhVQbjcbttjN8yLVyY5maqweRZsFSRBsrbo3335AiPWscYAVa66
    //
    // ═══════════════════════════════════════════════════════════════════════════

    txNew.vout.resize(7);

    // Output 0: Test Wallet (50M)
    txNew.vout[0].nValue = 50000000 * COIN;
    txNew.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("63d31c01f548cc5d314cf692f727157475b9d4a9") << OP_EQUALVERIFY << OP_CHECKSIG;

    // Output 1: MN1 Collateral (100)
    txNew.vout[1].nValue = 100 * COIN;
    txNew.vout[1].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("4e7875de8946177c9fd5fc55fcbc54a34c8a4ab9") << OP_EQUALVERIFY << OP_CHECKSIG;

    // Output 2: MN2 Collateral (100)
    txNew.vout[2].nValue = 100 * COIN;
    txNew.vout[2].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("86482b0b101caf70223a43ca2a68f91aaf02786d") << OP_EQUALVERIFY << OP_CHECKSIG;

    // Output 3: MN3 Collateral (100)
    txNew.vout[3].nValue = 100 * COIN;
    txNew.vout[3].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("c4d467187c9287c486e2954e72275cd767bf361a") << OP_EQUALVERIFY << OP_CHECKSIG;

    // Output 4: MN Ops Fund (119,700)
    txNew.vout[4].nValue = 119700 * COIN;
    txNew.vout[4].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("6d487b8e666a54a23bbdf5d5fcb6d55c677ee82a") << OP_EQUALVERIFY << OP_CHECKSIG;

    // Output 5: Swap Reserve (48.5M)
    txNew.vout[5].nValue = 48500000 * COIN;
    txNew.vout[5].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("5760804121da48fd43d266282cbddc8f0e7962af") << OP_EQUALVERIFY << OP_CHECKSIG;

    // Output 6: Reserve (500K M0)
    txNew.vout[6].nValue = 500000 * COIN;
    txNew.vout[6].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex("9ded13f5233a7fede9f7f70de3a9739d1405d001") << OP_EQUALVERIFY << OP_CHECKSIG;

    CBlock genesis;
    genesis.vtx.push_back(std::make_shared<const CTransaction>(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
// BATHRON will have its own genesis and checkpoint history
static MapCheckpoints mapCheckpoints = {};

static const CCheckpointData data = {
    &mapCheckpoints,
    0,    // * UNIX timestamp of last checkpoint block
    0,    // * total number of transactions between genesis and last checkpoint
    0     // * estimated number of transactions per day after checkpoint
};

static MapCheckpoints mapCheckpointsTestnet = {};

static const CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    0,
    0,
    0};

static MapCheckpoints mapCheckpointsRegtest = {};
static const CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    0,
    0,
    0};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        strNetworkID = "hu-main";

        // BATHRON Mainnet Genesis - Burn-only (0 coinbase)
        // All M0 from verified BTC burns via SPV. No premine.
        // PLACEHOLDER until launch: the REAL mainnet genesis gets re-mined launch-day with a
        // recency-proof message (doc/MAINNET-LAUNCH-CHECKLIST.md). Re-mined 2026-07-12
        // (identity refresh, retired "CLS" wording dropped): nBits 0x1e0ffff0,
        // nTime 1783814400 → nNonce 704096 (hash 00000071… ≤ target 00000ffff0…).
        genesis = CreateBathronGenesisBlock(1783814400, 704096, 0x1e0ffff0, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        // PINNED mainnet genesis — tamper-evident: any drift in the genesis params (time,
        // coinbase, nBits, merkle) trips these asserts at startup instead of silently forking.
        assert(consensus.hashGenesisBlock == uint256S("0x0000007179ceca37254c0d1e748f17a3ef6ccfd0291e708187dbaf861adbdc13"));
        assert(genesis.hashMerkleRoot == uint256S("0x6d2ea69563bc6c73712b86a5afb81cd6723c5548aa5b914c37f632c5e1c4c133"));

        // ═══════════════════════════════════════════════════════════════════════
        // HU Core Economic Parameters - MAINNET
        // ═══════════════════════════════════════════════════════════════════════
        consensus.nMaxMoneyOut = 21000000 * COIN;   // BTC cap: max M0 = max BTC (burn-only model)
        // MAINNET COLLATERAL = 0.01 BTC per MN (DECIDED 2026-06-30 — permissioned-launch deposit).
        // COIN/100 = 1,000,000 sats of M0 (= burned BTC). This is a launch deposit, NOT yet a
        // Sybil price (capturing ⌈N/3⌉ operators is cheap at this value) — fine while the
        // maintainer operates all nodes. RE-PRICE at open-network per capture-cost > VaR/window
        // (doc/MAINNET-LAUNCH-CHECKLIST.md D1). Integer COIN-notation (no float).
        consensus.nMNCollateralAmt = COIN / 100; // 0.01 BTC — launch value, re-price at opening
        consensus.nTargetSpacing = 1 * 60;          // HU: 60 second blocks
        consensus.nTimeSlotLength = 15;

        // ═══════════════════════════════════════════════════════════════════════
        // BP30 Timing Parameters - MAINNET (production values)
        // ═══════════════════════════════════════════════════════════════════════

        // Masternode collateral maturity: 1 day (prevents quorum manipulation)
        consensus.nMasternodeCollateralMinConf = 1440;  // 1 day × 1440 blocks/day

        // Blocks per day (for rate limiting, diagnostics)

        // ═══════════════════════════════════════════════════════════════════════
        // HU DMM + Finality Parameters - MAINNET
        // Quorum floor + per-block ECVRF sortition finality (threshold = ceil(2/3·min(E,N)))
        // ═══════════════════════════════════════════════════════════════════════
        consensus.nHuQuorumSize = 4;                // Sybil floor: min distinct OPERATORS to finalize. 4 = textbook 3f+1 (tolerates 1 fault: 1 down → 3 vote → 3>=ceil(2/3*4)). No producer exclusion, so the full N votes. Must be <= operator count at launch.
        consensus.nHuFinalityLagWarning = 12;       // Diagnostic: lag > 12 blocks → "lagging" (2x → critical)
        consensus.nHuFinalitySeedOffset = 6;        // Finality seed = hash(H-6) (anti double-lever)
        consensus.nHuExpectedCommitteeSize = 128;   // E = VRF committee CAP. Threshold = ceil(2/3·min(E,N)): N<=E whole population, N>E sampled ~E. One fixed E scales few→thousands of operators with no retuning.
        consensus.nHuLeaderTimeoutSeconds = 45;     // DMM leader timeout (fallback after 45s)
        consensus.nHuFallbackRecoverySeconds = 15;  // Recovery window for fallback MNs
        consensus.nDMMBootstrapHeight = 10;         // Bootstrap phase (no slot calculation for cold start)
        consensus.nHuMaxReorgDepth = 0;             // No artificial limit - reorg blocked by actual HU finality only
        consensus.nStaleChainTimeout = 3600;        // SECURITY: 1 hour for mainnet cold start recovery

        // BATHRON: spork system removed - see 03-SPORKS-MODERNIZATION blueprint

        // ═══════════════════════════════════════════════════════════════════════
        // BTC SPV & Burn Parameters - MAINNET
        // All burns (including pre-launch) detected by burn_claim_daemon
        // ═══════════════════════════════════════════════════════════════════════
        consensus.burnScanBtcHeightStart = 840000;   // MAINNET: Start at halving block (2024)
        consensus.burnScanBtcHeightEnd = 840000;     // MAINNET: No genesis burns range

        // ALL upgrades active from GENESIS (no height-based activation)
        // This is the BATHRON way: clean start, all features active from block 0
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V5_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // Sapling version
        consensus.vUpgrades[Consensus::UPGRADE_V6_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // BP30 settlement active from genesis
        consensus.vUpgrades[Consensus::UPGRADE_V7_0].nActivationHeight          =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // CTV-lite: not active on mainnet yet
        // BTC header reorg + R6 difficulty validation (BP-BTCHEADERS-REORG).
        // Fresh-genesis mainnet -> ALWAYS_ACTIVE so the V2 ruleset (reorg self-heal
        // + R6 difficulty, which blocks fake-burn M0 forgery, F1) is enforced from
        // block 1. No pre-existing history to transition, so no future height needed.
        consensus.vUpgrades[Consensus::UPGRADE_BTCHEADERS_REORG].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        // M1 receipt consensus protection (option B). Fresh-genesis mainnet ->
        // ALWAYS_ACTIVE: a bearer M1 receipt is spendable only by a reconciling
        // settlement tx (TX_UNLOCK / TX_TRANSFER_M1 / HTLC_CREATE_M1 /
        // HTLC_CREATE_3S) from block 1.
        consensus.vUpgrades[Consensus::UPGRADE_M1_RECEIPT_PROTECTED].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        // PoSe producer-decay rule. Fresh-genesis mainnet -> ALWAYS_ACTIVE: penalty
        // decays only when the MN successfully produces, so the 3-strike ban is
        // actually reachable from block 1 (the legacy every-block decay capped any
        // penalty at 1 — ban mathematically unreachable).
        consensus.vUpgrades[Consensus::UPGRADE_POSE_PRODUCER_DECAY].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_BTCSTATE].nActivationHeight             =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // A1: flip ALWAYS_ACTIVE at mainnet freeze (with UPGRADE_V7_0)
        consensus.vUpgrades[Consensus::UPGRADE_CSFS].nActivationHeight                 =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // CSFS: flip at mainnet freeze
        consensus.vUpgrades[Consensus::UPGRADE_CSV].nActivationHeight                  =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // CSV/BIP68: flip at mainnet freeze
        consensus.vUpgrades[Consensus::UPGRADE_OPCAT].nActivationHeight                =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // OP_CAT: flip at mainnet freeze
        consensus.vUpgrades[Consensus::UPGRADE_OUTPUTVALUE].nActivationHeight          =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // OP_CHECKOUTPUTVALUE: flip at mainnet freeze
        consensus.vUpgrades[Consensus::UPGRADE_OUTPUTSCRIPT].nActivationHeight         =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // OP_CHECKOUTPUTSCRIPT (CCV): flip at mainnet freeze
        consensus.vUpgrades[Consensus::UPGRADE_FEE_RECEIPT_PINNED].nActivationHeight   =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;  // B4.4 O2b: flip at mainnet freeze (fresh genesis)


        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        // BATHRON Mainnet Magic Bytes ("bthn") - distinct from PIVX/Dash/Bitcoin
        pchMessageStart[0] = 0xba;
        pchMessageStart[1] = 0x74;
        pchMessageStart[2] = 0x68;
        pchMessageStart[3] = 0x6e;
        nDefaultPort = 27170;


        // BATHRON mainnet identity (2026-07-12; replaces inherited PIVX bytes 30/13/212 + coin type 119):
        // P2PKH leads with 'B', P2SH with 'S'; WIF = PUBKEY+128; BIP32 magic = standard xpub/xprv.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 25);   // 'B...'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 63);   // 'S...'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 153);      // 25 + 128
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};            // xpub (standard BIP32)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};            // xprv (standard BIP32)
        // BIP44 coin type: 2717 (mnemonic: the 2717x port family). PROVISIONAL — register in
        // https://github.com/satoshilabs/slips/blob/master/slip-0044.md before mainnet launch.
        base58Prefixes[EXT_COIN_TYPE] = {0x80, 0x00, 0x0A, 0x9D};             // 0x80000A9D = 2717'

        vFixedSeeds = std::vector<uint8_t>();  // no fixed seeds - fleet bootstraps via addnode (launch item)

        // Reject non-standard transactions by default
        fRequireStandard = true;

        // Sapling
        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "bs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "bviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "bivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "b-secret-spending-key-main";
        bech32HRPs[SAPLING_EXTENDED_FVK]         = "bxviews";

        // Tier two
    }

    const CCheckpointData& Checkpoints() const
    {
        return data;
    }

};

/**
 * BATHRON Testnet - for testing MN-only consensus and BP30 settlement features
 */
class CTestNetParams : public CChainParams
{
public:
    CTestNetParams()
    {
        strNetworkID = "bathron-testnet";

        // ═══════════════════════════════════════════════════════════════════════
        // BATHRON Testnet Genesis - Burn-only (zero premine)
        // ═══════════════════════════════════════════════════════════════════════
        // Block 0: Coinbase = 0 BATHRON (symbolic, not spendable)
        // Block 1+: TX_BTC_HEADERS → TX_BURN_CLAIM → TX_MINT_M0BTC
        // ALL M0 from verified BTC Signet burns. No premine.
        // No virtual/genesis MN injection — MNs registered by ProRegTx at block 2+.
        // ═══════════════════════════════════════════════════════════════════════
        genesis = CreateBathronTestnetGenesisBlock(1733443200, 0, 0x1e0ffff0, 1);  // Dec 6, 2025
        consensus.hashGenesisBlock = genesis.GetHash();

        // PINNED testnet genesis — tamper-evident, same rationale as mainnet: any drift
        // in the genesis params trips these at startup instead of silently forking.
        // (Values = the LIVE testnet5 chain's block 0; genesis is accepted by hash
        // equality, no PoW check applies to it — hence nNonce 0 is fine.)
        assert(consensus.hashGenesisBlock == uint256S("0x0d241620b8beb492fd21bd8a92295260a4afa1b82e1bd816d18323cc3c98ea71"));
        assert(genesis.hashMerkleRoot == uint256S("0xac29023ab4ca879615c05a7ec9be67ba15b526daacbcfc633dbe14e934f57c7c"));

        // ═══════════════════════════════════════════════════════════════════════
        // HU Core Economic Parameters - TESTNET
        // ═══════════════════════════════════════════════════════════════════════
        consensus.nMaxMoneyOut = 21000000 * COIN;   // BTC cap: max M0 = max BTC (burn-only model)
        consensus.nMNCollateralAmt = COIN / 100; // 1,000,000 sats = 0.01 BTC-equiv (testnet; integer COIN-notation)
        consensus.nTargetSpacing = 1 * 60;          // HU: 60 second blocks
        consensus.nTimeSlotLength = 15;

        // ═══════════════════════════════════════════════════════════════════════
        // BP30 Timing Parameters - TESTNET (accelerated for testing)
        // ═══════════════════════════════════════════════════════════════════════

        // Masternode collateral maturity: 1 hour (faster testing)
        consensus.nMasternodeCollateralMinConf = 60;  // 1 hour × 1 block/min

        // Blocks per day (for rate limiting, diagnostics)

        // ═══════════════════════════════════════════════════════════════════════
        // HU DMM + Finality Parameters - TESTNET
        // Same quorum floor as mainnet (4 = 3f+1); shorter diagnostic windows for testing
        // ═══════════════════════════════════════════════════════════════════════
        consensus.nHuQuorumSize = 4;                // UNIFIED with mainnet (3f+1): testnet must mirror what mainnet ships. Requires >=4 distinct operators on the test fleet.
        consensus.nHuFinalityLagWarning = 3;        // Diagnostic: lag > 3 blocks → "lagging" (2x → critical)
        consensus.nHuFinalitySeedOffset = 3;        // Finality seed = hash(H-3) (anti double-lever)
        consensus.nHuExpectedCommitteeSize = 128;   // E = VRF committee CAP (same as mainnet). Threshold = ceil(2/3·min(E,N)); at N=3 today → min=3 → 2/3 (auto-scales as operators join)
        consensus.nHuLeaderTimeoutSeconds = 45;     // Leader timeout (was 30, increased for reliability)
        consensus.nHuFallbackRecoverySeconds = 15;  // Fallback window (was 10)
        consensus.nDMMBootstrapHeight = 250;         // Bootstrap: header catch-up + burn claims + 20 K_FINALITY + mint + MN reg + margin
        consensus.nHuMaxReorgDepth = 0;             // No artificial limit - reorg blocked by actual HU finality only
        consensus.nStaleChainTimeout = 600;         // 10 minutes for testnet cold start recovery

        // BATHRON: spork system removed - see 03-SPORKS-MODERNIZATION blueprint

        // ═══════════════════════════════════════════════════════════════════════
        // BTC SPV & Burn Parameters - TESTNET
        // All burns (including pre-launch) detected by burn_claim_daemon
        // ═══════════════════════════════════════════════════════════════════════
        consensus.burnScanBtcHeightStart = 200000;   // TESTNET/Signet: Start from checkpoint
        consensus.burnScanBtcHeightEnd = 300000;     // TESTNET/Signet: ~6 months after checkpoint

        // ALL upgrades active from GENESIS (no height-based activation)
        // This is the BATHRON way: clean start, all features active from block 0
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V5_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // Sapling version
        consensus.vUpgrades[Consensus::UPGRADE_V6_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // BP30 settlement active from genesis
        consensus.vUpgrades[Consensus::UPGRADE_V7_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // CTV-lite: active on testnet
        // BTC header reorg + R6 difficulty (BP-BTCHEADERS-REORG). Must be > current
        // height and AFTER the coordinated binary deploy to all validators (chain
        // does ~1 block/min). Lowered 2026-06-25 to heal sooner (was 191000).
        // 2026-06-28 (epoch 3 SPV-hardening genesis): ALWAYS_ACTIVE — the fresh
        // testnet mirrors mainnet exactly (V2 reorg + R6 difficulty from block 1),
        // instead of waiting until height 190044 to enforce the hardened ruleset.
        consensus.vUpgrades[Consensus::UPGRADE_BTCHEADERS_REORG].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        // M1 receipt consensus protection (option B): fresh testnet mirrors mainnet,
        // enforced from block 1 (bearer receipt spendable only by a reconciling
        // settlement tx: TX_UNLOCK / TX_TRANSFER_M1 / HTLC_CREATE_M1 / HTLC_CREATE_3S).
        consensus.vUpgrades[Consensus::UPGRADE_M1_RECEIPT_PROTECTED].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        // PoSe producer-decay rule: baked in at genesis (ALWAYS_ACTIVE, like mainnet).
        // The historical testnet h1500 height-gate is gone — the reset chain enforces
        // the real 3-strike decay from block 1.
        consensus.vUpgrades[Consensus::UPGRADE_POSE_PRODUCER_DECAY].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // baked in at genesis (was h1500 on the pre-reset chain)
        consensus.vUpgrades[Consensus::UPGRADE_BTCSTATE].nActivationHeight             =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // A1: active from next disposable genesis
        consensus.vUpgrades[Consensus::UPGRADE_CSFS].nActivationHeight                 =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // CSFS: active on testnet
        consensus.vUpgrades[Consensus::UPGRADE_CSV].nActivationHeight                  =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // CSV/BIP68: active on testnet
        consensus.vUpgrades[Consensus::UPGRADE_OPCAT].nActivationHeight                =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // OP_CAT: active on testnet
        consensus.vUpgrades[Consensus::UPGRADE_OUTPUTVALUE].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // OP_CHECKOUTPUTVALUE: active on testnet
        consensus.vUpgrades[Consensus::UPGRADE_OUTPUTSCRIPT].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // OP_CHECKOUTPUTSCRIPT (CCV): active on testnet
        consensus.vUpgrades[Consensus::UPGRADE_FEE_RECEIPT_PINNED].nActivationHeight   =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // B4.4 O2b: baked in at genesis (clean chain, active from block 1)

        // ═══════════════════════════════════════════════════════════════════════
        // BATHRON Testnet - clean genesis (no MN injection, no premine)
        // Block 0: pure genesis (coinbase=0). Block 1+: TX_BTC_HEADERS, then
        // burn-backed TX_MINT_M0BTC; MN collaterals funded from minted M0, then
        // ProRegTx registers the MNs. Burn-only, end to end.
        // ═══════════════════════════════════════════════════════════════════════

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        // BATHRON Testnet Magic Bytes - includes TESTNET_EPOCH to prevent old nodes connecting
        // When creating a new testnet genesis, increment TESTNET_EPOCH in version.h
        // Format: 0xfa 0xbf 0xb5 0x(da + TESTNET_EPOCH)
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda + TESTNET_EPOCH;  // Epoch 2 = 0xdc
        nDefaultPort = 27171;  // BATHRON Testnet P2P port


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet bathron addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet bathron script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x3a, 0x80, 0x61, 0xa0};
        base58Prefixes[EXT_SECRET_KEY] = {0x3a, 0x80, 0x58, 0x37};
        // Testnet bathron BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = {0x80, 0x00, 0x00, 0x01};

        vFixedSeeds = std::vector<uint8_t>();  // no fixed seeds - fleet bootstraps via addnode (launch item)

        fRequireStandard = false;

        // Sapling
        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ptestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "pviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "pivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "p-secret-spending-key-test";
        bech32HRPs[SAPLING_EXTENDED_FVK]         = "pxviewtestsapling";

        // Tier two
    }

    const CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};

/**
 * BATHRON Regression test - fast local testing
 * NOTE: Regtest uses convenience premine (not burn-only). See CreateBathronRegtestGenesisBlock.
 */
class CRegTestParams : public CChainParams
{
public:
    CRegTestParams()
    {
        strNetworkID = "regtest";

        // BATHRON Regtest Genesis - convenience premine for automated tests
        // NOT burn-only (intentional deviation for test convenience)
        genesis = CreateBathronRegtestGenesisBlock(1732924800, 0, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        // Regtest genesis hash is intentionally UNPINNED: it is recomputed at each
        // construction (message/params may evolve freely; regtest is local-only).
        // ═══════════════════════════════════════════════════════════════════════
        // HU Core Economic Parameters - REGTEST
        // ═══════════════════════════════════════════════════════════════════════
        consensus.nMaxMoneyOut = 99120000 * COIN;   // Regtest: includes convenience premine (not burn-only)
        consensus.nMNCollateralAmt = 10000 * COIN;   // 10k M0 = 0.0001 BTC (low for regtest)
        consensus.nTargetSpacing = 1 * 60;          // HU: 60 second blocks
        consensus.nTimeSlotLength = 15;

        // ═══════════════════════════════════════════════════════════════════════
        // BP30 Timing Parameters - REGTEST (ultra-fast for automated tests)
        // ═══════════════════════════════════════════════════════════════════════

        // Masternode collateral maturity: 1 block (instant for testing)
        consensus.nMasternodeCollateralMinConf = 1;  // Immediate for regtest

        // Blocks per day (for rate limiting, diagnostics)

        // ═══════════════════════════════════════════════════════════════════════
        // HU DMM + Finality Parameters - REGTEST
        // Trivial quorum (1 MN), instant finality for automated tests
        // ═══════════════════════════════════════════════════════════════════════
        consensus.nHuQuorumSize = 1;                // Single MN quorum
        consensus.nHuFinalityLagWarning = 1;        // Diagnostic: any lag → "lagging" (regtest)
        consensus.nHuFinalitySeedOffset = 1;        // Finality seed = hash(H-1) (single-MN regtest, no-op)
        consensus.nHuExpectedCommitteeSize = 1;     // E = VRF committee CAP (regtest: single MN)
        consensus.nHuLeaderTimeoutSeconds = 5;      // Short timeout (less relevant in regtest)
        consensus.nHuFallbackRecoverySeconds = 2;   // Ultra-fast for regtest
        consensus.nDMMBootstrapHeight = 2;          // Bootstrap phase (no slot calculation for cold start)
        consensus.nHuMaxReorgDepth = 100;           // Large tolerance for test scenarios
        consensus.nStaleChainTimeout = 60;          // 1 minute for regtest cold start recovery

        // BATHRON: spork system removed - see 03-SPORKS-MODERNIZATION blueprint

        // ═══════════════════════════════════════════════════════════════════════
        // BTC SPV & Burn Parameters - REGTEST
        // All burns detected by burn_claim_daemon
        // ═══════════════════════════════════════════════════════════════════════
        consensus.burnScanBtcHeightStart = 0;        // REGTEST: Scan all heights
        consensus.burnScanBtcHeightEnd = UINT32_MAX; // REGTEST: No height restriction

        // ALL upgrades active from GENESIS (no height-based activation)
        // This is the BATHRON way: clean start, all features active from block 0
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_V5_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // Sapling version
        consensus.vUpgrades[Consensus::UPGRADE_V6_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // BP30 settlement active from genesis
        consensus.vUpgrades[Consensus::UPGRADE_V7_0].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // CTV-lite: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_BTCHEADERS_REORG].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // BTC header reorg: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_M1_RECEIPT_PROTECTED].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // M1 receipt guard: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_POSE_PRODUCER_DECAY].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // PoSe producer-decay: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_BTCSTATE].nActivationHeight             =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // A1: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_CSFS].nActivationHeight                 =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // CSFS: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_CSV].nActivationHeight                  =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // CSV/BIP68: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_OPCAT].nActivationHeight                =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // OP_CAT: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_OUTPUTVALUE].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // OP_CHECKOUTPUTVALUE: active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_OUTPUTSCRIPT].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // OP_CHECKOUTPUTSCRIPT (CCV): active on regtest
        consensus.vUpgrades[Consensus::UPGRADE_FEE_RECEIPT_PINNED].nActivationHeight   =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;  // B4.4 O2b: active on regtest (tests)

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        // BATHRON Regtest Magic Bytes ("bthr")
        pchMessageStart[0] = 0xba;
        pchMessageStart[1] = 0x74;
        pchMessageStart[2] = 0x68;
        pchMessageStart[3] = 0x72;
        nDefaultPort = 27173;

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet bathron addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet bathron script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x3a, 0x80, 0x61, 0xa0};
        base58Prefixes[EXT_SECRET_KEY] = {0x3a, 0x80, 0x58, 0x37};
        // Testnet bathron BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = {0x80, 0x00, 0x00, 0x01};

        // Reject non-standard transactions by default
        fRequireStandard = true;

        // Sapling
        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ptestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "pviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "pivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "p-secret-spending-key-test";
        bech32HRPs[SAPLING_EXTENDED_FVK]         = "pxviewtestsapling";

        // Tier two
    }

    const CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params()
{
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    globalChainParams->UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
