// Copyright (c) 2018 The Zcash developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/upgrades.h"

/**
 * HU Network Upgrade Information
 * Ordered by Consensus::UpgradeIndex.
 *
 * Note: Upgrade indices are preserved for consensus compatibility.
 * User-facing names have been updated to HU branding.
 */
const struct NUInfo NetworkUpgradeInfo[Consensus::MAX_NETWORK_UPGRADES] = {
        {
                /*.strName =*/ "HU_base",
                /*.strInfo =*/ "HU network genesis",
        },
        {
                /*.strName =*/ "HU_bip65",
                /*.strInfo =*/ "CLTV (BIP65) activation",
        },
        {
                /*.strName =*/ "HU_v3",
                /*.strInfo =*/ "Block version 6 enforcement",
        },
        {
                /*.strName =*/ "HU_v4",
                /*.strInfo =*/ "Message signatures - time protocol",
        },
        {
                /*.strName =*/ "HU_sapling",
                /*.strInfo =*/ "Sapling Shield activation",
        },
        {
                /*.strName =*/ "HU_dmn",
                /*.strInfo =*/ "Deterministic Masternodes (DMM)",
        },
        {
                /*.strName =*/ "HU_ctv",
                /*.strInfo =*/ "OP_TEMPLATEVERIFY (CTV-lite covenants)",
        },
        {
                /*.strName =*/ "HU_btchdrreorg",
                /*.strInfo =*/ "Work-based BTC reorg in consensus header chain",
        },
        {
                /*.strName =*/ "HU_m1protect",
                /*.strInfo =*/ "M1 receipt consensus protection (bearer receipt guard)",
        },
        {
                /*.strName =*/ "HU_posedecay",
                /*.strInfo =*/ "PoSe decay on successful production only (makes the 3-strike ban reachable)",
        },
        {
                /*.strName =*/ "HU_btcstate",
                /*.strInfo =*/ "OP_BTCSTATEVERIFY (BTC header facts in script) + btcheaders max-reorg-depth",
        },
        {
                /*.strName =*/ "HU_csfs",
                /*.strInfo =*/ "OP_CHECKSIGFROMSTACK (signature over arbitrary message)",
        },
        {
                /*.strName =*/ "HU_csv",
                /*.strInfo =*/ "OP_CHECKSEQUENCEVERIFY (BIP112) + BIP68 relative lock-times",
        },
        {
                /*.strName =*/ "HU_opcat",
                /*.strInfo =*/ "Re-enable OP_CAT (BIP347 semantics, 520-byte result cap)",
        },
        {
                /*.strName =*/ "HU_outputvalue",
                /*.strInfo =*/ "OP_CHECKOUTPUTVALUE (amount introspection, verify form)",
        },
        {
                /*.strName =*/ "HU_outputscript",
                /*.strInfo =*/ "OP_CHECKOUTPUTSCRIPT (CCV/MATT recursive covenants, verify form)",
        },
        {
                /*.strName =*/ "HU_feereceiptpinned",
                /*.strInfo =*/ "M1 fee-receipts pinned to the including block's producer (B4.4 O2b)",
        },
        {
                /*.strName =*/ "HU_test",
                /*.strInfo =*/ "Test upgrade",
        },
};

UpgradeState NetworkUpgradeState(
        int nHeight,
        const Consensus::Params& params,
        Consensus::UpgradeIndex idx)
{
    assert(nHeight >= 0);
    assert(idx >= Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
    auto nActivationHeight = params.vUpgrades[idx].nActivationHeight;

    if (nActivationHeight == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT) {
        return UPGRADE_DISABLED;
    } else if (nHeight >= nActivationHeight) {
        // From ZIP200:
        //
        // ACTIVATION_HEIGHT
        //     The block height at which the network upgrade rules will come into effect.
        //
        //     For removal of ambiguity, the block at height ACTIVATION_HEIGHT - 1 is
        //     subject to the pre-upgrade consensus rules.
        return UPGRADE_ACTIVE;
    } else {
        return UPGRADE_PENDING;
    }
}

bool NetworkUpgradeActive(
        int nHeight,
        const Consensus::Params& params,
        Consensus::UpgradeIndex idx)
{
    return NetworkUpgradeState(nHeight, params, idx) == UPGRADE_ACTIVE;
}

bool IsActivationHeight(
        int nHeight,
        const Consensus::Params& params,
        Consensus::UpgradeIndex idx)
{
    assert(idx >= Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);

    // Don't count BASE_NETWORK as an activation height
    if (idx == Consensus::BASE_NETWORK) {
        return false;
    }

    return nHeight >= 0 && nHeight == params.vUpgrades[idx].nActivationHeight;
}

bool IsActivationHeightForAnyUpgrade(
        int nHeight,
        const Consensus::Params& params)
{
    if (nHeight < 0) {
        return false;
    }

    for (int idx = Consensus::BASE_NETWORK + 1; idx < (int) Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (nHeight == params.vUpgrades[idx].nActivationHeight)
            return true;
    }

    return false;
}

Optional<int> NextEpoch(int nHeight, const Consensus::Params& params) {
    if (nHeight < 0) {
        return nullopt;
    }

    // BASE_NETWORK is never pending
    for (auto idx = Consensus::BASE_NETWORK + 1; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (NetworkUpgradeState(nHeight, params, Consensus::UpgradeIndex(idx)) == UPGRADE_PENDING) {
            return idx;
        }
    }

    return nullopt;
}

Optional<int> NextActivationHeight(
        int nHeight,
        const Consensus::Params& params)
{
    auto idx = NextEpoch(nHeight, params);
    if (idx) {
        return params.vUpgrades[idx.get()].nActivationHeight;
    }
    return nullopt;
}
