// Copyright (c) 2020-2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_DESTINATION_IO_H
#define BATHRON_DESTINATION_IO_H

#include "chainparams.h"
#include "script/standard.h"

// Regular + shielded addresses variant.
typedef boost::variant<CTxDestination, libzcash::SaplingPaymentAddress> CWDestination;

namespace Standard {

    std::string EncodeDestination(const CWDestination &address, const CChainParams::Base58Type addrType = CChainParams::PUBKEY_ADDRESS);

    CWDestination DecodeDestination(const std::string& strAddress);
    CWDestination DecodeDestination(const std::string& strAddress, bool& isShielded);

    bool IsValidDestination(const CWDestination& dest);

    // boost::get wrapper
    const libzcash::SaplingPaymentAddress* GetShieldedDestination(const CWDestination& dest);
    const CTxDestination * GetTransparentDestination(const CWDestination& dest);

} // End Standard namespace

#endif // BATHRON_DESTINATION_IO_H
