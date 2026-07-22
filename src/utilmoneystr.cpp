// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2019 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilmoneystr.h"

#include "primitives/transaction.h"
#include "tinyformat.h"
#include "utilstrencodings.h"


std::string FormatMoney(const CAmount& n, bool fPlus)
{
    // BATHRON: 1 M0 = 1 satoshi, return raw integer (no BTC conversion)
    std::string str = strprintf("%d", n);
    if (fPlus && n > 0)
        str.insert((unsigned int)0, 1, '+');
    return str;
}


bool ParseMoney(const std::string& str, CAmount& nRet)
{
    return ParseMoney(str.c_str(), nRet);
}

bool ParseMoney(const char* pszIn, CAmount& nRet)
{
    // BATHRON: 1 M0 = 1 satoshi, parse raw integer (no BTC conversion)
    std::string strValue;
    const char* p = pszIn;

    // Skip leading whitespace
    while (isspace(*p))
        p++;

    // Parse digits
    for (; *p; p++) {
        if (isspace(*p))
            break;
        if (!isdigit(*p))
            return false;
        strValue.insert(strValue.end(), *p);
    }

    // Skip trailing whitespace
    for (; *p; p++)
        if (!isspace(*p))
            return false;

    if (strValue.empty() || strValue.size() > 18) // guard against overflow
        return false;

    nRet = atoi64(strValue);
    return true;
}
