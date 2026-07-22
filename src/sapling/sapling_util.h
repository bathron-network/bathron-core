// Copyright (c) 2016-2020 The ZCash developers
// Copyright (c) 2020 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_SAPLING_SAPLING_UTIL_H
#define BATHRON_SAPLING_SAPLING_UTIL_H

#include "fs.h"
#include "uint256.h"

#include <sodium.h>
#include <vector>
#include <cstdint>

std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes);
uint64_t convertVectorToInt(const std::vector<bool>& v);

// random number generator using sodium.
uint256 random_uint256();

#endif // BATHRON_SAPLING_SAPLING_UTIL_H
