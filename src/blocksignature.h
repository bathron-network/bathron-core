// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BLOCKSIGNATURE_H
#define BATHRON_BLOCKSIGNATURE_H

#include "key.h"
#include "primitives/block.h"

bool CheckBlockSignature(const CBlock& block);

#endif // BATHRON_BLOCKSIGNATURE_H
