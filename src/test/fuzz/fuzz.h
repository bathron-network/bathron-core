// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_TEST_FUZZ_FUZZ_H
#define BATHRON_TEST_FUZZ_FUZZ_H

#include <functional>
#include <stdint.h>
#include <string>
#include <vector>


const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

void test_one_input(std::vector<uint8_t> buffer);

#endif // BATHRON_TEST_FUZZ_FUZZ_H
