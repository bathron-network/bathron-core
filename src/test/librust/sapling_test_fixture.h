// Copyright (c) 2020-2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_TEST_LIBRUST_SAPLING_TEST_FIXTURE_H
#define BATHRON_TEST_LIBRUST_SAPLING_TEST_FIXTURE_H

#include "test/test_bathron.h"

/**
 * Testing setup that configures a complete environment for Sapling testing.
 */
struct SaplingTestingSetup : public TestingSetup
{
    explicit SaplingTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    ~SaplingTestingSetup();
};

/**
 * Regtest setup with sapling always active
 */
struct SaplingRegTestingSetup : public SaplingTestingSetup
{
    SaplingRegTestingSetup();
};


#endif // BATHRON_TEST_LIBRUST_SAPLING_TEST_FIXTURE_H
