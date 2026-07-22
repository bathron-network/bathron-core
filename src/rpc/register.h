// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_RPC_REGISTER_H
#define BATHRON_RPC_REGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void RegisterBlockchainRPCCommands(CRPCTable& tableRPC);
/** Register P2P networking RPC commands */
void RegisterNetRPCCommands(CRPCTable& tableRPC);
/** Register miscellaneous RPC commands */
void RegisterMiscRPCCommands(CRPCTable& tableRPC);
/** Register mining RPC commands */
void RegisterMiningRPCCommands(CRPCTable& tableRPC);
/** Register raw transaction RPC commands */
void RegisterRawTransactionRPCCommands(CRPCTable& tableRPC);
// BATHRON: Legacy RegisterMasternodeRPCCommands removed - DMN RPC in rpcevo.cpp
/** Register Evo RPC commands */
void RegisterEvoRPCCommands(CRPCTable &tableRPC);
/** Register Conditional Scripts RPC commands */
void RegisterConditionalRPCCommands(CRPCTable &tableRPC);
/** Register MN Stats RPC commands (Blueprint 18) */
void RegisterMNStatsRPCCommands(CRPCTable &tableRPC);
/** Register Settlement Layer RPC commands (BP30 - read-only state) */
void RegisterSettlementRPCCommands(CRPCTable &tableRPC);
/** Register Settlement Wallet RPC commands (BP30 - lock/unlock/transfer_m1) */
void RegisterSettlementWalletRPCCommands(CRPCTable &tableRPC);
/** Register BTC SPV RPC commands (BP09 - getbtctip, submitbtcheaders, etc.) */
void RegisterBtcSpvRPCCommands(CRPCTable &tableRPC);
/** Register Burn Claim RPC commands (BP10 - submitburnclaim, verifyburntx, etc.) */
void RegisterBurnClaimRPCCommands(CRPCTable &tableRPC);
/** Register BTC Headers RPC commands (BP-SPVMNPUB - getbtcheaderstip, publishbtcheaders, etc.) */
void RegisterBtcHeadersRPCCommands(CRPCTable &tableRPC);

static inline void RegisterAllCoreRPCCommands(CRPCTable& tableRPC)
{
    RegisterBlockchainRPCCommands(tableRPC);
    RegisterNetRPCCommands(tableRPC);
    RegisterMiscRPCCommands(tableRPC);
    RegisterMiningRPCCommands(tableRPC);
    RegisterRawTransactionRPCCommands(tableRPC);
    RegisterEvoRPCCommands(tableRPC);
    RegisterConditionalRPCCommands(tableRPC);
    RegisterMNStatsRPCCommands(tableRPC);
    RegisterSettlementRPCCommands(tableRPC);
    RegisterSettlementWalletRPCCommands(tableRPC);
    RegisterBtcSpvRPCCommands(tableRPC);
    RegisterBurnClaimRPCCommands(tableRPC);
    RegisterBtcHeadersRPCCommands(tableRPC);
}

#endif // BATHRON_RPC_REGISTER_H
