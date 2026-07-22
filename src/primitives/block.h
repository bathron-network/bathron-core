// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2015-2021 The PIVX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_PRIMITIVES_BLOCK_H
#define BATHRON_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "keystore.h"
#include "serialize.h"
#include "uint256.h"

/** The DMM-designated masternode collects new transactions into a block,
 * hashes them into a merkle tree, and signs the block with its operator key
 * (no PoW/PoS — deterministic producer selection, see blockproducer.cpp).
 * The first transaction is the coinbase: it carries ONLY recycled fees
 * (block reward = 0; all M0 originates from SPV-verified BTC burns).
 */
class CBlockHeader
{
public:
    // header
    static const int32_t CURRENT_VERSION=11;    // since v5.2.99
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 hashFinalSaplingRoot;               // only for version 8+

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj) {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);

        // Sapling active
        if (obj.nVersion >= 8)
            READWRITE(obj.hashFinalSaplingRoot);
    }

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        hashFinalSaplingRoot.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // block signature — ECDSA by the producing MN's operator key (see CheckBlockSignature)
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable bool fChecked{false};

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
        READWRITE(obj.vchBlockSig);  // DMM: MN block signature
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        vchBlockSig.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        if (nVersion >= 8)
            block.hashFinalSaplingRoot   = hashFinalSaplingRoot;
        return block;
    }

    std::string ToString() const;
    void print() const;
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BATHRON_PRIMITIVES_BLOCK_H
