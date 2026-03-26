// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/kawheavy/kawheavy.h>
#include <hash.h>
#include <primitives/block.h>
#include <uint256.h>


namespace {

unsigned int CalculateAdaptiveWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    static constexpr int64_t nWindow{60};

    if (!pindexLast || pindexLast->nHeight < nWindow) {
        return bnPowLimit.GetCompact();
    }

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 weighted_target_sum;
    int64_t total_weight{0};

    for (int64_t block = 1; block <= nWindow; ++block) {
        const arith_uint256 target = arith_uint256().SetCompact(pindex->nBits);
        const int64_t weight = block;
        weighted_target_sum += target * weight;
        total_weight += weight;

        if (block != nWindow) {
            if (pindex->pprev == nullptr) {
                return bnPowLimit.GetCompact();
            }
            pindex = pindex->pprev;
        }
    }

    arith_uint256 bnNew = weighted_target_sum / total_weight;

    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    const int64_t nTargetTimespan = (nWindow - 1) * params.nPowTargetSpacing;

    if (nActualTimespan < nTargetTimespan / 2) nActualTimespan = nTargetTimespan / 2;
    if (nActualTimespan > nTargetTimespan * 2) nActualTimespan = nTargetTimespan * 2;

    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

} // namespace

unsigned int GetNextWorkRequiredBTC(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 2.5 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 1 day worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

   return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    assert(pblock != nullptr);
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    // this is only active on devnets
    if (pindexLast->nHeight < params.nMinimumDifficultyBlocks) {
        return bnPowLimit.GetCompact();
    }

    // Note: GetNextWorkRequiredBTC has its own special difficulty rule,
    // so we only apply this to the adaptive algorithm used on live chains.
    if (params.fPowNoRetargeting) {
        return bnPowLimit.GetCompact();
    }

    if (params.fPowAllowMinDifficultyBlocks) {
        // recent block is more than 2 hours old
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + 2 * 60 * 60) {
            return bnPowLimit.GetCompact();
        }
        // recent block is more than 10 minutes old
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 4) {
            arith_uint256 bnNew = arith_uint256().SetCompact(pindexLast->nBits) * 10;
            if (bnNew > bnPowLimit) {
                return bnPowLimit.GetCompact();
            }
            return bnNew.GetCompact();
        }
    }

    return CalculateAdaptiveWorkRequired(pindexLast, params);
}

// for DIFF_BTC only!
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

uint256 GetKAWHeavyHash(const CBlockHeader& block, int32_t height, const Consensus::Params& params)
{
    return kawheavy::GetHash(block, height, params);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
