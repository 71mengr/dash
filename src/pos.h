// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POS_H
#define BITCOIN_POS_H

#include <consensus/params.h>
#include <uint256.h>

#include <cstdint>

class COutPoint;

uint256 GetStakeKernelHash(const COutPoint& prevout, uint32_t nTimeBlockFrom, uint32_t nTimeTx, uint32_t nTimeTxPrev);
bool CheckProofOfStakeKernelHash(const COutPoint& prevout, uint32_t nTimeBlockFrom, uint32_t nTimeTx, uint32_t nTimeTxPrev, unsigned int nBits, const Consensus::Params& params);

struct AlgorandSortitionResult
{
    uint256 hash;
    uint64_t sub_users{0};

    [[nodiscard]] bool selected() const { return sub_users > 0; }
};

uint256 GetAlgorandSortitionHash(const uint256& seed, uint64_t round, uint64_t step, const uint256& participant);
AlgorandSortitionResult SelectAlgorandCommittee(const uint256& seed, uint64_t round, uint64_t step, const uint256& participant, uint64_t user_weight, uint64_t total_weight, uint64_t expected_committee_size);
bool CheckAlgorandCommittee(const uint256& seed, uint64_t round, uint64_t step, const uint256& participant, uint64_t user_weight, uint64_t total_weight, uint64_t expected_committee_size, uint64_t claimed_sub_users);

#endif // BITCOIN_POS_H
