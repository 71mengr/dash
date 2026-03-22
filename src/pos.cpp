// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos.h>

#include <arith_uint256.h>
#include <hash.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace {
constexpr long double MAX_HASH_PLUS_ONE = 340282366920938463463374607431768211456.0L; // 2^128

long double HashToUnitInterval(const uint256& hash)
{
    const uint64_t hi = hash.GetUint64(3);
    const uint64_t hi_mid = hash.GetUint64(2);

    const long double numerator =
        static_cast<long double>(hi) * 18446744073709551616.0L +
        static_cast<long double>(hi_mid);

    long double sample = numerator / MAX_HASH_PLUS_ONE;
    if (sample >= 1.0L) {
        sample = std::nextafter(1.0L, 0.0L);
    }
    return std::max(0.0L, sample);
}

uint64_t SelectSubUsersFromHash(const uint256& hash, uint64_t user_weight, uint64_t total_weight, uint64_t expected_committee_size)
{
    if (user_weight == 0 || total_weight == 0 || expected_committee_size == 0) {
        return 0;
    }

    const long double p = std::min<long double>(1.0L,
        static_cast<long double>(expected_committee_size) / static_cast<long double>(total_weight));
    if (p >= 1.0L) {
        return user_weight;
    }
    const long double q = 1.0L - p;
    const long double u = HashToUnitInterval(hash);

    long double probability = std::pow(q, static_cast<long double>(user_weight));
    long double cumulative = probability;
    if (u < cumulative) {
        return 0;
    }

    for (uint64_t j = 1; j <= user_weight; ++j) {
        probability *= (static_cast<long double>(user_weight - (j - 1)) / static_cast<long double>(j)) * (p / std::max(q, std::numeric_limits<long double>::min()));
        cumulative += probability;
        if (u < cumulative || j == user_weight) {
            return j;
        }
    }

    return user_weight;
}
} // namespace

uint256 GetStakeKernelHash(const COutPoint& prevout, uint32_t nTimeBlockFrom, uint32_t nTimeTx, uint32_t nTimeTxPrev)
{
    HashWriter ss{};
    ss << prevout;
    ss << nTimeBlockFrom;
    ss << nTimeTxPrev;
    ss << nTimeTx;
    return ss.GetHash();
}

bool CheckProofOfStakeKernelHash(const COutPoint& prevout, uint32_t nTimeBlockFrom, uint32_t nTimeTx, uint32_t nTimeTxPrev, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    return UintToArith256(GetStakeKernelHash(prevout, nTimeBlockFrom, nTimeTx, nTimeTxPrev)) <= bnTarget;
}

uint256 GetAlgorandSortitionHash(const uint256& seed, uint64_t round, uint64_t step, const uint256& participant)
{
    HashWriter ss{};
    ss << seed;
    ss << round;
    ss << step;
    ss << participant;
    return ss.GetHash();
}

AlgorandSortitionResult SelectAlgorandCommittee(const uint256& seed, uint64_t round, uint64_t step, const uint256& participant, uint64_t user_weight, uint64_t total_weight, uint64_t expected_committee_size)
{
    const uint256 hash = GetAlgorandSortitionHash(seed, round, step, participant);
    return {hash, SelectSubUsersFromHash(hash, user_weight, total_weight, expected_committee_size)};
}

bool CheckAlgorandCommittee(const uint256& seed, uint64_t round, uint64_t step, const uint256& participant, uint64_t user_weight, uint64_t total_weight, uint64_t expected_committee_size, uint64_t claimed_sub_users)
{
    return SelectAlgorandCommittee(seed, round, step, participant, user_weight, total_weight, expected_committee_size).sub_users == claimed_sub_users;
}
