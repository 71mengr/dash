// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_KAWHEAVY_KAWHEAVY_H
#define BITCOIN_POW_KAWHEAVY_KAWHEAVY_H

#include <stdint.h>

class uint256;

namespace KAWHeavy {

struct Params {
    uint32_t epoch_length{7500};
    uint32_t progpow_rounds{64};
    uint32_t kheavy_rounds{16};
};

uint256 ComputeSeed(const uint256& header_hash, uint32_t nonce);
uint32_t GetEpoch(int32_t height, uint32_t epoch_length);
uint64_t DeriveProgramId(const uint256& seed, uint32_t epoch, uint32_t nonce);
uint256 Mix(const uint256& seed, uint32_t epoch, uint64_t program_id, uint32_t rounds);
uint256 Finalize(const uint256& mix, uint32_t rounds);
uint256 Hash(const uint256& header_hash, uint32_t nonce, int32_t height, const Params& params = Params{});

} // namespace KAWHeavy

#endif // BITCOIN_POW_KAWHEAVY_KAWHEAVY_H
