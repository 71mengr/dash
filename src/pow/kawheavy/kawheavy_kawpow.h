// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_KAWHEAVY_KAWPOW_H
#define BITCOIN_POW_KAWHEAVY_KAWPOW_H

#include <cstdint>

class uint256;

namespace KAWHeavy {

struct Params;

struct EffectiveParams {
    uint32_t epoch_length;
    uint32_t progpow_rounds;
    uint32_t kheavy_rounds;
};

EffectiveParams GetEffectiveParams(const Params& params);
uint256 Hash3(const uint256& a, uint32_t b, uint64_t c);
uint256 Hash4(const uint256& a, const uint256& b, uint32_t c, uint64_t d);

} // namespace KAWHeavy

#endif // BITCOIN_POW_KAWHEAVY_KAWPOW_H
