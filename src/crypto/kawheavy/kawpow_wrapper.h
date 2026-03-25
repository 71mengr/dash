// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_KAWHEAVY_KAWPOW_WRAPPER_H
#define BITCOIN_CRYPTO_KAWHEAVY_KAWPOW_WRAPPER_H

#include <uint256.h>
#include <vector>
#include <memory>

namespace kawheavy {

// Forward declarations
class DAG;
struct Params;

namespace kawpow {

/**
 * KawPow mixing function (memory-hard phase)
 * Uses DAG lookups for ASIC resistance
 */
uint256 Mix(
    const uint256& header_hash,
    uint32_t nonce,
    const DAG& dag,
    const Params& params
);

/**
 * Generate DAG item for a given index
 */
std::vector<uint8_t> GenerateDAGItem(
    const uint256& seed,
    uint64_t index
);

/**
 * Initialize KawPow subsystem
 */
void Init(const Params& params);

/**
 * Shutdown KawPow subsystem
 */
void Shutdown();

} // namespace kawpow
} // namespace kawheavy

#endif // BITCOIN_CRYPTO_KAWHEAVY_KAWPOW_WRAPPER_H
