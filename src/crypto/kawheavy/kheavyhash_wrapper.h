// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_KAWHEAVY_KHEAVYHASH_WRAPPER_H
#define BITCOIN_CRYPTO_KAWHEAVY_KHEAVYHASH_WRAPPER_H

#include <uint256.h>
#include <array>

namespace kawheavy {

struct Params;

namespace kheavyhash {

constexpr size_t MATRIX_DIM = 64;
constexpr size_t OUTPUT_SIZE = 32;

/**
 * KHeavyHash transformation (compute-hard phase)
 * Uses GF(16) matrix operations for ASIC resistance
 */
uint256 Transform(
    const uint256& input,
    uint32_t nonce,
    uint32_t height,
    const Params& params
);

/**
 * Final mixing with Blake3
 */
uint256 Finalize(
    const uint256& kawpow_result,
    const uint256& kheavy_result,
    uint32_t nonce,
    const Params& params
);

/**
 * GF(16) operations
 */
namespace gf16 {
    uint8_t mul(uint8_t a, uint8_t b);
    uint8_t add(uint8_t a, uint8_t b);
    uint8_t inv(uint8_t a);
}

/**
 * Matrix operations over GF(16)
 */
class Matrix {
private:
    std::array<std::array<uint8_t, MATRIX_DIM>, MATRIX_DIM> m_data;
    
public:
    Matrix() = default;
    
    uint8_t& operator()(size_t i, size_t j) { return m_data[i][j]; }
    const uint8_t& operator()(size_t i, size_t j) const { return m_data[i][j]; }
    
    uint8_t Rank() const;
    bool IsFullRank() const { return Rank() == MATRIX_DIM; }
    
    static Matrix Random(const std::array<uint8_t, 32>& seed);
    static Matrix GenerateFullRank(const std::array<uint8_t, 32>& seed);
};

} // namespace kheavyhash
} // namespace kawheavy

#endif // BITCOIN_CRYPTO_KAWHEAVY_KHEAVYHASH_WRAPPER_H
