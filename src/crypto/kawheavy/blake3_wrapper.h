// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_KAWHEAVY_BLAKE3_WRAPPER_H
#define BITCOIN_CRYPTO_KAWHEAVY_BLAKE3_WRAPPER_H

#include <span.h>
#include <uint256.h>
#include <string>
#include <array>

extern "C" {
#include "blake3/blake3.h"
}

namespace kawheavy {

/**
 * Blake3 hashing context for incremental hashing
 */
class CBlake3
{
private:
    blake3_hasher m_hasher;

public:
    CBlake3() { blake3_hasher_init(&m_hasher); }
    
    explicit CBlake3(Span<const uint8_t> key) {
        assert(key.size() == 32);
        blake3_hasher_init_keyed(&m_hasher, key.data());
    }
    
    explicit CBlake3(const std::string& context) {
        blake3_hasher_init_derive_key(&m_hasher, context.c_str());
    }
    
    CBlake3& Write(Span<const uint8_t> data) {
        blake3_hasher_update(&m_hasher, data.data(), data.size());
        return *this;
    }
    
    CBlake3& Write(const std::string& data) {
        blake3_hasher_update(&m_hasher, data.data(), data.size());
        return *this;
    }
    
    void Finalize(uint8_t output[32]) {
        blake3_hasher_finalize(&m_hasher, output, 32);
    }
    
    uint256 Finalize() {
        uint256 result;
        blake3_hasher_finalize(&m_hasher, result.begin(), 32);
        return result;
    }
    
    void Reset() {
        blake3_hasher_init(&m_hasher);
    }
};

/** Convenience one-shot hash functions */
uint256 Blake3(Span<const uint8_t> data);
uint256 Blake3(const std::string& data);
uint256 Blake3(const uint256& a, const uint256& b);
uint256 Blake3Keyed(Span<const uint8_t> key, Span<const uint8_t> data);
uint256 Blake3Context(const std::string& context, Span<const uint8_t> data);

} // namespace kawheavy

#endif // BITCOIN_CRYPTO_KAWHEAVY_BLAKE3_WRAPPER_H
