// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/kawheavy/blake3_wrapper.h>

namespace kawheavy {

uint256 Blake3(Span<const uint8_t> data) {
    CBlake3 hasher;
    hasher.Write(data);
    return hasher.Finalize();
}

uint256 Blake3(const std::string& data) {
    return Blake3(Span<const uint8_t>((const uint8_t*)data.data(), data.size()));
}

uint256 Blake3(const uint256& a, const uint256& b) {
    CBlake3 hasher;
    hasher.Write(MakeUCharSpan(a));
    hasher.Write(MakeUCharSpan(b));
    return hasher.Finalize();
}

uint256 Blake3Keyed(Span<const uint8_t> key, Span<const uint8_t> data) {
    assert(key.size() == 32);
    CBlake3 hasher(key);
    hasher.Write(data);
    return hasher.Finalize();
}

uint256 Blake3Context(const std::string& context, Span<const uint8_t> data) {
    CBlake3 hasher(context);
    hasher.Write(data);
    return hasher.Finalize();
}

} // namespace kawheavy
