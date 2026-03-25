// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_KAWHEAVY_KHEAVY_H
#define BITCOIN_POW_KAWHEAVY_KHEAVY_H

#include <array>
#include <cstdint>

namespace KAWHeavy {

void KHeavyHashRound(std::array<uint64_t, 4>& lanes, uint64_t round_tag);

} // namespace KAWHeavy

#endif // BITCOIN_POW_KAWHEAVY_KHEAVY_H
