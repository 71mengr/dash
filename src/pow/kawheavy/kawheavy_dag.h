// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_KAWHEAVY_DAG_H
#define BITCOIN_POW_KAWHEAVY_DAG_H

#include <array>
#include <cstdint>
#include <vector>

class uint256;

namespace KAWHeavy {

using DagItem = std::array<unsigned char, 32>;
using DagTable = std::vector<DagItem>;

const DagTable& GetOrCreateDagTable(const uint256& seed, uint32_t epoch);

} // namespace KAWHeavy

#endif // BITCOIN_POW_KAWHEAVY_DAG_H
