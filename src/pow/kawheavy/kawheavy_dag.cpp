// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/kawheavy/kawheavy_dag.h>

#include <pow/kawheavy/kawheavy_kawpow.h>

#include <crypto/common.h>
#include <uint256.h>

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace KAWHeavy {
namespace {

DagItem GenerateDagItem(const uint256& seed, uint32_t epoch, uint64_t index)
{
    uint256 item = Hash3(seed, epoch, index);
    for (uint32_t i = 0; i < 8; ++i) {
        item = Hash3(item, i, index ^ (static_cast<uint64_t>(i) << 32));
    }

    DagItem out{};
    std::copy_n(item.begin(), out.size(), out.begin());
    return out;
}

struct DagKey {
    uint256 seed;
    uint32_t epoch;

    bool operator==(const DagKey& other) const
    {
        return epoch == other.epoch && seed == other.seed;
    }
};

struct DagKeyHasher {
    size_t operator()(const DagKey& key) const
    {
        const uint64_t s0 = ReadLE64(key.seed.begin());
        const uint64_t s1 = ReadLE64(key.seed.begin() + 8);
        return static_cast<size_t>(s0 ^ (s1 << 1) ^ (static_cast<uint64_t>(key.epoch) << 33));
    }
};

class DagCache final {
public:
    static const DagTable& GetOrCreate(const uint256& seed, uint32_t epoch)
    {
        static DagCache cache;
        return cache.GetOrCreateInternal(seed, epoch);
    }

private:
    static constexpr size_t DAG_TABLE_ITEMS = 512;
    static constexpr size_t MAX_CACHED_TABLES = 4;

    const DagTable& GetOrCreateInternal(const uint256& seed, uint32_t epoch)
    {
        const DagKey key{seed, epoch};

        {
            std::shared_lock<std::shared_mutex> read_lock(m_mutex);
            auto it = m_tables.find(key);
            if (it != m_tables.end()) {
                return it->second;
            }
        }

        std::unique_lock<std::shared_mutex> write_lock(m_mutex);
        auto it = m_tables.find(key);
        if (it != m_tables.end()) {
            return it->second;
        }

        if (m_tables.size() >= MAX_CACHED_TABLES) {
            m_tables.erase(m_tables.begin());
        }

        DagTable table;
        table.reserve(DAG_TABLE_ITEMS);
        for (uint64_t i = 0; i < DAG_TABLE_ITEMS; ++i) {
            table.push_back(GenerateDagItem(seed, epoch, i));
        }

        auto [inserted_it, _] = m_tables.emplace(key, std::move(table));
        return inserted_it->second;
    }

    std::shared_mutex m_mutex;
    std::unordered_map<DagKey, DagTable, DagKeyHasher> m_tables;
};

} // namespace

const DagTable& GetOrCreateDagTable(const uint256& seed, uint32_t epoch)
{
    return DagCache::GetOrCreate(seed, epoch);
}

} // namespace KAWHeavy
