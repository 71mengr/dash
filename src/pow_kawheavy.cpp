// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_kawheavy.h>

#include <crypto/common.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace KAWHeavy {
namespace {

#if defined(USE_EXTERNAL_KAWPOW) || defined(USE_EXTERNAL_KHEAVYHASH)
#error "External KAWPOW/KHEAVYHASH backends are not wired in yet. Define both backend adapters before enabling these flags."
#endif

// Conservative upper bounds to keep hashing costs predictable even if callers
// pass extreme parameters.
constexpr uint32_t MAX_EPOCH_LENGTH = 2'000'000;
constexpr uint32_t MAX_PROGPOW_ROUNDS = 4'096;
constexpr uint32_t MAX_KHEAVY_ROUNDS = 1'024;

struct EffectiveParams {
    uint32_t epoch_length;
    uint32_t progpow_rounds;
    uint32_t kheavy_rounds;
};

EffectiveParams GetEffectiveParams(const Params& params)
{
    EffectiveParams out;
    out.epoch_length = std::clamp(params.epoch_length, 1U, MAX_EPOCH_LENGTH);
    out.progpow_rounds = std::clamp(params.progpow_rounds, 1U, MAX_PROGPOW_ROUNDS);
    out.kheavy_rounds = std::clamp(params.kheavy_rounds, 1U, MAX_KHEAVY_ROUNDS);
    return out;
}

uint256 Hash3(const uint256& a, uint32_t b, uint64_t c)
{
    std::array<unsigned char, sizeof(uint32_t)> b_bytes{};
    std::array<unsigned char, sizeof(uint64_t)> c_bytes{};
    WriteLE32(b_bytes.data(), b);
    WriteLE64(c_bytes.data(), c);
    uint256 out_sha2;
    std::array<unsigned char, 32> out_sha3{};
    CHash256()
        .Write(MakeUCharSpan(a))
        .Write(b_bytes)
        .Write(c_bytes)
        .Finalize(out_sha2);
    SHA3_256()
        .Write(MakeUCharSpan(a))
        .Write(b_bytes)
        .Write(c_bytes)
        .Finalize(out_sha3);

    uint256 out;
    for (size_t i = 0; i < uint256::size(); ++i) {
        out.begin()[i] = out_sha2.begin()[i] ^ out_sha3[uint256::size() - 1 - i];
    }
    return out;
}

uint256 Hash4(const uint256& a, const uint256& b, uint32_t c, uint64_t d)
{
    std::array<unsigned char, sizeof(uint32_t)> c_bytes{};
    std::array<unsigned char, sizeof(uint64_t)> d_bytes{};
    WriteLE32(c_bytes.data(), c);
    WriteLE64(d_bytes.data(), d);

    uint256 out_sha2;
    std::array<unsigned char, 32> out_sha3{};
    CHash256()
        .Write(MakeUCharSpan(a))
        .Write(MakeUCharSpan(b))
        .Write(c_bytes)
        .Write(d_bytes)
        .Finalize(out_sha2);
    SHA3_256()
        .Write(MakeUCharSpan(a))
        .Write(MakeUCharSpan(b))
        .Write(c_bytes)
        .Write(d_bytes)
        .Finalize(out_sha3);

    uint256 out;
    for (size_t i = 0; i < uint256::size(); ++i) {
        out.begin()[i] = out_sha2.begin()[i] ^ out_sha3[uint256::size() - 1 - i];
    }
    return out;
}

void KHeavyHashRound(std::array<uint64_t, 4>& lanes, uint64_t round_tag)
{
    lanes[0] = (lanes[0] ^ lanes[1]) + ((lanes[0] << 13) | (lanes[0] >> 51));
    lanes[1] = (lanes[1] ^ lanes[2]) + ((lanes[1] << 11) | (lanes[1] >> 53));
    lanes[2] = (lanes[2] ^ lanes[3]) + ((lanes[2] << 17) | (lanes[2] >> 47));
    lanes[3] = (lanes[3] ^ lanes[0]) + ((lanes[3] << 19) | (lanes[3] >> 45));

    lanes[0] ^= round_tag;
    lanes[1] ^= (round_tag << 7) | (round_tag >> 57);
    lanes[2] += 0x9e3779b185ebca87ULL ^ round_tag;
    lanes[3] += 0xd1b54a32d192ed03ULL ^ (round_tag << 1);
}

std::array<unsigned char, uint256::size()> GenerateDagItem(const uint256& seed, uint32_t epoch, uint64_t index)
{
    uint256 item = Hash3(seed, epoch, index);

    // Perform deterministic expansion/mixing to simulate memory-hard lookup
    // costs while keeping generation lightweight and reproducible.
    for (uint32_t i = 0; i < 8; ++i) {
        item = Hash3(item, i, index ^ (static_cast<uint64_t>(i) << 32));
    }

    std::array<unsigned char, uint256::size()> out{};
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
        // Mix epoch with two 64-bit chunks from seed for stable hashing.
        const uint64_t s0 = ReadLE64(key.seed.begin());
        const uint64_t s1 = ReadLE64(key.seed.begin() + 8);
        return static_cast<size_t>(s0 ^ (s1 << 1) ^ (static_cast<uint64_t>(key.epoch) << 33));
    }
};

using DagItem = std::array<unsigned char, uint256::size()>;
using DagTable = std::vector<DagItem>;

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
            // Simple bounded cache eviction: drop an arbitrary oldest-in-map entry.
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

bool TryExternalHybridHash(const uint256& header_hash, uint32_t nonce, int32_t height, const EffectiveParams& params, uint256& out)
{
    (void)header_hash;
    (void)nonce;
    (void)height;
    (void)params;
    (void)out;
    return false;
}

} // namespace

uint256 ComputeSeed(const uint256& header_hash, uint32_t nonce)
{
    return Hash3(header_hash, nonce, 0x4b415748ULL);
}

uint32_t GetEpoch(int32_t height, uint32_t epoch_length)
{
    if (height <= 0 || epoch_length == 0) {
        return 0;
    }
    return static_cast<uint32_t>(height) / epoch_length;
}

uint64_t DeriveProgramId(const uint256& seed, uint32_t epoch, uint32_t nonce)
{
    const uint256 program_material = Hash3(seed, epoch, nonce);
    // Use low 64 bits as deterministic selector.
    return ReadLE64(program_material.begin());
}

uint256 Mix(const uint256& seed, uint32_t epoch, uint64_t program_id, uint32_t rounds)
{
    uint256 state = Hash3(seed, epoch, program_id);
    const DagTable& dag_table = DagCache::GetOrCreate(seed, epoch);

    for (uint32_t round = 0; round < rounds; ++round) {
        const uint64_t salt = (program_id << 1) ^ (static_cast<uint64_t>(round) * 0x9e3779b185ebca87ULL);
        const size_t idx = ReadLE64(state.begin()) % dag_table.size();
        const auto& dag_item = dag_table[idx];

        for (size_t i = 0; i < uint256::size(); ++i) {
            state.begin()[i] ^= dag_item[(i + round) % dag_item.size()];
        }

        const uint256 hashed = Hash4(state, seed, round, salt);

        for (size_t i = 0; i < uint256::size(); ++i) {
            state.begin()[i] ^= hashed.begin()[uint256::size() - 1 - i] ^ static_cast<unsigned char>(round + i);
        }
    }

    return state;
}

uint256 Finalize(const uint256& mix, uint32_t rounds)
{
    uint256 state = mix;
    constexpr uint64_t kRoundConstant = 0xd1b54a32d192ed03ULL;

    for (uint32_t round = 0; round < rounds; ++round) {
        const uint64_t round_tag = kRoundConstant + (static_cast<uint64_t>(round) << 32);
        std::array<uint64_t, 4> lanes{
            ReadLE64(state.begin()),
            ReadLE64(state.begin() + 8),
            ReadLE64(state.begin() + 16),
            ReadLE64(state.begin() + 24),
        };

        // KHeavyHash-inspired integer mixing round.
        for (int i = 0; i < 8; ++i) {
            KHeavyHashRound(lanes, round_tag ^ static_cast<uint64_t>(i));
        }

        std::array<unsigned char, uint256::size()> heavy_state{};
        WriteLE64(heavy_state.data(), lanes[0]);
        WriteLE64(heavy_state.data() + 8, lanes[1]);
        WriteLE64(heavy_state.data() + 16, lanes[2]);
        WriteLE64(heavy_state.data() + 24, lanes[3]);

        uint256 heavy_uint;
        std::copy(heavy_state.begin(), heavy_state.end(), heavy_uint.begin());
        state = Hash4(state, heavy_uint, round, round_tag);
    }

    return ::Hash(state);
}

uint256 Hash(const uint256& header_hash, uint32_t nonce, int32_t height, const Params& params)
{
    const EffectiveParams effective = GetEffectiveParams(params);
    uint256 external_hash;
    if (TryExternalHybridHash(header_hash, nonce, height, effective, external_hash)) {
        return external_hash;
    }
    const uint256 seed = ComputeSeed(header_hash, nonce);
    const uint32_t epoch = GetEpoch(height, effective.epoch_length);
    const uint64_t program_id = DeriveProgramId(seed, epoch, nonce);
    const uint256 mixed = Mix(seed, epoch, program_id, effective.progpow_rounds);
    return Finalize(mixed, effective.kheavy_rounds);
}

} // namespace KAWHeavy
