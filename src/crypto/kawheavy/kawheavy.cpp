// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/kawheavy/kawheavy.h>
#include <crypto/kawheavy/blake3_wrapper.h>
#include <crypto/kawheavy/kawpow_wrapper.h>
#include <crypto/kawheavy/kheavyhash_wrapper.h>
#include <crypto/common.h>

#include <arith_uint256.h>
#include <hash.h>
#include <logging.h>
#include <pow.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <atomic>
#include <cstdio>
#include <chrono>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>

namespace kawheavy {

namespace {
    struct GlobalState {
        Params params;
        std::unique_ptr<DAG> current_dag;
        std::atomic<bool> initialized{false};
        std::atomic<uint64_t> hash_count{0};
        std::chrono::steady_clock::time_point start_time;
        
        GlobalState() : start_time(std::chrono::steady_clock::now()) {}
    };
    
    std::unique_ptr<GlobalState> g_state;
    std::once_flag g_init_flag;
    std::shared_mutex g_dag_mutex;

    void EnsureInitialized()
    {
        if (g_state == nullptr || !g_state->initialized.load()) {
            Init(Params::Mainnet());
        }
    }
}

//=============================================================================
// Parameter Presets
//=============================================================================

Params Params::Mainnet()
{
    Params p;
    p.epoch_length = 30000;
    p.progpow_rounds = 64;
    p.kheavy_rounds = 64;
    p.final_rounds = 8;
    return p;
}

Params Params::Testnet()
{
    Params p = Mainnet();
    p.epoch_length = 30000;
    return p;
}

Params Params::Regtest()
{
    Params p = Mainnet();
    p.epoch_length = 1000;
    return p;
}

//=============================================================================
// DAG Implementation
//=============================================================================

DAG::DAG(uint32_t epoch, const uint256& seed_hash, const Params& params)
    : m_epoch(epoch)
    , m_seed_hash(seed_hash)
{
    if (!LoadFromDisk()) {
        LogPrintf("KAWHeavy: Generating DAG for epoch %u...\n", epoch);
        if (!Generate(params)) {
            throw std::runtime_error(strprintf("KAWHeavy: Failed to generate DAG for epoch %u", epoch));
        }
        SaveToDisk();
    }
}

DAG::~DAG() = default;

DAG::DAG(DAG&& other) noexcept
    : m_epoch(other.m_epoch)
    , m_seed_hash(std::move(other.m_seed_hash))
    , m_items(std::move(other.m_items))
{
}

DAG& DAG::operator=(DAG&& other) noexcept
{
    if (this != &other) {
        m_epoch = other.m_epoch;
        m_seed_hash = std::move(other.m_seed_hash);
        m_items = std::move(other.m_items);
    }
    return *this;
}

bool DAG::Generate(const Params& params)
{
    const uint64_t item_count = 64 * 1024 * 1024 / 64; // 64MB for testing
    m_items.reserve(item_count);
    
    for (uint64_t i = 0; i < item_count; ++i) {
        std::array<uint8_t, 64> item;
        auto hash = Blake3Context("KAWHeavy_DAG", 
            Span<const uint8_t>(m_seed_hash.begin(), 32));
        memcpy(item.data(), hash.begin(), 32);
        m_items.push_back(item);
        
        if (i % (item_count / 100) == 0 && i > 0) {
            LogPrintf("KAWHeavy: DAG generation: %.1f%%\n", 100.0 * i / item_count);
        }
    }
    
    return true;
}

bool DAG::LoadFromDisk()
{
    const std::string path = GetFilePath(m_epoch);
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t epoch;
    uint256 seed_hash;
    uint64_t item_count;
    
    file.read(reinterpret_cast<char*>(&epoch), sizeof(epoch));
    file.read(reinterpret_cast<char*>(seed_hash.begin()), 32);
    file.read(reinterpret_cast<char*>(&item_count), sizeof(item_count));
    
    if (epoch != m_epoch || seed_hash != m_seed_hash) return false;
    
    m_items.resize(item_count);
    file.read(reinterpret_cast<char*>(m_items.data()), item_count * sizeof(m_items[0]));
    
    return file.good();
}

bool DAG::SaveToDisk() const
{
    const std::string path = GetFilePath(m_epoch);
    const std::string temp = path + ".tmp";
    
    std::ofstream file(temp, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t epoch = m_epoch;
    uint64_t item_count = m_items.size();
    
    file.write(reinterpret_cast<const char*>(&epoch), sizeof(epoch));
    file.write(reinterpret_cast<const char*>(m_seed_hash.begin()), 32);
    file.write(reinterpret_cast<const char*>(&item_count), sizeof(item_count));
    file.write(reinterpret_cast<const char*>(m_items.data()), item_count * sizeof(m_items[0]));
    file.close();
    
    return rename(temp.c_str(), path.c_str()) == 0;
}

std::string DAG::GetFilePath(uint32_t epoch)
{
    return strprintf("%s/kawheavy_dag_%u.dat", fs::PathToString(gArgs.GetDataDirNet()), epoch);
}

std::optional<const std::array<uint8_t, 64>*> DAG::GetItem(uint64_t index) const
{
    if (index >= m_items.size()) return std::nullopt;
    return &m_items[index];
}

std::shared_ptr<const DAG> DAG::LoadOrGenerate(uint32_t epoch, const Params& params)
{
    static std::mutex cache_mutex;
    static std::map<uint32_t, std::weak_ptr<const DAG>> cache;
    
    std::lock_guard<std::mutex> lock(cache_mutex);
    
    auto it = cache.find(epoch);
    if (it != cache.end()) {
        if (auto dag = it->second.lock()) return dag;
        cache.erase(it);
    }
    
    uint256 seed_hash = Blake3Context("KAWHeavy_DAGSeed", 
        Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&epoch), sizeof(epoch)));
    
    auto dag = std::make_shared<const DAG>(epoch, seed_hash, params);
    cache[epoch] = dag;
    return dag;
}

//=============================================================================
// Main Hash Function
//=============================================================================

bool IsActive(int32_t height, const Consensus::Params& consensus)
{
    (void)consensus;
    return height >= 0;
}

uint256 GetHash(const CBlockHeader& header, int32_t height, const Consensus::Params& consensus)
{
    EnsureInitialized();

    // Serialize header
    std::vector<uint8_t> header_data;
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, header_data, 0);
    ss << header;
    
    // Compute header hash
    uint256 header_hash = Blake3(header_data);
    
    // Get DAG for this epoch
    uint32_t epoch = height / g_state->params.epoch_length;
    auto dag = DAG::LoadOrGenerate(epoch, g_state->params);
    
    // Phase 1: KawPow mixing (memory-hard)
    uint256 kawpow_result = kawpow::Mix(header_hash, header.nNonce, *dag, g_state->params);
    
    // Phase 2: KHeavyHash transformation (compute-hard)
    uint256 kheavy_result = kheavyhash::Transform(kawpow_result, header.nNonce, height, g_state->params);
    
    // Phase 3: Final mixing with Blake3
    uint256 result = kheavyhash::Finalize(kawpow_result, kheavy_result, header.nNonce, g_state->params);
    
    // Update statistics
    g_state->hash_count++;
    if (g_state->hash_count % 1000 == 0) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - g_state->start_time).count();
        double hps = g_state->hash_count.load() / (double)elapsed;
        LogPrint(BCLog::BENCHMARK, "KAWHeavy: %.2f H/s\n", hps);
    }
    
    return result;
}

bool CheckProofOfWork(const CBlockHeader& header, int32_t height, const Consensus::Params& consensus)
{
    EnsureInitialized();

    if (!IsActive(height, consensus)) {
        return ::CheckProofOfWork(header.GetHash(), header.nBits, consensus);
    }
    
    const uint256 hash = GetHash(header, height, consensus);
    const arith_uint256 target = arith_uint256().SetCompact(header.nBits);
    
    return UintToArith256(hash) <= target;
}

namespace kawpow {
uint256 Mix(
    const uint256& header_hash,
    uint32_t nonce,
    const DAG& dag,
    const Params& params)
{
    const auto item_count = std::max<uint64_t>(1, dag.GetItemCount());
    uint64_t index = ReadLE64(header_hash.begin()) ^ static_cast<uint64_t>(nonce);
    std::array<uint8_t, 36> seed_buf{};
    memcpy(seed_buf.data(), header_hash.begin(), 32);
    WriteLE32(seed_buf.data() + 32, nonce);
    uint256 state = Blake3(Span<const uint8_t>(seed_buf.data(), seed_buf.size()));

    for (uint32_t round = 0; round < params.progpow_rounds; ++round) {
        index = (index + round * 0x9e3779b185ebca87ULL) % item_count;
        const auto item = dag.GetItem(index);
        if (!item.has_value()) continue;
        const auto* dag_item = *item;

        std::array<uint8_t, 64> mixed{};
        memcpy(mixed.data(), state.begin(), 32);
        for (size_t i = 0; i < mixed.size(); ++i) {
            mixed[i] ^= (*dag_item)[(i + round) % mixed.size()];
        }
        state = Blake3(Span<const uint8_t>(mixed.data(), mixed.size()));
    }

    return state;
}
} // namespace kawpow

namespace kheavyhash {
uint256 Transform(
    const uint256& input,
    uint32_t nonce,
    uint32_t height,
    const Params& params)
{
    uint256 state = input;
    for (uint32_t round = 0; round < params.kheavy_rounds; ++round) {
        std::array<uint8_t, 40> buf{};
        memcpy(buf.data(), state.begin(), 32);
        WriteLE32(buf.data() + 32, nonce);
        WriteLE32(buf.data() + 36, height ^ round);
        state = Blake3(Span<const uint8_t>(buf.data(), buf.size()));
    }
    return state;
}

uint256 Finalize(
    const uint256& kawpow_result,
    const uint256& kheavy_result,
    uint32_t nonce,
    const Params& params)
{
    uint256 state = Blake3(kawpow_result, kheavy_result);
    for (uint32_t round = 0; round < params.final_rounds; ++round) {
        std::array<uint8_t, 36> buf{};
        memcpy(buf.data(), state.begin(), 32);
        WriteLE32(buf.data() + 32, nonce + round);
        state = Blake3(Span<const uint8_t>(buf.data(), buf.size()));
    }
    return state;
}
} // namespace kheavyhash

void Init(const Params& params)
{
    std::call_once(g_init_flag, [&params]() {
        g_state = std::make_unique<GlobalState>();
        g_state->params = params;
        g_state->initialized = true;
        
        LogPrintf("KAWHeavy initialized:\n");
        LogPrintf("  Epoch length: %u\n", params.epoch_length);
        LogPrintf("  ProgPow rounds: %u\n", params.progpow_rounds);
        LogPrintf("  KHeavy rounds: %u\n", params.kheavy_rounds);
        LogPrintf("  Final rounds: %u\n", params.final_rounds);
    });
}

void Shutdown()
{
    g_state.reset();
}

} // namespace kawheavy
