// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_KAWHEAVY_H
#define BITCOIN_CRYPTO_KAWHEAVY_H

#include <consensus/params.h>
#include <primitives/block.h>
#include <uint256.h>

namespace kawheavy {

/**
 * KAWHeavy Proof of Work parameters
 */
struct Params {
    uint32_t epoch_length{30000};
    uint32_t progpow_rounds{64};
    uint32_t kheavy_rounds{64};
    uint32_t final_rounds{8};
    
    static Params Mainnet();
    static Params Testnet();
    static Params Regtest();
};

/**
 * DAG (Directed Acyclic Graph) for memory-hard PoW
 */
class DAG {
public:
    DAG(uint32_t epoch, const uint256& seed_hash, const Params& params);
    ~DAG();
    
    // Move-only
    DAG(const DAG&) = delete;
    DAG& operator=(const DAG&) = delete;
    DAG(DAG&&) noexcept;
    DAG& operator=(DAG&&) noexcept;
    
    uint32_t GetEpoch() const noexcept { return m_epoch; }
    const uint256& GetSeedHash() const noexcept { return m_seed_hash; }
    uint64_t GetItemCount() const noexcept { return m_items.size(); }
    
    std::optional<const std::array<uint8_t, 64>*> GetItem(uint64_t index) const;
    
    static std::shared_ptr<const DAG> LoadOrGenerate(uint32_t epoch, const Params& params);
    
private:
    uint32_t m_epoch;
    uint256 m_seed_hash;
    std::vector<std::array<uint8_t, 64>> m_items;
    
    bool Generate(const Params& params);
    bool LoadFromDisk();
    bool SaveToDisk() const;
    static std::string GetFilePath(uint32_t epoch);
};

/**
 * Check if KAWHeavy is active
 */
bool IsActive(const CBlockHeader& header, const Consensus::Params& consensus);

/**
 * Compute KAWHeavy hash (replaces X11)
 */
uint256 GetHash(const CBlockHeader& header, const Consensus::Params& consensus);

/**
 * Verify proof of work
 */
bool CheckProofOfWork(const CBlockHeader& header, const Consensus::Params& consensus);

/**
 * Initialize KAWHeavy subsystem
 */
void Init(const Params& params = Params::Mainnet());

/**
 * Shutdown KAWHeavy subsystem
 */
void Shutdown();

} // namespace kawheavy

#endif // BITCOIN_CRYPTO_KAWHEAVY_H
