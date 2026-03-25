// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/kawheavy/kawheavy.h>

#include <pow/kawheavy/kawheavy_kawpow.h>

#include <crypto/x11/sph_blake.h>
#include <uint256.h>

#include <array>
#include <cstddef>

namespace KAWHeavy {
namespace {

bool TryExternalHybridHash(const uint256& header_hash, uint32_t nonce, int32_t height, const EffectiveParams& params, uint256& out)
{
    (void)header_hash;
    (void)nonce;
    (void)height;
    (void)params;
    (void)out;
    return false;
}

uint256 FinalMixWithBlake3Compat(const uint256& kheavy_state)
{
    sph_blake512_context ctx_blake{};
    std::array<unsigned char, 64> blake_out{};
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, kheavy_state.begin(), uint256::size());
    sph_blake512_close(&ctx_blake, blake_out.data());

    uint256 out;
    for (size_t i = 0; i < uint256::size(); ++i) {
        out.begin()[i] = blake_out[i] ^ blake_out[i + uint256::size()];
    }
    return out;
}

} // namespace

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
    // Phase 1: KawPow mixing (memory-hard).
    const uint256 kawpow_mixed = Mix(seed, epoch, program_id, effective.progpow_rounds);
    // Phase 2: KHeavyHash transformation (compute-hard).
    const uint256 kheavy_state = Finalize(kawpow_mixed, effective.kheavy_rounds);
    // Phase 3: Final mixing with Blake3-compatible output folding.
    return FinalMixWithBlake3Compat(kheavy_state);
}

} // namespace KAWHeavy
