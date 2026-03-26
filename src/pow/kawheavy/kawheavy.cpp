// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/kawheavy/kawheavy.h>

#include <crypto/kawheavy/blake3_wrapper.h>
#include <pow/kawheavy/kawheavy_kawpow.h>
#include <uint256.h>


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

uint256 FinalMixWithBlake3(const uint256& kheavy_state)
{
    return kawheavy::Blake3(MakeUCharSpan(kheavy_state));
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
    // Phase 3: Final mixing with BLAKE3.
    return FinalMixWithBlake3(kheavy_state);
}

} // namespace KAWHeavy
