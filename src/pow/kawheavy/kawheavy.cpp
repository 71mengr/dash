// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/kawheavy/kawheavy.h>

#include <pow/kawheavy/kawheavy_kawpow.h>

#include <llvm-c-20/llvm-c/blake3.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <dlfcn.h>
#include <stdexcept>
#include <mutex>

namespace KAWHeavy {
namespace {

struct Blake3Api final {
    using InitFn = void (*)(llvm_blake3_hasher*);
    using UpdateFn = void (*)(llvm_blake3_hasher*, const void*, size_t);
    using FinalizeFn = void (*)(const llvm_blake3_hasher*, uint8_t*, size_t);

    void* handle{nullptr};
    InitFn init{nullptr};
    UpdateFn update{nullptr};
    FinalizeFn finalize{nullptr};
};

const Blake3Api& GetBlake3Api()
{
    static Blake3Api api;
    static std::once_flag once;
    std::call_once(once, [] {
        constexpr const char* candidates[] = {"libLLVM.so.20.1", "libLLVM.so.20", "libLLVM.so"};
        for (const char* soname : candidates) {
            api.handle = dlopen(soname, RTLD_LAZY | RTLD_LOCAL);
            if (api.handle != nullptr) {
                break;
            }
        }

        if (api.handle == nullptr) {
            return;
        }

        api.init = reinterpret_cast<Blake3Api::InitFn>(dlsym(api.handle, "llvm_blake3_hasher_init"));
        api.update = reinterpret_cast<Blake3Api::UpdateFn>(dlsym(api.handle, "llvm_blake3_hasher_update"));
        api.finalize = reinterpret_cast<Blake3Api::FinalizeFn>(dlsym(api.handle, "llvm_blake3_hasher_finalize"));
    });
    return api;
}

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
    const Blake3Api& api = GetBlake3Api();
    if (api.init == nullptr || api.update == nullptr || api.finalize == nullptr) {
        throw std::runtime_error("BLAKE3 symbols are unavailable: llvm_blake3_hasher_init/update/finalize");
    }

    llvm_blake3_hasher hasher{};
    std::array<uint8_t, LLVM_BLAKE3_OUT_LEN> blake3_out{};
    api.init(&hasher);
    api.update(&hasher, kheavy_state.begin(), uint256::size());
    api.finalize(&hasher, blake3_out.data(), blake3_out.size());
    uint256 out;
    static_assert(uint256::size() == LLVM_BLAKE3_OUT_LEN, "BLAKE3 output must be 32 bytes");
    std::copy(blake3_out.begin(), blake3_out.end(), out.begin());
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
    // Phase 3: Final mixing with BLAKE3.
    return FinalMixWithBlake3(kheavy_state);
}

} // namespace KAWHeavy
