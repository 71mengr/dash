// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_kawheavy.h>

#include <crypto/common.h>
#include <hash.h>
#include <uint256.h>

#include <algorithm>
#include <array>

namespace KAWHeavy {
namespace {

uint256 Hash3(const uint256& a, uint32_t b, uint64_t c)
{
    std::array<unsigned char, sizeof(uint32_t)> b_bytes{};
    std::array<unsigned char, sizeof(uint64_t)> c_bytes{};
    WriteLE32(b_bytes.data(), b);
    WriteLE64(c_bytes.data(), c);
    uint256 out;
    CHash256()
        .Write(MakeUCharSpan(a))
        .Write(b_bytes)
        .Write(c_bytes)
        .Finalize(out.begin());
    return out;
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

    for (uint32_t round = 0; round < rounds; ++round) {
        const uint64_t salt = (program_id << 1) ^ (static_cast<uint64_t>(round) * 0x9e3779b185ebca87ULL);
        uint256 hashed;
        CHash256()
            .Write(MakeUCharSpan(state))
            .Write(MakeUCharSpan(seed))
            .Write(Span{reinterpret_cast<const unsigned char*>(&salt), sizeof(salt)})
            .Finalize(hashed.begin());

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
        state = Hash3(state, round, round_tag);
    }

    return ::Hash(state);
}

uint256 Hash(const uint256& header_hash, uint32_t nonce, int32_t height, const Params& params)
{
    const uint256 seed = ComputeSeed(header_hash, nonce);
    const uint32_t epoch = GetEpoch(height, params.epoch_length);
    const uint64_t program_id = DeriveProgramId(seed, epoch, nonce);
    const uint256 mixed = Mix(seed, epoch, program_id, params.progpow_rounds);
    return Finalize(mixed, params.kheavy_rounds);
}

} // namespace KAWHeavy
