// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/kawheavy/kawheavy.h>
#include <pow/kawheavy/kawheavy_dag.h>
#include <pow/kawheavy/kawheavy_kawpow.h>

#include <crypto/common.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>

namespace KAWHeavy {

namespace {
constexpr uint32_t MAX_EPOCH_LENGTH = 2'000'000;
constexpr uint32_t MAX_PROGPOW_ROUNDS = 4'096;
constexpr uint32_t MAX_KHEAVY_ROUNDS = 1'024;
} // namespace

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
    return ReadLE64(program_material.begin());
}

uint256 Mix(const uint256& seed, uint32_t epoch, uint64_t program_id, uint32_t rounds)
{
    uint256 state = Hash3(seed, epoch, program_id);
    const DagTable& dag_table = GetOrCreateDagTable(seed, epoch);

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

} // namespace KAWHeavy
