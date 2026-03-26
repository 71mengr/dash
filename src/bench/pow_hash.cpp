// Copyright (c) 2025-2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <hash.h>
#include <pow/kawheavy/kawheavy.h>

#include <vector>

namespace {
//! Bytes to hash per iteration
static constexpr size_t BUFFER_SIZE{1000 * 1000};

inline void Pow_KAWHeavy(benchmark::Bench& bench, const size_t bytes)
{
    uint256 hash{};
    std::vector<uint8_t> in(bytes, 0);
    uint32_t nonce{0};
    constexpr int32_t height{0};

    bench.minEpochIterations(20).batch(in.size()).unit("byte").run([&] {
        const uint256 header_hash = Hash(in.begin(), in.end());
        hash = KAWHeavy::Hash(header_hash, nonce++, height);
    });
}
} // anonymous namespace

static void Pow_KAWHeavy_0032b(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, 32); }
static void Pow_KAWHeavy_0080b(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, 80); }
static void Pow_KAWHeavy_0128b(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, 128); }
static void Pow_KAWHeavy_0512b(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, 512); }
static void Pow_KAWHeavy_1024b(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, 1024); }
static void Pow_KAWHeavy_2048b(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, 2048); }
static void Pow_KAWHeavy_1M(benchmark::Bench& bench) { return Pow_KAWHeavy(bench, BUFFER_SIZE); }

BENCHMARK(Pow_KAWHeavy_0032b);
BENCHMARK(Pow_KAWHeavy_0080b);
BENCHMARK(Pow_KAWHeavy_0128b);
BENCHMARK(Pow_KAWHeavy_0512b);
BENCHMARK(Pow_KAWHeavy_1024b);
BENCHMARK(Pow_KAWHeavy_2048b);
BENCHMARK(Pow_KAWHeavy_1M);
