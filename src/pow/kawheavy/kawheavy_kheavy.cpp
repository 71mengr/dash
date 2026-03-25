// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/kawheavy/kawheavy.h>
#include <pow/kawheavy/kawheavy_kawpow.h>
#include <pow/kawheavy/kawheavy_kheavy.h>

#include <crypto/common.h>
#include <uint256.h>

#include <algorithm>
#include <array>

namespace KAWHeavy {

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

    return state;
}

} // namespace KAWHeavy
