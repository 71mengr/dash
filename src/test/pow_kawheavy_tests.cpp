// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_kawheavy.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_kawheavy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(epoch_derivation)
{
    BOOST_CHECK_EQUAL(KAWHeavy::GetEpoch(-1, 7500), 0U);
    BOOST_CHECK_EQUAL(KAWHeavy::GetEpoch(0, 7500), 0U);
    BOOST_CHECK_EQUAL(KAWHeavy::GetEpoch(7499, 7500), 0U);
    BOOST_CHECK_EQUAL(KAWHeavy::GetEpoch(7500, 7500), 1U);
    BOOST_CHECK_EQUAL(KAWHeavy::GetEpoch(15000, 7500), 2U);
    BOOST_CHECK_EQUAL(KAWHeavy::GetEpoch(15000, 0), 0U);
}

BOOST_AUTO_TEST_CASE(hash_test_vectors)
{
    const uint256 header_0 = uint256S("0x00");
    const uint256 header_1 = uint256S("1111111111111111111111111111111111111111111111111111111111111111");

    const auto hash_0 = KAWHeavy::Hash(header_0, 1, 1);
    const auto hash_1 = KAWHeavy::Hash(header_1, 42, 15000);

    BOOST_CHECK_EQUAL(hash_0.GetHex(), "bccef99adeeeba418e61754ecbd396cebbf66c978acad96d41d7b4bf1fb11780");
    BOOST_CHECK_EQUAL(hash_1.GetHex(), "6e5374e37d268db5e80f98ee9b3a88b3bd3b8af0d15d65b4e8f395f5ea66a28b");
}

BOOST_AUTO_TEST_CASE(program_id_stability)
{
    const uint256 seed = KAWHeavy::ComputeSeed(uint256S("0x1234"), 7);
    const auto id_a = KAWHeavy::DeriveProgramId(seed, 5, 7);
    const auto id_b = KAWHeavy::DeriveProgramId(seed, 5, 7);
    const auto id_c = KAWHeavy::DeriveProgramId(seed, 6, 7);

    BOOST_CHECK_EQUAL(id_a, id_b);
    BOOST_CHECK(id_a != id_c);
}

BOOST_AUTO_TEST_SUITE_END()
