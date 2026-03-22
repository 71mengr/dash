// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos.h>
#include <uint256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pos_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(algorand_sortition_is_deterministic)
{
    const uint256 seed = uint256S("01");
    const uint256 participant = uint256S("02");

    const auto first = SelectAlgorandCommittee(seed, /*round=*/7, /*step=*/3, participant, /*user_weight=*/25, /*total_weight=*/100, /*expected_committee_size=*/10);
    const auto second = SelectAlgorandCommittee(seed, /*round=*/7, /*step=*/3, participant, /*user_weight=*/25, /*total_weight=*/100, /*expected_committee_size=*/10);
    const auto changed = SelectAlgorandCommittee(seed, /*round=*/8, /*step=*/3, participant, /*user_weight=*/25, /*total_weight=*/100, /*expected_committee_size=*/10);

    BOOST_CHECK_EQUAL(first.hash, second.hash);
    BOOST_CHECK_EQUAL(first.sub_users, second.sub_users);
    BOOST_CHECK(first.hash != changed.hash || first.sub_users != changed.sub_users);
}

BOOST_AUTO_TEST_CASE(algorand_sortition_respects_zero_inputs)
{
    const uint256 seed = uint256S("03");
    const uint256 participant = uint256S("04");

    BOOST_CHECK_EQUAL(SelectAlgorandCommittee(seed, 1, 1, participant, /*user_weight=*/0, /*total_weight=*/100, /*expected_committee_size=*/10).sub_users, 0U);
    BOOST_CHECK_EQUAL(SelectAlgorandCommittee(seed, 1, 1, participant, /*user_weight=*/10, /*total_weight=*/0, /*expected_committee_size=*/10).sub_users, 0U);
    BOOST_CHECK_EQUAL(SelectAlgorandCommittee(seed, 1, 1, participant, /*user_weight=*/10, /*total_weight=*/100, /*expected_committee_size=*/0).sub_users, 0U);
}

BOOST_AUTO_TEST_CASE(algorand_sortition_verifier_matches_selection)
{
    const uint256 seed = uint256S("05");
    const uint256 participant = uint256S("06");

    const auto result = SelectAlgorandCommittee(seed, /*round=*/11, /*step=*/4, participant, /*user_weight=*/40, /*total_weight=*/250, /*expected_committee_size=*/30);

    BOOST_CHECK(CheckAlgorandCommittee(seed, 11, 4, participant, 40, 250, 30, result.sub_users));
    BOOST_CHECK(!CheckAlgorandCommittee(seed, 11, 4, participant, 40, 250, 30, result.sub_users + 1));
}

BOOST_AUTO_TEST_SUITE_END()
