// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <util/zero_knowledge.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(zero_knowledge_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(range_proof_detects_tampered_challenge)
{
    zkproof::RangeProof proof;
    BOOST_REQUIRE(proof.Create(/*value=*/21, /*min=*/18, /*max=*/65));

    auto extended = proof.GetProof();
    BOOST_REQUIRE(proof.Verify(/*min=*/18, /*max=*/65));

    extended.challenge_hash = uint256::ONE;

    zkproof::RangeProof tampered;
    BOOST_REQUIRE(tampered.SetProof(extended));
    BOOST_CHECK(!tampered.Verify(/*min=*/18, /*max=*/65));
}

BOOST_AUTO_TEST_CASE(composite_proof_rejects_trailing_bytes)
{
    const auto age_proof = zkproof::utils::CreateAgeProof(/*birth_date=*/1, /*min_age=*/0);
    BOOST_REQUIRE(age_proof.type == zkproof::ProofType::RANGE_PROOF);

    zkproof::CompositeProof composite;
    BOOST_REQUIRE(composite.AddProof(age_proof));
    BOOST_REQUIRE(composite.Create());

    auto extended = composite.GetProof();
    extended.proof_data.push_back(0x42);
    extended.challenge_hash = uint256();

    zkproof::CompositeProof reparsed;
    BOOST_CHECK(!reparsed.SetProof(extended));
}

BOOST_AUTO_TEST_SUITE_END()
