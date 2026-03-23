#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet credential RPCs and address generation gating."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class WalletCredentialTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Create a wallet and immediately start the verification flow")
        onboarding = self.nodes[0].createwallet(
            wallet_name="flow_wallet",
            require_verification=True,
            kyc_level="basic",
            kyc_callback_url="https://callback.example/kyc",
        )
        assert_equal(onboarding["name"], "flow_wallet")
        assert "verification_session" in onboarding
        assert onboarding["verification_session"]["session_id"]
        assert onboarding["verification_session"]["verification_url"]
        assert onboarding["verification_session"]["verification_url"].startswith("local-verification://start?")
        assert_equal(onboarding["verification_session"]["status"], "pending")

        flow_wallet = self.nodes[0].get_wallet_rpc("flow_wallet")
        flow_info = flow_wallet.getwalletinfo()["verification"]
        assert_equal(flow_info["status"], "pending")
        assert_equal(flow_info["is_verified"], False)
        assert_equal(flow_info["can_generate_addresses"], False)
        assert_raises_rpc_error(
            -4,
            "Cannot generate new address: KYC verification is still pending",
            flow_wallet.getnewaddress,
        )

        self.log.info("Use the production local verification flow and confirm it returns a wallet address")
        local_result = flow_wallet.local_verify("Ada Lovelace", 36, "United Kingdom")
        assert_equal(local_result["success"], True)
        assert_equal(local_result["wallet_verified"], True)
        assert_equal(local_result["wallet_name"], "flow_wallet")
        assert local_result["wallet_address"]
        assert_equal(flow_wallet.getaddressinfo(local_result["wallet_address"])["ismine"], True)

        flow_credential = flow_wallet.getwalletcredential()
        ownership = flow_wallet.confirmownership(flow_credential["credential_hash"])
        assert_equal(ownership["matches"], True)
        assert_equal(ownership["is_verified"], True)
        assert_equal(ownership["wallet_name"], "flow_wallet")
        assert_equal(ownership["full_name"], "Ada Lovelace")
        assert_equal(ownership["country"], "UNITED KINGDOM")
        assert_equal(ownership["age"], 36)
        assert_equal(ownership["wallet_address"], local_result["wallet_address"])

        assert_raises_rpc_error(
            -8,
            "Credential hash does not belong to this wallet",
            flow_wallet.confirmownership,
            "00" * 32,
        )

        self.log.info("Create a wallet that explicitly requires verification")
        self.nodes[0].createwallet(wallet_name="verified_only", require_verification=True)
        wallet = self.nodes[0].get_wallet_rpc("verified_only")

        self.log.info("Check that an unverified verification-required wallet cannot generate addresses")
        info = wallet.getwalletinfo()["verification"]
        assert_equal(info["status"], "none")
        assert_equal(info["is_verified"], False)
        assert_equal(info["can_generate_addresses"], False)
        assert_raises_rpc_error(
            -4,
            "Cannot generate new address: Wallet is not KYC verified",
            wallet.getnewaddress,
        )
        assert_raises_rpc_error(
            -4,
            "Cannot generate change address: Wallet is not KYC verified",
            wallet.getrawchangeaddress,
        )
        assert_raises_rpc_error(
            -4,
            "Cannot create multisig address: Wallet is not KYC verified",
            wallet.addmultisigaddress,
            1,
            [
                "0250863AD64A87AE8A2FE83C1AF1A8403CB5562B4D6FEE9C4E5B1C7E2C4A1F8D8B",
                "03F02889207B4C2F0A0EAB42E7A0B7F9A8EE0FB13BCE2C5A6C5D918ECB0CDC95B6",
            ],
        )
        assert_raises_rpc_error(
            -4,
            "Cannot create new keypool: Wallet is not KYC verified",
            wallet.newkeypool,
        )
        assert_raises_rpc_error(
            -4,
            "Cannot create transaction: Wallet is not KYC verified",
            wallet.walletcreatefundedpsbt,
            [],
            {self.nodes[0].get_wallet_rpc(self.default_wallet_name).getnewaddress(): 1},
        )

        self.log.info("Set a credential and verify address generation works")
        result = wallet.setwalletcredential("basic", "test-suite", 30)
        assert_equal(result["status"], "basic")
        assert_equal(result["is_verified"], True)
        assert_equal(result["wallet_name"], "verified_only")

        credential = wallet.getwalletcredential()
        assert_equal(credential["status"], "basic")
        assert_equal(credential["is_verified"], True)
        assert_equal(credential["is_valid"], True)
        assert_equal(credential["issuer"], "test-suite")
        assert_equal(credential["credential_type"], "basic")
        assert "credential_hash" in credential
        assert credential["expires_at"] > 0

        info = wallet.getwalletinfo()["verification"]
        assert_equal(info["status"], "basic")
        assert_equal(info["is_verified"], True)
        assert_equal(info["can_generate_addresses"], True)
        assert_equal(info["issuer"], "test-suite")
        assert_equal(info["credential_type"], "basic")

        address = wallet.getnewaddress()
        change_address = wallet.getrawchangeaddress()
        multisig = wallet.addmultisigaddress(
            1,
            [
                wallet.getaddressinfo(wallet.getnewaddress())["pubkey"],
                wallet.getaddressinfo(wallet.getnewaddress())["pubkey"],
            ],
        )
        wallet.newkeypool()
        assert_equal(wallet.getaddressinfo(address)["ismine"], True)
        assert_equal(wallet.getaddressinfo(change_address)["ischange"], True)
        assert_equal(wallet.getaddressinfo(multisig["address"])["ismine"], True)


if __name__ == '__main__':
    WalletCredentialTest().main()
