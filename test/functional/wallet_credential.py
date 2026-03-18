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
        wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        self.log.info("Check that an unverified wallet cannot generate addresses")
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

        self.log.info("Set a credential and verify address generation works")
        result = wallet.setwalletcredential("basic", "test-suite", 30)
        assert_equal(result["status"], "basic")
        assert_equal(result["is_verified"], True)
        assert_equal(result["wallet_name"], self.default_wallet_name)

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
        assert_equal(wallet.getaddressinfo(address)["ismine"], True)
        assert_equal(wallet.getaddressinfo(change_address)["ischange"], True)


if __name__ == '__main__':
    WalletCredentialTest().main()
