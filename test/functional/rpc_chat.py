#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC command validations for wallet chat."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class RPCChatTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]

        self.log.info("chat list should reject malformed addresses")
        assert_raises_rpc_error(-5, "Invalid Dash address", node.chat, "list", "not_a_dash_address")


if __name__ == '__main__':
    RPCChatTest().main()
