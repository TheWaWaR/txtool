#!/usr/bin/env python
# coding: utf-8

import requests
from jsonrpcclient.http_client import HTTPClient


class JSONRpcClient(object):

    def __init__(self, url):
        self.url = url
        self.client = HTTPClient(url)

    def block_number(self):
        resp = self.client.request("cita_blockNumber", [])
        return int(resp, 16)

    def get_nonce(self, sender, block_number):
        resp = self.client.request("eth_getTransactionCount", [sender, block_number])
        return str(int(resp, 16))

    def send_transaction(self, bytecode):
        return requests.post(self.url, json={
            'jsonrpc': '2.0',
            'method': 'cita_sendTransaction',
            'id': 1,
            'params': [bytecode]
        }).json()
        # return self.client.request("cita_sendTransaction", [bytecode])

    def get_receipt(self, tx_hash):
        return self.client.request("eth_getTransactionReceipt", [tx_hash])

