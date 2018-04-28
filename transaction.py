#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

import argparse
import json
import sys
import os
import random
from multiprocessing import Process

import sha3
import uuid
import pysodium
import binascii
from secp256k1 import PrivateKey
from ecdsa import SigningKey, SECP256k1
from ethereum.utils import sha3 as eth_sha3

import transaction_pb2 as proto
from jsonrpc import JSONRpcClient


def hex2bytes(hex_string):
    return bytes(bytearray.fromhex(hex_string))


def remove_hex_0x(hex_string):
    result = hex_string
    if hex_string is not None:
        if hex_string.startswith('0x') or hex_string.startswith('0X'):
            result = hex_string[2:]

    return result


def privkey_address(privkey):
    """
    privkey: str, such as "node0"
    """
    keccak = sha3.keccak_256()
    priv = SigningKey.from_string(hex2bytes(privkey), curve=SECP256k1)
    pubkey = priv.get_verifying_key().to_string()
    keccak.update(pubkey)
    return keccak.hexdigest()[24:]


def make_deploycode(tx, message, privkey):
    """
    Generate Hexadecimal representation of the binary signature transactions
    """
    privkey = PrivateKey(hex2bytes(privkey))
    sign_recover = privkey.ecdsa_sign_recoverable(message, raw=True)
    sig = privkey.ecdsa_recoverable_serialize(sign_recover)

    signature = binascii.hexlify(
        sig[0]) + binascii.hexlify(bytes(bytearray([sig[1]])))

    unverify_tx = proto.UnverifiedTransaction()
    unverify_tx.transaction.CopyFrom(tx)
    unverify_tx.signature = hex2bytes(signature)
    unverify_tx.crypto = proto.Crypto.Value('SECP')
    return binascii.hexlify(unverify_tx.SerializeToString())


def make_tx(
        sender, to_address, data, quota, chain_id,
        valid_until, nonce,
        version=0,
):
    tx = proto.Transaction()
    tx.chain_id = chain_id
    tx.data = hex2bytes(data)
    tx.valid_until_block = valid_until
    tx.nonce = nonce
    tx.quota = quota
    tx.version = version
    tx.to = to_address
    return tx


def get_contract_code(path, name=None):
    from solc import compile_standard
    with open(path) as f:
        content = f.read()
        data = compile_standard({
            'language': 'Solidity',
            'sources': {'Contract.sol': {'content': content}}
        })
        print(data)
        if name is None and len(data) > 1:
            raise ValueError(
                'Please select contract name: ({})'.format(data.keys())
            )
        if name is None:
            name = data.keys()[0]
        return data[name]['bin']


class Transaction(object):
    pass


def parse_args():
    # default_to = ''
    default_to = '0xffffffffffffffffffffffffffffffffffffffff'
    default_chain_id = 123
    default_quota = 100000
    default_version = 0
    default_crypto_algo = 'secp256k1'
    default_hash_algo = 'sha3'
    default_processes = 10
    default_limit = 5000

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--crypto-algo',
        default=default_crypto_algo,
        choices=['ed25519', 'secp256k1', 'sm2'],
        help='Crypto algorithm to use [default: {}]'.format(default_crypto_algo)
    )
    parser.add_argument(
        '--hash-algo',
        default=default_hash_algo,
        choices=['sha3', 'blake2b', 'sm3'],
        help='Hash algorithm to use [default: {}]'.format(default_hash_algo)
    )
    # FIXME: use a separated subcommand
    parser.add_argument(
        '--contract-file',
        metavar='FILE',
        help='Solidity contract file to generate bytecode'
    )
    # FIXME: use a separated subcommand
    parser.add_argument(
        '--contract-name',
        metavar='STRING',
        help='Solidity contract name to generate bytecode'
    )
    parser.add_argument(
        '--data',
        metavar='STRING',
        default='xxx',
        help='Transaction content data'
    )
    parser.add_argument(
        '--privkey',
        metavar='STRING',
        default='ef98e68db428906d626cd37782cdfb052ac282132beee53a99948738ea553b4a',
        help="Sender's privkey"
    )
    parser.add_argument(
        '--chain-id',
        type=int,
        metavar='INT',
        default=default_chain_id,
        help='The chain id of the transaction'
    )
    parser.add_argument(
        '--to',
        metavar='ADDRESS',
        default=default_to,
        help='The address to send [default="{}"]'.format(default_to)
    )
    parser.add_argument(
        '--quota',
        type=int,
        metavar='INT',
        default=default_quota,
        help='The quota of the transaction [default={}]'.format(default_quota)
    )
    parser.add_argument(
        '--valid-until',
        type=int,
        metavar='INT',
        help='Valid until a block number'
    )
    parser.add_argument(
        '--version',
        type=int,
        metavar='INT',
        default=default_version,
        help='The transaction version [default={}]'.format(default_version)
    )
    parser.add_argument(
        '--get-receipt',
        action='store_true',
        help='Get the receipt of the transaction after send a transaction'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=default_limit,
        help='Max transactions to send'
    )
    parser.add_argument(
        '--processes',
        type=int,
        default=default_processes,
        help='Max processes to spawn'
    )
    parser.add_argument(
        '--url',
        help='The JSONRPC url'
    )
    return parser.parse_args()


def worker(args, i):
    sys.stderr.write('Args={}\n'.format(args))

    from datetime import datetime
    t1 = datetime.now()
    sys.stderr.write('start={}\n'.format(t1))

    urls = [
        'http://192.168.2.191:1337',
        'http://192.168.2.191:1338',
        'http://192.168.2.191:1339',
        'http://192.168.2.191:1340',
    ]
    url = random.choice(urls) if not args.url else args.url
    sys.stderr.write('url={}\n'.format(url))
    client = JSONRpcClient(url)

    data = '7' * 1024
    sender = privkey_address(args.privkey)
    valid_until = (
        args.valid_until if args.valid_until is not None
        else client.block_number() + 50
    )
    if not os.path.exists('logs'):
        os.mkdir('logs')
    filename = 'logs/{}-{}.log'.format(i, os.getpid())
    with open(filename, 'w') as f:
        for i in range(args.limit):
            # nonce = client.get_nonce(sender, 'latest')
            nonce = uuid.uuid4().hex
            tx = make_tx(
                args.privkey,
                args.to,
                data,
                args.quota,
                args.chain_id,
                valid_until,
                nonce,
                version=args.version
            )
            if (i + 1) % 1000 == 0:
                valid_until = client.block_number() + 50

            message = eth_sha3(tx.SerializeToString())
            bytecode = make_deploycode(tx, message, args.privkey)
            resp = client.send_transaction(bytecode)
            f.write(json.dumps({
                'time': str(datetime.now()),
                'n': i,
                'result': resp['result'],
            }))
            f.write('\n')
        # print('Time={}, Number: {}, response={}'.format(datetime.now(), i, resp))

    t2 = datetime.now()
    sys.stderr.write('[{}]: end={}, cost={}\n'.format(os.getpid(), t2, t2 - t1))


def main():
    args = parse_args()
    processes = []
    for i in range(args.processes):
        p = Process(target=worker, args=(args, i))
        p.start()
        processes.append(p)

    [p.join() for p in processes]
    print('>>> ALL DONE')


if __name__ == '__main__':
    main()
