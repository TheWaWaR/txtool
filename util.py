#!/usr/bin/env python
# coding: utf-8

import sha3
from ecdsa import SigningKey, SECP256k1


def generate_address(privkey=None):
    """
    privkey: str, such as "node0"
    """
    keccak = sha3.keccak_256()
    priv = SigningKey.from_string(hex2bytes(privkey), curve=SECP256k1)
    pubkey = priv.get_verifying_key().to_string()
    keccak.update(pubkey)
    address = keccak.hexdigest()[24:]

    return address
