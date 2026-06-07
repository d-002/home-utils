from __future__ import annotations

import json
import time

from timestamp import TimestampHandler

from nacl.exceptions import BadSignatureError
from nacl.public import Box
from nacl.utils import random
from nacl.signing import SigningKey, VerifyKey
from fastapi import HTTPException
from cryptography.hazmat.primitives import serialization


def load_signing_key(path: str) -> SigningKey:
    with open(path, 'rb') as f:
        pem_data = f.read()

    openssl_pkey = serialization.load_pem_private_key(pem_data, None)
    raw_seed_bytes = openssl_pkey.private_bytes_raw()  # type: ignore
    return SigningKey(raw_seed_bytes)


def create_payload(
    data: dict, src_signing_key: SigningKey, dst_key_hex: str
) -> dict:
    data['signing_key'] = bytes(src_signing_key.verify_key).hex()
    data['timestamp'] = time.time()

    try:
        dst_key = VerifyKey(bytes.fromhex(dst_key_hex))
        box = Box(
            src_signing_key.to_curve25519_private_key(),
            dst_key.to_curve25519_public_key(),
        )

        ciphertext = box.encrypt(json.dumps(data).encode('utf-8'))
    except Exception:
        raise HTTPException(400, 'Failed to encrypt payload')

    return {
        'signing_key': bytes(src_signing_key.verify_key).hex(),
        'ciphertext': bytes(ciphertext).hex(),
    }


def check_payload(
    body: dict,
    expected: set[str],
    dst_signing_key: SigningKey,
    timestamp_handler: TimestampHandler,
) -> dict:
    # set up encryption
    try:
        src_key = VerifyKey(bytes.fromhex(body['signing_key']))
        box = Box(
            dst_signing_key.to_curve25519_private_key(),
            src_key.to_curve25519_public_key(),
        )
        ciphertext = bytes.fromhex(body['ciphertext'])
    except Exception:
        raise HTTPException(
            400, detail='Failed to process payload encryption settings'
        )

    # decode payload
    try:
        payload = json.loads(box.decrypt(ciphertext))
    except Exception:
        raise HTTPException(400, detail='Failed to decrypt payload')

    # check if all expected values are present
    for value in expected.union({'signing_key', 'timestamp'}):
        if value not in payload:
            raise HTTPException(
                400, detail=f'Missing element in payload: {value}'
            )

    # check timestamp
    timestamp_handler.check_valid_timestamp(
        body['signing_key'], payload['timestamp']
    )
    timestamp_handler.persist_timestamp(body['signing_key'], payload['timestamp'])

    return payload
