from __future__ import annotations

import json

from pydantic import BaseModel

from nacl.exceptions import BadSignatureError
from nacl.public import SealedBox
from nacl.signing import SigningKey, VerifyKey
from fastapi import HTTPException
from cryptography.hazmat.primitives import serialization


def hex2verify(text: str) -> VerifyKey:
    return VerifyKey(bytes.fromhex(text))


def verify2hex(key: VerifyKey) -> str:
    return bytes(key).hex()


def get_signing_key(path: str) -> SigningKey:
    with open(path, 'rb') as f:
        pem_data = f.read()

    openssl_pkey = serialization.load_pem_private_key(pem_data, None)
    raw_seed_bytes = openssl_pkey.private_bytes_raw()  # type: ignore
    return SigningKey(raw_seed_bytes)


def check_integrity(body: dict) -> None:
    try:
        signature_bytes = bytes.fromhex(body['signature'])
        verify_key = hex2verify(body['signing_key'])

        verify_key.verify(body['payload_str'].encode('utf-8'), signature_bytes)
    except (BadSignatureError, ValueError):
        raise HTTPException(401, detail='Bad signature')


def check_payload(
    body: dict, expected: set[str], signing_key: SigningKey
) -> dict:
    # decode payload
    try:
        dec_box = SealedBox(signing_key.to_curve25519_private_key())
        payload_raw = dec_box.decrypt(body['payload_str'])
    except Exception:
        raise HTTPException(400, detail='Failed to decode payload with own sk')

    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        raise HTTPException(400, detail='payload_str: not valid JSON')

    print(body)
    print(payload_raw)
    print(payload)

    # check if all expected values are present
    for value in expected:
        if value not in payload:
            raise HTTPException(401, detail=f'Missing key in payload: {value}')

    # check integrity with signing key
    check_integrity(body)

    # if signing_key is also in payload, check if both keys have the same value
    if 'signing_key' in expected:
        if body['signing_key'] != payload['signing_key']:
            raise HTTPException(
                400, detail='key in body and encrypted payload do not match'
            )

    return payload


class SignedPayload(BaseModel):
    signing_key: str
    payload_str: str
    signature: str

    @classmethod
    def create(
        cls,
        src_signing_key: SigningKey,
        payload: dict,
        dest_signing_key: VerifyKey,
    ) -> SignedPayload:
        payload_str = json.dumps(payload)

        # create encryption keys using signing keys
        dest_pubkey = dest_signing_key.to_curve25519_public_key()
        enc_box = SealedBox(dest_pubkey)

        # create the payload
        signing_key_hex = verify2hex(src_signing_key.verify_key)
        payload_enc = enc_box.encrypt(payload_str.encode('utf-8'))
        signature = src_signing_key.sign(payload_str.encode('utf-8')).signature.hex()

        return cls(
            signing_key=signing_key_hex,
            payload_str=payload_enc,
            signature=signature,
        )
