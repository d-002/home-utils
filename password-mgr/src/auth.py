from __future__ import annotations

import json

from pydantic import BaseModel

from nacl.signing import SigningKey
from cryptography.hazmat.primitives import serialization


def get_signing_key(path: str) -> SigningKey:
    with open(path, 'rb') as f:
        pem_data = f.read()

    openssl_pkey = serialization.load_pem_private_key(pem_data, None)
    raw_seed_bytes = openssl_pkey.private_bytes_raw()  # type: ignore
    return SigningKey(raw_seed_bytes)


class SignedPayload(BaseModel):
    signing_key: str
    payload_str: str
    signature: str

    @classmethod
    def create(cls, signing_key: SigningKey, payload: dict) -> SignedPayload:
        payload_str = json.dumps(payload)

        signing_key_ = bytes(signing_key.verify_key).hex()
        payload_str = payload_str
        signature = signing_key.sign(
            payload_str.encode('utf-8')
        ).signature.hex()

        return cls(
            signing_key=signing_key_,
            payload_str=payload_str,
            signature=signature,
        )

    def payload_from_fastapi(self) -> dict:
        try:
            return json.loads(self.payload_str)
        except json.JSONDecodeError:
            return {}
