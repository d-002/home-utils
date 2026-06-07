import json

from db import DataBase
from auth import (
    create_payload,
    load_signing_key,
    check_payload,
)

from pydantic import BaseModel
from nacl.signing import SigningKey, VerifyKey
from fastapi import FastAPI, Response, HTTPException
from contextlib import asynccontextmanager


def setup_api(db: DataBase) -> FastAPI:
    signing_key = load_signing_key('server.pem')

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        db.close()

    app = FastAPI(lifespan=lifespan)

    class EncryptedPayload(BaseModel):
        signing_key: str
        ciphertext: str

    def success_message(dst_key_hex: str, message='success'):
        return create_payload({'message': message}, signing_key, dst_key_hex)

    @app.get('/test', summary='Test endpoint without encryption')
    async def test_unencrypted():
        return {'message': 'Hello world'}

    @app.get(
        '/pubkey',
        summary='Get the server\'s public signing key as bytes',
    )
    async def get_pubkey():
        pubkey_hex = bytes(signing_key.verify_key).hex().encode('utf-8')
        return Response(pubkey_hex, media_type='binary/octet-stream')

    @app.post('/test', summary='Test endpoint with encryption')
    async def test(body: EncryptedPayload):
        check_payload(body.model_dump(), set(), signing_key)

        return success_message(body.signing_key, 'Hello world')

    @app.post(
        '/user',
        summary='Add a new user',
        description='Asymmetric encryption is used for message exchange, but '
        'additional, password-seeded symmetric encryption is used on the '
        'client side to encrypt sensitive information further. This endpoint '
        'supports sending a password hash to allow clients to later check '
        'whether they inputted the right password and prevent corruption.',
    )
    async def user_new(body: EncryptedPayload):
        payload = check_payload(body.model_dump(), {'signing_key', 'password_hash'}, signing_key)

        db.add_user(body.signing_key, payload['password_hash'])
        return success_message(body.signing_key)

    @app.delete('/user', summary='Delete an user')
    async def user_delete(body: EncryptedPayload):
        check_payload(body.model_dump(), {'signing_key'}, signing_key)

        db.delete_user(body.signing_key)
        return success_message(body.signing_key)

    @app.post('/user/password-hash', summary='Get the hashed password that was stored when creating this user')
    async def user_password_hash(body: EncryptedPayload):
        check_payload(body.model_dump(), {'signing_key'}, signing_key)

        res = db.get_password_hash(body.signing_key)
        return create_payload(res, signing_key, body.signing_key)

    @app.post(
        '/password',
        summary='Add a password',
        description='Add a password to a user, for a specific website and '
        'username. The username and password should be encrypted symmetrically '
        'and the website should be hashed',
    )
    async def password_add(body: EncryptedPayload):
        payload = check_payload(
            body.model_dump(), {'website', 'username', 'password'}, signing_key
        )

        db.add_password(
            body.signing_key,
            payload['website'],
            payload['username'],
            payload['password'],
        )
        return success_message(body.signing_key)

    @app.delete('/password', summary='Delete a password')
    async def password_delete(body: EncryptedPayload):
        payload = check_payload(
            body.model_dump(), {'website', 'username', 'password'}, signing_key
        )

        db.delete_password(
            body.signing_key,
            payload['website'],
            payload['username'],
            payload['password'],
        )
        return success_message(body.signing_key)

    @app.patch(
        '/password',
        summary='Update a password',
        description='Equivalent to calling DELETE /password (old) then POST '
        '/password (new)',
    )
    async def password_patch(body: EncryptedPayload):
        payload = check_payload(
            body.model_dump(),
            {
                'website_old',
                'username_old',
                'password_old',
                'website_new',
                'username_new',
                'password_new',
            },
            signing_key,
        )

        db.patch_password(
            body.signing_key,
            payload['website_old'],
            payload['username_old'],
            payload['password_old'],
            payload['website_new'],
            payload['username_new'],
            payload['password_new'],
        )
        return success_message(body.signing_key)

    @app.post(
        '/passwords',
        summary='Get all passwords from a user',
        description='Optionally filter by website with ?website=...',
    )
    async def user_all_passwords(
        body: EncryptedPayload, website: str | None = None
    ):
        check_payload(body.model_dump(), {'signing_key'}, signing_key)

        if website is None:
            res = db.all_passwords(body.signing_key)
        else:
            res = db.website_passwords(body.signing_key, website)

        return create_payload(res, signing_key, body.signing_key)

    return app
