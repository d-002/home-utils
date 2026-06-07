import json

from db import DataBase
from auth import (
    hex2verify,
    verify2hex,
    get_signing_key,
    check_payload,
    SignedPayload,
)

from fastapi import FastAPI, Response, HTTPException
from contextlib import asynccontextmanager

signing_key = get_signing_key('server.pem')


def setup_api(db: DataBase) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        db.close()

    app = FastAPI(lifespan=lifespan)

    class SuccessMessage:
        message: str
        signing_key: str

        def __init__(self, signing_key: str, message='success'):
            self.message = message
            self.signing_key = signing_key

        def get_signed(self) -> SignedPayload:
            return SignedPayload.create(
                signing_key,
                {'message': self.message},
                hex2verify(self.signing_key),
            )

    @app.get('/test', summary='Test endpoint, the only non-encrypted one')
    async def test_unencrypted():
        return {'message': 'Hello world'}

    @app.get(
        '/pubkey', summary='Get the unencrypted public signing key as bytes'
    )
    async def get_pubkey():
        pubkey_hex = verify2hex(signing_key.verify_key).encode('utf-8')
        return Response(pubkey_hex, media_type='application/octet-stream')

    @app.post('/test', summary='Test endpoint with encryption')
    async def test(body: SignedPayload):
        check_payload(body.model_dump(), set(), signing_key)
        return SuccessMessage('Hello world').get_signed()

    @app.post('/user', summary='Add a new user')
    async def user_new(body: SignedPayload):
        check_payload(body.model_dump(), {'signing_key'}, signing_key)

        db.add_user(body.signing_key)
        return SuccessMessage(body.signing_key).get_signed()

    @app.delete('/user', summary='Delete an user')
    async def user_delete(body: SignedPayload):
        check_payload(body.model_dump(), {'signing_key'}, signing_key)

        db.delete_user(body.signing_key)
        return SuccessMessage(body.signing_key).get_signed()

    @app.post(
        '/password',
        summary='Add a password',
        description='Add a password to a user, for a specific website and '
        'username. The username and password should be encrypted symmetrically '
        'and the website should be hashed',
    )
    async def password_add(body: SignedPayload):
        payload = check_payload(
            body.model_dump(), {'website', 'username', 'password'}, signing_key
        )

        db.add_password(
            body.signing_key,
            payload['website'],
            payload['username'],
            payload['password'],
        )
        return SuccessMessage(body.signing_key).get_signed()

    @app.delete('/password', summary='Delete a password')
    async def password_delete(body: SignedPayload):
        payload = check_payload(
            body.model_dump(), {'website', 'username', 'password'}, signing_key
        )

        db.delete_password(
            body.signing_key,
            payload['website'],
            payload['username'],
            payload['password'],
        )
        return SuccessMessage(body.signing_key).get_signed()

    @app.patch(
        '/password',
        summary='Patch a password',
        description='Equivalent to calling DELETE /password (old) then POST '
        '/password (new)',
    )
    async def password_patch(body: SignedPayload):
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
        return SuccessMessage(body.signing_key).get_signed()

    @app.post(
        '/passwords',
        summary='Get all passwords from a user',
        description='Optionally filter by website with ?website=...',
    )
    async def user_all_passwords(
        body: SignedPayload, website: str | None = None
    ):
        check_payload(body.model_dump(), {'signing_key'}, signing_key)
        dest_key = hex2verify(body.signing_key)

        if website is None:
            return SignedPayload.create(
                signing_key, db.all_passwords(body.signing_key), dest_key
            )
        return SignedPayload.create(
            signing_key,
            db.website_passwords(body.signing_key, website),
            dest_key,
        )

    return app
