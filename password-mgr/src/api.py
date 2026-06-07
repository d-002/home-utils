import json

from db import DataBase
from auth import get_signing_key, SignedPayload

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from fastapi import FastAPI, HTTPException
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

        def __init__(self, message='success'):
            self.message = message

        def get_signed(self) -> SignedPayload:
            return SignedPayload.create(signing_key, {'message': self.message})

    def check_payload(body: SignedPayload, expected: set[str]) -> dict:
        # decode payload
        try:
            payload = json.loads(body.payload_str)
        except json.JSONDecodeError:
            raise HTTPException(400, detail='payload_str: not valid JSON')

        # check if all expected values are present
        for value in expected:
            if value not in payload:
                raise HTTPException(
                    401, detail=f'Missing key in payload: {value}'
                )

        # check integrity with signing key
        try:
            key_bytes = bytes.fromhex(body.signing_key)
            signature_bytes = bytes.fromhex(body.signature)
            verify_key = VerifyKey(key_bytes)

            verify_key.verify(body.payload_str.encode('utf-8'), signature_bytes)
        except (BadSignatureError, ValueError):
            raise HTTPException(401, detail='Bad signature')

        return payload

    @app.get('/test', summary='Test endpoint')
    async def test():
        return SuccessMessage('Hello world').get_signed()

    @app.post('/user', summary='Add a new user')
    async def user_new(body: SignedPayload):
        check_payload(body, {'signing_key'})

        db.add_user(body.signing_key)
        return SuccessMessage().get_signed()

    @app.delete('/user', summary='Delete an user')
    async def user_delete(body: SignedPayload):
        check_payload(body, {'signing_key'})

        db.delete_user(body.signing_key)
        return SuccessMessage().get_signed()

    @app.post(
        '/password',
        summary='Add a password',
        description='Add a password to a user, for a specific website and '
        'username. The username and password should be encrypted symmetrically '
        'and the website should be hashed',
    )
    async def password_add(body: SignedPayload):
        payload = check_payload(body, {'website', 'username', 'password'})

        db.add_password(
            body.signing_key,
            payload['website'],
            payload['username'],
            payload['password'],
        )
        return SuccessMessage().get_signed()

    @app.delete('/password', summary='Delete a password')
    async def password_delete(body: SignedPayload):
        payload = check_payload(body, {'website', 'username', 'password'})

        db.delete_password(
            body.signing_key,
            payload['website'],
            payload['username'],
            payload['password'],
        )
        return SuccessMessage().get_signed()

    @app.patch(
        '/password',
        summary='Patch a password',
        description='Equivalent to calling DELETE /password (old) then POST '
        '/password (new)',
    )
    async def password_patch(body: SignedPayload):
        payload = check_payload(
            body,
            {
                'website_old',
                'username_old',
                'password_old',
                'website_new',
                'username_new',
                'password_new',
            },
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
        return SuccessMessage().get_signed()

    @app.post(
        '/passwords',
        summary='Get all passwords from a user',
        description='Optionally filter by website with ?website=...',
    )
    async def user_all_passwords(
        body: SignedPayload, website: str | None = None
    ):
        check_payload(body, {'signing_key'})

        if website is None:
            return SignedPayload.create(
                signing_key, db.all_passwords(body.signing_key)
            )
        return SignedPayload.create(
            signing_key, db.website_passwords(body.signing_key, website)
        )

    return app
