import requests

from nacl.signing import VerifyKey
from auth import (
    hex2verify,
    verify2hex,
    get_signing_key,
    check_payload,
    SignedPayload,
)


def get_server_pubkey() -> VerifyKey:
    res = requests.get(api_path + '/pubkey')
    if not res.ok:
        raise ValueError('Could not query server for public key')
    return hex2verify(res.text)


def wrapper(endpoint, method='get', **kwargs):
    # make request and get result

    func = getattr(requests, method)
    res = func(api_path + endpoint, **kwargs)
    print(res.status_code, res.reason)
    if not res.ok:
        print(res.text)
        return

    # check authenticity and extract message
    payload = check_payload(res.json(), set(), signing_key)

    print(payload)


def api_test():
    body = SignedPayload.create(signing_key, {}, server_pubkey)
    wrapper('/test', 'post', json=body.model_dump())


def api_useradd():
    body = SignedPayload.create(
        signing_key, {'signing_key': pubkey}, server_pubkey
    )
    wrapper('/user', 'post', json=body.model_dump())


def api_userdel():
    body = SignedPayload.create(
        signing_key, {'signing_key': pubkey}, server_pubkey
    )
    wrapper('/user', 'delete', json=body.model_dump())


def api_passadd(website: str, username: str, password: str):
    body = SignedPayload.create(
        signing_key,
        {'website': website, 'username': username, 'password': password},
        server_pubkey,
    )
    wrapper('/password', 'post', json=body.model_dump())


def api_passdel(website, username, password):
    body = SignedPayload.create(
        signing_key,
        {'website': website, 'username': username, 'password': password},
        server_pubkey,
    )
    wrapper('/password', 'delete', json=body.model_dump())


def api_list():
    body = SignedPayload.create(
        signing_key, {'signing_key': pubkey}, server_pubkey
    )
    wrapper('/passwords', 'post', json=body.model_dump())


def api_website(website: str):
    body = SignedPayload.create(
        signing_key, {'signing_key': pubkey}, server_pubkey
    )
    wrapper(f'/passwords?website={website}', 'post', json=body.model_dump())


if __name__ == '__main__':
    api_path = 'http://localhost:8080'

    signing_key = get_signing_key('client.pem')
    pubkey = verify2hex(signing_key.verify_key)
    server_pubkey = get_server_pubkey()

    while True:
        command = input('> ').strip().split(' ')
        command, args = command[0], command[1:]
        match command:
            case 'test':
                api_test()
            case 'useradd':
                api_useradd()
            case 'userdel':
                api_userdel()
            case 'passadd':
                api_passadd(*args)
            case 'passdel':
                api_passdel(*args)
            case 'list':
                api_list(*args)
            case 'website':
                api_website(*args)
            case 'exit':
                break
            case '':
                pass
            case other:
                print(f'{other}: command not found')
