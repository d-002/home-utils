import requests

from nacl.signing import VerifyKey
from auth import (
    create_payload,
    load_signing_key,
    check_payload,
)


def get_server_pubkey() -> str:
    res = requests.get(api_path + '/pubkey')
    if not res.ok:
        raise ValueError('Could not query server for public key')
    return res.text


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
    body = create_payload({}, signing_key, server_key_hex)
    wrapper('/test', 'post', json=body)


def api_useradd(password_hash: str):
    body = create_payload({'password_hash': password_hash}, signing_key, server_key_hex)
    wrapper('/user', 'post', json=body)


def api_userdel():
    body = create_payload({}, signing_key, server_key_hex)
    wrapper('/user', 'delete', json=body)


def api_userhash():
    body = create_payload({}, signing_key, server_key_hex)
    wrapper('/user/password-hash', 'post', json=body)


def api_passadd(website: str, username: str, password: str):
    body = create_payload(
        {'website': website, 'username': username, 'password': password},
        signing_key,
        server_key_hex,
    )
    wrapper('/password', 'post', json=body)


def api_passdel(website, username, password):
    body = create_payload(
        {'website': website, 'username': username, 'password': password},
        signing_key,
        server_key_hex,
    )
    wrapper('/password', 'delete', json=body)


def api_list():
    body = create_payload({}, signing_key, server_key_hex)
    wrapper('/passwords', 'post', json=body)


def api_website(website: str):
    body = create_payload({}, signing_key, server_key_hex)
    wrapper(f'/passwords?website={website}', 'post', json=body)


if __name__ == '__main__':
    api_path = 'http://localhost:8080'

    signing_key = load_signing_key('client.pem')
    server_key_hex = get_server_pubkey()

    while True:
        command = input('> ').strip().split(' ')
        command, args = command[0], command[1:]
        match command:
            case 'test':
                api_test()
            case 'useradd':
                api_useradd(*args)
            case 'userdel':
                api_userdel()
            case 'hash':
                api_userhash()
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
