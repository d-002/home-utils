import requests

from auth import get_signing_key, SignedPayload


signing_key = get_signing_key('client.pem')
pubkey = bytes(signing_key.verify_key).hex()


def wrapper(endpoint, method='get', **kwargs):
    func = getattr(requests, method)
    res = func('http://localhost:8080' + endpoint, **kwargs)
    print(res.status_code, res.reason)
    if res.ok:
        print(res.json())
    else:
        print(res.text)


def api_test():
    wrapper('/test')


def api_useradd():
    body = SignedPayload.create(signing_key, {'signing_key': pubkey})
    wrapper('/user', 'post', json=body.model_dump())


def api_userdel():
    body = SignedPayload.create(signing_key, {'signing_key': pubkey})
    wrapper('/user', 'delete', json=body.model_dump())


def api_passadd(website: str, username: str, password: str):
    body = SignedPayload.create(
        signing_key,
        {'website': website, 'username': username, 'password': password},
    )
    wrapper('/password', 'post', json=body.model_dump())


def api_passdel(website, username, password):
    body = SignedPayload.create(
        signing_key,
        {'website': website, 'username': username, 'password': password},
    )
    wrapper('/password', 'delete', json=body.model_dump())


def api_list():
    body = SignedPayload.create(signing_key, {'signing_key': pubkey})
    wrapper('/passwords', 'post', json=body.model_dump())


def api_website(website: str):
    body = SignedPayload.create(signing_key, {'signing_key': pubkey})
    wrapper(f'/passwords?website={website}', 'post', json=body.model_dump())


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
