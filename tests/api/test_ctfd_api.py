"""CTFd API tests. Needs CTFD_URL (default http://localhost:8000) and CTFD_ADMIN_TOKEN.

Run with: pytest tests/api -n 4
"""

import re
import uuid

import pytest
import requests

from tests.helpers import ALL_APPS, challenge_config, nonce_from

pytestmark = pytest.mark.api

TIMEOUT = 15
PASSWORD = 'Lab-password-123!'


@pytest.fixture(scope='module')
def admin_session(ctfd_url, ctfd_admin_token):
    session = requests.Session()
    # CTFd only applies token auth to JSON requests, so the content type is required on GETs too.
    session.headers.update({'Authorization': f'Token {ctfd_admin_token}', 'Content-Type': 'application/json'})
    return session


@pytest.fixture(scope='module')
def challenges_by_name(ctfd_url, admin_session):
    r = admin_session.get(f'{ctfd_url}/api/v1/challenges', timeout=TIMEOUT)
    assert r.status_code == 200, r.text
    return {c['name']: c for c in r.json()['data']}


@pytest.fixture(scope='module')
def all_flags(ctfd_url, admin_session):
    r = admin_session.get(f'{ctfd_url}/api/v1/flags', timeout=TIMEOUT)
    assert r.status_code == 200, r.text
    return r.json()['data']


def register_player(ctfd_url):
    """Create a new player account through the registration form, return (session, csrf)."""
    session = requests.Session()
    page = session.get(f'{ctfd_url}/register', timeout=TIMEOUT)
    nonce = nonce_from(page.text)
    name = f'api-{uuid.uuid4().hex[:10]}'
    r = session.post(
        f'{ctfd_url}/register',
        data={
            'name': name,
            'email': f'{name}@example.test',
            'password': PASSWORD,
            'nonce': nonce,
            'submit': 'Submit',
        },
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    assert r.status_code == 302, r.text[:300]
    me = session.get(f'{ctfd_url}/api/v1/users/me', timeout=TIMEOUT)
    assert me.status_code == 200, 'player is not logged in after registration'
    # Logging in rotates the session nonce, so read the CSRF token from a page loaded after login.
    csrf = re.search(r"'csrfNonce': \"([0-9a-f]+)\"", session.get(f'{ctfd_url}/challenges', timeout=TIMEOUT).text)
    return session, csrf.group(1)


def submit(ctfd_url, session, csrf, challenge_id, flag):
    r = session.post(
        f'{ctfd_url}/api/v1/challenges/attempt',
        json={'challenge_id': challenge_id, 'submission': flag},
        headers={'CSRF-Token': csrf},
        timeout=TIMEOUT,
    )
    assert r.status_code == 200, r.text[:300]
    return r.json()['data']['status']


@pytest.mark.parametrize('app', ALL_APPS)
def test_challenge_is_installed_with_yml_values(app, ctfd_url, admin_session, challenges_by_name):
    expected = challenge_config(app)
    assert expected['title'] in challenges_by_name, f"'{expected['title']}' not installed in CTFd"
    challenge_id = challenges_by_name[expected['title']]['id']
    # The list endpoint omits `state`, so read the detail endpoint.
    installed = admin_session.get(f'{ctfd_url}/api/v1/challenges/{challenge_id}', timeout=TIMEOUT).json()['data']
    assert installed['value'] == expected['value']
    assert installed['category'] == 'Web Security'
    assert installed['state'] == 'visible'


@pytest.mark.parametrize('app', ALL_APPS)
def test_flags_match_challenge_yml(app, challenges_by_name, all_flags):
    expected = challenge_config(app)
    challenge_id = challenges_by_name[expected['title']]['id']
    installed = sorted(f['content'] for f in all_flags if f['challenge_id'] == challenge_id)
    assert installed == sorted(expected['flags'])


def test_wrong_flag_is_incorrect(ctfd_url, challenges_by_name):
    session, csrf = register_player(ctfd_url)
    challenge_id = challenges_by_name[challenge_config('jwt-1')['title']]['id']
    assert submit(ctfd_url, session, csrf, challenge_id, 'FLAG{wrong}') == 'incorrect'


def test_challenge_needs_both_flags(ctfd_url, challenges_by_name):
    # logic: all in challenge.yml, so one flag is only a partial solve.
    session, csrf = register_player(ctfd_url)
    config = challenge_config('jwt-1')
    challenge_id = challenges_by_name[config['title']]['id']
    user_flag, admin_flag = config['flags']
    assert submit(ctfd_url, session, csrf, challenge_id, user_flag) == 'partial'
    assert submit(ctfd_url, session, csrf, challenge_id, admin_flag) == 'correct'
    assert submit(ctfd_url, session, csrf, challenge_id, admin_flag) == 'already_solved'


def test_flag_from_another_challenge_is_incorrect(ctfd_url, challenges_by_name):
    session, csrf = register_player(ctfd_url)
    challenge_id = challenges_by_name[challenge_config('jwt-1')['title']]['id']
    other_flag = challenge_config('jwt-2')['flags'][0]
    assert submit(ctfd_url, session, csrf, challenge_id, other_flag) == 'incorrect'


def test_anonymous_user_cannot_submit(ctfd_url, challenges_by_name):
    challenge_id = challenges_by_name[challenge_config('jwt-1')['title']]['id']
    r = requests.post(
        f'{ctfd_url}/api/v1/challenges/attempt',
        json={'challenge_id': challenge_id, 'submission': 'FLAG{x}'},
        timeout=TIMEOUT,
    )
    assert r.status_code in (401, 403)
