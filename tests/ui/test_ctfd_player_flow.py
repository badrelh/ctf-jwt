"""Browser tests of a player going through CTFd and the jwt-1 challenge.

Run with: pytest tests/ui --browser-channel chrome   (or without the option to use Playwright's Chromium)
"""

import re
import uuid

import pytest
from playwright.sync_api import expect

from tests.helpers import (
    app_url,
    challenge_config,
    flag_in,
    forge_none,
    jwt1_guest_creds,
)

pytestmark = pytest.mark.ui

PASSWORD = 'Lab-password-123!'
JWT1_TITLE = challenge_config('jwt-1')['title']
JWT1_USER_FLAG, JWT1_ADMIN_FLAG = challenge_config('jwt-1')['flags']


def register_player(page, ctfd_url):
    name = f'ui-{uuid.uuid4().hex[:10]}'
    page.goto(f'{ctfd_url}/register')
    page.fill('input[name=name]', name)
    page.fill('input[name=email]', f'{name}@example.test')
    page.fill('input[name=password]', PASSWORD)
    page.click('input[type=submit]')
    expect(page).not_to_have_url(re.compile(r'/register'))
    return name


def submit_flag(page, ctfd_url, title, flag):
    page.goto(f'{ctfd_url}/challenges')
    page.locator('.challenge-button', has_text=title).click()
    page.fill('#challenge-input', flag)
    page.click('#challenge-submit')


def expect_result(page, pattern):
    expect(page.locator('.notification-row, .modal-body, .alert').filter(has_text=pattern).first).to_be_visible()


def test_player_registers_and_solves_jwt1_in_browser(page, context, ctfd_url):
    player = register_player(page, ctfd_url)

    # The player finds the guest account in the backup file the challenge exposes.
    challenge_page = context.new_page()
    user, password = jwt1_guest_creds(app_url('jwt-1'))
    challenge_page.goto(app_url('jwt-1'))
    challenge_page.click('a[data-section="guest"]')
    challenge_page.fill('#username', user)
    challenge_page.fill('#password', password)
    challenge_page.click('#login-form button[type=submit]')
    expect(challenge_page.locator('#login-result')).to_contain_text('success', ignore_case=True)

    # User flag from the profile panel.
    challenge_page.click('a[data-section="user"]')
    challenge_page.click('#fetch-me')
    expect(challenge_page.locator('#user-result .flag')).to_be_visible()
    user_flag = flag_in(challenge_page.locator('#user-result .flag').inner_text())
    assert user_flag == JWT1_USER_FLAG

    # logic: all, so the user flag alone is a partial solve.
    submit_flag(page, ctfd_url, JWT1_TITLE, user_flag)
    expect_result(page, 'more flags are required')

    # Admin flag: the player forges an alg=none token and puts it in the app's localStorage.
    forged = forge_none({'username': user, 'role': 'admin'})
    challenge_page.evaluate('token => localStorage.setItem("jwt_token", token)', forged)
    challenge_page.click('a[data-section="admin"]')
    challenge_page.click('#fetch-admin')
    expect(challenge_page.locator('#admin-result .flag')).to_be_visible()
    admin_flag = flag_in(challenge_page.locator('#admin-result .flag').inner_text())
    assert admin_flag == JWT1_ADMIN_FLAG

    submit_flag(page, ctfd_url, JWT1_TITLE, admin_flag)
    expect_result(page, re.compile(r'\bCorrect\b'))

    # Both flags are counted on the scoreboard.
    page.goto(f'{ctfd_url}/scoreboard')
    player_row = page.locator('tr', has_text=player).first
    expect(player_row).to_contain_text(str(challenge_config('jwt-1')['value']))


def test_wrong_flag_is_reported_as_incorrect_in_browser(page, ctfd_url):
    register_player(page, ctfd_url)
    submit_flag(page, ctfd_url, JWT1_TITLE, 'FLAG{not-the-flag}')
    expect_result(page, re.compile('incorrect', re.IGNORECASE))
