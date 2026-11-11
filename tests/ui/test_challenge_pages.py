"""Browser smoke tests for the challenge front-ends. Run with: pytest tests/ui"""

import pytest
from playwright.sync_api import expect

from tests.helpers import ALL_APPS, app_url

pytestmark = pytest.mark.ui


@pytest.mark.parametrize('app', ALL_APPS)
def test_front_end_loads_without_js_errors(app, page):
    errors = []
    page.on('pageerror', lambda exc: errors.append(str(exc)))
    response = page.goto(app_url(app))
    assert response is not None and response.status == 200
    assert page.title().strip()
    page.wait_for_load_state('networkidle')
    assert errors == []


def test_jwt1_wrong_password_shows_error(page):
    page.goto(app_url('jwt-1'))
    page.click('a[data-section="guest"]')
    page.fill('#username', 'guest')
    page.fill('#password', 'wrong-password')
    page.click('#login-form button[type=submit]')
    expect(page.locator('#login-result')).to_contain_text('Invalid', ignore_case=True)


def test_server_front_end_login_form_is_present(page):
    page.goto(app_url('server'))
    expect(page.locator('#btnLogin')).to_be_visible()
    expect(page.locator('#password')).to_be_visible()
