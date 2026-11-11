import os

import pytest


@pytest.fixture(scope='session')
def ctfd_url():
    return os.getenv('CTFD_URL', 'http://localhost:8000').rstrip('/')


@pytest.fixture(scope='session')
def ctfd_admin_token():
    token = os.getenv('CTFD_ADMIN_TOKEN')
    if not token:
        pytest.skip('set CTFD_ADMIN_TOKEN to run tests that need the CTFd admin API')
    return token
