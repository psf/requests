# -*- coding: utf-8 -*-

import pytest
from requests.compat import urljoin


def prepare_url(value):
    # Issue #1483: Make sure the URL always has a trailing slash
    httpbin_url = value.url.rstrip('/') + '/'

    def inner(*suffix):
        return urljoin(httpbin_url, '/'.join(suffix))

    return inner


@pytest.fixture
def httpbin(httpbin):
    return prepare_url(httpbin)


@pytest.fixture
def httpbin_secure(httpbin_secure):
    return prepare_url(httpbin_secure)
