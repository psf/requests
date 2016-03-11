# coding: utf-8
import os
from io import BytesIO

import pytest
from requests import compat
from requests.utils import (
    address_in_network, dotted_netmask,
    get_auth_from_url, get_encodings_from_content,
    get_environ_proxies, guess_filename,
    is_ipv4_address, is_valid_cidr, requote_uri,
    select_proxy, super_len)

from .compat import StringIO, cStringIO


class TestSuperLen:
    @pytest.mark.parametrize(
        'stream, value', (
            (StringIO.StringIO, 'Test'),
            (BytesIO, b'Test'),
            pytest.mark.skipif('cStringIO is None')((cStringIO, 'Test')),
        ))
    def test_io_streams(self, stream, value):
        """Ensures that we properly deal with different kinds of IO streams."""
        assert super_len(stream()) == 0
        assert super_len(stream(value)) == 4

    def test_super_len_correctly_calculates_len_of_partially_read_file(self):
        """Ensure that we handle partially consumed file like objects."""
        s = StringIO.StringIO()
        s.write('foobarbogus')
        assert super_len(s) == 0

    @pytest.mark.parametrize('error', [IOError, OSError])
    def test_super_len_handles_files_raising_weird_errors_in_tell(self, error):
        """
        If tell() raises errors, assume the cursor is at position zero.
        """
        class BoomFile(object):
            def __len__(self):
                return 5

            def tell(self):
                raise error()

        assert super_len(BoomFile()) == 0


class TestGetEnvironProxies:
    """Ensures that IP addresses are correctly matches with ranges
    in no_proxy variable."""

    @pytest.yield_fixture(scope='class', autouse=True, params=['no_proxy', 'NO_PROXY'])
    def no_proxy(self, request):
        os.environ[request.param] = '192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1'
        yield
        del os.environ[request.param]

    @pytest.mark.parametrize(
        'url', (
            'http://192.168.0.1:5000/',
            'http://192.168.0.1/',
            'http://172.16.1.1/',
            'http://172.16.1.1:5000/',
            'http://localhost.localdomain:5000/v1.0/',
        ))
    def test_bypass(self, url):
        assert get_environ_proxies(url) == {}

    @pytest.mark.parametrize(
        'url', (
            'http://192.168.1.1:5000/',
            'http://192.168.1.1/',
            'http://www.requests.com/',
        ))
    def test_not_bypass(self, url):
        assert get_environ_proxies(url) != {}


class TestIsIPv4Address:

    def test_valid(self):
        assert is_ipv4_address('8.8.8.8')

    @pytest.mark.parametrize('value', ('8.8.8.8.8', 'localhost.localdomain'))
    def test_invalid(self, value):
        assert not is_ipv4_address(value)


class TestIsValidCIDR:

    def test_valid(self):
        assert is_valid_cidr('192.168.1.0/24')

    @pytest.mark.parametrize(
        'value', (
            '8.8.8.8',
            '192.168.1.0/a',
            '192.168.1.0/128',
            '192.168.1.0/-1',
            '192.168.1.999/24',
        ))
    def test_invalid(self, value):
        assert not is_valid_cidr(value)


class TestAddressInNetwork:

    def test_valid(self):
        assert address_in_network('192.168.1.1', '192.168.1.0/24')

    def test_invalid(self):
        assert not address_in_network('172.16.0.1', '192.168.1.0/24')


class TestGuessFilename:

    @pytest.mark.parametrize(
        'value', (1, type('Fake', (object,), {'name': 1})()),
    )
    def test_guess_filename_invalid(self, value):
        assert guess_filename(value) is None

    @pytest.mark.parametrize(
        'value, expected_type', (
            (b'value', compat.bytes),
            (b'value'.decode('utf-8'), compat.str)
        ))
    def test_guess_filename_valid(self, value, expected_type):
        obj = type('Fake', (object,), {'name': value})()
        result = guess_filename(obj)
        assert result == value
        assert isinstance(result, expected_type)


class TestContentEncodingDetection:

    def test_none(self):
        encodings = get_encodings_from_content('')
        assert not len(encodings)

    @pytest.mark.parametrize(
        'content', (
            # HTML5 meta charset attribute
            '<meta charset="UTF-8">',
            # HTML4 pragma directive
            '<meta http-equiv="Content-type" content="text/html;charset=UTF-8">',
            # XHTML 1.x served with text/html MIME type
            '<meta http-equiv="Content-type" content="text/html;charset=UTF-8" />',
            # XHTML 1.x served as XML
            '<?xml version="1.0" encoding="UTF-8"?>',
        ))
    def test_pragmas(self, content):
        encodings = get_encodings_from_content(content)
        assert len(encodings) == 1
        assert encodings[0] == 'UTF-8'

    def test_precedence(self):
        content = '''
        <?xml version="1.0" encoding="XML"?>
        <meta charset="HTML5">
        <meta http-equiv="Content-type" content="text/html;charset=HTML4" />
        '''.strip()
        assert get_encodings_from_content(content) == ['HTML5', 'HTML4', 'XML']


USER = PASSWORD = "%!*'();:@&=+$,/?#[] "
ENCODED_USER = compat.quote(USER, '')
ENCODED_PASSWORD = compat.quote(PASSWORD, '')


@pytest.mark.parametrize(
    'url, auth', (
        (
            'http://' + ENCODED_USER + ':' + ENCODED_PASSWORD + '@' +
            'request.com/url.html#test',
            (USER, PASSWORD)
        ),
        (
            'http://user:pass@complex.url.com/path?query=yes',
            ('user', 'pass')
        ),
        (
            'http://user:pass%20pass@complex.url.com/path?query=yes',
            ('user', 'pass pass')
        ),
        (
            'http://user:pass pass@complex.url.com/path?query=yes',
            ('user', 'pass pass')
        ),
        (
            'http://user%25user:pass@complex.url.com/path?query=yes',
            ('user%user', 'pass')
        ),
        (
            'http://user:pass%23pass@complex.url.com/path?query=yes',
            ('user', 'pass#pass')
        ),
    ))
def test_get_auth_from_url(url, auth):
    assert get_auth_from_url(url) == auth


@pytest.mark.parametrize(
    'uri, expected', (
        (
            # Ensure requoting doesn't break expectations
            'http://example.com/fiz?buz=%25ppicture',
            'http://example.com/fiz?buz=%25ppicture',
        ),
        (
            # Ensure we handle unquoted percent signs in redirects
            'http://example.com/fiz?buz=%ppicture',
            'http://example.com/fiz?buz=%25ppicture',
        ),
    ))
def test_requote_uri_with_unquoted_percents(uri, expected):
    """See: https://github.com/kennethreitz/requests/issues/2356
    """
    assert requote_uri(uri) == expected


@pytest.mark.parametrize(
    'mask, expected', (
        (8, '255.0.0.0'),
        (24, '255.255.255.0'),
        (25, '255.255.255.128'),
    ))
def test_dotted_netmask(mask, expected):
    assert dotted_netmask(mask) == expected


@pytest.mark.parametrize(
    'url, expected', (
        ('hTTp://u:p@Some.Host/path', 'http://some.host.proxy'),
        ('hTTp://u:p@Other.Host/path', 'http://http.proxy'),
        ('hTTps://Other.Host', None),
    ))
def test_select_proxies(url, expected):
    """Make sure we can select per-host proxies correctly."""
    proxies = {'http': 'http://http.proxy',
               'http://some.host': 'http://some.host.proxy'}
    assert select_proxy(url, proxies) == expected
