# -*- coding: utf-8 -*-

import os
import copy
import filecmp
from io import BytesIO
import zipfile
from collections import deque

import pytest
from requests import compat
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict
from requests.utils import (
    address_in_network, dotted_netmask, extract_zipped_paths,
    get_auth_from_url, _parse_content_type_header, get_encoding_from_headers,
    get_encodings_from_content, get_environ_proxies,
    guess_filename, guess_json_utf, is_ipv4_address,
    is_valid_cidr, iter_slices, parse_dict_header,
    parse_header_links, prepend_scheme_if_needed,
    requote_uri, select_proxy, should_bypass_proxies, super_len,
    to_key_val_list, to_native_string,
    unquote_header_value, unquote_unreserved,
    urldefragauth, add_dict_to_cookiejar, set_environ)
from requests._internal_utils import unicode_is_ascii

from .compat import StringIO, cStringIO


class TestSuperLen:

    @pytest.mark.parametrize(
        'stream, value', (
            (StringIO.StringIO, 'Test'),
            (BytesIO, b'Test'),
            pytest.param(cStringIO, 'Test',
                         marks=pytest.mark.skipif('cStringIO is None')),
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
        """If tell() raises errors, assume the cursor is at position zero."""
        class BoomFile(object):
            def __len__(self):
                return 5

            def tell(self):
                raise error()

        assert super_len(BoomFile()) == 0

    @pytest.mark.parametrize('error', [IOError, OSError])
    def test_super_len_tell_ioerror(self, error):
        """Ensure that if tell gives an IOError super_len doesn't fail"""
        class NoLenBoomFile(object):
            def tell(self):
                raise error()

            def seek(self, offset, whence):
                pass

        assert super_len(NoLenBoomFile()) == 0

    def test_string(self):
        assert super_len('Test') == 4

    @pytest.mark.parametrize(
        'mode, warnings_num', (
            ('r', 1),
            ('rb', 0),
        ))
    def test_file(self, tmpdir, mode, warnings_num, recwarn):
        file_obj = tmpdir.join('test.txt')
        file_obj.write('Test')
        with file_obj.open(mode) as fd:
            assert super_len(fd) == 4
        assert len(recwarn) == warnings_num

    def test_super_len_with__len__(self):
        foo = [1,2,3,4]
        len_foo = super_len(foo)
        assert len_foo == 4

    def test_super_len_with_no__len__(self):
        class LenFile(object):
            def __init__(self):
                self.len = 5

        assert super_len(LenFile()) == 5

    def test_super_len_with_tell(self):
        foo = StringIO.StringIO('12345')
        assert super_len(foo) == 5
        foo.read(2)
        assert super_len(foo) == 3

    def test_super_len_with_fileno(self):
        with open(__file__, 'rb') as f:
            length = super_len(f)
            file_data = f.read()
        assert length == len(file_data)

    def test_super_len_with_no_matches(self):
        """Ensure that objects without any length methods default to 0"""
        assert super_len(object()) == 0


class TestToKeyValList:

    @pytest.mark.parametrize(
        'value, expected', (
            ([('key', 'val')], [('key', 'val')]),
            ((('key', 'val'), ), [('key', 'val')]),
            ({'key': 'val'}, [('key', 'val')]),
            (None, None)
        ))
    def test_valid(self, value, expected):
        assert to_key_val_list(value) == expected

    def test_invalid(self):
        with pytest.raises(ValueError):
            to_key_val_list('string')


class TestUnquoteHeaderValue:

    @pytest.mark.parametrize(
        'value, expected', (
            (None, None),
            ('Test', 'Test'),
            ('"Test"', 'Test'),
            ('"Test\\\\"', 'Test\\'),
            ('"\\\\Comp\\Res"', '\\Comp\\Res'),
        ))
    def test_valid(self, value, expected):
        assert unquote_header_value(value) == expected

    def test_is_filename(self):
        assert unquote_header_value('"\\\\Comp\\Res"', True) == '\\\\Comp\\Res'


class TestGetEnvironProxies:
    """Ensures that IP addresses are correctly matches with ranges
    in no_proxy variable.
    """

    @pytest.fixture(autouse=True, params=['no_proxy', 'NO_PROXY'])
    def no_proxy(self, request, monkeypatch):
        monkeypatch.setenv(request.param, '192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1')

    @pytest.mark.parametrize(
        'url', (
            'http://192.168.0.1:5000/',
            'http://192.168.0.1/',
            'http://172.16.1.1/',
            'http://172.16.1.1:5000/',
            'http://localhost.localdomain:5000/v1.0/',
        ))
    def test_bypass(self, url):
        assert get_environ_proxies(url, no_proxy=None) == {}

    @pytest.mark.parametrize(
        'url', (
            'http://192.168.1.1:5000/',
            'http://192.168.1.1/',
            'http://www.requests.com/',
        ))
    def test_not_bypass(self, url):
        assert get_environ_proxies(url, no_proxy=None) != {}

    @pytest.mark.parametrize(
        'url', (
            'http://192.168.1.1:5000/',
            'http://192.168.1.1/',
            'http://www.requests.com/',
        ))
    def test_bypass_no_proxy_keyword(self, url):
        no_proxy = '192.168.1.1,requests.com'
        assert get_environ_proxies(url, no_proxy=no_proxy) == {}

    @pytest.mark.parametrize(
        'url', (
            'http://192.168.0.1:5000/',
            'http://192.168.0.1/',
            'http://172.16.1.1/',
            'http://172.16.1.1:5000/',
            'http://localhost.localdomain:5000/v1.0/',
        ))
    def test_not_bypass_no_proxy_keyword(self, url, monkeypatch):
        # This is testing that the 'no_proxy' argument overrides the
        # environment variable 'no_proxy'
        monkeypatch.setenv('http_proxy', 'http://proxy.example.com:3128/')
        no_proxy = '192.168.1.1,requests.com'
        assert get_environ_proxies(url, no_proxy=no_proxy) != {}


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


class TestExtractZippedPaths:

    @pytest.mark.parametrize(
        'path', (
            '/',
            __file__,
            pytest.__file__,
            '/etc/invalid/location',
        ))
    def test_unzipped_paths_unchanged(self, path):
        assert path == extract_zipped_paths(path)

    def test_zipped_paths_extracted(self, tmpdir):
        zipped_py = tmpdir.join('test.zip')
        with zipfile.ZipFile(zipped_py.strpath, 'w') as f:
            f.write(__file__)

        _, name = os.path.splitdrive(__file__)
        zipped_path = os.path.join(zipped_py.strpath, name.lstrip(r'\/'))
        extracted_path = extract_zipped_paths(zipped_path)

        assert extracted_path != zipped_path
        assert os.path.exists(extracted_path)
        assert filecmp.cmp(extracted_path, __file__)

    def test_invalid_unc_path(self):
        path = r"\\localhost\invalid\location"
        assert extract_zipped_paths(path) == path


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


class TestGuessJSONUTF:

    @pytest.mark.parametrize(
        'encoding', (
            'utf-32', 'utf-8-sig', 'utf-16', 'utf-8', 'utf-16-be', 'utf-16-le',
            'utf-32-be', 'utf-32-le'
        ))
    def test_encoded(self, encoding):
        data = '{}'.encode(encoding)
        assert guess_json_utf(data) == encoding

    def test_bad_utf_like_encoding(self):
        assert guess_json_utf(b'\x00\x00\x00\x00') is None

    @pytest.mark.parametrize(
        ('encoding', 'expected'), (
            ('utf-16-be', 'utf-16'),
            ('utf-16-le', 'utf-16'),
            ('utf-32-be', 'utf-32'),
            ('utf-32-le', 'utf-32')
        ))
    def test_guess_by_bom(self, encoding, expected):
        data = u'\ufeff{}'.encode(encoding)
        assert guess_json_utf(data) == expected


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
        (
            'http://complex.url.com/path?query=yes',
            ('', '')
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
    """See: https://github.com/psf/requests/issues/2356"""
    assert requote_uri(uri) == expected


@pytest.mark.parametrize(
    'uri, expected', (
        (
            # Illegal bytes
            'http://example.com/?a=%--',
            'http://example.com/?a=%--',
        ),
        (
            # Reserved characters
            'http://example.com/?a=%300',
            'http://example.com/?a=00',
        )
    ))
def test_unquote_unreserved(uri, expected):
    assert unquote_unreserved(uri) == expected


@pytest.mark.parametrize(
    'mask, expected', (
        (8, '255.0.0.0'),
        (24, '255.255.255.0'),
        (25, '255.255.255.128'),
    ))
def test_dotted_netmask(mask, expected):
    assert dotted_netmask(mask) == expected


http_proxies = {'http': 'http://http.proxy',
                'http://some.host': 'http://some.host.proxy'}
all_proxies = {'all': 'socks5://http.proxy',
               'all://some.host': 'socks5://some.host.proxy'}
mixed_proxies = {'http': 'http://http.proxy',
                 'http://some.host': 'http://some.host.proxy',
                 'all': 'socks5://http.proxy'}
@pytest.mark.parametrize(
    'url, expected, proxies', (
        ('hTTp://u:p@Some.Host/path', 'http://some.host.proxy', http_proxies),
        ('hTTp://u:p@Other.Host/path', 'http://http.proxy', http_proxies),
        ('hTTp:///path', 'http://http.proxy', http_proxies),
        ('hTTps://Other.Host', None, http_proxies),
        ('file:///etc/motd', None, http_proxies),

        ('hTTp://u:p@Some.Host/path', 'socks5://some.host.proxy', all_proxies),
        ('hTTp://u:p@Other.Host/path', 'socks5://http.proxy', all_proxies),
        ('hTTp:///path', 'socks5://http.proxy', all_proxies),
        ('hTTps://Other.Host', 'socks5://http.proxy', all_proxies),

        ('http://u:p@other.host/path', 'http://http.proxy', mixed_proxies),
        ('http://u:p@some.host/path', 'http://some.host.proxy', mixed_proxies),
        ('https://u:p@other.host/path', 'socks5://http.proxy', mixed_proxies),
        ('https://u:p@some.host/path', 'socks5://http.proxy', mixed_proxies),
        ('https://', 'socks5://http.proxy', mixed_proxies),
        # XXX: unsure whether this is reasonable behavior
        ('file:///etc/motd', 'socks5://http.proxy', all_proxies),
    ))
def test_select_proxies(url, expected, proxies):
    """Make sure we can select per-host proxies correctly."""
    assert select_proxy(url, proxies) == expected


@pytest.mark.parametrize(
    'value, expected', (
        ('foo="is a fish", bar="as well"', {'foo': 'is a fish', 'bar': 'as well'}),
        ('key_without_value', {'key_without_value': None})
    ))
def test_parse_dict_header(value, expected):
    assert parse_dict_header(value) == expected


@pytest.mark.parametrize(
    'value, expected', (
        (
            'application/xml',
            ('application/xml', {})
        ),
        (
            'application/json ; charset=utf-8',
            ('application/json', {'charset': 'utf-8'})
        ),
        (
            'application/json ; Charset=utf-8',
            ('application/json', {'charset': 'utf-8'})
        ),
        (
            'text/plain',
            ('text/plain', {})
        ),
        (
            'multipart/form-data; boundary = something ; boundary2=\'something_else\' ; no_equals ',
            ('multipart/form-data', {'boundary': 'something', 'boundary2': 'something_else', 'no_equals': True})
        ),
        (
                'multipart/form-data; boundary = something ; boundary2="something_else" ; no_equals ',
                ('multipart/form-data', {'boundary': 'something', 'boundary2': 'something_else', 'no_equals': True})
        ),
        (
            'multipart/form-data; boundary = something ; \'boundary2=something_else\' ; no_equals ',
            ('multipart/form-data', {'boundary': 'something', 'boundary2': 'something_else', 'no_equals': True})
        ),
        (
            'multipart/form-data; boundary = something ; "boundary2=something_else" ; no_equals ',
            ('multipart/form-data', {'boundary': 'something', 'boundary2': 'something_else', 'no_equals': True})
        ),
        (
            'application/json ; ; ',
            ('application/json', {})
        )
    ))
def test__parse_content_type_header(value, expected):
    assert _parse_content_type_header(value) == expected


@pytest.mark.parametrize(
    'value, expected', (
        (
            CaseInsensitiveDict(),
            None
        ),
        (
            CaseInsensitiveDict({'content-type': 'application/json; charset=utf-8'}),
            'utf-8'
        ),
        (
            CaseInsensitiveDict({'content-type': 'text/plain'}),
            'ISO-8859-1'
        ),
    ))
def test_get_encoding_from_headers(value, expected):
    assert get_encoding_from_headers(value) == expected


@pytest.mark.parametrize(
    'value, length', (
        ('', 0),
        ('T', 1),
        ('Test', 4),
        ('Cont', 0),
        ('Other', -5),
        ('Content', None),
    ))
def test_iter_slices(value, length):
    if length is None or (length <= 0 and len(value) > 0):
        # Reads all content at once
        assert len(list(iter_slices(value, length))) == 1
    else:
        assert len(list(iter_slices(value, 1))) == length


@pytest.mark.parametrize(
    'value, expected', (
        (
            '<http:/.../front.jpeg>; rel=front; type="image/jpeg"',
            [{'url': 'http:/.../front.jpeg', 'rel': 'front', 'type': 'image/jpeg'}]
        ),
        (
            '<http:/.../front.jpeg>',
            [{'url': 'http:/.../front.jpeg'}]
        ),
        (
            '<http:/.../front.jpeg>;',
            [{'url': 'http:/.../front.jpeg'}]
        ),
        (
            '<http:/.../front.jpeg>; type="image/jpeg",<http://.../back.jpeg>;',
            [
                {'url': 'http:/.../front.jpeg', 'type': 'image/jpeg'},
                {'url': 'http://.../back.jpeg'}
            ]
        ),
        (
            '',
            []
        ),
    ))
def test_parse_header_links(value, expected):
    assert parse_header_links(value) == expected


@pytest.mark.parametrize(
    'value, expected', (
        ('example.com/path', 'http://example.com/path'),
        ('//example.com/path', 'http://example.com/path'),
    ))
def test_prepend_scheme_if_needed(value, expected):
    assert prepend_scheme_if_needed(value, 'http') == expected


@pytest.mark.parametrize(
    'value, expected', (
        ('T', 'T'),
        (b'T', 'T'),
        (u'T', 'T'),
    ))
def test_to_native_string(value, expected):
    assert to_native_string(value) == expected


@pytest.mark.parametrize(
    'url, expected', (
        ('http://u:p@example.com/path?a=1#test', 'http://example.com/path?a=1'),
        ('http://example.com/path', 'http://example.com/path'),
        ('//u:p@example.com/path', '//example.com/path'),
        ('//example.com/path', '//example.com/path'),
        ('example.com/path', '//example.com/path'),
        ('scheme:u:p@example.com/path', 'scheme://example.com/path'),
    ))
def test_urldefragauth(url, expected):
    assert urldefragauth(url) == expected


@pytest.mark.parametrize(
    'url, expected', (
            ('http://192.168.0.1:5000/', True),
            ('http://192.168.0.1/', True),
            ('http://172.16.1.1/', True),
            ('http://172.16.1.1:5000/', True),
            ('http://localhost.localdomain:5000/v1.0/', True),
            ('http://google.com:6000/', True),
            ('http://172.16.1.12/', False),
            ('http://172.16.1.12:5000/', False),
            ('http://google.com:5000/v1.0/', False),
            ('file:///some/path/on/disk', True),
    ))
def test_should_bypass_proxies(url, expected, monkeypatch):
    """Tests for function should_bypass_proxies to check if proxy
    can be bypassed or not
    """
    monkeypatch.setenv('no_proxy', '192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1, google.com:6000')
    monkeypatch.setenv('NO_PROXY', '192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1, google.com:6000')
    assert should_bypass_proxies(url, no_proxy=None) == expected


@pytest.mark.parametrize(
    'url, expected', (
            ('http://172.16.1.1/', '172.16.1.1'),
            ('http://172.16.1.1:5000/', '172.16.1.1'),
            ('http://user:pass@172.16.1.1', '172.16.1.1'),
            ('http://user:pass@172.16.1.1:5000', '172.16.1.1'),
            ('http://hostname/', 'hostname'),
            ('http://hostname:5000/', 'hostname'),
            ('http://user:pass@hostname', 'hostname'),
            ('http://user:pass@hostname:5000', 'hostname'),
    ))
def test_should_bypass_proxies_pass_only_hostname(url, expected, mocker):
    """The proxy_bypass function should be called with a hostname or IP without
    a port number or auth credentials.
    """
    proxy_bypass = mocker.patch('requests.utils.proxy_bypass')
    should_bypass_proxies(url, no_proxy=None)
    proxy_bypass.assert_called_once_with(expected)


@pytest.mark.parametrize(
    'cookiejar', (
        compat.cookielib.CookieJar(),
        RequestsCookieJar()
    ))
def test_add_dict_to_cookiejar(cookiejar):
    """Ensure add_dict_to_cookiejar works for
    non-RequestsCookieJar CookieJars
    """
    cookiedict = {'test': 'cookies',
                  'good': 'cookies'}
    cj = add_dict_to_cookiejar(cookiejar, cookiedict)
    cookies = {cookie.name: cookie.value for cookie in cj}
    assert cookiedict == cookies


@pytest.mark.parametrize(
    'value, expected', (
                (u'test', True),
                (u'æíöû', False),
                (u'ジェーピーニック', False),
    )
)
def test_unicode_is_ascii(value, expected):
    assert unicode_is_ascii(value) is expected


@pytest.mark.parametrize(
    'url, expected', (
            ('http://192.168.0.1:5000/', True),
            ('http://192.168.0.1/', True),
            ('http://172.16.1.1/', True),
            ('http://172.16.1.1:5000/', True),
            ('http://localhost.localdomain:5000/v1.0/', True),
            ('http://172.16.1.12/', False),
            ('http://172.16.1.12:5000/', False),
            ('http://google.com:5000/v1.0/', False),
    ))
def test_should_bypass_proxies_no_proxy(
        url, expected, monkeypatch):
    """Tests for function should_bypass_proxies to check if proxy
    can be bypassed or not using the 'no_proxy' argument
    """
    no_proxy = '192.168.0.0/24,127.0.0.1,localhost.localdomain,172.16.1.1'
    # Test 'no_proxy' argument
    assert should_bypass_proxies(url, no_proxy=no_proxy) == expected


@pytest.mark.skipif(os.name != 'nt', reason='Test only on Windows')
@pytest.mark.parametrize(
    'url, expected, override', (
            ('http://192.168.0.1:5000/', True, None),
            ('http://192.168.0.1/', True, None),
            ('http://172.16.1.1/', True, None),
            ('http://172.16.1.1:5000/', True, None),
            ('http://localhost.localdomain:5000/v1.0/', True, None),
            ('http://172.16.1.22/', False, None),
            ('http://172.16.1.22:5000/', False, None),
            ('http://google.com:5000/v1.0/', False, None),
            ('http://mylocalhostname:5000/v1.0/', True, '<local>'),
            ('http://192.168.0.1/', False, ''),
    ))
def test_should_bypass_proxies_win_registry(url, expected, override,
                                            monkeypatch):
    """Tests for function should_bypass_proxies to check if proxy
    can be bypassed or not with Windows registry settings
    """
    if override is None:
        override = '192.168.*;127.0.0.1;localhost.localdomain;172.16.1.1'
    if compat.is_py3:
        import winreg
    else:
        import _winreg as winreg

    class RegHandle:
        def Close(self):
            pass

    ie_settings = RegHandle()
    proxyEnableValues = deque([1, "1"])

    def OpenKey(key, subkey):
        return ie_settings

    def QueryValueEx(key, value_name):
        if key is ie_settings:
            if value_name == 'ProxyEnable':
                # this could be a string (REG_SZ) or a 32-bit number (REG_DWORD)
                proxyEnableValues.rotate()
                return [proxyEnableValues[0]]
            elif value_name == 'ProxyOverride':
                return [override]

    monkeypatch.setenv('http_proxy', '')
    monkeypatch.setenv('https_proxy', '')
    monkeypatch.setenv('ftp_proxy', '')
    monkeypatch.setenv('no_proxy', '')
    monkeypatch.setenv('NO_PROXY', '')
    monkeypatch.setattr(winreg, 'OpenKey', OpenKey)
    monkeypatch.setattr(winreg, 'QueryValueEx', QueryValueEx)
    assert should_bypass_proxies(url, None) == expected


@pytest.mark.parametrize(
    'env_name, value', (
            ('no_proxy', '192.168.0.0/24,127.0.0.1,localhost.localdomain'),
            ('no_proxy', None),
            ('a_new_key', '192.168.0.0/24,127.0.0.1,localhost.localdomain'),
            ('a_new_key', None),
    ))
def test_set_environ(env_name, value):
    """Tests set_environ will set environ values and will restore the environ."""
    environ_copy = copy.deepcopy(os.environ)
    with set_environ(env_name, value):
        assert os.environ.get(env_name) == value

    assert os.environ == environ_copy


def test_set_environ_raises_exception():
    """Tests set_environ will raise exceptions in context when the
    value parameter is None."""
    with pytest.raises(Exception) as exception:
        with set_environ('test1', None):
            raise Exception('Expected exception')

    assert 'Expected exception' in str(exception.value)
