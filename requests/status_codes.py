# -*- coding: utf-8 -*-

r"""
The ``codes`` object defines a mapping from common names for HTTP statuses
to their numerical codes, accessible either as attributes or as dictionary
items.

Example::

    >>> import requests
    >>> requests.codes['temporary_redirect']
    307
    >>> requests.codes.teapot
    418
    >>> requests.codes['\o/']
    200

Some codes have multiple names, and both upper- and lower-case versions of
the names are allowed. For example, ``codes.ok``, ``codes.OK``, and
``codes.okay`` all correspond to the HTTP status code 200.
"""

from .structures import LookupDict

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
_official = {

    # Informational.
    100: ('continue',),
    101: ('switching_protocols',),
    103: ('checkpoint',),
    122: ('uri_too_long', 'request_uri_too_long'),  # Unable to find, and looks like an error?

    # Success.
    200: ('ok', 'okay', 'all_ok', 'all_okay', 'all_good', '\\o/', '✓'),
    201: ('created',),
    202: ('accepted',),
    203: ('non_authoritative_info', 'non_authoritative_information'),
    204: ('no_content',),
    205: ('reset_content', 'reset'),
    206: ('partial_content', 'partial'),
    226: ('im_used',),

    # Redirection.
    300: ('multiple_choices',),
    301: ('moved_permanently', 'moved', '\\o-'),
    302: ('found',),
    303: ('see_other', 'other'),
    304: ('not_modified',),
    305: ('use_proxy',),
    306: ('switch_proxy',),
    307: ('temporary_redirect', 'temporary_moved', 'temporary'),
    308: ('permanent_redirect',
          'resume_incomplete', 'resume',),  # These 2 to be removed in 3.0

    # Client Error.
    400: ('bad_request', 'bad'),
    401: ('unauthorized',),
    402: ('payment_required', 'payment'),
    403: ('forbidden',),
    404: ('not_found', '-o-'),
    405: ('method_not_allowed', 'not_allowed'),
    406: ('not_acceptable',),
    407: ('proxy_authentication_required', 'proxy_auth', 'proxy_authentication'),
    408: ('request_timeout', 'timeout'),
    409: ('conflict',),
    410: ('gone',),
    411: ('length_required',),
    412: ('precondition_failed', 'precondition'),
    413: ('payload_too_large', 'request_entity_too_large'),
    414: ('uri_too_long', 'request_uri_too_large'),
    415: ('unsupported_media_type', 'unsupported_media', 'media_type'),
    416: ('requested_range_not_satisfiable', 'requested_range', 'range_not_satisfiable'),
    417: ('expectation_failed',),
    418: ('im_a_teapot', 'teapot', 'i_am_a_teapot'),
    421: ('misdirected_request',),
    425: ('unordered_collection', 'unordered'),
    426: ('upgrade_required', 'upgrade'),
    428: ('precondition_required', 'precondition'),
    429: ('too_many_requests', 'too_many'),
    431: ('header_fields_too_large', 'fields_too_large'),
    451: ('unavailable_for_legal_reasons', 'legal_reasons'),  # IIS: Redirect

    # Server Error.
    500: ('internal_server_error', 'server_error', '/o\\', '✗'),
    501: ('not_implemented',),
    502: ('bad_gateway',),
    503: ('service_unavailable', 'unavailable'),
    504: ('gateway_timeout',),
    505: ('http_version_not_supported', 'http_version'),
    506: ('variant_also_negotiates',),
    509: ('bandwidth_limit_exceeded', 'bandwidth'),
    510: ('not_extended',),
    511: ('network_authentication_required', 'network_auth', 'network_authentication'),
}

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
_webdav = {
    # Informational.
    102: ('processing',),

    # Success.
    207: ('multi_status', 'multiple_status', 'multi_stati', 'multiple_stati'),
    208: ('already_reported',),

    # Client Error.
    422: ('unprocessable_entity', 'unprocessable'),
    423: ('locked',),
    424: ('failed_dependency', 'dependency'),

    # Server Error.
    507: ('insufficient_storage',),
    508: ('loop_detected',),
}

# https://www.nginx.com/resources/wiki/extending/api/http/
# TODO Complete list.
_nginx = {
    444: ('no_response', 'none'),
    499: ('client_closed_request',),
}

# https://docs.microsoft.com/en-us/troubleshoot/iis/http-status-code
# TODO Complete list.
_iis = {
    449: ('retry_with', 'retry'),  # Not officially listed, but on Wikipedia.
}

# Unable to find documentation.
_microsoft = {
    450: ('blocked_by_windows_parental_controls', 'parental_controls'),
}

_codes = {}
_codes.update(_official)
_codes.update(_webdav)
_codes.update(_nginx)
_codes.update(_iis)
_codes.update(_microsoft)

codes = LookupDict(name='status_codes')

def _init():
    for code, titles in _codes.items():
        for title in titles:
            setattr(codes, title, code)
            if not title.startswith(('\\', '/')):
                setattr(codes, title.upper(), code)

    def doc(code):
        names = ', '.join('``%s``' % n for n in _codes[code])
        return '* %d: %s' % (code, names)

    global __doc__
    __doc__ = (__doc__ + '\n' +
               '\n'.join(doc(code) for code in sorted(_codes))
               if __doc__ is not None else None)

_init()
