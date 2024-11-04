import re
from urllib.parse import quote
from html import _replace_charref


_expand_tab_re = re.compile(r'^( {0,3})\t', flags=re.M)


def expand_leading_tab(text: str, width=4):
    def repl(m):
        s = m.group(1)
        return s + ' ' * (width - len(s))
    return _expand_tab_re.sub(repl, text)


def expand_tab(text: str, space: str='    '):
    repl = r'\1' + space
    return _expand_tab_re.sub(repl, text)


def escape(s: str, quote: bool=True):
    """Escape characters of ``&<>``. If quote=True, ``"`` will be
    converted to ``&quote;``."""
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;")
    return s


def escape_url(link: str):
    """Escape URL for safety."""
    safe = (
        ':/?#@'           # gen-delims - '[]' (rfc3986)
        '!$&()*+,;='      # sub-delims - "'" (rfc3986)
        '%'               # leave already-encoded octets alone
    )
    return escape(quote(unescape(link), safe=safe))


def safe_entity(s: str):
    """Escape characters for safety."""
    return escape(unescape(s))


def unikey(s: str):
    """Generate a unique key for links and footnotes."""
    key = ' '.join(s.split()).strip()
    return key.lower().upper()


_charref_re = re.compile(
    r'&(#[0-9]{1,7};'
    r'|#[xX][0-9a-fA-F]+;'
    r'|[^\t\n\f <&#;]{1,32};)'
)


def unescape(s: str):
    """
    Copy from `html.unescape`, but `_charref` is different. CommonMark
    does not accept entity references without a trailing semicolon
    """
    if '&' not in s:
        return s
    return _charref_re.sub(_replace_charref, s)


_striptags_re = re.compile(r'(<!--.*?-->|<[^>]*>)')


def striptags(s: str):
    return _striptags_re.sub('', s)


_strip_end_re = re.compile(r'\n\s+$')


def strip_end(src: str):
    return _strip_end_re.sub('\n', src)
