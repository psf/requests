import re
import string
from .util import escape_url

PREVENT_BACKSLASH = r'(?<!\\)(?:\\\\)*'
PUNCTUATION = r'[' + re.escape(string.punctuation) + r']'

LINK_LABEL = r'(?:[^\\\[\]]|\\.){0,500}'

LINK_BRACKET_START = re.compile(r'[ \t]*\n?[ \t]*<')
LINK_BRACKET_RE = re.compile(r'<([^<>\n\\\x00]*)>')
LINK_HREF_BLOCK_RE = re.compile(r'[ \t]*\n?[ \t]*([^\s]+)(?:\s|$)')
LINK_HREF_INLINE_RE = re.compile(
    r'[ \t]*\n?[ \t]*([^ \t\n]*?)(?:[ \t\n]|'
    r'(?:' + PREVENT_BACKSLASH + r'\)))'
)

LINK_TITLE_RE = re.compile(
    r'[ \t\n]+('
    r'"(?:\\' + PUNCTUATION + r'|[^"\x00])*"|'  # "title"
    r"'(?:\\" + PUNCTUATION + r"|[^'\x00])*'"  # 'title'
    r')'
)
PAREN_END_RE = re.compile(r'\s*\)')

HTML_TAGNAME = r'[A-Za-z][A-Za-z0-9-]*'
HTML_ATTRIBUTES = (
    r'(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*'
    r'(?:\s*=\s*(?:[^ !"\'=<>`]+|\'[^\']*?\'|"[^\"]*?"))?)*'
)

BLOCK_TAGS = (
    'address', 'article', 'aside', 'base', 'basefont', 'blockquote',
    'body', 'caption', 'center', 'col', 'colgroup', 'dd', 'details',
    'dialog', 'dir', 'div', 'dl', 'dt', 'fieldset', 'figcaption',
    'figure', 'footer', 'form', 'frame', 'frameset', 'h1', 'h2', 'h3',
    'h4', 'h5', 'h6', 'head', 'header', 'hr', 'html', 'iframe',
    'legend', 'li', 'link', 'main', 'menu', 'menuitem', 'meta', 'nav',
    'noframes', 'ol', 'optgroup', 'option', 'p', 'param', 'section',
    'source', 'summary', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead',
    'title', 'tr', 'track', 'ul'
)
PRE_TAGS = ('pre', 'script', 'style', 'textarea')

_INLINE_LINK_LABEL_RE = re.compile(LINK_LABEL + r'\]')
_INLINE_SQUARE_BRACKET_RE = re.compile(PREVENT_BACKSLASH + r'[\[\]]')
_ESCAPE_CHAR_RE = re.compile(r'\\(' + PUNCTUATION + r')')


def unescape_char(text):
    return _ESCAPE_CHAR_RE.sub(r'\1', text)


def parse_link_text(src, pos):
    level = 1
    found = False
    start_pos = pos

    while pos < len(src):
        m = _INLINE_SQUARE_BRACKET_RE.search(src, pos)
        if not m:
            break

        pos = m.end()
        marker = m.group(0)
        if marker == ']':
            level -= 1
            if level == 0:
                found = True
                break
        else:
            level += 1

    if found:
        text = src[start_pos:pos-1]
        return text, pos
    return None, None


def parse_link_label(src, start_pos):
    m = _INLINE_LINK_LABEL_RE.match(src, start_pos)
    if m:
        label = m.group(0)[:-1]
        return label, m.end()
    return None, None


def parse_link_href(src, start_pos, block=False):
    m = LINK_BRACKET_START.match(src, start_pos)
    if m:
        start_pos = m.end() - 1
        m = LINK_BRACKET_RE.match(src, start_pos)
        if m:
            return m.group(1), m.end()
        return None, None

    if block:
        m = LINK_HREF_BLOCK_RE.match(src, start_pos)
    else:
        m = LINK_HREF_INLINE_RE.match(src, start_pos)

    if not m:
        return None, None

    end_pos = m.end()
    href = m.group(1)

    if block and src[end_pos - 1] == href[-1]:
        return href, end_pos
    return href, end_pos - 1


def parse_link_title(src, start_pos, max_pos):
    m = LINK_TITLE_RE.match(src, start_pos, max_pos)
    if m:
        title = m.group(1)[1:-1]
        title = unescape_char(title)
        return title, m.end()
    return None, None


def parse_link(src, pos):
    href, href_pos = parse_link_href(src, pos)
    if href is None:
        return None, None

    title, title_pos = parse_link_title(src, href_pos, len(src))
    next_pos = title_pos or href_pos
    m = PAREN_END_RE.match(src, next_pos)
    if not m:
        return None, None

    href = unescape_char(href)
    attrs = {'url': escape_url(href)}
    if title:
        attrs['title'] = title
    return attrs, m.end()
