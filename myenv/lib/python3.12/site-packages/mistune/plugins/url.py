from ..util import escape_url

__all__ = ['url']

URL_LINK_PATTERN = r'''https?:\/\/[^\s<]+[^<.,:;"')\]\s]'''


def parse_url_link(inline, m, state):
    text = m.group(0)
    pos = m.end()
    if state.in_link:
        inline.process_text(text, state)
        return pos
    state.append_token({
        'type': 'link',
        'children': [{'type': 'text', 'raw': text}],
        'attrs': {'url': escape_url(text)},
    })
    return pos


def url(md):
    md.inline.register('url_link', URL_LINK_PATTERN, parse_url_link)
