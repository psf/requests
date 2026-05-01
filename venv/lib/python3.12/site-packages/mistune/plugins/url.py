from typing import TYPE_CHECKING, Match

from ..util import escape_url

if TYPE_CHECKING:
    from ..core import InlineState
    from ..inline_parser import InlineParser
    from ..markdown import Markdown

__all__ = ["url"]

URL_LINK_PATTERN = r"""https?:\/\/[^\s<]+[^<.,:;"')\]\s]"""


def parse_url_link(inline: "InlineParser", m: Match[str], state: "InlineState") -> int:
    text = m.group(0)
    pos = m.end()
    if state.in_link:
        inline.process_text(text, state)
        return pos
    state.append_token(
        {
            "type": "link",
            "children": [{"type": "text", "raw": text}],
            "attrs": {"url": escape_url(text)},
        }
    )
    return pos


def url(md: "Markdown") -> None:
    md.inline.register("url_link", URL_LINK_PATTERN, parse_url_link)
