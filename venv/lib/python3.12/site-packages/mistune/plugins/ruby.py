import re
from typing import TYPE_CHECKING, Any, Dict, List, Match, Optional

from ..helpers import parse_link, parse_link_label
from ..util import unikey

if TYPE_CHECKING:
    from ..core import BaseRenderer, InlineState
    from ..inline_parser import InlineParser
    from ..markdown import Markdown


RUBY_PATTERN = r"\[(?:\w+\([\w ]+\))+\]"
_ruby_re = re.compile(RUBY_PATTERN)


def parse_ruby(inline: "InlineParser", m: Match[str], state: "InlineState") -> int:
    text = m.group(0)[1:-2]
    items = text.split(")")
    tokens = []
    for item in items:
        rb, rt = item.split("(")
        tokens.append({"type": "ruby", "raw": rb, "attrs": {"rt": rt}})

    end_pos = m.end()

    next_match = _ruby_re.match(state.src, end_pos)
    if next_match:
        for tok in tokens:
            state.append_token(tok)
        return parse_ruby(inline, next_match, state)

    # repeat link logic
    if end_pos < len(state.src):
        link_pos = _parse_ruby_link(inline, state, end_pos, tokens)
        if link_pos:
            return link_pos

    for tok in tokens:
        state.append_token(tok)
    return end_pos


def _parse_ruby_link(
    inline: "InlineParser", state: "InlineState", pos: int, tokens: List[Dict[str, Any]]
) -> Optional[int]:
    c = state.src[pos]
    if c == "(":
        # standard link [text](<url> "title")
        attrs, link_pos = parse_link(state.src, pos + 1)
        if link_pos:
            state.append_token(
                {
                    "type": "link",
                    "children": tokens,
                    "attrs": attrs,
                }
            )
            return link_pos

    elif c == "[":
        # standard ref link [text][label]
        label, link_pos = parse_link_label(state.src, pos + 1)
        if label and link_pos:
            ref_links = state.env["ref_links"]
            key = unikey(label)
            env = ref_links.get(key)
            if env:
                attrs = {"url": env["url"], "title": env.get("title")}
                state.append_token(
                    {
                        "type": "link",
                        "children": tokens,
                        "attrs": attrs,
                    }
                )
            else:
                for tok in tokens:
                    state.append_token(tok)
                state.append_token(
                    {
                        "type": "text",
                        "raw": "[" + label + "]",
                    }
                )
            return link_pos
    return None


def render_ruby(renderer: "BaseRenderer", text: str, rt: str) -> str:
    return "<ruby>" + text + "<rt>" + rt + "</rt></ruby>"


def ruby(md: "Markdown") -> None:
    """A mistune plugin to support ``<ruby>`` tag. The syntax is defined
    at https://lepture.com/en/2022/markdown-ruby-markup:

    .. code-block:: text

        [漢字(ㄏㄢˋㄗˋ)]
        [漢(ㄏㄢˋ)字(ㄗˋ)]

        [漢字(ㄏㄢˋㄗˋ)][link]
        [漢字(ㄏㄢˋㄗˋ)](/url "title")

        [link]: /url "title"

    :param md: Markdown instance
    """
    md.inline.register("ruby", RUBY_PATTERN, parse_ruby, before="link")
    if md.renderer and md.renderer.NAME == "html":
        md.renderer.register("ruby", render_ruby)
