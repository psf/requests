import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Match

from ..util import strip_end

if TYPE_CHECKING:
    from ..block_parser import BlockParser
    from ..core import BaseRenderer, BlockState
    from ..markdown import Markdown

__all__ = ["def_list"]

# https://michelf.ca/projects/php-markdown/extra/#def-list

DEF_PATTERN = (
    r"^(?P<def_list_head>(?:[^\n]+\n)+?)"
    r"\n?(?:"
    r"\:[ \t]+.*\n"
    r"(?:[^\n]+\n)*"  # lazy continue line
    r"(?:(?:[ \t]*\n)*[ \t]+[^\n]+\n)*"
    r"(?:[ \t]*\n)*"
    r")+"
)
DEF_RE = re.compile(DEF_PATTERN, re.M)
DD_START_RE = re.compile(r"^:[ \t]+", re.M)
TRIM_RE = re.compile(r"^ {0,4}", re.M)
HAS_BLANK_LINE_RE = re.compile(r"\n[ \t]*\n$")


def parse_def_list(block: "BlockParser", m: Match[str], state: "BlockState") -> int:
    pos = m.end()
    children = list(_parse_def_item(block, m))

    m2 = DEF_RE.match(state.src, pos)
    while m2:
        children.extend(list(_parse_def_item(block, m2)))
        pos = m2.end()
        m2 = DEF_RE.match(state.src, pos)

    state.append_token(
        {
            "type": "def_list",
            "children": children,
        }
    )
    return pos


def _parse_def_item(block: "BlockParser", m: Match[str]) -> Iterable[Dict[str, Any]]:
    head = m.group("def_list_head")
    for line in head.splitlines():
        yield {
            "type": "def_list_head",
            "text": line,
        }

    src = m.group(0)
    end = len(head)

    m2 = DD_START_RE.search(src, end)
    assert m2 is not None
    start = m2.start()
    prev_blank_line = src[end:start] == "\n"
    while m2:
        m2 = DD_START_RE.search(src, start + 1)
        if not m2:
            break

        end = m2.start()
        text = src[start:end].replace(":", " ", 1)
        children = _process_text(block, text, prev_blank_line)
        prev_blank_line = bool(HAS_BLANK_LINE_RE.search(text))
        yield {
            "type": "def_list_item",
            "children": children,
        }
        start = end

    text = src[start:].replace(":", " ", 1)
    children = _process_text(block, text, prev_blank_line)
    yield {
        "type": "def_list_item",
        "children": children,
    }


def _process_text(block: "BlockParser", text: str, loose: bool) -> List[Any]:
    text = TRIM_RE.sub("", text)
    state = block.state_cls()
    state.process(strip_end(text))
    # use default list rules
    block.parse(state, block.list_rules)
    tokens = state.tokens
    if not loose and len(tokens) == 1 and tokens[0]["type"] == "paragraph":
        tokens[0]["type"] = "block_text"
    return tokens


def render_def_list(renderer: "BaseRenderer", text: str) -> str:
    return "<dl>\n" + text + "</dl>\n"


def render_def_list_head(renderer: "BaseRenderer", text: str) -> str:
    return "<dt>" + text + "</dt>\n"


def render_def_list_item(renderer: "BaseRenderer", text: str) -> str:
    return "<dd>" + text + "</dd>\n"


def def_list(md: "Markdown") -> None:
    """A mistune plugin to support def list, spec defined at
    https://michelf.ca/projects/php-markdown/extra/#def-list

    Here is an example:

    .. code-block:: text

        Apple
        :   Pomaceous fruit of plants of the genus Malus in
            the family Rosaceae.

        Orange
        :   The fruit of an evergreen tree of the genus Citrus.

    It will be converted into HTML:

    .. code-block:: html

        <dl>
        <dt>Apple</dt>
        <dd>Pomaceous fruit of plants of the genus Malus in
        the family Rosaceae.</dd>

        <dt>Orange</dt>
        <dd>The fruit of an evergreen tree of the genus Citrus.</dd>
        </dl>

    :param md: Markdown instance
    """
    md.block.register("def_list", DEF_PATTERN, parse_def_list, before="paragraph")
    if md.renderer and md.renderer.NAME == "html":
        md.renderer.register("def_list", render_def_list)
        md.renderer.register("def_list_head", render_def_list_head)
        md.renderer.register("def_list_item", render_def_list_item)
