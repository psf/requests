import re
import string
from typing import TYPE_CHECKING, Match

if TYPE_CHECKING:
    from ..block_parser import BlockParser
    from ..core import BlockState, InlineState
    from ..inline_parser import InlineParser
    from ..markdown import Markdown

# because mismatch is too slow, add parsers for paragraph and text

HARD_LINEBREAK_RE = re.compile(r" *\n\s*")
PARAGRAPH = (
    # start with none punctuation, not number, not whitespace
    r"(?:^[^\s\d" + re.escape(string.punctuation) + r"][^\n]*\n)+"
)

__all__ = ["speedup"]


def parse_text(inline: "InlineParser", m: Match[str], state: "InlineState") -> int:
    text = m.group(0)
    text = HARD_LINEBREAK_RE.sub("\n", text)
    inline.process_text(text, state)
    return m.end()


def parse_paragraph(block: "BlockParser", m: Match[str], state: "BlockState") -> int:
    text = m.group(0)
    state.add_paragraph(text)
    return m.end()


def speedup(md: "Markdown") -> None:
    """Increase the speed of parsing paragraph and inline text."""
    md.block.register("paragraph", PARAGRAPH, parse_paragraph)

    punc = r"\\><!\[_*`~\^\$="
    text_pattern = r"[\s\S]+?(?=[" + punc + r"]|"
    if "url_link" in md.inline.rules:
        text_pattern += "https?:|"

    if md.inline.hard_wrap:
        text_pattern += r" *\n|"
    else:
        text_pattern += r" {2,}\n|"

    text_pattern += r"$)"
    md.inline.register("text", text_pattern, parse_text)
