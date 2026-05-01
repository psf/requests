"""because list is complex, split list parser in a new file"""

import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple, Match
from .util import expand_leading_tab, expand_tab, strip_end

if TYPE_CHECKING:
    from .block_parser import BlockParser
    from .core import BlockState

LIST_PATTERN = (
    r"^(?P<list_1> {0,3})"
    r"(?P<list_2>[\*\+-]|\d{1,9}[.)])"
    r"(?P<list_3>[ \t]*|[ \t].+)$"
)

_LINE_HAS_TEXT = re.compile(r"(\s*)\S")


def parse_list(block: "BlockParser", m: Match[str], state: "BlockState") -> int:
    """Parse tokens for ordered and unordered list."""
    text = m.group("list_3")
    if not text.strip():
        # Example 285
        # an empty list item cannot interrupt a paragraph
        end_pos = state.append_paragraph()
        if end_pos:
            return end_pos

    marker = m.group("list_2")
    ordered = len(marker) > 1
    depth = state.depth()
    token: Dict[str, Any] = {
        "type": "list",
        "children": [],
        "tight": True,
        "bullet": marker[-1],
        "attrs": {
            "depth": depth,
            "ordered": ordered,
        },
    }
    if ordered:
        start = int(marker[:-1])
        if start != 1:
            # Example 304
            # we allow only lists starting with 1 to interrupt paragraphs
            end_pos = state.append_paragraph()
            if end_pos:
                return end_pos
            token["attrs"]["start"] = start

    state.cursor = m.end() + 1
    groups: Optional[Tuple[str, str, str]] = (m.group("list_1"), marker, text)

    if depth >= block.max_nested_level - 1:
        rules = list(block.list_rules)
        rules.remove("list")
    else:
        rules = block.list_rules

    bullet = _get_list_bullet(marker[-1])
    while groups:
        groups = _parse_list_item(block, bullet, groups, token, state, rules)

    end_pos = token.pop("_end_pos", None)
    _transform_tight_list(token)
    if end_pos:
        index = token.pop("_tok_index")
        state.tokens.insert(index, token)
        return end_pos

    state.append_token(token)
    return state.cursor


def _transform_tight_list(token: Dict[str, Any]) -> None:
    if token["tight"]:
        # reset tight list item
        for list_item in token["children"]:
            for tok in list_item["children"]:
                if tok["type"] == "paragraph":
                    tok["type"] = "block_text"
                elif tok["type"] == "list":
                    _transform_tight_list(tok)


def _parse_list_item(
    block: "BlockParser",
    bullet: str,
    groups: Tuple[str, str, str],
    token: Dict[str, Any],
    state: "BlockState",
    rules: List[str],
) -> Optional[Tuple[str, str, str]]:
    spaces, marker, text = groups

    leading_width = len(spaces) + len(marker)
    text, continue_width = _compile_continue_width(text, leading_width)
    item_pattern = _compile_list_item_pattern(bullet, leading_width)
    list_item_breaks = [
        "thematic_break",
        "fenced_code",
        "atx_heading",
        "block_quote",
        "block_html",
        "list",
    ]
    if "fenced_directive" in block.specification:
        list_item_breaks.insert(1, "fenced_directive")

    pairs = [(name, block.specification[name]) for name in list_item_breaks]
    if leading_width < 3:
        _repl_w = str(leading_width)
        pairs = [(n, p.replace("3", _repl_w, 1)) for n, p in pairs]

    pairs.insert(1, ("list_item", item_pattern))
    regex = "|".join(r"(?P<%s>(?<=\n)%s)" % pair for pair in pairs)
    sc = re.compile(regex, re.M)

    src = ""
    next_group = None
    prev_blank_line = False
    pos = state.cursor

    continue_space = " " * continue_width
    while pos < state.cursor_max:
        pos = state.find_line_end()
        line = state.get_text(pos)
        if block.BLANK_LINE.match(line):
            src += "\n"
            prev_blank_line = True
            state.cursor = pos
            continue

        line = expand_leading_tab(line)
        if line.startswith(continue_space):
            if prev_blank_line and not text and not src.strip():
                # Example 280
                # A list item can begin with at most one blank line
                break

            src += line
            prev_blank_line = False
            state.cursor = pos
            continue

        m = sc.match(state.src, state.cursor)
        if m:
            tok_type = m.lastgroup
            if tok_type == "list_item":
                if prev_blank_line:
                    token["tight"] = False
                next_group = (m.group("listitem_1"), m.group("listitem_2"), m.group("listitem_3"))
                state.cursor = m.end() + 1
                break

            if tok_type == "list":
                break

            tok_index = len(state.tokens)
            end_pos = block.parse_method(m, state)
            if end_pos:
                token["_tok_index"] = tok_index
                token["_end_pos"] = end_pos
                break

        if prev_blank_line and not line.startswith(continue_space):
            # not a continue line, and previous line is blank
            break

        src += line
        state.cursor = pos

    text += _clean_list_item_text(src, continue_width)
    child = state.child_state(strip_end(text))

    block.parse(child, rules)

    if token["tight"] and _is_loose_list(child.tokens):
        token["tight"] = False

    token["children"].append(
        {
            "type": "list_item",
            "children": child.tokens,
        }
    )
    if next_group:
        return next_group

    return None


def _get_list_bullet(c: str) -> str:
    if c == ".":
        bullet = r"\d{0,9}\."
    elif c == ")":
        bullet = r"\d{0,9}\)"
    elif c == "*":
        bullet = r"\*"
    elif c == "+":
        bullet = r"\+"
    else:
        bullet = "-"
    return bullet


def _compile_list_item_pattern(bullet: str, leading_width: int) -> str:
    if leading_width > 3:
        leading_width = 3
    return (
        r"^(?P<listitem_1> {0," + str(leading_width) + "})"
        r"(?P<listitem_2>" + bullet + ")"
        r"(?P<listitem_3>[ \t]*|[ \t][^\n]+)$"
    )


def _compile_continue_width(text: str, leading_width: int) -> Tuple[str, int]:
    text = expand_leading_tab(text, 3)
    text = expand_tab(text)

    m2 = _LINE_HAS_TEXT.match(text)
    if m2:
        # indent code, startswith 5 spaces
        if text.startswith("     "):
            space_width = 1
        else:
            space_width = len(m2.group(1))

        text = text[space_width:] + "\n"
    else:
        space_width = 1
        text = ""

    continue_width = leading_width + space_width
    return text, continue_width


def _clean_list_item_text(src: str, continue_width: int) -> str:
    # according to Example 7, tab should be treated as 3 spaces
    rv = []
    trim_space = " " * continue_width
    lines = src.split("\n")
    for line in lines:
        if line.startswith(trim_space):
            line = line.replace(trim_space, "", 1)
            # according to CommonMark Example 5
            # tab should be treated as 4 spaces
            line = expand_tab(line)
            rv.append(line)
        else:
            rv.append(line)

    return "\n".join(rv)


def _is_loose_list(tokens: Iterable[Dict[str, Any]]) -> bool:
    paragraph_count = 0
    for tok in tokens:
        if tok["type"] == "blank_line":
            return True
        if tok["type"] == "paragraph":
            paragraph_count += 1
            if paragraph_count > 1:
                return True
    return False
