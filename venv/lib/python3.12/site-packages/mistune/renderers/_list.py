from typing import TYPE_CHECKING, Any, Dict, Iterable, cast

from ..util import strip_end

if TYPE_CHECKING:
    from ..core import BaseRenderer, BlockState


def render_list(renderer: "BaseRenderer", token: Dict[str, Any], state: "BlockState") -> str:
    attrs = token["attrs"]
    if attrs["ordered"]:
        children = _render_ordered_list(renderer, token, state)
    else:
        children = _render_unordered_list(renderer, token, state)

    text = "".join(children)
    parent = token.get("parent")
    if parent:
        if parent["tight"]:
            return text
        return text + "\n"
    return strip_end(text) + "\n"


def _render_list_item(
    renderer: "BaseRenderer",
    parent: Dict[str, Any],
    item: Dict[str, Any],
    state: "BlockState",
) -> str:
    leading = cast(str, parent["leading"])
    text = ""
    for tok in item["children"]:
        if tok["type"] == "list":
            tok["parent"] = parent
        elif tok["type"] == "blank_line":
            continue
        text += renderer.render_token(tok, state)

    lines = text.splitlines()
    text = (lines[0] if lines else "") + "\n"
    prefix = " " * len(leading)
    for line in lines[1:]:
        if line:
            text += prefix + line + "\n"
        else:
            text += "\n"
    return leading + text


def _render_ordered_list(renderer: "BaseRenderer", token: Dict[str, Any], state: "BlockState") -> Iterable[str]:
    attrs = token["attrs"]
    start = attrs.get("start", 1)
    for item in token["children"]:
        leading = str(start) + token["bullet"] + " "
        parent = {
            "leading": leading,
            "tight": token["tight"],
        }
        yield _render_list_item(renderer, parent, item, state)
        start += 1


def _render_unordered_list(renderer: "BaseRenderer", token: Dict[str, Any], state: "BlockState") -> Iterable[str]:
    parent = {
        "leading": token["bullet"] + " ",
        "tight": token["tight"],
    }
    for item in token["children"]:
        yield _render_list_item(renderer, parent, item, state)
