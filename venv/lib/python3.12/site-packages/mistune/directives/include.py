import os
from typing import TYPE_CHECKING, Any, Dict, List, Match, Union

from ._base import BaseDirective, DirectivePlugin

if TYPE_CHECKING:
    from ..block_parser import BlockParser
    from ..core import BaseRenderer, BlockState
    from ..markdown import Markdown


class Include(DirectivePlugin):
    def parse(
        self, block: "BlockParser", m: Match[str], state: "BlockState"
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        source_file = state.env.get("__file__")
        if not source_file:
            return {"type": "block_error", "raw": "Missing source file"}

        encoding = "utf-8"
        options = self.parse_options(m)
        if options:
            attrs = dict(options)
            if "encoding" in attrs:
                encoding = attrs["encoding"]
        else:
            attrs = {}

        relpath = self.parse_title(m)
        dest = os.path.join(os.path.dirname(source_file), relpath)
        dest = os.path.normpath(dest)

        if dest == source_file:
            return {
                "type": "block_error",
                "raw": "Could not include self: " + relpath,
            }

        if not os.path.isfile(dest):
            return {
                "type": "block_error",
                "raw": "Could not find file: " + relpath,
            }

        with open(dest, "rb") as f:
            content = f.read().decode(encoding)

        ext = os.path.splitext(relpath)[1]
        if ext in {".md", ".markdown", ".mkd"}:
            new_state = block.state_cls()
            new_state.env["__file__"] = dest
            new_state.process(content)
            block.parse(new_state)
            return new_state.tokens

        elif ext in {".html", ".xhtml", ".htm"}:
            return {"type": "block_html", "raw": content}

        attrs["filepath"] = dest
        return {
            "type": "include",
            "raw": content,
            "attrs": attrs,
        }

    def __call__(self, directive: BaseDirective, md: "Markdown") -> None:
        directive.register("include", self.parse)
        if md.renderer and md.renderer.NAME == "html":
            md.renderer.register("include", render_html_include)


def render_html_include(renderer: "BaseRenderer", text: str, **attrs: Any) -> str:
    return '<pre class="directive-include">\n' + text + "</pre>\n"
