"""
mistune
~~~~~~~

A fast yet powerful Python Markdown parser with renderers and
plugins, compatible with sane CommonMark rules.

Documentation: https://mistune.lepture.com/
"""

from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, Literal
from .block_parser import BlockParser
from .core import BaseRenderer, BlockState, InlineState
from .inline_parser import InlineParser
from .markdown import Markdown
from .plugins import Plugin, PluginRef, import_plugin
from .renderers.html import HTMLRenderer
from .util import escape, escape_url, safe_entity, unikey

RendererRef = Union[Literal["html", "ast"], BaseRenderer]


def create_markdown(
    escape: bool = True,
    hard_wrap: bool = False,
    renderer: Optional[RendererRef] = "html",
    plugins: Optional[Iterable[PluginRef]] = None,
) -> Markdown:
    """Create a Markdown instance based on the given condition.

    :param escape: Boolean. If using html renderer, escape html.
    :param hard_wrap: Boolean. Break every new line into ``<br>``.
    :param renderer: renderer instance, default is HTMLRenderer.
    :param plugins: List of plugins.

    This method is used when you want to re-use a Markdown instance::

        markdown = create_markdown(
            escape=False,
            hard_wrap=True,
        )
        # re-use markdown function
        markdown('.... your text ...')
    """
    if renderer == "ast":
        # explicit and more similar to 2.x's API
        renderer = None
    elif renderer == "html":
        renderer = HTMLRenderer(escape=escape)

    inline = InlineParser(hard_wrap=hard_wrap)
    real_plugins: Optional[Iterable[Plugin]] = None
    if plugins is not None:
        real_plugins = [import_plugin(n) for n in plugins]
    return Markdown(renderer=renderer, inline=inline, plugins=real_plugins)


html: Markdown = create_markdown(escape=False, plugins=["strikethrough", "footnotes", "table", "speedup"])


__cached_parsers: Dict[Tuple[bool, Optional[RendererRef], Optional[Iterable[Any]]], Markdown] = {}


def markdown(
    text: str,
    escape: bool = True,
    renderer: Optional[RendererRef] = "html",
    plugins: Optional[Iterable[Any]] = None,
) -> Union[str, List[Dict[str, Any]]]:
    if renderer == "ast":
        # explicit and more similar to 2.x's API
        renderer = None
    key = (escape, renderer, plugins)
    if key in __cached_parsers:
        return __cached_parsers[key](text)

    md = create_markdown(escape=escape, renderer=renderer, plugins=plugins)
    # improve the speed for markdown parser creation
    __cached_parsers[key] = md
    return md(text)


__all__ = [
    "Markdown",
    "HTMLRenderer",
    "BlockParser",
    "BlockState",
    "BaseRenderer",
    "InlineParser",
    "InlineState",
    "escape",
    "escape_url",
    "safe_entity",
    "unikey",
    "html",
    "create_markdown",
    "markdown",
]

__version__ = "3.1.4"
__homepage__ = "https://mistune.lepture.com/"
