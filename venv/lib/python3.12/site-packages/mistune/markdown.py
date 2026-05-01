from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from .block_parser import BlockParser
from .core import BaseRenderer, BlockState
from .inline_parser import InlineParser
from .plugins import Plugin


class Markdown:
    """Markdown instance to convert markdown text into HTML or other formats.
    Here is an example with the HTMLRenderer::

        from mistune import HTMLRenderer

        md = Markdown(renderer=HTMLRenderer(escape=False))
        md('hello **world**')

    :param renderer: a renderer to convert parsed tokens
    :param block: block level syntax parser
    :param inline: inline level syntax parser
    :param plugins: mistune plugins to use
    """

    def __init__(
        self,
        renderer: Optional[BaseRenderer] = None,
        block: Optional[BlockParser] = None,
        inline: Optional[InlineParser] = None,
        plugins: Optional[Iterable[Plugin]] = None,
    ):
        if block is None:
            block = BlockParser()

        if inline is None:
            inline = InlineParser()

        self.renderer = renderer
        self.block: BlockParser = block
        self.inline: InlineParser = inline
        self.before_parse_hooks: List[Callable[["Markdown", BlockState], None]] = []
        self.before_render_hooks: List[Callable[["Markdown", BlockState], Any]] = []
        self.after_render_hooks: List[
            Callable[["Markdown", Union[str, List[Dict[str, Any]]], BlockState], Union[str, List[Dict[str, Any]]]]
        ] = []

        if plugins:
            for plugin in plugins:
                plugin(self)

    def use(self, plugin: Plugin) -> None:
        plugin(self)

    def render_state(self, state: BlockState) -> Union[str, List[Dict[str, Any]]]:
        data = self._iter_render(state.tokens, state)
        if self.renderer:
            return self.renderer(data, state)
        return list(data)

    def _iter_render(self, tokens: Iterable[Dict[str, Any]], state: BlockState) -> Iterable[Dict[str, Any]]:
        for tok in tokens:
            if "children" in tok:
                children = self._iter_render(tok["children"], state)
                tok["children"] = list(children)
            elif "text" in tok:
                text = tok.pop("text")
                # process inline text
                # avoid striping emsp or other unicode spaces
                tok["children"] = self.inline(text.strip(" \r\n\t\f"), state.env)
            yield tok

    def parse(self, s: str, state: Optional[BlockState] = None) -> Tuple[Union[str, List[Dict[str, Any]]], BlockState]:
        """Parse and convert the given markdown string. If renderer is None,
        the returned **result** will be parsed markdown tokens.

        :param s: markdown string
        :param state: instance of BlockState
        :returns: result, state
        """
        if state is None:
            state = self.block.state_cls()

        # normalize line separator
        s = s.replace("\r\n", "\n")
        s = s.replace("\r", "\n")
        if not s.endswith("\n"):
            s += "\n"

        state.process(s)

        for hook in self.before_parse_hooks:
            hook(self, state)

        self.block.parse(state)

        for hook2 in self.before_render_hooks:
            hook2(self, state)

        result = self.render_state(state)

        for hook3 in self.after_render_hooks:
            result = hook3(self, result, state)
        return result, state

    def read(
        self, filepath: str, encoding: str = "utf-8", state: Optional[BlockState] = None
    ) -> Tuple[Union[str, List[Dict[str, Any]]], BlockState]:
        if state is None:
            state = self.block.state_cls()

        state.env["__file__"] = filepath
        with open(filepath, "rb") as f:
            s = f.read()

        s2 = s.decode(encoding)
        return self.parse(s2, state)

    def __call__(self, s: str) -> Union[str, List[Dict[str, Any]]]:
        if s is None:
            s = "\n"
        return self.parse(s)[0]
