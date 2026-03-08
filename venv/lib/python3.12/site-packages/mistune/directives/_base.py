import re
from abc import ABCMeta, abstractmethod
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Match,
    Optional,
    Tuple,
    Type,
    Union,
)

if TYPE_CHECKING:
    from ..block_parser import BlockParser
    from ..core import BlockState
    from ..markdown import Markdown


class DirectiveParser(ABCMeta):
    name = "directive"

    @staticmethod
    @abstractmethod
    def parse_type(m: Match[str]) -> str:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def parse_title(m: Match[str]) -> str:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def parse_content(m: Match[str]) -> str:
        raise NotImplementedError()

    @classmethod
    def parse_tokens(cls, block: "BlockParser", text: str, state: "BlockState") -> Iterable[Dict[str, Any]]:
        if state.depth() >= block.max_nested_level - 1 and cls.name in block.rules:
            rules = list(block.rules)
            rules.remove(cls.name)
        else:
            rules = block.rules
        child = state.child_state(text)
        block.parse(child, rules)
        return child.tokens

    @staticmethod
    def parse_options(m: Match[str]) -> List[Tuple[str, str]]:
        text = m.group("options")
        if not text.strip():
            return []

        options = []
        for line in re.split(r"\n+", text):
            line = line.strip()[1:]
            if not line:
                continue
            i = line.find(":")
            k = line[:i]
            v = line[i + 1 :].strip()
            options.append((k, v))
        return options


class BaseDirective(metaclass=ABCMeta):
    parser: Type[DirectiveParser]
    directive_pattern: Optional[str] = None

    def __init__(self, plugins: List["DirectivePlugin"]):
        self._methods: Dict[
            str,
            Callable[
                ["BlockParser", Match[str], "BlockState"],
                Union[Dict[str, Any], List[Dict[str, Any]]],
            ],
        ] = {}
        self.__plugins = plugins

    def register(
        self,
        name: str,
        fn: Callable[
            ["BlockParser", Match[str], "BlockState"],
            Union[Dict[str, Any], List[Dict[str, Any]]],
        ],
    ) -> None:
        self._methods[name] = fn

    def parse_method(
        self, block: "BlockParser", m: Match[str], state: "BlockState"
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        _type = self.parser.parse_type(m)
        method = self._methods.get(_type)
        if method:
            try:
                token = method(block, m, state)
            except ValueError as e:
                token = {"type": "block_error", "raw": str(e)}
        else:
            text = m.group(0)
            token = {
                "type": "block_error",
                "raw": text,
            }

        if isinstance(token, list):
            for tok in token:
                state.append_token(tok)
        else:
            state.append_token(token)
        return token

    @abstractmethod
    def parse_directive(self, block: "BlockParser", m: Match[str], state: "BlockState") -> Optional[int]:
        raise NotImplementedError()

    def register_block_parser(self, md: "Markdown", before: Optional[str] = None) -> None:
        md.block.register(
            self.parser.name,
            self.directive_pattern,
            self.parse_directive,
            before=before,
        )

    def __call__(self, markdown: "Markdown") -> None:
        for plugin in self.__plugins:
            plugin.parser = self.parser
            plugin(self, markdown)


class DirectivePlugin:
    parser: Type[DirectiveParser]

    def __init__(self) -> None: ...

    def parse_options(self, m: Match[str]) -> List[Tuple[str, str]]:
        return self.parser.parse_options(m)

    def parse_type(self, m: Match[str]) -> str:
        return self.parser.parse_type(m)

    def parse_title(self, m: Match[str]) -> str:
        return self.parser.parse_title(m)

    def parse_content(self, m: Match[str]) -> str:
        return self.parser.parse_content(m)

    def parse_tokens(self, block: "BlockParser", text: str, state: "BlockState") -> Iterable[Dict[str, Any]]:
        return self.parser.parse_tokens(block, text, state)

    def parse(
        self, block: "BlockParser", m: Match[str], state: "BlockState"
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        raise NotImplementedError()

    def __call__(self, directive: BaseDirective, md: "Markdown") -> None:
        raise NotImplementedError()
