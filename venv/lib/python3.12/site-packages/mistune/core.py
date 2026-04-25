import re
import sys
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Generic,
    Iterable,
    List,
    Match,
    MutableMapping,
    Optional,
    Pattern,
    Type,
    TypeVar,
    Union,
    cast,
)

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

_LINE_END = re.compile(r"\n|$")


class BlockState:
    """The state to save block parser's cursor and tokens."""

    src: str
    tokens: List[Dict[str, Any]]
    cursor: int
    cursor_max: int
    list_tight: bool
    parent: Any
    env: MutableMapping[str, Any]

    def __init__(self, parent: Optional[Any] = None) -> None:
        self.src = ""
        self.tokens = []

        # current cursor position
        self.cursor = 0
        self.cursor_max = 0

        # for list and block quote chain
        self.list_tight = True
        self.parent = parent

        # for saving def references
        if parent:
            self.env = parent.env
        else:
            self.env = {"ref_links": {}}

    def child_state(self, src: str) -> "BlockState":
        child = self.__class__(self)
        child.process(src)
        return child

    def process(self, src: str) -> None:
        self.src = src
        self.cursor_max = len(src)

    def find_line_end(self) -> int:
        m = _LINE_END.search(self.src, self.cursor)
        assert m is not None
        return m.end()

    def get_text(self, end_pos: int) -> str:
        return self.src[self.cursor : end_pos]

    def last_token(self) -> Any:
        if self.tokens:
            return self.tokens[-1]

    def prepend_token(self, token: Dict[str, Any]) -> None:
        """Insert token before the last token."""
        self.tokens.insert(len(self.tokens) - 1, token)

    def append_token(self, token: Dict[str, Any]) -> None:
        """Add token to the end of token list."""
        self.tokens.append(token)

    def add_paragraph(self, text: str) -> None:
        last_token = self.last_token()
        if last_token and last_token["type"] == "paragraph":
            last_token["text"] += text
        else:
            self.tokens.append({"type": "paragraph", "text": text})

    def append_paragraph(self) -> Optional[int]:
        last_token = self.last_token()
        if last_token and last_token["type"] == "paragraph":
            pos = self.find_line_end()
            last_token["text"] += self.get_text(pos)
            return pos
        return None

    def depth(self) -> int:
        d = 0
        parent = self.parent
        while parent:
            d += 1
            parent = parent.parent
        return d


class InlineState:
    """The state to save inline parser's tokens."""

    def __init__(self, env: MutableMapping[str, Any]):
        self.env = env
        self.src = ""
        self.tokens: List[Dict[str, Any]] = []
        self.in_image = False
        self.in_link = False
        self.in_emphasis = False
        self.in_strong = False

    def prepend_token(self, token: Dict[str, Any]) -> None:
        """Insert token before the last token."""
        self.tokens.insert(len(self.tokens) - 1, token)

    def append_token(self, token: Dict[str, Any]) -> None:
        """Add token to the end of token list."""
        self.tokens.append(token)

    def copy(self) -> "InlineState":
        """Create a copy of current state."""
        state = self.__class__(self.env)
        state.in_image = self.in_image
        state.in_link = self.in_link
        state.in_emphasis = self.in_emphasis
        state.in_strong = self.in_strong
        return state


ST = TypeVar("ST", InlineState, BlockState)


class Parser(Generic[ST]):
    sc_flag: "re._FlagsType" = re.M
    state_cls: Type[ST]

    SPECIFICATION: ClassVar[Dict[str, str]] = {}
    DEFAULT_RULES: ClassVar[Iterable[str]] = []

    def __init__(self) -> None:
        self.specification = self.SPECIFICATION.copy()
        self.rules = list(self.DEFAULT_RULES)
        self._methods: Dict[
            str,
            Callable[[Match[str], ST], Optional[int]],
        ] = {}

        self.__sc: Dict[str, Pattern[str]] = {}

    def compile_sc(self, rules: Optional[List[str]] = None) -> Pattern[str]:
        if rules is None:
            key = "$"
            rules = self.rules
        else:
            key = "|".join(rules)

        sc = self.__sc.get(key)
        if sc:
            return sc

        regex = "|".join(r"(?P<%s>%s)" % (k, self.specification[k]) for k in rules)
        sc = re.compile(regex, self.sc_flag)
        self.__sc[key] = sc
        return sc

    def register(
        self,
        name: str,
        pattern: Union[str, None],
        func: Callable[[Self, Match[str], ST], Optional[int]],
        before: Optional[str] = None,
    ) -> None:
        """Register a new rule to parse the token. This method is usually used to
        create a new plugin.

        :param name: name of the new grammar
        :param pattern: regex pattern in string
        :param func: the parsing function
        :param before: insert this rule before a built-in rule
        """
        self._methods[name] = lambda m, state: func(self, m, state)
        if pattern:
            self.specification[name] = pattern
        if name not in self.rules:
            self.insert_rule(self.rules, name, before=before)

    def register_rule(self, name: str, pattern: str, func: Any) -> None:
        raise DeprecationWarning("This plugin is not compatible with mistune v3.")

    @staticmethod
    def insert_rule(rules: List[str], name: str, before: Optional[str] = None) -> None:
        if before:
            try:
                index = rules.index(before)
                rules.insert(index, name)
            except ValueError:
                rules.append(name)
        else:
            rules.append(name)

    def parse_method(self, m: Match[str], state: ST) -> Optional[int]:
        lastgroup = m.lastgroup
        assert lastgroup
        func = self._methods[lastgroup]
        return func(m, state)


class BaseRenderer(object):
    NAME: ClassVar[str] = "base"

    def __init__(self) -> None:
        self.__methods: Dict[str, Callable[..., str]] = {}

    def register(self, name: str, method: Callable[..., str]) -> None:
        """Register a render method for the named token. For example::

        def render_wiki(renderer, key, title):
            return f'<a href="/wiki/{key}">{title}</a>'

        renderer.register('wiki', render_wiki)
        """
        # bind self into renderer method
        self.__methods[name] = lambda *arg, **kwargs: method(self, *arg, **kwargs)

    def _get_method(self, name: str) -> Callable[..., str]:
        try:
            return cast(Callable[..., str], object.__getattribute__(self, name))
        except AttributeError:
            method = self.__methods.get(name)
            if not method:
                raise AttributeError('No renderer "{!r}"'.format(name))
            return method

    def render_token(self, token: Dict[str, Any], state: BlockState) -> str:
        func = self._get_method(token["type"])
        return func(token, state)

    def iter_tokens(self, tokens: Iterable[Dict[str, Any]], state: BlockState) -> Iterable[str]:
        for tok in tokens:
            yield self.render_token(tok, state)

    def render_tokens(self, tokens: Iterable[Dict[str, Any]], state: BlockState) -> str:
        return "".join(self.iter_tokens(tokens, state))

    def __call__(self, tokens: Iterable[Dict[str, Any]], state: BlockState) -> str:
        return self.render_tokens(tokens, state)
