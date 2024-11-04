import re
from typing import Dict, Any

_LINE_END = re.compile(r'\n|$')


class BlockState:
    """The state to save block parser's cursor and tokens."""
    def __init__(self, parent=None):
        self.src = ''
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
            self.env = {'ref_links': {}}

    def child_state(self, src: str):
        child = self.__class__(self)
        child.process(src)
        return child

    def process(self, src: str):
        self.src = src
        self.cursor_max = len(src)

    def find_line_end(self):
        m = _LINE_END.search(self.src, self.cursor)
        return m.end()

    def get_text(self, end_pos: int):
        return self.src[self.cursor:end_pos]

    def last_token(self):
        if self.tokens:
            return self.tokens[-1]

    def prepend_token(self, token: Dict[str, Any]):
        """Insert token before the last token."""
        self.tokens.insert(len(self.tokens) - 1, token)

    def append_token(self, token: Dict[str, Any]):
        """Add token to the end of token list."""
        self.tokens.append(token)

    def add_paragraph(self, text: str):
        last_token = self.last_token()
        if last_token and last_token['type'] == 'paragraph':
            last_token['text'] += text
        else:
            self.tokens.append({'type': 'paragraph', 'text': text})

    def append_paragraph(self):
        last_token = self.last_token()
        if last_token and last_token['type'] == 'paragraph':
            pos = self.find_line_end()
            last_token['text'] += self.get_text(pos)
            return pos

    def depth(self):
        d = 0
        parent = self.parent
        while parent:
            d += 1
            parent = parent.parent
        return d


class InlineState:
    """The state to save inline parser's tokens."""
    def __init__(self, env: Dict[str, Any]):
        self.env = env
        self.src = ''
        self.tokens = []
        self.in_image = False
        self.in_link = False
        self.in_emphasis = False
        self.in_strong = False

    def prepend_token(self, token: Dict[str, Any]):
        """Insert token before the last token."""
        self.tokens.insert(len(self.tokens) - 1, token)

    def append_token(self, token: Dict[str, Any]):
        """Add token to the end of token list."""
        self.tokens.append(token)

    def copy(self):
        """Create a copy of current state."""
        state = self.__class__(self.env)
        state.in_image = self.in_image
        state.in_link = self.in_link
        state.in_emphasis = self.in_emphasis
        state.in_strong = self.in_strong
        return state


class Parser:
    sc_flag = re.M
    state_cls = BlockState

    SPECIFICATION = {}
    DEFAULT_RULES = []

    def __init__(self):
        self.specification = self.SPECIFICATION.copy()
        self.rules = list(self.DEFAULT_RULES)
        self._methods = {}

        self.__sc = {}

    def compile_sc(self, rules=None):
        if rules is None:
            key = '$'
            rules = self.rules
        else:
            key = '|'.join(rules)

        sc = self.__sc.get(key)
        if sc:
            return sc

        regex = '|'.join(r'(?P<%s>%s)' % (k, self.specification[k]) for k in rules)
        sc = re.compile(regex, self.sc_flag)
        self.__sc[key] = sc
        return sc

    def register(self, name: str, pattern, func, before=None):
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

    def register_rule(self, name, pattern, func):
        raise DeprecationWarning('This plugin is not compatible with mistune v3.')

    @staticmethod
    def insert_rule(rules, name, before=None):
        if before:
            try:
                index = rules.index(before)
                rules.insert(index, name)
            except ValueError:
                rules.append(name)
        else:
            rules.append(name)

    def parse_method(self, m, state):
        func = self._methods[m.lastgroup]
        return func(m, state)


class BaseRenderer(object):
    NAME = 'base'

    def __init__(self):
        self.__methods = {}

    def register(self, name: str, method):
        """Register a render method for the named token. For example::

            def render_wiki(renderer, key, title):
                return f'<a href="/wiki/{key}">{title}</a>'

            renderer.register('wiki', render_wiki)
        """
        # bind self into renderer method
        self.__methods[name] = lambda *arg, **kwargs: method(self, *arg, **kwargs)

    def _get_method(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            method = self.__methods.get(name)
            if not method:
                raise AttributeError('No renderer "{!r}"'.format(name))
            return method

    def render_token(self, token, state):
        func = self._get_method(token['type'])
        return func(token, state)

    def iter_tokens(self, tokens, state):
        for tok in tokens:
            yield self.render_token(tok, state)

    def render_tokens(self, tokens, state):
        return ''.join(self.iter_tokens(tokens, state))

    def __call__(self, tokens, state):
        return self.render_tokens(tokens, state)
