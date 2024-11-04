import re
from typing import Optional, List, Dict, Any, Match
from .core import Parser, InlineState
from .util import (
    escape,
    escape_url,
    unikey,
)
from .helpers import (
    PREVENT_BACKSLASH,
    PUNCTUATION,
    HTML_TAGNAME,
    HTML_ATTRIBUTES,
    unescape_char,
    parse_link,
    parse_link_label,
    parse_link_text,
)

PAREN_END_RE = re.compile(r'\s*\)')

AUTO_EMAIL = (
    r'''<[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9]'''
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*>'
)

INLINE_HTML = (
    r'<' + HTML_TAGNAME + HTML_ATTRIBUTES + r'\s*/?>|'  # open tag
    r'</' + HTML_TAGNAME + r'\s*>|'  # close tag
    r'<!--(?!>|->)(?:(?!--)[\s\S])+?(?<!-)-->|'  # comment
    r'<\?[\s\S]+?\?>|'    # script like <?php?>
    r'<![A-Z][\s\S]+?>|'  # doctype
    r'<!\[CDATA[\s\S]+?\]\]>'  # cdata
)

EMPHASIS_END_RE = {
    '*': re.compile(r'(?:' + PREVENT_BACKSLASH + r'\\\*|[^\s*])\*(?!\*)'),
    '_': re.compile(r'(?:' + PREVENT_BACKSLASH + r'\\_|[^\s_])_(?!_)\b'),

    '**': re.compile(r'(?:' + PREVENT_BACKSLASH + r'\\\*|[^\s*])\*\*(?!\*)'),
    '__': re.compile(r'(?:' + PREVENT_BACKSLASH + r'\\_|[^\s_])__(?!_)\b'),

    '***': re.compile(r'(?:' + PREVENT_BACKSLASH + r'\\\*|[^\s*])\*\*\*(?!\*)'),
    '___': re.compile(r'(?:' + PREVENT_BACKSLASH + r'\\_|[^\s_])___(?!_)\b'),
}


class InlineParser(Parser):
    sc_flag = 0
    state_cls = InlineState

    #: linebreak leaves two spaces at the end of line
    STD_LINEBREAK = r'(?:\\| {2,})\n\s*'

    #: every new line becomes <br>
    HARD_LINEBREAK = r' *\n\s*'

    # we only need to find the start pattern of an inline token
    SPECIFICATION = {
        # e.g. \`, \$
        'escape': r'(?:\\' + PUNCTUATION + ')+',

        # `code, ```code
        'codespan': r'`{1,}',

        # *w, **w, _w, __w
        'emphasis': r'\*{1,3}(?=[^\s*])|\b_{1,3}(?=[^\s_])',

        # [link], ![img]
        'link': r'!?\[',

        # <https://example.com>. regex copied from commonmark.js
        'auto_link': r'<[A-Za-z][A-Za-z0-9.+-]{1,31}:[^<>\x00-\x20]*>',
        'auto_email': AUTO_EMAIL,

        'inline_html': INLINE_HTML,

        'linebreak': STD_LINEBREAK,
        'softbreak': HARD_LINEBREAK,

        'prec_auto_link': r'<[A-Za-z][A-Za-z\d.+-]{1,31}:',
        'prec_inline_html': r'</?' + HTML_TAGNAME + r'|<!|<\?',
    }
    DEFAULT_RULES = (
        'escape',
        'codespan',
        'emphasis',
        'link',
        'auto_link',
        'auto_email',
        'inline_html',
        'linebreak',
    )

    def __init__(self, hard_wrap: bool=False):
        super(InlineParser, self).__init__()

        self.hard_wrap = hard_wrap
        # lazy add linebreak
        if hard_wrap:
            self.specification['linebreak'] = self.HARD_LINEBREAK
        else:
            self.rules.append('softbreak')

        self._methods = {
            name: getattr(self, 'parse_' + name) for name in self.rules
        }

    def parse_escape(self, m: Match, state: InlineState) -> int:
        text = m.group(0)
        text = unescape_char(text)
        state.append_token({
            'type': 'text',
            'raw': text,
        })
        return m.end()

    def parse_link(self, m: Match, state: InlineState) -> Optional[int]:
        pos = m.end()

        marker = m.group(0)
        is_image = marker[0] == '!'
        if is_image and state.in_image:
            state.append_token({'type': 'text', 'raw': marker})
            return pos
        elif not is_image and state.in_link:
            state.append_token({'type': 'text', 'raw': marker})
            return pos

        text = None
        label, end_pos = parse_link_label(state.src, pos)
        if label is None:
            text, end_pos = parse_link_text(state.src, pos)
            if text is None:
                return

        if text is None:
            text = label

        if end_pos >= len(state.src) and label is None:
            return

        rules = ['codespan', 'prec_auto_link', 'prec_inline_html']
        prec_pos = self.precedence_scan(m, state, end_pos, rules)
        if prec_pos:
            return prec_pos

        if end_pos < len(state.src):
            c = state.src[end_pos]
            if c == '(':
                # standard link [text](<url> "title")
                attrs, pos2 = parse_link(state.src, end_pos + 1)
                if pos2:
                    token = self.__parse_link_token(is_image, text, attrs, state)
                    state.append_token(token)
                    return pos2

            elif c == '[':
                # standard ref link [text][label]
                label2, pos2 = parse_link_label(state.src, end_pos + 1)
                if pos2:
                    end_pos = pos2
                    if label2:
                        label = label2

        if label is None:
            return

        ref_links = state.env.get('ref_links')
        if not ref_links:
            return

        key = unikey(label)
        env = ref_links.get(key)
        if env:
            attrs = {'url': env['url'], 'title': env.get('title')}
            token = self.__parse_link_token(is_image, text, attrs, state)
            token['ref'] = key
            token['label'] = label
            state.append_token(token)
            return end_pos

    def __parse_link_token(self, is_image, text, attrs, state):
        new_state = state.copy()
        new_state.src = text
        if is_image:
            new_state.in_image = True
            token = {
                'type': 'image',
                'children': self.render(new_state),
                'attrs': attrs,
            }
        else:
            new_state.in_link = True
            token = {
                'type': 'link',
                'children': self.render(new_state),
                'attrs': attrs,
            }
        return token

    def parse_auto_link(self, m: Match, state: InlineState) -> int:
        text = m.group(0)
        pos = m.end()
        if state.in_link:
            self.process_text(text, state)
            return pos

        text = text[1:-1]
        self._add_auto_link(text, text, state)
        return pos

    def parse_auto_email(self, m: Match, state: InlineState) -> int:
        text = m.group(0)
        pos = m.end()
        if state.in_link:
            self.process_text(text, state)
            return pos

        text = text[1:-1]
        url = 'mailto:' + text
        self._add_auto_link(url, text, state)
        return pos

    def _add_auto_link(self, url, text, state):
        state.append_token({
            'type': 'link',
            'children': [{'type': 'text', 'raw': text}],
            'attrs': {'url': escape_url(url)},
        })

    def parse_emphasis(self, m: Match, state: InlineState) -> int:
        pos = m.end()

        marker = m.group(0)
        mlen = len(marker)
        if mlen == 1 and state.in_emphasis:
            state.append_token({'type': 'text', 'raw': marker})
            return pos
        elif mlen == 2 and state.in_strong:
            state.append_token({'type': 'text', 'raw': marker})
            return pos

        _end_re = EMPHASIS_END_RE[marker]
        m1 = _end_re.search(state.src, pos)
        if not m1:
            state.append_token({'type': 'text', 'raw': marker})
            return pos

        end_pos = m1.end()
        text = state.src[pos:end_pos-mlen]

        prec_pos = self.precedence_scan(m, state, end_pos)
        if prec_pos:
            return prec_pos

        new_state = state.copy()
        new_state.src = text
        if mlen == 1:
            new_state.in_emphasis = True
            children = self.render(new_state)
            state.append_token({'type': 'emphasis', 'children': children})
        elif mlen == 2:
            new_state.in_strong = True
            children = self.render(new_state)
            state.append_token({'type': 'strong', 'children': children})
        else:
            new_state.in_emphasis = True
            new_state.in_strong = True

            children = [{
                'type': 'strong',
                'children': self.render(new_state)
            }]
            state.append_token({
                'type': 'emphasis',
                'children': children,
            })
        return end_pos

    def parse_codespan(self, m: Match, state: InlineState) -> int:
        marker = m.group(0)
        # require same marker with same length at end

        pattern = re.compile(r'(.*?[^`])' + marker + r'(?!`)', re.S)

        pos = m.end()
        m = pattern.match(state.src, pos)
        if m:
            end_pos = m.end()
            code = m.group(1)
            # Line endings are treated like spaces
            code = code.replace('\n', ' ')
            if len(code.strip()):
                if code.startswith(' ') and code.endswith(' '):
                    code = code[1:-1]
            state.append_token({'type': 'codespan', 'raw': escape(code)})
            return end_pos
        else:
            state.append_token({'type': 'text', 'raw': marker})
            return pos

    def parse_linebreak(self, m: Match, state: InlineState) -> int:
        state.append_token({'type': 'linebreak'})
        return m.end()

    def parse_softbreak(self, m: Match, state: InlineState) -> int:
        state.append_token({'type': 'softbreak'})
        return m.end()

    def parse_inline_html(self, m: Match, state: InlineState) -> int:
        end_pos = m.end()
        html = m.group(0)
        state.append_token({'type': 'inline_html', 'raw': html})
        if html.startswith(('<a ', '<a>', '<A ', '<A>')):
            state.in_link = True
        elif html.startswith(('</a ', '</a>', '</A ', '</A>')):
            state.in_link = False
        return end_pos

    def process_text(self, text: str, state: InlineState):
        state.append_token({'type': 'text', 'raw': text})

    def parse(self, state: InlineState) -> List[Dict[str, Any]]:
        pos = 0
        sc = self.compile_sc()
        while pos < len(state.src):
            m = sc.search(state.src, pos)
            if not m:
                break

            end_pos = m.start()
            if end_pos > pos:
                hole = state.src[pos:end_pos]
                self.process_text(hole, state)

            new_pos = self.parse_method(m, state)
            if not new_pos:
                # move cursor 1 character forward
                pos = end_pos + 1
                hole = state.src[end_pos:pos]
                self.process_text(hole, state)
            else:
                pos = new_pos

        if pos == 0:
            # special case, just pure text
            self.process_text(state.src, state)
        elif pos < len(state.src):
            self.process_text(state.src[pos:], state)
        return state.tokens

    def precedence_scan(self, m: Match, state: InlineState, end_pos: int, rules=None):
        if rules is None:
            rules = ['codespan', 'link', 'prec_auto_link', 'prec_inline_html']

        mark_pos = m.end()
        sc = self.compile_sc(rules)
        m1 = sc.search(state.src, mark_pos, end_pos)
        if not m1:
            return

        rule_name = m1.lastgroup.replace('prec_', '')
        sc = self.compile_sc([rule_name])
        m2 = sc.match(state.src, m1.start())
        if not m2:
            return

        func = self._methods[rule_name]
        new_state = state.copy()
        new_state.src = state.src
        m2_pos = func(m2, new_state)
        if not m2_pos or m2_pos < end_pos:
            return

        raw_text = state.src[m.start():m2.start()]
        state.append_token({'type': 'text', 'raw': raw_text})
        for token in new_state.tokens:
            state.append_token(token)
        return m2_pos

    def render(self, state: InlineState):
        self.parse(state)
        return state.tokens

    def __call__(self, s, env):
        state = self.state_cls(env)
        state.src = s
        return self.render(state)
