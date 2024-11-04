import re
from typing import Dict, Any
from textwrap import indent
from ._list import render_list
from ..core import BaseRenderer, BlockState
from ..util import strip_end

fenced_re = re.compile(r'^[`~]+', re.M)


class MarkdownRenderer(BaseRenderer):
    """A renderer to re-format Markdown text."""
    NAME = 'markdown'

    def __call__(self, tokens, state: BlockState):
        out = self.render_tokens(tokens, state)
        # special handle for line breaks
        out += '\n\n'.join(self.render_referrences(state)) + '\n'
        return strip_end(out)

    def render_referrences(self, state: BlockState):
        ref_links = state.env['ref_links']
        for key in ref_links:
            attrs = ref_links[key]
            text = '[' + attrs['label'] + ']: ' + attrs['url']
            title = attrs.get('title')
            if title:
                text += ' "' + title + '"'
            yield text

    def render_children(self, token, state: BlockState):
        children = token['children']
        return self.render_tokens(children, state)

    def text(self, token: Dict[str, Any], state: BlockState) -> str:
        return token['raw']

    def emphasis(self, token: Dict[str, Any], state: BlockState) -> str:
        return '*' + self.render_children(token, state) + '*'

    def strong(self, token: Dict[str, Any], state: BlockState) -> str:
        return '**' + self.render_children(token, state) + '**'

    def link(self, token: Dict[str, Any], state: BlockState) -> str:
        label = token.get('label')
        text = self.render_children(token, state)
        out = '[' + text + ']'
        if label:
            return out + '[' + label + ']'

        attrs = token['attrs']
        url = attrs['url']
        title = attrs.get('title')
        if text == url and not title:
            return '<' + text + '>'
        elif 'mailto:' + text == url and not title:
            return '<' + text + '>'

        out += '('
        if '(' in url or ')' in url:
            out += '<' + url + '>'
        else:
            out += url
        if title:
            out += ' "' + title + '"'
        return out + ')'

    def image(self, token: Dict[str, Any], state: BlockState) -> str:
        return '!' + self.link(token, state)

    def codespan(self, token: Dict[str, Any], state: BlockState) -> str:
        return '`' + token['raw'] + '`'

    def linebreak(self, token: Dict[str, Any], state: BlockState) -> str:
        return '  \n'

    def softbreak(self, token: Dict[str, Any], state: BlockState) -> str:
        return '\n'

    def blank_line(self, token: Dict[str, Any], state: BlockState) -> str:
        return ''

    def inline_html(self, token: Dict[str, Any], state: BlockState) -> str:
        return token['raw']

    def paragraph(self, token: Dict[str, Any], state: BlockState) -> str:
        text = self.render_children(token, state)
        return text + '\n\n'

    def heading(self, token: Dict[str, Any], state: BlockState) -> str:
        level = token['attrs']['level']
        marker = '#' * level
        text = self.render_children(token, state)
        return marker + ' ' + text + '\n\n'

    def thematic_break(self, token: Dict[str, Any], state: BlockState) -> str:
        return '***\n\n'

    def block_text(self, token: Dict[str, Any], state: BlockState) -> str:
        return self.render_children(token, state) + '\n'

    def block_code(self, token: Dict[str, Any], state: BlockState) -> str:
        attrs = token.get('attrs', {})
        info = attrs.get('info', '')
        code = token['raw']
        if code and code[-1] != '\n':
            code += '\n'

        marker = token.get('marker')
        if not marker:
            marker = _get_fenced_marker(code)
        return marker + info + '\n' + code + marker + '\n\n'

    def block_quote(self, token: Dict[str, Any], state: BlockState) -> str:
        text = indent(self.render_children(token, state), '> ')
        return text + '\n\n'

    def block_html(self, token: Dict[str, Any], state: BlockState) -> str:
        return token['raw'] + '\n\n'

    def block_error(self, token: Dict[str, Any], state: BlockState) -> str:
        return ''

    def list(self, token: Dict[str, Any], state: BlockState) -> str:
        return render_list(self, token, state)


def _get_fenced_marker(code):
    found = fenced_re.findall(code)
    if not found:
        return '```'

    ticks = []  # `
    waves = []  # ~
    for s in found:
        if s[0] == '`':
            ticks.append(len(s))
        else:
            waves.append(len(s))

    if not ticks:
        return '```'

    if not waves:
        return '~~~'
    return '`' * (max(ticks) + 1)
