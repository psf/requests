import re
import types
from ..util import escape
from ..helpers import PREVENT_BACKSLASH

__all__ = ['abbr']

# https://michelf.ca/projects/php-markdown/extra/#abbr
REF_ABBR = (
  r'^ {0,3}\*\[(?P<abbr_key>[^\]]+)'+ PREVENT_BACKSLASH + r'\]:'
  r'(?P<abbr_text>(?:[ \t]*\n(?: {3,}|\t)[^\n]+)|(?:[^\n]*))$'
)


def parse_ref_abbr(block, m, state):
    ref = state.env.get('ref_abbrs')
    if not ref:
        ref = {}
    key = m.group('abbr_key')
    text = m.group('abbr_text')
    ref[key] = text.strip()
    state.env['ref_abbrs'] = ref
    # abbr definition can split paragraph
    state.append_token({'type': 'blank_line'})
    return m.end() + 1


def process_text(inline, text, state):
    ref = state.env.get('ref_abbrs')
    if not ref:
        return state.append_token({'type': 'text', 'raw': text})

    if state.tokens:
        last = state.tokens[-1]
        if last['type'] == 'text':
            state.tokens.pop()
            text = last['raw'] + text

    abbrs_re = state.env.get('abbrs_re')
    if not abbrs_re:
        abbrs_re = re.compile(r'|'.join(re.escape(k) for k in ref.keys()))
        state.env['abbrs_re'] = abbrs_re

    pos = 0
    while pos < len(text):
        m = abbrs_re.search(text, pos)
        if not m:
            break

        end_pos = m.start()
        if end_pos > pos:
            hole = text[pos:end_pos]
            state.append_token({'type': 'text', 'raw': hole})

        label = m.group(0)
        state.append_token({
            'type': 'abbr',
            'children': [{'type': 'text', 'raw': label}],
            'attrs': {'title': ref[label]}
        })
        pos = m.end()

    if pos == 0:
        # special case, just pure text
        state.append_token({'type': 'text', 'raw': text})
    elif pos < len(text):
        state.append_token({'type': 'text', 'raw': text[pos:]})


def render_abbr(renderer, text, title):
    if not title:
        return '<abbr>' + text + '</abbr>'
    return '<abbr title="' + escape(title) + '">' + text + '</abbr>'


def abbr(md):
    """A mistune plugin to support abbreviations, spec defined at
    https://michelf.ca/projects/php-markdown/extra/#abbr

    Here is an example:

    .. code-block:: text

        The HTML specification
        is maintained by the W3C.

        *[HTML]: Hyper Text Markup Language
        *[W3C]:  World Wide Web Consortium

    It will be converted into HTML:

    .. code-block:: html

        The <abbr title="Hyper Text Markup Language">HTML</abbr> specification
        is maintained by the <abbr title="World Wide Web Consortium">W3C</abbr>.

    :param md: Markdown instance
    """
    md.block.register('ref_abbr', REF_ABBR, parse_ref_abbr, before='paragraph')
    # replace process_text
    md.inline.process_text = types.MethodType(process_text, md.inline)
    if md.renderer and md.renderer.NAME == 'html':
        md.renderer.register('abbr', render_abbr)
