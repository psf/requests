import re

__all__ = ['spoiler']

_BLOCK_SPOILER_START = re.compile(r'^ {0,3}! ?', re.M)
_BLOCK_SPOILER_MATCH = re.compile(r'^( {0,3}![^\n]*\n)+$')

INLINE_SPOILER_PATTERN = r'>!\s*(?P<spoiler_text>.+?)\s*!<'


def parse_block_spoiler(block, m, state):
    text, end_pos = block.extract_block_quote(m, state)
    if not text.endswith('\n'):
        # ensure it endswith \n to make sure
        # _BLOCK_SPOILER_MATCH.match works
        text += '\n'

    depth = state.depth()
    if not depth and _BLOCK_SPOILER_MATCH.match(text):
        text = _BLOCK_SPOILER_START.sub('', text)
        tok_type = 'block_spoiler'
    else:
        tok_type = 'block_quote'

    # scan children state
    child = state.child_state(text)
    if state.depth() >= block.max_nested_level - 1:
        rules = list(block.block_quote_rules)
        rules.remove('block_quote')
    else:
        rules = block.block_quote_rules

    block.parse(child, rules)
    token = {'type': tok_type, 'children': child.tokens}
    if end_pos:
        state.prepend_token(token)
        return end_pos
    state.append_token(token)
    return state.cursor


def parse_inline_spoiler(inline, m, state):
    text = m.group('spoiler_text')
    new_state = state.copy()
    new_state.src = text
    children = inline.render(new_state)
    state.append_token({'type': 'inline_spoiler', 'children': children})
    return m.end()


def render_block_spoiler(renderer, text):
    return '<div class="spoiler">\n' + text + '</div>\n'


def render_inline_spoiler(renderer, text):
    return '<span class="spoiler">' + text + '</span>'


def spoiler(md):
    """A mistune plugin to support block and inline spoiler. The
    syntax is inspired by stackexchange:

    .. code-block:: text

        Block level spoiler looks like block quote, but with `>!`:

        >! this is spoiler
        >!
        >! the content will be hidden

        Inline spoiler is surrounded by `>!` and `!<`, such as >! hide me !<.

    :param md: Markdown instance
    """
    # reset block quote parser with block spoiler parser
    md.block.register('block_quote', None, parse_block_spoiler)
    md.inline.register('inline_spoiler', INLINE_SPOILER_PATTERN, parse_inline_spoiler)
    if md.renderer and md.renderer.NAME == 'html':
        md.renderer.register('block_spoiler', render_block_spoiler)
        md.renderer.register('inline_spoiler', render_inline_spoiler)
