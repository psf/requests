__all__ = ['math', 'math_in_quote', 'math_in_list']

BLOCK_MATH_PATTERN = r'^ {0,3}\$\$[ \t]*\n(?P<math_text>[\s\S]+?)\n\$\$[ \t]*$'
INLINE_MATH_PATTERN = r'\$(?!\s)(?P<math_text>.+?)(?!\s)\$'


def parse_block_math(block, m, state):
    text = m.group('math_text')
    state.append_token({'type': 'block_math', 'raw': text})
    return m.end() + 1


def parse_inline_math(inline, m, state):
    text = m.group('math_text')
    state.append_token({'type': 'inline_math', 'raw': text})
    return m.end()


def render_block_math(renderer, text):
    return '<div class="math">$$\n' + text + '\n$$</div>\n'


def render_inline_math(renderer, text):
    return r'<span class="math">\(' + text + r'\)</span>'


def math(md):
    """A mistune plugin to support math. The syntax is used
    by many markdown extensions:

    .. code-block:: text

        Block math is surrounded by $$:

        $$
        f(a)=f(b)
        $$

        Inline math is surrounded by `$`, such as $f(a)=f(b)$

    :param md: Markdown instance
    """
    md.block.register('block_math', BLOCK_MATH_PATTERN, parse_block_math, before='list')
    md.inline.register('inline_math', INLINE_MATH_PATTERN, parse_inline_math, before='link')
    if md.renderer and md.renderer.NAME == 'html':
        md.renderer.register('block_math', render_block_math)
        md.renderer.register('inline_math', render_inline_math)


def math_in_quote(md):
    """Enable block math plugin in block quote."""
    md.block.insert_rule(md.block.block_quote_rules, 'block_math', before='list')


def math_in_list(md):
    """Enable block math plugin in list."""
    md.block.insert_rule(md.block.list_rules, 'block_math', before='list')
