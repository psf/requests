"""
    TOC directive
    ~~~~~~~~~~~~~

    The TOC directive syntax looks like::

        .. toc:: Title
           :min-level: 1
           :max-level: 3

    "Title", "min-level", and "max-level" option can be empty. "min-level"
    and "max-level" are integers >= 1 and <= 6, which define the allowed
    heading levels writers want to include in the table of contents.
"""

from ._base import DirectivePlugin
from ..toc import normalize_toc_item, render_toc_ul


class TableOfContents(DirectivePlugin):
    def __init__(self, min_level=1, max_level=3):
        self.min_level = min_level
        self.max_level = max_level

    def generate_heading_id(self, token, index):
        return 'toc_' + str(index + 1)

    def parse(self, block, m, state):
        title = self.parse_title(m)
        options = self.parse_options(m)
        if options:
            d_options = dict(options)
            collapse = 'collapse' in d_options
            min_level = _normalize_level(d_options, 'min-level', self.min_level)
            max_level = _normalize_level(d_options, 'max-level', self.max_level)
            if min_level < self.min_level:
                raise ValueError(f'"min-level" option MUST be >= {self.min_level}')
            if max_level > self.max_level:
                raise ValueError(f'"max-level" option MUST be <= {self.max_level}')
            if min_level > max_level:
                raise ValueError('"min-level" option MUST be less than "max-level" option')
        else:
            collapse = False
            min_level = self.min_level
            max_level = self.max_level

        attrs = {
            'min_level': min_level,
            'max_level': max_level,
            'collapse': collapse,
        }
        return {'type': 'toc', 'text': title or '', 'attrs': attrs}

    def toc_hook(self, md, state):
        sections = []
        headings = []

        for tok in state.tokens:
            if tok['type'] == 'toc':
                sections.append(tok)
            elif tok['type'] == 'heading':
                headings.append(tok)

        if sections:
            toc_items = []
            # adding ID for each heading
            for i, tok in enumerate(headings):
                tok['attrs']['id'] = self.generate_heading_id(tok, i)
                toc_items.append(normalize_toc_item(md, tok))

            for sec in sections:
                _min = sec['attrs']['min_level']
                _max = sec['attrs']['max_level']
                toc = [item for item in toc_items if _min <= item[0] <= _max]
                sec['attrs']['toc'] = toc

    def __call__(self, directive, md):
        if md.renderer and md.renderer.NAME == 'html':
            # only works with HTML renderer
            directive.register('toc', self.parse)
            md.before_render_hooks.append(self.toc_hook)
            md.renderer.register('toc', render_html_toc)


def render_html_toc(renderer, title, collapse=False, **attrs):
    if not title:
        title = 'Table of Contents'
    toc = attrs['toc']
    content = render_toc_ul(attrs['toc'])

    html = '<details class="toc"'
    if not collapse:
        html += ' open'
    html += '>\n<summary>' + title + '</summary>\n'
    return html + content + '</details>\n'


def _normalize_level(options, name, default):
    level = options.get(name)
    if not level:
        return default
    try:
        return int(level)
    except (ValueError, TypeError):
        raise ValueError(f'"{name}" option MUST be integer')
