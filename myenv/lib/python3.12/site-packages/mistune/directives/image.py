import re
from ._base import DirectivePlugin
from ..util import escape as escape_text, escape_url

__all__ = ['Image', 'Figure']

_num_re = re.compile(r'^\d+(?:\.\d*)?')
_allowed_aligns = ["top", "middle", "bottom", "left", "center", "right"]


def _parse_attrs(options):
    attrs = {}
    if 'alt' in options:
        attrs['alt'] = options['alt']

    # validate align
    align = options.get('align')
    if align and align in _allowed_aligns:
        attrs['align'] = align

    height = options.get('height')
    width = options.get('width')
    if height and _num_re.match(height):
        attrs['height'] = height
    if width and _num_re.match(width):
        attrs['width'] = width
    if 'target' in options:
        attrs['target'] = escape_url(options['target'])
    return attrs


class Image(DirectivePlugin):
    NAME = 'image'

    def parse(self, block, m, state):
        options = dict(self.parse_options(m))
        attrs = _parse_attrs(options)
        attrs['src'] = self.parse_title(m)
        return {'type': 'block_image', 'attrs': attrs}

    def __call__(self, directive, md):
        directive.register(self.NAME, self.parse)
        if md.renderer.NAME == 'html':
            md.renderer.register('block_image', render_block_image)


def render_block_image(self, src: str, alt=None, width=None, height=None, **attrs):
    img = '<img src="' + src + '"'
    style = ''
    if alt:
        img += ' alt="' + escape_text(alt) + '"'
    if width:
        if width.isdigit():
            img += ' width="' + width + '"'
        else:
            style += 'width:' + width + ';'
    if height:
        if height.isdigit():
            img += ' height="' + height + '"'
        else:
            style += 'height:' + height + ';'
    if style:
        img += ' style="' + escape_text(style) + '"'

    img += ' />'

    _cls = 'block-image'
    align = attrs.get('align')
    if align:
        _cls += ' align-' + align

    target = attrs.get('target')
    if target:
        href = escape_text(self.safe_url(target))
        outer = '<a class="' + _cls + '" href="' + href + '">'
        return outer + img + '</a>\n'
    else:
        return '<div class="' + _cls + '">' + img + '</div>\n'


class Figure(DirectivePlugin):
    NAME = 'figure'

    def parse_directive_content(self, block, m, state):
        content = self.parse_content(m)
        if not content:
            return

        tokens = self.parse_tokens(block, content, state)
        caption = tokens[0]
        if caption['type'] == 'paragraph':
            caption['type'] = 'figcaption'
            children = [caption]
            if len(tokens) > 1:
                children.append({
                    'type': 'legend',
                    'children': tokens[1:]
                })
            return children

    def parse(self, block, m, state):
        options = dict(self.parse_options(m))
        image_attrs = _parse_attrs(options)
        image_attrs['src'] = self.parse_title(m)

        align = image_attrs.pop('align', None)
        fig_attrs = {}
        if align:
            fig_attrs['align'] = align
        for k in ['figwidth', 'figclass']:
            if k in options:
                fig_attrs[k] = options[k]

        children = [{'type': 'block_image', 'attrs': image_attrs}]
        content = self.parse_directive_content(block, m, state)
        if content:
            children.extend(content)
        return {
            'type': 'figure',
            'attrs': fig_attrs,
            'children': children,
        }

    def __call__(self, directive, md):
        directive.register(self.NAME, self.parse)

        if md.renderer.NAME == 'html':
            md.renderer.register('figure', render_figure)
            md.renderer.register('block_image', render_block_image)
            md.renderer.register('figcaption', render_figcaption)
            md.renderer.register('legend', render_legend)


def render_figure(self, text, align=None, figwidth=None, figclass=None):
    _cls = 'figure'
    if align:
        _cls += ' align-' + align
    if figclass:
        _cls += ' ' + figclass

    html = '<figure class="' + _cls + '"'
    if figwidth:
        html += ' style="width:' + figwidth + '"'
    return html + '>\n' + text + '</figure>\n'


def render_figcaption(self, text):
    return '<figcaption>' + text + '</figcaption>\n'


def render_legend(self, text):
    return '<div class="legend">\n' + text + '</div>\n'
