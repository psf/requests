from ._base import DirectivePlugin


class Admonition(DirectivePlugin):
    SUPPORTED_NAMES = {
        "attention", "caution", "danger", "error", "hint",
        "important", "note", "tip", "warning",
    }

    def parse(self, block, m, state):
        name = self.parse_type(m)
        attrs = {'name': name}
        options = dict(self.parse_options(m))
        if 'class' in options:
            attrs['class'] = options['class']

        title = self.parse_title(m)
        if not title:
            title = name.capitalize()

        content = self.parse_content(m)
        children = [
            {
                'type': 'admonition_title',
                'text': title,
            },
            {
                'type': 'admonition_content',
                'children': self.parse_tokens(block, content, state),
            }
        ]
        return {
            'type': 'admonition',
            'children': children,
            'attrs': attrs,
        }

    def __call__(self, directive, md):
        for name in self.SUPPORTED_NAMES:
            directive.register(name, self.parse)

        if md.renderer.NAME == 'html':
            md.renderer.register('admonition', render_admonition)
            md.renderer.register('admonition_title', render_admonition_title)
            md.renderer.register('admonition_content', render_admonition_content)


def render_admonition(self, text, name, **attrs):
    html = '<section class="admonition ' + name
    _cls = attrs.get('class')
    if _cls:
        html += ' ' + _cls
    return html + '">\n' + text + '</section>\n'


def render_admonition_title(self, text):
    return '<p class="admonition-title">' + text + '</p>\n'


def render_admonition_content(self, text):
    return text
