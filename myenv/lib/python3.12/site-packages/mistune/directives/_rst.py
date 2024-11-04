import re
from ._base import DirectiveParser, BaseDirective

__all__ = ['RSTDirective']


_directive_re = re.compile(
    r'\.\.( +)(?P<type>[a-zA-Z0-9_-]+)\:\: *(?P<title>[^\n]*)(?:\n|$)'
    r'(?P<options>(?:  \1 {0,3}\:[a-zA-Z0-9_-]+\: *[^\n]*\n+)*)'
    r'\n*(?P<text>(?:  \1 {0,3}[^\n]*\n+)*)'
)


class RSTParser(DirectiveParser):
    name = 'rst_directive'

    @staticmethod
    def parse_type(m: re.Match):
        return m.group('type')

    @staticmethod
    def parse_title(m: re.Match):
        return m.group('title')

    @staticmethod
    def parse_content(m: re.Match):
        full_content = m.group(0)
        text = m.group('text')
        pretext = full_content[:-len(text)]
        leading = len(m.group(1)) + 2
        return '\n'.join(line[leading:] for line in text.splitlines()) + '\n'


class RSTDirective(BaseDirective):
    """A RST style of directive syntax is inspired by reStructuredText.
    The syntax is very powerful that you can define a lot of custom
    features on your own. The syntax looks like:

    .. code-block:: text

        .. directive-type:: directive value
           :option-key: option value
           :option-key: option value

           content text here

    To use ``RSTDirective``, developers can add it into plugin list in
    the :class:`Markdown` instance:

    .. code-block:: python

        import mistune
        from mistune.directives import RSTDirective, Admonition

        md = mistune.create_markdown(plugins=[
            # ...
            RSTDirective([Admonition()]),
        ])
    """
    parser = RSTParser
    directive_pattern = r'^\.\. +[a-zA-Z0-9_-]+\:\:'

    def parse_directive(self, block, m, state):
        m = _directive_re.match(state.src, state.cursor)
        if not m:
            return

        self.parse_method(block, m, state)
        return m.end()

    def __call__(self, md):
        super(RSTDirective, self).__call__(md)
        self.register_block_parser(md)
