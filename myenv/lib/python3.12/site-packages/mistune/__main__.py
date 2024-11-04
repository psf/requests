import sys
import argparse
from .renderers.rst import RSTRenderer
from .renderers.markdown import MarkdownRenderer
from . import (
    create_markdown,
    __version__ as version
)


def _md(args):
    if args.plugin:
        plugins = args.plugin
    else:
        # default plugins
        plugins = ['strikethrough', 'footnotes', 'table', 'speedup']

    if args.renderer == 'rst':
        renderer = RSTRenderer()
    elif args.renderer == 'markdown':
        renderer = MarkdownRenderer()
    else:
        renderer = args.renderer
    return create_markdown(
        escape=args.escape,
        hard_wrap=args.hardwrap,
        renderer=renderer,
        plugins=plugins,
    )


def _output(text, args):
    if args.output:
        with open(args.output, 'w') as f:
            f.write(text)
    else:
        print(text)


CMD_HELP = '''Mistune, a sane and fast python markdown parser.

Here are some use cases of the command line tool:

    $ python -m mistune -m "Hi **Markdown**"
    <p>Hi <strong>Markdown</strong></p>

    $ python -m mistune -f README.md
    <p>...

    $ cat README.md | python -m mistune
    <p>...
'''


def cli():
    parser = argparse.ArgumentParser(
        prog='python -m mistune',
        description=CMD_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '-m', '--message',
        help='the markdown message to convert',
    )
    parser.add_argument(
        '-f', '--file',
        help='the markdown file to convert',
    )
    parser.add_argument(
        '-p', '--plugin',
        metavar='NAME',
        action='extend',
        nargs='+',
        help='specifiy a plugin to use',
    )
    parser.add_argument(
        '--escape',
        action='store_true',
        help='turn on escape option',
    )
    parser.add_argument(
        '--hardwrap',
        action='store_true',
        help='turn on hardwrap option',
    )
    parser.add_argument(
        '-o', '--output',
        help='write the rendered result into file',
    )
    parser.add_argument(
        '-r', '--renderer',
        default='html',
        help='specify the output renderer',
    )
    parser.add_argument('--version', action='version', version='mistune ' + version)
    args = parser.parse_args()

    message = args.message
    if not message and not args.file:
        message = read_stdin()

    if message:
        md = _md(args)
        text = md(message)
        _output(text, args)
    elif args.file:
        md = _md(args)
        text = md.read(args.file)[0]
        _output(text, args)
    else:
        print('You MUST specify a message or file')
        return sys.exit(1)


def read_stdin():
    is_stdin_pipe = not sys.stdin.isatty()
    if is_stdin_pipe:
        return sys.stdin.read()
    else:
        return None


if __name__ == '__main__':
    cli()
