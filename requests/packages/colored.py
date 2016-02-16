# -*- coding: utf-8 -*-

"""
clint.colored
~~~~~~~~~~~~~

This module provides a simple and elegant wrapper for colorama.

Extracted from the `clint project <https://github.com/kennethreitz/clint>`_.
"""


from __future__ import absolute_import

import os
import re
import sys

PY3 = sys.version_info[0] >= 3

from . import colorama

__all__ = (
    'red', 'green', 'yellow', 'blue',
    'black', 'magenta', 'cyan', 'white',
    'clean', 'disable'
)

COLORS = __all__[:-2]

if 'get_ipython' in dir():
    """
       when ipython is fired lot of variables like _oh, etc are used.
       There are so many ways to find current python interpreter is ipython.
       get_ipython is easiest is most appealing for readers to understand.
    """
    DISABLE_COLOR = True
else:
    DISABLE_COLOR = False


class ColoredString(object):
    """Enhanced string for __len__ operations on Colored output."""
    def __init__(self, color, s, always_color=False, bold=False):
        super(ColoredString, self).__init__()
        self.s = s
        self.color = color
        self.always_color = always_color
        self.bold = bold
        if os.environ.get('CLINT_FORCE_COLOR'):
            self.always_color = True

    def __getattr__(self, att):
        def func_help(*args, **kwargs):
            result = getattr(self.s, att)(*args, **kwargs)
            try:
                is_result_string = isinstance(result, basestring)
            except NameError:
                is_result_string = isinstance(result, str)
            if is_result_string:
                return self._new(result)
            elif isinstance(result, list):
                return [self._new(x) for x in result]
            else:
                return result
        return func_help

    @property
    def color_str(self):
        style = 'BRIGHT' if self.bold else 'NORMAL'
        c = '%s%s%s%s%s' % (getattr(colorama.Fore, self.color), getattr(colorama.Style, style), self.s, colorama.Fore.RESET, getattr(colorama.Style, 'NORMAL'))

        if self.always_color:
            return c
        elif sys.stdout.isatty() and not DISABLE_COLOR:
            return c
        else:
            return self.s


    def __len__(self):
        return len(self.s)

    def __repr__(self):
        return "<%s-string: '%s'>" % (self.color, self.s)

    def __unicode__(self):
        value = self.color_str
        if isinstance(value, bytes):
            return value.decode('utf8')
        return value

    if PY3:
        __str__ = __unicode__
    else:
        def __str__(self):
            value = self.color_str
            if isinstance(value, bytes):
                return value
            return value.encode('utf8')

    def __iter__(self):
        return iter(self.color_str)

    def __add__(self, other):
        return str(self.color_str) + str(other)

    def __radd__(self, other):
        return str(other) + str(self.color_str)

    def __mul__(self, other):
        return (self.color_str * other)

    def _new(self, s):
        return ColoredString(self.color, s)


def clean(s):
    strip = re.compile("([^-_a-zA-Z0-9!@#%&=,/'\";:~`\$\^\*\(\)\+\[\]\.\{\}\|\?\<\>\\]+|[^\s]+)")
    txt = strip.sub('', str(s))

    strip = re.compile(r'\[\d+m')
    txt = strip.sub('', txt)

    return txt


def black(string, always=False, bold=False):
    return ColoredString('BLACK', string, always_color=always, bold=bold)

def red(string, always=False, bold=False):
    return ColoredString('RED', string, always_color=always, bold=bold)

def green(string, always=False, bold=False):
    return ColoredString('GREEN', string, always_color=always, bold=bold)

def yellow(string, always=False, bold=False):
    return ColoredString('YELLOW', string, always_color=always, bold=bold)

def blue(string, always=False, bold=False):
    return ColoredString('BLUE', string, always_color=always, bold=bold)

def magenta(string, always=False, bold=False):
    return ColoredString('MAGENTA', string, always_color=always, bold=bold)

def cyan(string, always=False, bold=False):
    return ColoredString('CYAN', string, always_color=always, bold=bold)

def white(string, always=False, bold=False):
    return ColoredString('WHITE', string, always_color=always, bold=bold)

def disable():
    """Disables colors."""
    global DISABLE_COLOR

    DISABLE_COLOR = True
