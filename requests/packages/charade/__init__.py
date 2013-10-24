######################## BEGIN LICENSE BLOCK ########################
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301  USA
######################### END LICENSE BLOCK #########################

__version__ = "1.0.3"
from sys import version_info


def detect(aBuf):
    if ((version_info < (3, 0) and isinstance(aBuf, unicode)) or
            (version_info >= (3, 0) and not isinstance(aBuf, bytes))):
        raise ValueError('Expected a bytes object, not a unicode object')

    from . import universaldetector
    u = universaldetector.UniversalDetector()
    u.reset()
    u.feed(aBuf)
    u.close()
    return u.result

def _description_of(path):
    """Return a string describing the probable encoding of a file."""
    from charade.universaldetector import UniversalDetector

    u = UniversalDetector()
    for line in open(path, 'rb'):
        u.feed(line)
    u.close()
    result = u.result
    if result['encoding']:
        return '%s: %s with confidence %s' % (path,
                                              result['encoding'],
                                              result['confidence'])
    else:
        return '%s: no result' % path


def charade_cli():
    """
    Script which takes one or more file paths and reports on their detected
    encodings

    Example::

        % chardetect.py somefile someotherfile
        somefile: windows-1252 with confidence 0.5
        someotherfile: ascii with confidence 1.0

    """
    from sys import argv
    for path in argv[1:]:
        print(_description_of(path))
        