######################## BEGIN LICENSE BLOCK ########################
# The Original Code is Mozilla Universal charset detector code.
#
# The Initial Developer of the Original Code is
# Netscape Communications Corporation.
# Portions created by the Initial Developer are Copyright (C) 2001
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Mark Pilgrim - port to Python
#   Shy Shalom - original C code
#
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

import sys
from . import constants
from .latin1prober import Latin1Prober  # windows-1252
from .mbcsgroupprober import MBCSGroupProber  # multi-byte character sets
from .sbcsgroupprober import SBCSGroupProber  # single-byte character sets
from .escprober import EscCharSetProber  # ISO-2122, etc.
import re
import logging

logger = logging.getLogger(__name__)

MINIMUM_THRESHOLD = 0.20
ePureAscii = 0
eEscAscii = 1
eHighbyte = 2


class UniversalDetector:
    def __init__(self):
        self._highBitDetector = re.compile(b'[\x80-\xFF]')
        self._escDetector = re.compile(b'(\033|~{)')
        self._mEscCharSetProber = None
        self._mCharSetProbers = []
        self.reset()

    def reset(self):
        self.result = {'encoding': None, 'confidence': 0.0}
        self.done = False
        self._mStart = True
        self._mGotData = False
        self._mInputState = ePureAscii
        self._mLastChar = b''
        if self._mEscCharSetProber:
            self._mEscCharSetProber.reset()
        for prober in self._mCharSetProbers:
            prober.reset()

    def feed(self, aBuf):
        if self.done:
            return

        charmap = (
            # EF BB BF  UTF-8 with BOM
            ('\xEF\xBB\xBF', {'encoding': "UTF-8", 'confidence': 1.0}),
            # FF FE 00 00  UTF-32, little-endian BOM
            ('\xFF\xFE\x00\x00', {'encoding': "UTF-32LE", 'confidence': 1.0}),
            # 00 00 FE FF  UTF-32, big-endian BOM
            ('\x00\x00\xFE\xFF', {'encoding': "UTF-32BE", 'confidence': 1.0}),
            # FE FF 00 00  UCS-4, unusual octet order BOM (3412)
            ('\xFE\xFF\x00\x00', {'encoding': "X-ISO-10646-UCS-4-3412",
                                  'confidence': 1.0}),
            # 00 00 FF FE  UCS-4, unusual octet order BOM (2143)
            ('\x00\x00\xFF\xFE', {'encoding': "X-ISO-10646-UCS-4-2143",
                                  'confidence': 1.0}),
            # FF FE  UTF-16, little endian BOM
            ('\xFF\xFE', {'encoding': "UTF-16LE", 'confidence': 1.0}),
            # FE FF  UTF-16, big endian BOM
            ('\xFE\xFF', {'encoding': "UTF-16BE", 'confidence': 1.0}),
        )

        aLen = len(aBuf)
        if not aLen:
            return

        if not self._mGotData:
            # If the data starts with BOM, we know it is UTF
            for chunk, result in charmap:
                if aBuf[:len(chunk)] == chunk:
                    self.result = result
                    break

        self._mGotData = True
        if self.result['encoding'] and (self.result['confidence'] > 0.0):
            self.done = True
            return

        if self._mInputState == ePureAscii:
            if self._highBitDetector.search(aBuf):
                self._mInputState = eHighbyte
            elif ((self._mInputState == ePureAscii) and
                    self._escDetector.search(self._mLastChar + aBuf)):
                self._mInputState = eEscAscii

        self._mLastChar = aBuf[-1:]

        if self._mInputState == eEscAscii:
            if not self._mEscCharSetProber:
                self._mEscCharSetProber = EscCharSetProber()
            if self._mEscCharSetProber.feed(aBuf) == constants.eFoundIt:
                self.result = {
                    'encoding': self._mEscCharSetProber.get_charset_name(),
                    'confidence': self._mEscCharSetProber.get_confidence(),
                }
                self.done = True
        elif self._mInputState == eHighbyte:
            if not self._mCharSetProbers:
                self._mCharSetProbers = [MBCSGroupProber(), SBCSGroupProber(),
                                         Latin1Prober()]
            for prober in self._mCharSetProbers:
                try:
                    if prober.feed(aBuf) == constants.eFoundIt:
                        self.result = {'encoding': prober.get_charset_name(),
                                       'confidence': prober.get_confidence()}
                        self.done = True
                        break
                except (UnicodeDecodeError, UnicodeEncodeError) as e:
                    logger.exception(e)

    def close(self):
        if self.done:
            return
        if not self._mGotData:
            if constants._debug:
                sys.stderr.write('no data received!\n')
            return
        self.done = True

        if self._mInputState == ePureAscii:
            self.result = {'encoding': 'ascii', 'confidence': 1.0}
            return self.result

        if self._mInputState == eHighbyte:
            proberConfidence = None
            maxProberConfidence = 0.0
            maxProber = None
            for prober in self._mCharSetProbers:
                if not prober:
                    continue
                proberConfidence = prober.get_confidence()
                if proberConfidence > maxProberConfidence:
                    maxProberConfidence = proberConfidence
                    maxProber = prober
            if maxProber and (maxProberConfidence > MINIMUM_THRESHOLD):
                self.result = {'encoding': maxProber.get_charset_name(),
                               'confidence': maxProber.get_confidence()}
                return self.result

        if constants._debug:
            sys.stderr.write('no probers hit minimum threshhold\n')
            for prober in self._mCharSetProbers[0].mProbers:
                if not prober:
                    continue
                sys.stderr.write('%s confidence = %s\n' %
                                 (prober.get_charset_name(),
                                  prober.get_confidence()))
