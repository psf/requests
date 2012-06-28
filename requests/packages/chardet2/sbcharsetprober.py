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

from . import constants
import sys
from .charsetprober import CharSetProber

SAMPLE_SIZE = 64
SB_ENOUGH_REL_THRESHOLD = 1024
POSITIVE_SHORTCUT_THRESHOLD = 0.95
NEGATIVE_SHORTCUT_THRESHOLD = 0.05
SYMBOL_CAT_ORDER = 250
NUMBER_OF_SEQ_CAT = 4
POSITIVE_CAT = NUMBER_OF_SEQ_CAT - 1
#NEGATIVE_CAT = 0
 
class SingleByteCharSetProber(CharSetProber):
    def __init__(self, model, reversed=False, nameProber=None):
        CharSetProber.__init__(self)
        self._mModel = model
        self._mReversed = reversed # TRUE if we need to reverse every pair in the model lookup
        self._mNameProber = nameProber # Optional auxiliary prober for name decision
        self.reset()

    def reset(self):
        CharSetProber.reset(self)
        self._mLastOrder = 255 # char order of last character
        self._mSeqCounters = [0] * NUMBER_OF_SEQ_CAT
        self._mTotalSeqs = 0
        self._mTotalChar = 0
        self._mFreqChar = 0 # characters that fall in our sampling range

    def get_charset_name(self):
        if self._mNameProber:
            return self._mNameProber.get_charset_name()
        else:
            return self._mModel['charsetName']

    def feed(self, aBuf):
        if not self._mModel['keepEnglishLetter']:
            aBuf = self.filter_without_english_letters(aBuf)
        aLen = len(aBuf)
        if not aLen:
            return self.get_state()
        for c in aBuf:
            order = self._mModel['charToOrderMap'][c]
            if order < SYMBOL_CAT_ORDER:
                self._mTotalChar += 1
            if order < SAMPLE_SIZE:
                self._mFreqChar += 1
                if self._mLastOrder < SAMPLE_SIZE:
                    self._mTotalSeqs += 1
                    if not self._mReversed:
                        self._mSeqCounters[self._mModel['precedenceMatrix'][(self._mLastOrder * SAMPLE_SIZE) + order]] += 1
                    else: # reverse the order of the letters in the lookup
                        self._mSeqCounters[self._mModel['precedenceMatrix'][(order * SAMPLE_SIZE) + self._mLastOrder]] += 1
            self._mLastOrder = order

        if self.get_state() == constants.eDetecting:
            if self._mTotalSeqs > SB_ENOUGH_REL_THRESHOLD:
                cf = self.get_confidence()
                if cf > POSITIVE_SHORTCUT_THRESHOLD:
                    if constants._debug:
                        sys.stderr.write('%s confidence = %s, we have a winner\n' % (self._mModel['charsetName'], cf))
                    self._mState = constants.eFoundIt
                elif cf < NEGATIVE_SHORTCUT_THRESHOLD:
                    if constants._debug:
                        sys.stderr.write('%s confidence = %s, below negative shortcut threshhold %s\n' % (self._mModel['charsetName'], cf, NEGATIVE_SHORTCUT_THRESHOLD))
                    self._mState = constants.eNotMe

        return self.get_state()

    def get_confidence(self):
        r = 0.01
        if self._mTotalSeqs > 0:
#            print self._mSeqCounters[POSITIVE_CAT], self._mTotalSeqs, self._mModel['mTypicalPositiveRatio']
            r = (1.0 * self._mSeqCounters[POSITIVE_CAT]) / self._mTotalSeqs / self._mModel['mTypicalPositiveRatio']
#            print r, self._mFreqChar, self._mTotalChar
            r = r * self._mFreqChar / self._mTotalChar
            if r >= 1.0:
                r = 0.99
        return r
