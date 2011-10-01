# -*- coding: utf-8 -*-

#   __
#  /__)  _  _     _   _ _/   _
# / (   (- (/ (/ (- _)  /  _)
#          /

"""
requests.core
~~~~~~~~~~~~~

This module implements the main Requests system.

:copyright: (c) 2011 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""


__title__ = 'requests'
__version__ = '0.6.2 (dev)'
__build__ = 0x000602
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'

import logging
logging.basicConfig()

from api import *
from exceptions import *
from models import Request, Response
from sessions import session
from status_codes import codes

import utils
