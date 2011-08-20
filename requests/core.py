# -*- coding: utf-8 -*-

"""
requests.core
~~~~~~~~~~~~~

This module implements the main Requests system.

:copyright: (c) 2011 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""

__title__ = 'requests'
__version__ = '0.6.1'
__build__ = 0x000601
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'


from models import HTTPError
from api import *
from exceptions import *
from sessions import session
from status_codes import codes
from config import settings