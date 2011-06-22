# -*- coding: utf-8 -*-

"""
requests.core
~~~~~~~~~~~~~

This module implements the main Requests system.

:copyright: (c) 2011 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""

__title__ = 'requests'
__version__ = '0.5.0'
__build__ = 0x000500
__author__ = 'Kenneth Reitz'
__license__ = 'ISC'
__copyright__ = 'Copyright 2011 Kenneth Reitz'


from models import HTTPError, auth_manager
from api import *
from exceptions import *
from config import settings