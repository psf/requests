# -*- coding: utf-8 -*-

"""
requests.adpaters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Requests uses to define
and maintain connections.
"""

# TODO: Decide to pass in a session or not... hmm
class BaseAdapter(object):
    """The Base Transport Adapter"""

    def __init__(self, config=None):
        super(BaseAdapter, self).__init__()
        self.config = config or {}
