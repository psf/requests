# -*- coding: utf-8 -*-

"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.
"""

import warnings

def dispatch_hook(key, hooks, hook_data):
    """"""

    hooks = hooks or dict()

    if key in hooks:
        try:
            return hooks.get(key).__call__(hook_data) or hook_data

        except Exception, why:
            warnings.warn(str(why))


    return hook_data
