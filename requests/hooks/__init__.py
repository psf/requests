# -*- coding: utf-8 -*-

"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``args``:
    A dictionary of the arguments being sent to Request().

``pre_request``:
    The Request object, directly before being sent.

``post_request``:
    The Request object, directly after being sent.

``response``:
    The response generated from a Request.

"""

import warnings
from collections import Iterable
from .. import config
from response import unicode_response, decode_response

def setup_hooks(hooks):
    """Setup hooks as a dictionary. Each value is a set of hooks."""

    for key, values in hooks.items():
        hook_list = values if isinstance(values, Iterable) else [values]
        hooks[key] = set(hook_list) 

    # Also, based on settings, 
    if config.settings.unicode_response:
        hooks.setdefault('response', set()).add(unicode_response)
    if config.settings.decode_response:
        hooks.setdefault('response', set()).add(decode_response)
    return hooks

def dispatch_hooks(hooks, hook_data):
    """Dispatches multiple hooks on a given piece of data.

    :param key: the hooks group to lookup
    :type key: str
    :param hooks: the hooks dictionary. The value of each key can be a callable
                  object, or a list of callable objects.
    :type hooks: dict
    :param hook_data: the object on witch the hooks should be applied
    :type hook_data: object
    """
    for hook in hooks:
        try:
            # hook must be a callable
            hook_data = hook(hook_data)
        except Exception, why:
            warnings.warn(str(why))
    return hook_data
