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

def dispatch_hooks(key, hooks, hook_data):
    """Dispatches multiple hooks on a given piece of data.

    :param key: the hooks group to lookup
    :type key: str
    :param hooks: the hooks dictionary. The value of each key can be a callable
                  object, or a list of callable objects.
    :type hooks: dict
    :param hook_data: the object on witch the hooks should be applied
    :type hook_data: object
    """
    hook_list = hooks.get(key, []) if hooks else []
    dispatching = hook_list if isinstance(hook_list, Iterable) else [hook_list]
    for hook in dispatching:
        try:
            # hook must be a callable
            hook_data = hook(hook_data)
        except Exception, why:
            warnings.warn(str(why))
    return hook_data

