# -*- coding: utf-8 -*-

"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``args``:
    A dictionary of the arguments being sent to Request().

``pre_request``:
    The Request object, directly after being created.

``pre_send``:
    The Request object, directly before being sent.

``post_request``:
    The Request object, directly after being sent.

``response``:
    The response generated from a Request.

"""


HOOKS = ('args', 'pre_request', 'pre_send', 'post_request', 'response')


def dispatch_hook(key, hooks, hook_data):
    """Dispatches a hook dictionary on a given piece of data."""

    hooks = hooks or dict()

    if key in hooks:
        hooks = hooks.get(key)

        if hasattr(hooks, '__call__'):
            hooks = [hooks]

        for hook in hooks:
            _hook_data = hook(hook_data)
            if _hook_data is not None:
                hook_data = _hook_data


    return hook_data
