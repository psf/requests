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
from . import args
from . import pre_request
from . import post_request
from . import response

def setup_hooks(supplied):
    """Setup the supplied dictionary of hooks.
    Each value is a list of hooks and will extend **default_hooks**.

    :param supplied: a dictionary of hooks. Each value can either be a callable
                     or a list of callables.
    :type supplied: dict
    :returns: a dictionary of hooks that extends the **default_hooks** dictionary.
    :rtype: dict
    """

    # Copy the default hooks settings.
    dispatching = dict([(k, v[:]) for k, v in config.settings.default_hooks])

    # I abandoned the idea of a dictionary of sets because sets may not keep
    # insertion order, while it may be important. Also, there is no real reason
    # to force hooks to run once.
    for hooks, values in supplied.items():
        hook_list = values if isinstance(values, Iterable) else [values]
        dispatching[hooks].extends(hook_list)

    # If header is set, maybe response is encoded. Whatever hook you want to
    # run on response, content decoding should be first.
    if config.settings.base_headers.get('Accept-Encoding', ''):
        dispatching['response'].insert(0, response.decode_encoding)

    if config.settings.decode_unicode:
        try:
            # Try unicode encoding just after content decoding...
            index = dispatching['response'].index(response.decode_encoding) + 1
        except ValueError:
            # ... Or as first hook
            index = 0
        dispatching['response'].insert(index, response.decode_unicode)

    return dispatching

def dispatch_hooks(hooks, data):
    """Dispatches multiple hooks on a given piece of data.

    :param key: the hooks group to lookup
    :type key: str
    :param hooks: the hooks dictionary. The value of each key can be a callable
                  object, or a list of callable objects.
    :type hooks: dict
    :param data: the object on witch the hooks should be applied
    :type data: object
    """
    for hook in hooks:
        try:
            # hook must be a callable.
            data = hook(data)

        except Exception, why:

            # Letting users to choose a policy may be an idea. It can be as
            # simple as "be gracefull, or not":
            #
            # config.settings.gracefull_hooks = True | False
            if not config.settings.gracefull_hooks: raise

            warnings.warn(str(why))

    return data
