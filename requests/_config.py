# -*- coding: utf-8 -*-

"""
requests.config
~~~~~~~~~~~~~~~

This module provides the Requests configuration defaults.

settings parameters:

- :base_headers: - Sets default User-Agent to `python-requests.org`
- :accept_gzip:  - Whether or not to accept gzip-compressed data
- :proxies: - http proxies?
- :verbose: - display verbose information?
- :timeout: - timeout time until request terminates
- :max_redirects: - maximum number of allowed redirects?
- :decode_unicode: - whether or not to accept unicode?

"""

def get_config(config=None, default_config=None):
    """Merges two given configurations."""

    # Allow raw calls.
    if config is None:
        config=dict()

    # Use the module-level defaults, if none is given.
    if default_config is None:
        default_config = defaults.copy()


    d = default_config.copy()
    d.update(config)

    return d


# Module-level defaults.
defaults = dict()

defaults['base_headers'] = {'User-Agent': 'python-requests.org'}
defaults['accept_gzip'] = True
defaults['proxies'] = {}
defaults['verbose'] = None
defaults['timeout'] = None
defaults['max_redirects'] = 30
defaults['decode_unicode'] = True
defaults['keepalive'] = True


