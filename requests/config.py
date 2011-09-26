# -*- coding: utf-8 -*-

"""
requests.config
~~~~~~~~~~~~~~~

This module provides the Requests settings feature set.

settings parameters:

- :base_headers: - Sets default User-Agent to `python-requests.org`
- :accept_gzip:  - Whether or not to accept gzip-compressed data
- :proxies: - http proxies?
- :verbose: - display verbose information?
- :timeout: - timeout time until request terminates
- :max_redirects: - maximum number of allowed redirects?
- :decode_unicode: - whether or not to accept unicode?

"""

def merge_configs(config, default_config=None):
    """Merge two given configurations."""

    # Use the module-level defaults, if none is given.
    if default_config is None:
        default_config = config.copy()

    d = default_config.copy()
    d.update(config)

    return d

# Module-level defaults.
config = dict()

config['base_headers'] = {'User-Agent': 'python-requests.org'}
config['accept_gzip'] = True
config['proxies'] = {}
config['verbose'] = None
config['timeout'] = None
config['max_redirects'] = 30
config['decode_unicode'] = True


