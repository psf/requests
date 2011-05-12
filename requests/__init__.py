# -*- coding: utf-8 -*-

import inspect

import packages
from core import *

from core import __version__

timeout = None

class settings:
    """Context manager for settings."""
    
    cache = {}
    
    def __init__(self, timeout):
        self.module = inspect.getmodule(self)
        
        # Cache settings
        self.cache['timeout'] = self.module.timeout
        
        self.module.timeout = timeout
        
    def __enter__(self):
        pass
        
    def __exit__(self, type, value, traceback):
        # Restore settings 
        for key in self.cache:
            setattr(self.module, key, self.cache[key])
