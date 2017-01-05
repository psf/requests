import sys


def delete_module(modname):
    """
    Delete module and sub-modules from `sys.module`
    """
    try:
        _ = sys.modules[modname]
    except KeyError:
        raise ValueError("Module not found in sys.modules: '{}'".format(modname))

    for module in list(sys.modules.keys()):
        if module and module.startswith(modname):
            del sys.modules[module]


def reload_module(module):
    try:
        # For Python 2.x
        reload(module)
    except (ImportError, NameError):
        # For <= Python3.3:
        import imp
        imp.reload(module)
    except (ImportError, NameError):
        # For >= Python3.4
        import importlib
        importlib.reload(module)

def load_idna(func):
    """
    Decorator to load idna to execute idna related operation for specific function
    and delete the idna module from imports once the task is done.
    Needed to free the memory consumed due to idna imports.
    """
    def inner(*args, **kwargs):
        import idna

        # Add `idna` entry in `sys.modules`. After deleting the module
        # from `sys.modules` and re-importing the module don't update
        # the module entry in `sys.modules` dict
        sys.modules[idna.__package__] = idna

        reload_module(idna)

        value = func(*args, **kwargs)

        # delete idna module
        delete_module('idna')
        del idna  # delete reference to idna

        return value
    return inner
