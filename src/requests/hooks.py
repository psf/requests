"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``response``:
    The response generated from a Request.
"""
HOOKS = ["response"]


def default_hooks():
    """
    Returns a default hook configuration dictionary where each event in HOOKS maps to an empty list, enabling users to extend or customize request behavior through hooks. This provides a consistent starting point for adding custom logic during request lifecycle events, aligning with Requests' goal of offering flexible, extensible HTTP interactions.
    
    Returns:
        Dictionary mapping each hook event to an empty list, serving as the baseline configuration for request hooks
    """
    return {event: [] for event in HOOKS}


# TODO: response is the only one


def dispatch_hook(key, hooks, hook_data, **kwargs):
    """
    Dispatches a series of hooks for a given request operation to allow extensibility and customization of request behavior.
    
    Hooks are used to modify or inspect data at various stages of the request lifecycle, such as before sending a request or after receiving a response. This function enables the Requests library to support plugin-like functionality, allowing users to extend behavior without modifying core code.
    
    Args:
        key: The hook category (e.g., 'request', 'response') used to retrieve the appropriate hook(s) from the hooks dictionary.
        hooks: A dictionary mapping hook keys to callable functions or lists of callables to be executed.
        hook_data: The data (e.g., request or response object) to be processed by the hooks.
        **kwargs: Additional arguments passed to each hook function.
    
    Returns:
        The potentially modified data after all applicable hooks have been applied, allowing for chainable transformations.
    """
    hooks = hooks or {}
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, "__call__"):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data
