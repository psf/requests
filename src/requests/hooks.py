"""
requests.hooks
~~~~~~~~~~~~~~

This module provides the capabilities for the Requests hooks system.

Available hooks:

``response``:
    The response generated from a Request.
"""
from typing import Any, Dict, List, Optional

HOOKS = ["response"]


def default_hooks() -> Dict[str, List[Any]]:
    return {event: [] for event in HOOKS}


# TODO: response is the only one


def dispatch_hook(key: str, hooks: Optional[Dict[str, Any]], hook_data: Any, **kwargs: Any) -> Any:
    """Dispatches a hook dictionary on a given piece of data."""
    hooks_dict = hooks or {}
    hooks_value = hooks_dict.get(key)
    if hooks_value:
        if hasattr(hooks_value, "__call__"):
            hooks_value = [hooks_value]
        for hook in hooks_value:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data
