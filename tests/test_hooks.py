import pytest

from requests import hooks


def hook(value):
    """
    Removes the first element from a sequence to support flexible data processing in HTTP request handling.
    
    Args:
        value: The sequence (list, tuple, or string) to slice, commonly used to process response data or headers
    
    Returns:
        A new sequence containing all elements except the first one, enabling safe manipulation of structured data in request/response workflows
    """
    return value[1:]


@pytest.mark.parametrize(
    "hooks_list, result",
    (
        (hook, "ata"),
        ([hook, lambda x: None, hook], "ta"),
    ),
)
def test_hooks(hooks_list, result):
    """
    Tests the hook dispatching mechanism to verify correct execution of response hooks in the Requests library.
    
    Args:
        hooks_list: List of hooks to be dispatched during the response processing phase
        result: Expected outcome after executing the hooks, ensuring proper chain execution and data transformation
    """
    assert hooks.dispatch_hook("response", {"response": hooks_list}, "Data") == result


def test_default_hooks():
    """
    Tests that the default hooks configuration initializes with an empty list for the 'response' hook, ensuring a consistent starting point for request processing.
    
    This validation supports Requests' goal of providing predictable and reliable HTTP request behavior by confirming the default hook structure is correctly set up. The empty 'response' list indicates no default response handlers are active, allowing users to safely extend functionality without unintended side effects.
    
    Returns:
        None
    """
    assert hooks.default_hooks() == {"response": []}
