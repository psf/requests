import contextlib
import os


@contextlib.contextmanager
def override_environ(**kwargs):
    """
    Temporarily modifies environment variables to control HTTP behavior during testing or execution, ensuring isolated and predictable environment states.
    
    Args:
        **kwargs: Key-value pairs where keys are environment variable names and values are the new values to set. If a value is None, the environment variable is removed.
    """
    save_env = dict(os.environ)
    for key, value in kwargs.items():
        if value is None:
            del os.environ[key]
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(save_env)
