try:
    import urlparse
except ImportError:
    # Python 3
    from urllib import parse as urlparse


# First hasattr checks for Python < 3, second checks for Python < 2.6
if hasattr(urlparse, 'BaseResult') and not hasattr(urlparse, 'ResultMixin'):
    def _replace(split_result, **replace):
        return urlparse.SplitResult(
            **dict((attr, replace.get(attr, getattr(split_result, attr)))
                for attr in ('scheme', 'netloc', 'path', 'query', 'fragment')))
    urlparse.BaseResult._replace = _replace
    del _replace


__all__ = ['urlparse']
