from ._base import DirectiveParser, BaseDirective, DirectivePlugin
from ._rst import RSTDirective
from ._fenced import FencedDirective
from .admonition import Admonition
from .toc import TableOfContents
from .include import Include
from .image import Image, Figure

    
class RstDirective(RSTDirective):  # pragma: no cover
    def __init__(self, plugins):
        super(RstDirective, self).__init__(plugins)
        import warnings
        warnings.warn(
            "'RstDirective' is deprecated, please use 'RSTDirective' instead.",
            DeprecationWarning,
            stacklevel=2,
        )


__all__ = [
    'DirectiveParser',
    'BaseDirective',
    'DirectivePlugin',
    'RSTDirective',
    'FencedDirective',
    'Admonition',
    'TableOfContents',
    'Include',
    'Image', 'Figure',
]
