from typing import List

from ._base import BaseDirective, DirectiveParser, DirectivePlugin
from ._fenced import FencedDirective
from ._rst import RSTDirective
from .admonition import Admonition
from .image import Figure, Image
from .include import Include
from .toc import TableOfContents


class RstDirective(RSTDirective):  # pragma: no cover
    def __init__(self, plugins: List[DirectivePlugin]) -> None:
        super(RstDirective, self).__init__(plugins)
        import warnings

        warnings.warn(
            "'RstDirective' is deprecated, please use 'RSTDirective' instead.",
            DeprecationWarning,
            stacklevel=2,
        )


__all__ = [
    "DirectiveParser",
    "BaseDirective",
    "DirectivePlugin",
    "RSTDirective",
    "FencedDirective",
    "Admonition",
    "TableOfContents",
    "Include",
    "Image",
    "Figure",
]
