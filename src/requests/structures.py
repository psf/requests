"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power Requests.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Iterator, Mapping
from typing import Any, Generic, TypeVar, overload

from .compat import MutableMapping

_VT = TypeVar("_VT")
_D = TypeVar("_D")


class CaseInsensitiveDict(MutableMapping[str, _VT], Generic[_VT]):
    """
    A case-insensitive dict-like object.

    The contract is that keys must be strings (or bytes that can be
    decoded as utf-8 to a string). The dict-style methods
    ``__setitem__``, ``__contains__``, ``__delitem__``, and ``__iter__``
    used to call ``key.lower()`` without a type check, so passing a
    non-string key produced a misleading ``AttributeError: 'int'
    object has no attribute 'lower'`` rather than a clear ``TypeError``.
    The new ``_validate_key`` helper is invoked at the boundary, so
    callers now get ``TypeError: CaseInsensitiveDict keys must be
    str (or bytes decodable as utf-8), not int`` at the call site.
    """

    _store: OrderedDict[str, tuple[str, _VT]]

    @staticmethod
    def _validate_key(key: Any) -> str:
        if isinstance(key, str):
            return key
        if isinstance(key, bytes):
            try:
                return key.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise TypeError(
                    "CaseInsensitiveDict bytes keys must be decodable as utf-8, "
                    f"got {key!r}"
                ) from exc
        raise TypeError(
            "CaseInsensitiveDict keys must be str (or bytes decodable as utf-8),"
            f" not {type(key).__name__}: {key!r}"
        )

    def __init__(
        self,
        data: Mapping[str, _VT] | Iterable[tuple[str, _VT]] | None = None,
        **kwargs: _VT,
    ) -> None:
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key: str, value: _VT) -> None:
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        key = self._validate_key(key)
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key: str) -> _VT:
        key = self._validate_key(key)
        return self._store[key.lower()][1]

    def __delitem__(self, key: str) -> None:
        key = self._validate_key(key)
        del self._store[key.lower()]

    def __contains__(self, key: object) -> bool:  # type: ignore[override]
        if not isinstance(key, (str, bytes)):
            return False
        try:
            key = self._validate_key(key)
        except TypeError:
            return False
        return key.lower() in self._store

    def __iter__(self) -> Iterator[str]:
        return (casedkey for casedkey, _ in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def lower_items(self) -> Iterator[tuple[str, _VT]]:
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            try:
                other_dict: CaseInsensitiveDict[Any] = CaseInsensitiveDict(other)  # type: ignore[reportUnknownArgumentType]
            except TypeError:
                # `other` is a Mapping whose keys are not strings (e.g.
                # ``{1: 'one'}``). CaseInsensitiveDict rejects non-string
                # keys with a TypeError, but the __eq__ contract requires
                # us to return NotImplemented for any value we cannot
                # compare against so Python can fall back to the
                # right-hand operand and ultimately produce False rather
                # than propagating an exception.
                return NotImplemented
            # Compare insensitively
            return dict(self.lower_items()) == dict(other_dict.lower_items())
        return NotImplemented

    # Copy is required
    def copy(self) -> CaseInsensitiveDict[_VT]:
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self) -> str:
        return str(dict(self.items()))


class LookupDict(dict[str, _VT]):
    """Dictionary lookup object."""

    name: Any

    def __init__(self, name: Any = None) -> None:
        self.name = name
        super().__init__()

    def __repr__(self) -> str:
        return f"<lookup '{self.name}'>"

    def __getattr__(self, key: str) -> _VT | None:
        # We need this for type checkers to infer typing
        # on attribute access with status_codes.py
        if key in self.__dict__:
            return self.__dict__[key]
        else:
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{key}'"
            )

    def __getitem__(self, key: str) -> _VT | None:  # type: ignore[override]
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    @overload
    def get(self, key: str, default: None = None) -> _VT | None: ...

    @overload
    def get(self, key: str, default: _D | _VT) -> _D | _VT: ...

    def get(self, key: str, default: _D | None = None) -> _VT | _D | None:
        return self.__dict__.get(key, default)
