# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import dataclasses
import sys
import typing

if sys.version_info < (3, 11):
    import typing_extensions

    # We use the `include_extras` parameter of `get_type_hints`, which was
    # added in Python 3.9. This can be replaced by the `typing` version
    # once the min version is >= 3.9
    if sys.version_info < (3, 9):
        get_type_hints = typing_extensions.get_type_hints
    else:
        get_type_hints = typing.get_type_hints
else:
    get_type_hints = typing.get_type_hints

from cryptography.hazmat.bindings._rust import declarative_asn1

T = typing.TypeVar("T", covariant=True)
U = typing.TypeVar("U")


encode_der = declarative_asn1.encode_der


def _normalize_field_type(
    field_type: typing.Any, field_name: str
) -> declarative_asn1.AnnotatedType:
    annotation = declarative_asn1.Annotation()

    if hasattr(field_type, "__asn1_root__"):
        annotated_root = field_type.__asn1_root__
        if not isinstance(annotated_root, declarative_asn1.AnnotatedType):
            raise TypeError(f"unsupported root type: {annotated_root}")
        return annotated_root
    else:
        rust_field_type = declarative_asn1.non_root_python_to_rust(field_type)

    return declarative_asn1.AnnotatedType(rust_field_type, annotation)


def _annotate_fields(
    raw_fields: dict[str, type],
) -> dict[str, declarative_asn1.AnnotatedType]:
    fields = {}
    for field_name, field_type in raw_fields.items():
        # Recursively normalize the field type into something that the
        # Rust code can understand.
        annotated_field_type = _normalize_field_type(field_type, field_name)
        fields[field_name] = annotated_field_type

    return fields


def _register_asn1_sequence(cls: type[U]) -> None:
    raw_fields = get_type_hints(cls, include_extras=True)
    root = declarative_asn1.AnnotatedType(
        declarative_asn1.Type.Sequence(cls, _annotate_fields(raw_fields)),
        declarative_asn1.Annotation(),
    )

    setattr(cls, "__asn1_root__", root)


# Due to https://github.com/python/mypy/issues/19731, we can't define an alias
# for `dataclass_transform` that conditionally points to `typing` or
# `typing_extensions` depending on the Python version (like we do for
# `get_type_hints`).
# We work around it by making the whole decorated class conditional on the
# Python version.
if sys.version_info < (3, 11):

    @typing_extensions.dataclass_transform(kw_only_default=True)
    def sequence(cls: type[U]) -> type[U]:
        # We use `dataclasses.dataclass` to add an __init__ method
        # to the class with keyword-only parameters.
        if sys.version_info >= (3, 10):
            dataclass_cls = dataclasses.dataclass(
                repr=False,
                eq=False,
                # `match_args` was added in Python 3.10 and defaults
                # to True
                match_args=False,
                # `kw_only` was added in Python 3.10 and defaults to
                # False
                kw_only=True,
            )(cls)
        else:
            dataclass_cls = dataclasses.dataclass(
                repr=False,
                eq=False,
            )(cls)
        _register_asn1_sequence(dataclass_cls)
        return dataclass_cls

else:

    @typing.dataclass_transform(kw_only_default=True)
    def sequence(cls: type[U]) -> type[U]:
        # Only add an __init__ method, with keyword-only
        # parameters.
        dataclass_cls = dataclasses.dataclass(
            repr=False,
            eq=False,
            match_args=False,
            kw_only=True,
        )(cls)
        _register_asn1_sequence(dataclass_cls)
        return dataclass_cls
