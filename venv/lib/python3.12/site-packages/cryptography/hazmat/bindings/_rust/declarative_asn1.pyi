# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import typing

def encode_der(value: typing.Any) -> bytes: ...
def non_root_python_to_rust(cls: type) -> Type: ...

# Type is a Rust enum with tuple variants. For now, we express the type
# annotations like this:
class Type:
    Sequence: typing.ClassVar[type]
    PyInt: typing.ClassVar[type]

class Annotation:
    def __new__(
        cls,
    ) -> Annotation: ...

class AnnotatedType:
    inner: Type
    annotation: Annotation

    def __new__(cls, inner: Type, annotation: Annotation) -> AnnotatedType: ...

class AnnotatedTypeObject:
    annotated_type: AnnotatedType
    value: typing.Any

    def __new__(
        cls, annotated_type: AnnotatedType, value: typing.Any
    ) -> AnnotatedTypeObject: ...
