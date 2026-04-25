# coding: utf-8
import inspect

from flask.views import MethodView

import flasgger

try:
    import marshmallow
    from marshmallow import fields
    from apispec.ext.marshmallow import openapi
    from apispec import APISpec as BaseAPISpec

    # Note that openapi_converter is initialized with trivial
    #   schema_name_resolver. Resolving circular reference is not
    #   supported for now. See issue #314 .
    # Also see: https://github.com/marshmallow-code/apispec/pull/447
    openapi_converter = openapi.OpenAPIConverter(
        openapi_version='2.0',
        schema_name_resolver=lambda schema: None,
        spec=None
    )
    schema2jsonschema = openapi_converter.schema2jsonschema
    schema2parameters = openapi_converter.schema2parameters

    class Schema(marshmallow.Schema):
        swag_in = "body"
        swag_validate = True
        swag_validation_function = None
        swag_validation_error_handler = None
        swag_require_data = True

        def to_specs_dict(self):
            specs = {'parameters': self.__class__}
            definitions = {}
            specs.update(convert_schemas(specs, definitions))
            specs['definitions'] = definitions
            return specs

except ImportError:
    Schema = None
    fields = None
    schema2jsonschema = lambda schema: {}  # noqa
    schema2parameters = lambda schema, location: []  # noqa
    BaseAPISpec = object


class APISpec(BaseAPISpec):
    """
    Wrapper around APISpec to add `to_flasgger` method
    """

    def to_flasgger(self, app=None, definitions=None, paths=None):
        """
        Converts APISpec dict to flasgger suitable dict
        also adds definitions and paths (optional)
        """
        if Schema is None:
            raise RuntimeError('Please install marshmallow and apispec')

        return flasgger.utils.apispec_to_template(
            app,
            self,
            definitions=definitions,
            paths=paths
        )


class SwaggerView(MethodView):
    """
    A Swagger view
    """
    parameters = []
    responses = {}
    definitions = {}
    tags = []
    consumes = ['application/json']
    produces = ['application/json']
    schemes = []
    security = []
    deprecated = False
    operationId = None
    externalDocs = {}
    summary = None
    description = None
    validation = False
    validation_function = None
    validation_error_handler = None

    def dispatch_request(self, *args, **kwargs):
        """
        If validation=True perform validation
        """
        if self.validation:
            specs = {}
            attrs = flasgger.constants.OPTIONAL_FIELDS + [
                'parameters', 'definitions', 'responses',
                'summary', 'description'
            ]
            for attr in attrs:
                specs[attr] = getattr(self, attr)
            definitions = {}
            specs.update(convert_schemas(specs, definitions))
            specs['definitions'] = definitions
            flasgger.utils.validate(
                specs=specs, validation_function=self.validation_function,
                validation_error_handler=self.validation_error_handler
            )
        return super(SwaggerView, self).dispatch_request(*args, **kwargs)


def convert_schemas(d, definitions=None):
    """
    Convert Marshmallow schemas to dict definitions

    Also updates the optional definitions argument with any definitions
    entries contained within the schema.
    """
    if definitions is None:
        definitions = {}
    definitions.update(d.get('definitions', {}))

    new = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = convert_schemas(v, definitions)
        if isinstance(v, (list, tuple)):
            new_v = []
            for item in v:
                if isinstance(item, dict):
                    new_v.append(convert_schemas(item, definitions))
                else:
                    new_v.append(item)
            v = new_v
        if inspect.isclass(v) and issubclass(v, Schema):

            if Schema is None:
                raise RuntimeError('Please install marshmallow and apispec')

            definitions[v.__name__] = schema2jsonschema(v)
            ref = {
                "$ref": "#/definitions/{0}".format(v.__name__)
            }
            if k == 'parameters':
                new[k] = schema2parameters(v, location=v.swag_in)
                new[k][0]['schema'] = ref
                if len(definitions[v.__name__]['required']) != 0:
                    new[k][0]['required'] = True
            else:
                new[k] = ref
        else:
            new[k] = v

    # This key is not permitted anywhere except the very top level.
    if 'definitions' in new:
        del new['definitions']

    return new
