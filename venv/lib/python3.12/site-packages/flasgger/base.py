"""
What's the big idea?

An endpoint that traverses all restful endpoints producing a swagger 2.0 schema
If a swagger yaml description is found in the docstrings for an endpoint
we add the endpoint to swagger specification output

"""
import re
import os
import codecs
import yaml
try:
    import simplejson as json
except ImportError:
    import json
from functools import wraps, partial
from collections import defaultdict
from flask import Blueprint
from flask import current_app
from flask import jsonify, Response
from flask import redirect
from flask import render_template
from flask import request, url_for
from flask import abort
from flask.views import MethodView
try:
    from flask.json.provider import DefaultJSONProvider
except ImportError:
    from flask.json import JSONEncoder as DefaultJSONProvider
try:
    from flask_restful.reqparse import RequestParser
except ImportError:
    RequestParser = None
import jsonschema
try:
    from markupsafe import Markup
except ImportError:
    from flask import Markup
from mistune import markdown
from .constants import OPTIONAL_FIELDS, OPTIONAL_OAS3_FIELDS
from .utils import LazyString
from .utils import extract_definitions
from .utils import get_schema_specs
from .utils import get_specs
from .utils import get_vendor_extension_fields
from .utils import is_openapi3
from .utils import parse_definition_docstring
from .utils import parse_imports
from .utils import swag_annotation
from .utils import validate
from .utils import extract_schema
from . import __version__


def NO_SANITIZER(text):
    return text


def BR_SANITIZER(text):
    return text.replace('\n', '<br/>') if text else text


def MK_SANITIZER(text):
    return Markup(markdown(text)) if text else text


class APIDocsView(MethodView):
    """
    The /apidocs
    """

    def __init__(self, *args, **kwargs):
        view_args = kwargs.pop('view_args', {})
        self.config = view_args.get('config')
        super(APIDocsView, self).__init__(*args, **kwargs)

    def get(self):
        """
        The data under /apidocs
        json or Swagger UI
        """
        base_endpoint = self.config.get('endpoint', 'flasgger')
        specs = [
            {
                "url": url_for(".".join((base_endpoint, spec['endpoint']))),
                "title": spec.get('title', 'API Spec 1'),
                "name": spec.get('name', None),
                "version": spec.get("version", '0.0.1'),
                "endpoint": spec.get('endpoint')
            }
            for spec in self.config.get('specs', [])
        ]
        urls = [
            {
                "name": spec["name"],
                "url": spec["url"]
            }
            for spec in specs if spec["name"]
        ]
        data = {
            "specs": specs,
            "urls": urls,
            "title": self.config.get('title', 'Flasgger')
        }
        if request.args.get('json'):
            # calling with ?json returns specs
            return jsonify(data)
        else:  # pragma: no cover
            data['flasgger_config'] = self.config
            data['json'] = json
            data['flasgger_version'] = __version__
            data['favicon'] = self.config.get(
                'favicon',
                url_for('flasgger.static', filename='favicon-32x32.png')
            )
            data['swagger_ui_bundle_js'] = self.config.get(
                'swagger_ui_bundle_js',
                url_for('flasgger.static', filename='swagger-ui-bundle.js')
            )
            data['swagger_ui_standalone_preset_js'] = self.config.get(
                'swagger_ui_standalone_preset_js',
                url_for('flasgger.static',
                        filename='swagger-ui-standalone-preset.js')
            )
            data['jquery_js'] = self.config.get(
                'jquery_js',
                url_for('flasgger.static', filename='lib/jquery.min.js')
            )
            data['swagger_ui_css'] = self.config.get(
                'swagger_ui_css',
                url_for('flasgger.static', filename='swagger-ui.css')
            )
            return render_template(
                'flasgger/index.html',
                **data
            )


class OAuthRedirect(MethodView):
    """
    The OAuth2 redirect HTML for Swagger UI standard/implicit flow
    """
    def get(self):
        return render_template(
            ['flasgger/oauth2-redirect.html', 'flasgger/o2c.html'],
        )


class APISpecsView(MethodView):
    """
    The /apispec_1.json and other specs
    """

    def __init__(self, *args, **kwargs):
        self.loader = kwargs.pop('loader')
        super(APISpecsView, self).__init__(*args, **kwargs)

    def get(self):
        """
        The Swagger view get method outputs to /apispecs_1.json
        """
        try:
            return jsonify(self.loader())
        except:  # noqa
            import logging
            logging.exception('jsonify failure; defaulting to json.dumps')
            specs = json.dumps(self.loader())
            return Response(specs, mimetype='application/json')


class SwaggerDefinition(object):
    """
    Class based definition
    """

    def __init__(self, name, obj, tags=None):
        self.name = name
        self.obj = obj
        self.tags = tags or []


class Swagger(object):

    DEFAULT_ENDPOINT = 'apispec_1'
    DEFAULT_CONFIG = {
        "headers": [
        ],
        "specs": [
            {
                "endpoint": DEFAULT_ENDPOINT,
                "route": '/{}.json'.format(DEFAULT_ENDPOINT),
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
            }
        ],
        "static_url_path": "/flasgger_static",
        # "static_folder": "static",  # must be set by user
        "swagger_ui": True,
        "specs_route": "/apidocs/"
    }

    SCHEMA_TYPES = {'string': str, 'integer': int, 'number': float,
                    'boolean': bool}
    SCHEMA_LOCATIONS = {'query': 'args', 'header': 'headers',
                        'formData': 'form', 'body': 'json', 'path': 'path'}

    def _init_config(self, config, merge):
        """ Initializes self.config. If merge is set to true, then
        self.config will be set to with config + DEFAULT_CONFIG.
        """
        if config and merge:
            self.config = dict(self.DEFAULT_CONFIG.copy(), **config)
        elif config and not merge:
            self.config = config
        elif not config:
            self.config = self.DEFAULT_CONFIG.copy()
        else:  # The above branches must be exhaustive
            raise ValueError

    def __init__(
            self, app=None, config=None, sanitizer=None, template=None,
            template_file=None, decorators=None, validation_function=None,
            validation_error_handler=None, parse=False, format_checker=None,
            merge=False
    ):
        self._configured = False
        self.endpoints = []
        self.definition_models = []  # not in app, so track here
        self.sanitizer = sanitizer or BR_SANITIZER

        self._init_config(config, merge)

        self.template = template
        self.template_file = template_file
        self.decorators = decorators
        self.format_checker = format_checker or jsonschema.FormatChecker()

        def default_validation_function(data, schema):
            return jsonschema.validate(
                data, schema, format_checker=self.format_checker,
            )

        def default_error_handler(e, _, __):
            return abort(400, e.message)

        self.validation_function = validation_function\
            or default_validation_function

        self.validation_error_handler = validation_error_handler\
            or default_error_handler
        self.apispecs = {}  # cached apispecs
        self.parse = parse
        if app:
            self.init_app(app)

    def init_app(self, app, decorators=None):
        """
        Initialize the app with Swagger plugin
        """
        self.decorators = decorators or self.decorators
        self.app = app
        self.app.add_url_rule = swag_annotation(self.app.add_url_rule)

        self.load_config(app)
        # self.load_apispec(app)
        if self.template_file is not None:
            self.template = self.load_swagger_file(self.template_file)
        self.register_views(app)
        self.add_headers(app)

        if self.parse:
            if RequestParser is None:
                raise RuntimeError('Please install flask_restful')
            self.parsers = {}
            self.schemas = {}
            self.parse_request(app)

        self._configured = True
        app.swag = self

    def load_swagger_file(self, filename):
        if not filename.startswith('/'):
            filename = os.path.join(
                self.app.root_path,
                filename
            )

        if filename.endswith('.json'):
            loader = json.load
        elif filename.endswith('.yml') or filename.endswith('.yaml'):
            def loader(stream):
                return yaml.safe_load(parse_imports(stream.read(), filename))
        else:
            with codecs.open(filename, 'r', 'utf-8') as f:
                contents = f.read()
                contents = contents.strip()
                if contents[0] in ['{', '[']:
                    loader = json.load
                else:
                    def loader(stream):
                        return yaml.safe_load(
                            parse_imports(stream.read(), filename))
        with codecs.open(filename, 'r', 'utf-8') as f:
            return loader(f)

    @property
    def configured(self):
        """
        Return if `init_app` is configured
        """
        return self._configured

    def get_url_mappings(self, rule_filter=None):
        """
        Returns all werkzeug rules
        """
        rule_filter = rule_filter or (lambda rule: True)
        app_rules = [
            rule for rule in current_app.url_map.iter_rules()
            if rule_filter(rule)
        ]
        return app_rules

    def get_def_models(self, definition_filter=None):
        """
        Used for class based definitions
        """
        model_filter = definition_filter or (lambda tag: True)
        return {
            definition.name: definition.obj
            for definition in self.definition_models
            if model_filter(definition)
        }

    def get_apispecs(self, endpoint='apispec_1'):
        if not self.app.debug and endpoint in self.apispecs:
            return self.apispecs[endpoint]

        spec = None
        for _spec in self.config['specs']:
            if _spec['endpoint'] == endpoint:
                spec = _spec
                break
        if not spec:
            raise RuntimeError(
                'Can`t find specs by endpoint {},'
                ' check your flasger`s config'.format(endpoint))

        data = {
            # try to get from config['SWAGGER']['info']
            # then config['SWAGGER']['specs'][x]
            # then config['SWAGGER']
            # then default
            "info": self.config.get('info') or {
                "version": spec.get(
                    'version', self.config.get('version', "0.0.1")
                ),
                "title": spec.get(
                    'title', self.config.get('title', "A swagger API")
                ),
                "description": spec.get(
                    'description', self.config.get('description',
                                                   "powered by Flasgger")
                ),
                "termsOfService": spec.get(
                    'termsOfService', self.config.get('termsOfService',
                                                      "/tos")
                ),
            },
            "paths": self.config.get('paths') or defaultdict(dict),
            "definitions": self.config.get('definitions') or defaultdict(dict)
        }

        openapi_version = self.config.get('openapi')

        # If it's openapi3, #/components/schemas replaces #/definitions
        if is_openapi3(openapi_version):
            data.setdefault('components', {})['schemas'] = data['definitions']

        if openapi_version:
            data["openapi"] = openapi_version
        else:
            data["swagger"] = self.config.get('swagger') or self.config.get(
                'swagger_version', "2.0"
            )

        # Support extension properties in the top level config
        top_level_extension_options = get_vendor_extension_fields(self.config)
        if top_level_extension_options:
            data.update(top_level_extension_options)

        # if True schemaa ids will be prefized by function_method_{id}
        # for backwards compatibility with <= 0.5.14
        prefix_ids = self.config.get('prefix_ids')

        if self.config.get('host'):
            data['host'] = self.config.get('host')
        if self.config.get("basePath"):
            data["basePath"] = self.config.get('basePath')
        if self.config.get('schemes'):
            data['schemes'] = self.config.get('schemes')
        if self.config.get("securityDefinitions"):
            data["securityDefinitions"] = self.config.get(
                'securityDefinitions'
            )

        if is_openapi3(openapi_version):
            # enable oas3 fields when openapi_version is 3.*.*
            optional_oas3_fields = self.config.get(
                'optional_oas3_fields') or OPTIONAL_OAS3_FIELDS
            for key in optional_oas3_fields:
                if self.config.get(key):
                    data[key] = self.config.get(key)

        # set defaults from template
        if self.template is not None:
            data.update(self.template)

        paths = data['paths']
        definitions = extract_schema(data)
        ignore_verbs = set(
            self.config.get('ignore_verbs', ("HEAD", "OPTIONS"))
        )

        # technically only responses is non-optional
        optional_fields = self.config.get('optional_fields') or OPTIONAL_FIELDS

        for name, def_model in self.get_def_models(
                spec.get('definition_filter')).items():
            description, swag = parse_definition_docstring(
                def_model, self.sanitizer)
            if name and swag:
                if description:
                    swag.update({'description': description})
                definitions[name].update(swag)

        specs = get_specs(
            self.get_url_mappings(spec.get('rule_filter')), ignore_verbs,
            optional_fields, self.sanitizer,
            openapi_version=openapi_version,
            doc_dir=self.config.get('doc_dir'))

        http_methods = ['get', 'post', 'put', 'delete']
        for rule, verbs in specs:
            operations = dict()
            for verb, swag in verbs:

                if is_openapi3(openapi_version):
                    update_dict = swag.get('components', {}).get('schemas', {})
                else:  # openapi2
                    update_dict = swag.get('definitions', {})

                if type(update_dict) == list and type(update_dict[0]) == dict:
                    # pop, assert single element
                    update_dict, = update_dict
                definitions.update(update_dict)
                defs = []  # swag.get('definitions', [])
                defs += extract_definitions(
                    defs, endpoint=rule.endpoint, verb=verb,
                    prefix_ids=prefix_ids,
                    openapi_version=openapi_version
                )

                params = swag.get('parameters', [])
                if verb in swag.keys():
                    verb_swag = swag.get(verb)
                    if len(params) == 0 and verb.lower() in http_methods:
                        params = verb_swag.get('parameters', [])

                defs += extract_definitions(params,
                                            endpoint=rule.endpoint,
                                            verb=verb,
                                            prefix_ids=prefix_ids,
                                            openapi_version=openapi_version)

                request_body = swag.get('requestBody')
                if request_body:
                    content = request_body.get("content", {})
                    extract_definitions(
                        list(content.values()),
                        endpoint=rule.endpoint,
                        verb=verb,
                        prefix_ids=prefix_ids,
                        openapi_version=openapi_version
                    )

                callbacks = swag.get("callbacks", {})
                if callbacks:
                    callbacks = {
                        str(key): value
                        for key, value in callbacks.items()
                    }
                    extract_definitions(
                        list(callbacks.values()),
                        endpoint=rule.endpoint,
                        verb=verb,
                        prefix_ids=prefix_ids,
                        openapi_version=openapi_version
                    )

                responses = None
                if 'responses' in swag:
                    responses = swag.get('responses', {})
                    responses = {
                        str(key): value
                        for key, value in responses.items()
                    }
                    if responses is not None:
                        defs = defs + extract_definitions(
                            responses.values(),
                            endpoint=rule.endpoint,
                            verb=verb,
                            prefix_ids=prefix_ids,
                            openapi_version=openapi_version
                        )
                    for definition in defs:
                        if 'id' not in definition:
                            definitions.update(definition)
                            continue
                        def_id = definition.pop('id')
                        if def_id is not None:
                            definitions[def_id].update(definition)

                operation = {}
                if swag.get('summary'):
                    operation['summary'] = swag.get('summary')
                if swag.get('description'):
                    operation['description'] = swag.get('description')
                if request_body:
                    operation['requestBody'] = request_body
                if callbacks:
                    operation['callbacks'] = callbacks
                if responses:
                    operation['responses'] = responses
                # parameters - swagger ui dislikes empty parameter lists
                if len(params) > 0:
                    operation['parameters'] = params
                # other optionals
                for key in optional_fields:
                    if key in swag:
                        value = swag.get(key)
                        if key in ('produces', 'consumes'):
                            if not isinstance(value, (list, tuple)):
                                value = [value]

                        operation[key] = value
                operations[verb] = operation

            if len(operations):
                try:
                    # Add reverse proxy prefix to route
                    prefix = self.template['swaggerUiPrefix']
                except (KeyError, TypeError):
                    prefix = ''
                srule = '{0}{1}'.format(prefix, rule)

                try:
                    # handle basePath
                    base_path = self.template['basePath']

                    if base_path:
                        if base_path.endswith('/'):
                            base_path = base_path[:-1]
                        if base_path:
                            # suppress base_path from srule if needed.
                            # Otherwise we will get definitions twice...
                            if srule.startswith(base_path):
                                srule = srule[len(base_path):]
                except (KeyError, TypeError):
                    pass

                # old regex '(<(.*?\:)?(.*?)>)'
                for arg in re.findall('(<([^<>]*:)?([^<>]*)>)', srule):
                    srule = srule.replace(arg[0], '{%s}' % arg[2])

                for key, val in operations.items():
                    if srule not in paths:
                        paths[srule] = {}
                    if key in paths[srule]:
                        paths[srule][key].update(val)
                    else:
                        paths[srule][key] = val
        self.apispecs[endpoint] = data

        if is_openapi3(openapi_version):
            del data['definitions']

        return data

    def definition(self, name, tags=None):
        """
        Decorator to add class based definitions
        """
        def wrapper(obj):
            self.definition_models.append(SwaggerDefinition(name, obj,
                                                            tags=tags))
            return obj
        return wrapper

    def load_config(self, app):
        """
        Copy config from app
        """
        self.config.update(app.config.get('SWAGGER', {}))

    def register_views(self, app):
        """
        Register Flasgger views
        """

        # Wrap the views in an arbitrary number of decorators.
        def wrap_view(view):
            if self.decorators:
                for decorator in self.decorators:
                    view = decorator(view)
            return view

        if self.config.get('swagger_ui', True):
            uiversion = self.config.get('uiversion', 3)
            blueprint = Blueprint(
                self.config.get('endpoint', 'flasgger'),
                __name__,
                url_prefix=self.config.get('url_prefix', None),
                subdomain=self.config.get('subdomain', None),
                template_folder=self.config.get(
                    'template_folder', 'ui{0}/templates'.format(uiversion)
                ),
                static_folder=self.config.get(
                    'static_folder', 'ui{0}/static'.format(uiversion)
                ),
                static_url_path=self.config.get('static_url_path', None)
            )

            specs_route = self.config.get('specs_route', '/apidocs/')
            blueprint.add_url_rule(
                specs_route,
                'apidocs',
                view_func=wrap_view(APIDocsView().as_view(
                    'apidocs',
                    view_args=dict(config=self.config)
                ))
            )

            if uiversion < 3:
                redirect_default = specs_route + '/o2c.html'
            else:
                redirect_default = "/oauth2-redirect.html"

            blueprint.add_url_rule(
                self.config.get('oauth_redirect', redirect_default),
                'oauth_redirect',
                view_func=wrap_view(OAuthRedirect().as_view(
                    'oauth_redirect'
                ))
            )

            # backwards compatibility with old url style
            blueprint.add_url_rule(
                '/apidocs/index.html',
                view_func=lambda: redirect(url_for('flasgger.apidocs'))
            )
        else:
            blueprint = Blueprint(
                self.config.get('endpoint', 'flasgger'),
                __name__
            )

        for spec in self.config['specs']:
            self.endpoints.append(spec['endpoint'])
            blueprint.add_url_rule(
                spec['route'],
                spec['endpoint'],
                view_func=wrap_view(APISpecsView.as_view(
                    spec['endpoint'],
                    loader=partial(
                        self.get_apispecs, endpoint=spec['endpoint'])
                ))
            )
        app.register_blueprint(blueprint)

    def add_headers(self, app):
        """
        Inject headers after request
        """
        @app.after_request
        def after_request(response):  # noqa
            for header, value in self.config.get('headers'):
                response.headers[header] = value
            return response

    def parse_request(self, app):
        @app.before_request
        def before_request():  # noqa
            """
            Parse and validate request data(query, form, header and body),
            set data to `request.parsed_data`
            """
            # convert "/api/items/<int:id>/" to "/api/items/{id}/"
            subs = []
            for sub in str(request.url_rule).split('/'):
                if '<' in sub:
                    if ':' in sub:
                        start = sub.index(':') + 1
                    else:
                        start = 1
                    subs.append('{{{:s}}}'.format(sub[start:-1]))
                else:
                    subs.append(sub)
            path = '/'.join(subs)
            path_key = path + request.method.lower()

            if not self.app.debug and path_key in self.parsers:
                parsers = self.parsers[path_key]
                schemas = self.schemas[path_key]
            else:
                doc = None
                definitions = None
                for spec in self.config['specs']:
                    apispec = self.get_apispecs(endpoint=spec['endpoint'])
                    if path in apispec['paths']:
                        if request.method.lower() in apispec['paths'][path]:
                            doc = apispec['paths'][path][
                                request.method.lower()]
                            definitions = extract_schema(apispec)
                            break
                if not doc:
                    return

                parsers = defaultdict(RequestParser)
                schemas = defaultdict(
                    lambda: {'type': 'object', 'properties': defaultdict(dict)}
                )
                self.update_schemas_parsers(doc, schemas, parsers, definitions)
                self.schemas[path_key] = schemas
                self.parsers[path_key] = parsers

            parsed_data = {'path': request.view_args}
            for location in parsers.keys():
                parsed_data[location] = parsers[location].parse_args()
            if 'json' in schemas:
                parsed_data['json'] = request.json or {}
            for location, data in parsed_data.items():
                try:
                    ret = self.validation_function(data, schemas[location])
                    print(ret)
                except jsonschema.ValidationError as e:
                    self.validation_error_handler(e, data, schemas[location])

            setattr(request, 'parsed_data', parsed_data)

    def update_schemas_parsers(self, doc, schemas, parsers, definitions):
        '''
        Schemas and parsers would be updated here from doc
        '''
        if self.is_openapi3():
            # 'json' to comply with self.SCHEMA_LOCATIONS's {'body':'json'}
            location = 'json'
            json_schema = None

            # For openapi3, currently only support single schema
            for name, value in doc.get('requestBody', {}).get('content', {})\
                    .items():
                if 'application/json' in name:
                    # `$ref` to json, lookup in #/components/schema
                    json_schema = value.get('schema', {})
                else:  # schema set in requesty body
                    # Since osa3 might changed, repeat openapi2's code
                    parsers[location].add_argument(
                        name,
                        type=self.SCHEMA_TYPES[
                            value['schema'].get('type', None)
                            if 'schema' in value
                            else value.get('type', None)],
                        required=value.get('required', False),

                        # Parsed in body
                        location=self.SCHEMA_LOCATIONS['body'],
                        store_missing=False
                    )

            # TODO support anyOf and oneOf in the future
            if (json_schema is not None) and type(json_schema) == dict:

                schemas[location] = json_schema
                self.set_schemas(schemas, location, definitions)

        else:  # openapi2
            for param in doc.get('parameters', []):
                location = self.SCHEMA_LOCATIONS[param['in']]
                if location == 'json':  # load data from 'request.json'
                    schemas[location] = param['schema']
                    self.set_schemas(schemas, location, definitions)
                else:
                    name = param['name']
                    if location != 'path':
                        parsers[location].add_argument(
                            name,
                            type=self.SCHEMA_TYPES[
                                param['schema'].get('type', None)
                                if 'schema' in param
                                else param.get('type', None)],
                            required=param.get('required', False),
                            location=self.SCHEMA_LOCATIONS[
                                param['in']],
                            store_missing=False)

                    for k in param:
                        if k != 'required':
                            schemas[
                                location]['properties'][name][k] = param[k]

    def set_schemas(self, schemas: dict, location: str,
                    definitions: dict):
        if is_openapi3(self.config.get('openapi')):
            schemas[location]['components'] = {'schemas': dict(definitions)}
        else:
            schemas[location]['definitions'] = dict(definitions)

    def validate(
            self, schema_id, validation_function=None,
            validation_error_handler=None):
        """
        A decorator that is used to validate incoming requests data
        against a schema

            swagger = Swagger(app)

            @app.route('/pets', methods=['POST'])
            @swagger.validate('Pet')
            @swag_from("pet_post_endpoint.yml")
            def post():
                return db.insert(request.data)

        This annotation only works if the endpoint is already swagged,
        i.e. placing @swag_from above @validate or not declaring the
        swagger specifications in the method's docstring *won't work*

        Naturally, if you use @app.route annotation it still needs to
        be the outermost annotation

        :param schema_id: the id of the schema with which the data will
            be validated

        :param validation_function: custom validation function which
            takes the positional arguments: data to be validated at
            first and schema to validate against at second

        :param validation_error_handler: custom function to handle
            exceptions thrown when validating which takes the exception
            thrown as the first, the data being validated as the second
            and the schema being used to validate as the third argument
        """

        if validation_function is None:
            validation_function = self.validation_function

        if validation_error_handler is None:
            validation_error_handler = self.validation_error_handler

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                specs = get_schema_specs(schema_id, self)
                validate(
                    schema_id=schema_id, specs=specs,
                    validation_function=validation_function,
                    validation_error_handler=validation_error_handler,
                    openapi_version=self.config.get('openapi')
                )
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def get_schema(self, schema_id):
        """
        This method finds a schema known to Flasgger and returns it.

        :raise KeyError: when the specified :param schema_id: is not
        found by Flasgger

        :param schema_id: the id of the desired schema
        """
        schema_specs = get_schema_specs(schema_id, self)

        if schema_specs is None:
            raise KeyError(
                'Specified schema_id \'{0}\' not found'.format(schema_id))

        for schema in (
                parameter.get('schema') for parameter in
                schema_specs['parameters']):
            if schema is not None and schema.get('id').lower() == schema_id:
                return schema

    def is_openapi3(self):
        return is_openapi3(self.config.get('openapi'))


# backwards compatibility
Flasgger = Swagger  # noqa


class LazyJSONEncoder(DefaultJSONProvider):
    def default(self, obj):
        if isinstance(obj, LazyString):
            return str(obj)
        return super(LazyJSONEncoder, self).default(obj)
