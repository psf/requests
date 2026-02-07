# coding: utf-8

import codecs
import copy
import importlib
import inspect
import os
import re
import sys
import jsonschema
import yaml
from six import string_types, text_type
from copy import deepcopy
from functools import wraps
from importlib import import_module
from collections import OrderedDict, defaultdict
from flask import Response
from flask import abort
from flask import current_app
from flask import request
from flask.views import MethodView

try:
    from flask_mongorest import methods as fmr_methods
except ImportError:
    fmr_methods = None

from .constants import OPTIONAL_FIELDS, DEFAULT_FIELDS
from .marshmallow_apispec import SwaggerView
from .marshmallow_apispec import convert_schemas
from .marshmallow_apispec import Schema


def merge_specs(target, source):
    """
    Update target dictionary with values from the source, recursively.
    List items will be merged.
    """

    for key, value in source.items():
        if isinstance(value, dict):
            node = target.setdefault(key, {})
            merge_specs(node, value)
        elif isinstance(value, list):
            node = target.setdefault(key, [])
            node.extend(value)
        else:
            target[key] = value


def get_schema_specs(schema_id, swagger):
    ignore_verbs = set(
        swagger.config.get('ignore_verbs', ("HEAD", "OPTIONS")))

    # technically only responses is non-optional
    optional_fields \
        = swagger.config.get('optional_fields') or OPTIONAL_FIELDS

    openapi_version = swagger.config.get('openapi')

    with swagger.app.app_context():
        specs = get_specs(
            current_app.url_map.iter_rules(), ignore_verbs,
            optional_fields, swagger.sanitizer, openapi_version)

        swags = (swag for _, verbs in specs for _, swag in verbs
                 if swag is not None)

    for swag in swags:
        for d in swag.get('parameters', []):
            d_schema_id = d.get('schema', {}).get('id')
            if d_schema_id is not None \
                    and d_schema_id.lower() == schema_id.lower():
                return swag


def get_specs(rules, ignore_verbs, optional_fields, sanitizer,
              openapi_version, doc_dir=None):

    specs = []
    for rule in rules:
        endpoint = current_app.view_functions[rule.endpoint]
        methods = dict()
        is_mv = is_valid_method_view(endpoint)

        for verb in rule.methods.difference(ignore_verbs):
            if not is_mv and has_valid_dispatch_view_docs(endpoint):
                endpoint.methods = endpoint.methods or ['GET']
                if verb in endpoint.methods:
                    methods[verb.lower()] = endpoint
            elif getattr(endpoint, 'methods', None) is not None:
                if isinstance(endpoint.methods, set):
                    if verb in endpoint.methods:
                        verb = verb.lower()
                        methods[verb] = getattr(endpoint.view_class, verb)
                elif fmr_methods is not None:  # flask-mongorest
                    endpoint_methods = set(m.method for m in endpoint.methods)
                    if verb in endpoint_methods:
                        proxy_verb = rule.endpoint.replace(
                            endpoint.__name__, ''
                        )
                        if proxy_verb:
                            methods[verb.lower()] = getattr(
                                fmr_methods, proxy_verb
                            )
                else:
                    raise TypeError
            else:
                methods[verb.lower()] = endpoint

        verbs = []
        for verb, method in methods.items():

            klass = method.__dict__.get('view_class', None)
            if not is_mv and klass and hasattr(klass, 'verb'):
                method = getattr(klass, 'verb', None)
            elif klass and hasattr(klass, 'dispatch_request'):
                method = getattr(klass, 'dispatch_request', None)
            if method is None:  # for MethodView
                method = getattr(klass, verb, None)

            if method is None:
                if is_mv:  # #76 Empty MethodViews
                    continue
                raise RuntimeError(
                    'Cannot detect view_func for rule {0}'.format(rule)
                )

            swag = {}
            swag_def = {}

            swagged = False

            if getattr(method, 'specs_dict', None):
                definition = {}
                merge_specs(
                    swag,
                    convert_schemas(deepcopy(method.specs_dict), definition)
                )
                swag_def = definition
                swagged = True

            view_class = getattr(endpoint, 'view_class', None)
            if view_class and issubclass(view_class, SwaggerView):
                apispec_swag = {}

                # Don't need to alter definitions here
                # Since it only stays in apispec_attrs
                apispec_attrs = optional_fields + [
                    'parameters', 'definitions', 'responses',
                    'summary', 'description'
                ]
                for attr in apispec_attrs:
                    value = getattr(view_class, attr)
                    if value:
                        apispec_swag[attr] = value
                # Don't need to change 'definitions' here
                # Since it would be appended later according to openapi
                apispec_definitions = apispec_swag.get('definitions', {})
                swag.update(
                    convert_schemas(apispec_swag, apispec_definitions)
                )
                swag_def = apispec_definitions

                swagged = True

            if doc_dir:
                if view_class:
                    file_path = os.path.join(
                        doc_dir, endpoint.__name__, method.__name__ + '.yml')
                else:
                    file_path = os.path.join(
                        doc_dir, endpoint.__name__ + '.yml')
                if os.path.isfile(file_path):
                    func = method.__func__ \
                        if hasattr(method, '__func__') else method
                    setattr(func, 'swag_type', 'yml')
                    setattr(func, 'swag_path', file_path)

            doc_summary, doc_description, doc_swag = parse_docstring(
                method, sanitizer, endpoint=rule.endpoint, verb=verb)

            if is_openapi3(openapi_version):
                swag.setdefault('components', {})['schemas'] = swag_def
            else:  # openapi2
                swag['definitions'] = swag_def

            if doc_swag:
                merge_specs(swag, doc_swag)
                swagged = True

            if swagged:
                if doc_summary:
                    swag['summary'] = doc_summary

                if doc_description:
                    swag['description'] = doc_description

                verbs.append((verb, swag))

        if verbs:
            specs.append((rule, verbs))

    return specs


def swag_from(
        specs=None, filetype=None, endpoint=None, methods=None,
        validation=False, schema_id=None, data=None, definition=None,
        validation_function=None, validation_error_handler=None):
    """
    Takes a filename.yml, a dictionary or object and loads swagger specs.

    :param specs: a filepath, a dictionary or an object
    :param filetype: yml or yaml (json and py to be implemented)
    :param endpoint: endpoint to build definition name
    :param methods: method to build method based specs
    :param validation: perform validation?
    :param schema_id: Definition id ot name to use for validation
    :param data: data to validate (default is request.json)
    :param definition: alias to schema_id
    :param validation_function:
        custom validation function which takes the positional
        arguments: data to be validated at first and schema to validate
        against at second
    :param validation_error_handler: custom function to handle
        exceptions thrown when validating which takes the exception
        thrown as the first, the data being validated as the second and
        the schema being used to validate as the third argument
    """

    def resolve_path(function, filepath):
        try:
            from pathlib import Path
            if isinstance(filepath, Path):
                filepath = str(filepath)
        except ImportError:
            pass
        if not filepath.startswith('/'):
            if not hasattr(function, 'root_path'):
                function.root_path = get_root_path(function)
            res = os.path.join(function.root_path, filepath)
            return res
        return filepath

    def set_from_filepath(function):
        final_filepath = resolve_path(function, specs)
        function.swag_type = filetype or final_filepath.split('.')[-1]

        if endpoint or methods:
            if not hasattr(function, 'swag_paths'):
                function.swag_paths = {}

        if not endpoint and not methods:
            function.swag_path = final_filepath
        elif endpoint and methods:
            for verb in methods:
                key = "{}_{}".format(endpoint, verb.lower())
                function.swag_paths[key] = final_filepath
        elif endpoint and not methods:
            function.swag_paths[endpoint] = final_filepath
        elif methods and not endpoint:
            for verb in methods:
                function.swag_paths[verb.lower()] = final_filepath

    def set_from_specs_dict(function):
        function.specs_dict = specs

    def is_path(specs):
        """ Returns True if specs is a string or pathlib.Path
        """
        is_str_path = isinstance(specs, string_types)
        try:
            from pathlib import Path
            is_py3_path = isinstance(specs, Path)
            return is_str_path or is_py3_path
        except ImportError:
            return is_str_path

    def decorator(function):

        if is_path(specs):
            set_from_filepath(function)
            # function must have or a single swag_path or a list of them
            swag_path = getattr(function, 'swag_path', None)
            swag_paths = getattr(function, 'swag_paths', None)
            validate_args = {
                'filepath': swag_path or swag_paths,
                'root': getattr(function, 'root_path', None)
            }
        if isinstance(specs, dict):
            set_from_specs_dict(function)
            validate_args = {'specs': specs}

        @wraps(function)
        def wrapper(*args, **kwargs):
            if validation is True:
                validate(
                    data,
                    schema_id or definition,
                    validation_function=validation_function,
                    validation_error_handler=validation_error_handler,
                    **validate_args
                )
            return function(*args, **kwargs)
        return wrapper

    return decorator


def __replace_ref(schema, relative_path, swag):
    """ TODO: add dev docs

    :param schema:
    :param relative_path:
    :param swag:
    :return:
    """
    absolute_path = os.path.dirname(sys.argv[0])
    new_value = {}
    for key, value in schema.items():
        if isinstance(value, dict):
            new_value[key] = __replace_ref(value, relative_path, swag)
        elif key == '$ref':
            # see:
            # https://swagger.io/docs/specification/describing-request-body/
            if len(value) > 2 and value.startswith('#/'):  # $ref is local
                content = swag
                for id in value.split('/')[1:]:
                    content = content[id]
                return __replace_ref(content, relative_path, swag) \
                    if isinstance(content, dict) else content

            if len(value) > 0 and value[0] == '/':
                file_ref_path = absolute_path + value
            else:
                file_ref_path = relative_path + '/' + value
            relative_path = os.path.dirname(file_ref_path)
            with open(file_ref_path) as file:
                file_content = file.read()
                comment_index = file_content.rfind('---')
                if comment_index > 0:
                    comment_index = comment_index + 3
                else:
                    comment_index = 0
                content = yaml.safe_load((file_content[comment_index:]))
                new_value = content
                if isinstance(content, dict):
                    new_value = __replace_ref(content, relative_path, swag)
        else:
            new_value[key] = value
    return new_value


def validate(
        data=None, schema_id=None, filepath=None, root=None, definition=None,
        specs=None, validation_function=None, validation_error_handler=None,
        require_data=True, openapi_version=None):
    """
    This method is available to use YAML swagger definitions file
    or specs (dict or object) to validate data against its jsonschema.

    example:
        validate({"item": 1}, 'item_schema', 'defs.yml', root=__file__)
        validate(request.json, 'User', specs={'definitions': {'User': ...}})

    :param data: data to validate, by default is request.json
    :param schema_id: The definition id to use to validate (from specs)
    :param filepath: definition filepath to load specs
    :param root: root folder (inferred if not provided), unused if path
        starts with `/`
    :param definition: Alias to schema_id (kept for backwards
        compatibility)
    :param specs: load definitions from dict or object passed here
        instead of a file.
    :param validation_function: custom validation function which takes
        the positional arguments: data to be validated at first and
        schema to validate against at second
    :param validation_error_handler: custom function to handle
        exceptions thrown when validating which takes the exception
        thrown as the first, the data being validated as the second and
        the schema being used to validate as the third argument
    :param require_data: is the data param required?
    """
    schema_id = schema_id or definition

    # for backwards compatibility with function signature
    if filepath is None and specs is None:
        abort(Response('Filepath or specs is needed to validate', status=500))

    if data is None:
        data = request.json  # defaults
    elif callable(data):
        # data=lambda: request.json
        data = data()

    if not data and require_data:
        abort(Response('No data to validate', status=400))

    # not used anymore but kept to reuse with marshmallow
    endpoint = request.endpoint.lower().replace('.', '_')
    verb = request.method.lower()

    if filepath is not None:
        if not root:
            try:
                frame_info = inspect.stack()[1]
                root = os.path.dirname(os.path.abspath(frame_info[1]))
            except Exception:
                root = None
        else:
            root = os.path.dirname(root)

        if not filepath.startswith('/'):
            final_filepath = os.path.join(root, filepath)
        else:
            final_filepath = filepath
        full_doc = load_from_file(final_filepath)
        yaml_start = full_doc.find('---')
        swag = yaml.safe_load(full_doc[yaml_start if yaml_start >= 0 else 0:])
    else:
        swag = copy.deepcopy(specs)

    params = [
        item for item in swag.get('parameters', [])
        if item.get('schema')
    ]

    definitions = {}
    main_def = {}
    raw_definitions = extract_definitions(params, endpoint=endpoint, verb=verb,
                                          openapi_version=openapi_version)

    if schema_id is None:
        for param in params:
            if param.get('in') == 'body':
                schema_id = param.get('schema', {}).get('$ref')
                if schema_id:
                    schema_id = schema_id.split('/')[-1]
                    break  # consider only the first

    if schema_id is None:
        # if it is still none use first raw_definition extracted
        if raw_definitions:
            schema_id = raw_definitions[0].get('id')

    for defi in raw_definitions:
        if defi['id'].lower() == schema_id.lower():
            main_def = defi.copy()
        else:
            definitions[defi['id']] = defi

    # support definitions informed in dict
    if schema_id in extract_schema(swag):
        main_def = extract_schema(swag).get(schema_id)

    # Doensn't need to alter 'definitions' according to open api
    # Since it main_def exists only in this function
    main_def['definitions'] = definitions

    for key, value in definitions.items():
        if 'id' in value:
            del value['id']

    if validation_function is None:
        validation_function = jsonschema.validate

    absolute_path = os.path.dirname(sys.argv[0])
    if filepath is None:
        relative_path = absolute_path
    else:
        relative_path = os.path.dirname(filepath)
    main_def = __replace_ref(main_def, relative_path, swag)

    try:
        validation_function(data, main_def)
    except Exception as err:
        if validation_error_handler is not None:
            validation_error_handler(err, data, main_def)
        else:
            abort(Response(str(err), status=400))


def apispec_to_template(app, spec, definitions=None, paths=None):
    """
    Converts apispec object in to flasgger definitions template
    :param app: Current app
    :param spec: apispec.APISpec
    :param definitions: a list of [Schema, ..] or [('Name', Schema), ..]
    :param paths: A list of flask views
    """
    definitions = definitions or []
    paths = paths or []

    with app.app_context():
        for definition in definitions:
            if isinstance(definition, (tuple, list)):
                name, schema = definition
            else:
                schema = definition
                name = schema.__name__.replace('Schema', '')

            spec.components.schema(name, schema=schema)

        for path in paths:
            spec.path(view=path)

    spec_dict = spec.to_dict()
    ret = ordered_dict_to_dict(spec_dict)
    return ret


def ordered_dict_to_dict(d):
    """
    Converts inner OrderedDict to bare dict
    """
    ret = {}
    new_d = deepcopy(d)
    for k, v in new_d.items():
        if isinstance(v, OrderedDict):
            v = dict(v)
        if isinstance(v, dict):
            v = ordered_dict_to_dict(v)
        ret[k] = v
    return ret


def remove_suffix(fpath):  # pragma: no cover
    """Remove all file ending suffixes"""
    return os.path.splitext(fpath)[0]


def is_python_file(fpath):  # pragma: no cover
    """Naive Python module filterer"""
    return fpath.endswith(".py") and "__" not in fpath


def pathify(basenames, examples_dir="examples/"):  # pragma: no cover
    """*nix to python module path"""
    example = examples_dir.replace("/", ".")
    return [example + basename for basename in basenames]


def get_examples(examples_dir="examples/"):  # pragma: no cover
    """All example modules"""
    all_files = os.listdir(examples_dir)
    python_files = [f for f in all_files if is_python_file(f)]
    basenames = [remove_suffix(f) for f in python_files]
    modules = [import_module(module) for module in pathify(basenames)]
    return [
        module for module in modules
        if getattr(module, 'app', None) is not None
    ]


def get_path_from_doc(full_doc):
    """
    If `file:` is provided import the file.
    """
    swag_path = full_doc.replace('file:', '').strip()
    swag_type = swag_path.split('.')[-1]
    return swag_path, swag_type


def json_to_yaml(content):
    """
    TODO: convert json to yaml
    """
    return content


def load_from_file(swag_path, swag_type='yml', root_path=None):
    """
    Load specs from YAML file
    """
    if swag_type not in ('yaml', 'yml'):
        raise AttributeError("Currently only yaml or yml supported")
        # TODO: support JSON

    try:
        enc = detect_by_bom(swag_path)
        with codecs.open(swag_path, encoding=enc) as yaml_file:
            return yaml_file.read()
    except IOError:
        # not in the same dir, add dirname
        swag_path = os.path.join(
            root_path or os.path.dirname(__file__), swag_path
        )
        try:
            enc = detect_by_bom(swag_path)
            with codecs.open(swag_path, encoding=enc) as yaml_file:
                return yaml_file.read()
        except IOError:  # pragma: no cover
            # if package dir
            # see https://github.com/rochacbruno/flasgger/pull/104
            # Still not able to reproduce this case
            # test are in examples/package_example
            # need more detail on how to reproduce IOError here
            swag_path = swag_path.replace("/", os.sep).replace("\\", os.sep)
            path = swag_path.replace(
                (root_path or os.path.dirname(__file__)), ''
            ).split(os.sep)[1:]
            package_spec = importlib.util.find_spec(path[0])
            if package_spec.has_location:
                # Improvement idea: Use package_spec.submodule_search_locations
                # if we're sure there's only going to be one search location.
                site_package = package_spec.origin.replace('/__init__.py', '')
            else:
                raise RuntimeError("Package does not have origin")
            swag_path = os.path.join(site_package, os.sep.join(path[1:]))
            with open(swag_path) as yaml_file:
                return yaml_file.read()


def detect_by_bom(path, default='utf-8'):
    with open(path, 'rb') as f:
        raw = f.read(4)  # will read less if the file is smaller
    for enc, boms in \
            ('utf-8-sig', (codecs.BOM_UTF8,)),\
            ('utf-16', (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)),\
            ('utf-32', (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        if any(raw.startswith(bom) for bom in boms):
            return enc
    return default


def parse_docstring(obj, process_doc, endpoint=None, verb=None):
    """
    Gets swag data for method/view docstring
    """
    first_line, other_lines, swag = None, None, None

    full_doc = None
    swag_path = getattr(obj, 'swag_path', None)
    swag_type = getattr(obj, 'swag_type', 'yml')
    swag_paths = getattr(obj, 'swag_paths', None)
    root_path = get_root_path(obj)
    from_file = False

    if swag_path is not None:
        full_doc = load_from_file(swag_path, swag_type)
        from_file = True
    elif swag_paths is not None:
        for key in ("{}_{}".format(endpoint, verb), endpoint, verb.lower()):
            if key in swag_paths:
                full_doc = load_from_file(swag_paths[key], swag_type)
                break
        from_file = True
        # TODO: handle multiple root_paths
        # to support `import: ` from multiple places
    else:
        full_doc = inspect.getdoc(obj)

    if full_doc:

        if full_doc.startswith('file:'):
            if not hasattr(obj, 'root_path'):
                obj.root_path = root_path
            swag_path, swag_type = get_path_from_doc(full_doc)
            doc_filepath = os.path.join(obj.root_path, swag_path)
            full_doc = load_from_file(doc_filepath, swag_type)
            from_file = True

        full_doc = parse_imports(full_doc, root_path)

        yaml_sep = full_doc.find('---')

        if yaml_sep != -1:
            line_feed = full_doc.find('\n')
            if line_feed != -1:
                first_line = process_doc(full_doc[:line_feed])
                other_lines = process_doc(
                    full_doc[line_feed + 1: yaml_sep]
                )
                swag = yaml.safe_load(full_doc[yaml_sep + 4:])
        else:
            if from_file:
                swag = yaml.safe_load(full_doc)
            else:
                first_line = full_doc

    return first_line, other_lines, swag


def get_root_path(obj):
    """
    Get file path for object and returns its dirname
    """
    try:
        filename = os.path.abspath(obj.__globals__['__file__'])
    except (KeyError, AttributeError):
        if getattr(obj, '__wrapped__', None):
            # decorator package has been used in view
            return get_root_path(obj.__wrapped__)
        filename = inspect.getfile(obj)
    return os.path.dirname(filename)


def parse_definition_docstring(obj, process_doc):
    """
    Gets swag data from docstring for class based definitions
    """
    doc_lines, swag = None, None

    full_doc = None
    swag_path = getattr(obj, 'swag_path', None)
    swag_type = getattr(obj, 'swag_type', 'yml')

    if swag_path is not None:
        full_doc = load_from_file(swag_path, swag_type)
    else:
        full_doc = inspect.getdoc(obj)

    if full_doc:

        if full_doc.startswith('file:'):
            if not hasattr(obj, 'root_path'):
                obj.root_path = get_root_path(obj)
            swag_path, swag_type = get_path_from_doc(full_doc)
            doc_filepath = os.path.join(obj.root_path, swag_path)
            full_doc = load_from_file(doc_filepath, swag_type)

        yaml_sep = full_doc.find('---')
        if yaml_sep != -1:
            doc_lines = process_doc(
                full_doc[:yaml_sep - 1]
            ) if yaml_sep else None
            swag = yaml.safe_load(full_doc[yaml_sep:])
        else:
            doc_lines = process_doc(full_doc)

    return doc_lines, swag


def parse_imports(full_doc, root_path=None):
    """
    Supports `import: otherfile.yml` in docstring specs
    """
    regex = re.compile('import: "(.*)"')
    import_prop = regex.search(full_doc)
    if import_prop:
        start = import_prop.start()
        spaces_num = start - full_doc.rfind('\n', 0, start) - 1
        filepath = import_prop.group(1)
        if filepath.startswith('/'):
            imported_doc = load_from_file(filepath)
        else:
            imported_doc = load_from_file(filepath, root_path=root_path)
        indented_imported_doc = imported_doc.replace(
            '\n', '\n' + ' ' * spaces_num
        )
        full_doc = regex.sub(indented_imported_doc, full_doc, count=1)
        return parse_imports(full_doc)
    return full_doc


def extract_definitions(alist, level=None, endpoint=None, verb=None,
                        prefix_ids=False, openapi_version=None):
    """
    Since we couldn't be bothered to register models elsewhere
    our definitions need to be extracted from the parameters.
    We require an 'id' field for the schema to be correctly
    added to the definitions list.
    """
    endpoint = endpoint or request.endpoint.lower()
    verb = verb or request.method.lower()
    endpoint = endpoint.replace('.', '_')

    def _extract_array_defs(source):
        """
        Extracts definitions identified by `id`
        """
        # extract any definitions that are within arrays
        # this occurs recursively
        ret = []
        items = source.get('items')
        if items is not None and 'schema' in items:
            ret += extract_definitions(
                [items], level + 1, endpoint, verb, prefix_ids,
                openapi_version)
        return ret

    # for tracking level of recursion
    if level is None:
        level = 0

    defs = list()
    for item in alist:
        if not getattr(item, 'get'):
            raise RuntimeError('definitions must be a list of dicts')
        schema = item.get("schema")
        if schema is not None:
            schema_id = schema.get("id")
            if schema_id is not None:
                # add endpoint_verb to schema id to avoid conflicts
                if prefix_ids:
                    schema['id'] = schema_id = "{}_{}_{}".format(
                        endpoint, verb, schema_id
                    )
                # ^ api['SWAGGER']['prefix_ids'] = True
                # ... for backwards compatibility with <= 0.5.14

                defs.append(schema)

                ref_path = None
                if is_openapi3(openapi_version):
                    ref_path = "#/components/schemas/"
                else:
                    ref_path = "#/definitions/"
                ref = {"$ref": "{}{}".format(ref_path, schema_id)}

                # only add the reference as a schema if we are in a
                # response or a parameter i.e. at the top level
                # directly ref if a definition is used within another
                # definition
                if level == 0:
                    item['schema'] = ref
                else:
                    item.update(ref)
                    del item['schema']

            # extract any definitions that are within properties
            # this occurs recursively
            properties = schema.get('properties')
            if properties is not None:
                defs += extract_definitions(
                    properties.values(), level + 1, endpoint, verb, prefix_ids,
                    openapi_version)

            defs += _extract_array_defs(schema)

        defs += _extract_array_defs(item)

    return defs


def has_valid_dispatch_view_docs(endpoint):
    """
    Return True if dispatch_request is swaggable
    """
    klass = endpoint.__dict__.get('view_class', None)
    return klass and hasattr(klass, 'dispatch_request') \
        and hasattr(endpoint, 'methods') \
        and getattr(klass, 'dispatch_request').__doc__


def is_valid_method_view(endpoint):
    """
    Return True if obj is MethodView
    """
    klass = endpoint.__dict__.get('view_class', None)
    try:
        return issubclass(klass, MethodView)
    except TypeError:
        return False


def get_vendor_extension_fields(mapping):
    """
    Identify vendor extension fields and extract them into a new dictionary.
    Examples:
        >>> get_vendor_extension_fields({'test': 1})
        {}
        >>> get_vendor_extension_fields({'test': 1, 'x-test': 2})
        {'x-test': 2}
    """
    return {k: v for k, v in mapping.items() if k.startswith('x-')}


class StringLike(object):
    """
    Class to mimic the behavior of a regular string. Classes that inherit (or
    mixin) this class must implement the `__str__` magic method. Whatever that
    method returns is used by the various string-like methods.
    """

    def __getattr__(self, attr):
        """
        Forwards any non-magic methods to the resulting string's class. This
        allows support for string methods like `upper()`, `lower()`, etc.
        """
        string = self.text_type(self)
        if hasattr(string, attr):
            return getattr(string, attr)
        raise AttributeError(attr)

    def __len__(self):
        return len(self.text_type(self))

    def __getitem__(self, key):
        return self.text_type(self)[key]

    def __iter__(self):
        return iter(self.text_type(self))

    def __contains__(self, item):
        return item in self.text_type(self)

    def __add__(self, other):
        return self.text_type(self) + other

    def __radd__(self, other):
        return other + self.text_type(self)

    def __mul__(self, other):
        return self.text_type(self) * other

    def __rmul__(self, other):
        return other * self.text_type(self)

    def __lt__(self, other):
        return self.text_type(self) < other

    def __le__(self, other):
        return self.text_type(self) <= other

    def __eq__(self, other):
        return self.text_type(self) == other

    def __ne__(self, other):
        return self.text_type(self) != other

    def __gt__(self, other):
        return self.text_type(self) > other

    def __ge__(self, other):
        return self.text_type(self) >= other

    @property
    def text_type(self):
        return text_type


class LazyString(StringLike):
    """
    A lazy string *without* caching. The resulting string is regenerated for
    every request.
    """

    def __init__(self, func):
        """
        Creates a `LazyString` object using `func` as the delayed closure.
        `func` must return a string.
        """
        self._func = func

    def __str__(self):
        """
        Returns the actual string.
        """
        return self.text_type(self._func())


class CachedLazyString(LazyString):
    """
    A lazy string with caching.
    """

    def __init__(self, func):
        """
        Uses `__init__()` from the parent and initializes a cache.
        """
        super(CachedLazyString, self).__init__(func)
        self._cache = None

    def __str__(self):
        """
        Returns the actual string and caches the result.
        """
        if not self._cache:
            self._cache = self.text_type(self._func())
        return self._cache


def swag_annotation(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        if not kwargs.pop("swag", False):
            return f(*args, **kwargs)

        function = args[2]

        specs = {}
        for key, value in DEFAULT_FIELDS.items():
            specs[key] = kwargs.pop(key, value)

        for variable, annotation in function.__annotations__.items():

            if issubclass(annotation, Schema):
                annotation = annotation()
                data = annotation.to_specs_dict()

                for row in data["parameters"]:
                    specs["parameters"].append(row)
                specs["definitions"].update(data["definitions"])

                function = validate_annotation(annotation, variable)(function)

            elif issubclass(annotation, int):
                m = {"name": variable,
                     "in": "path",
                     "type": "integer",
                     "required": True}
                if ("int(signed=True):" + variable) in args[0]:
                    m['minimum'] = 0
                specs["parameters"].append(m)

            elif issubclass(annotation, str):
                specs["parameters"].append({"name": variable,
                                            "in": "path",
                                            "type": "string",
                                            "required": True})

        function.specs_dict = specs
        args = list(args)
        args[2] = function
        args = tuple(args)

        return f(*args, **kwargs)
    return wrapper


def validate_annotation(an, var):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            if an.swag_validate:

                payload = None

                if an.swag_in == "query":
                    payload = dict(request.args)

                elif an.swag_in == "body" and request.is_json:
                    payload = request.json

                validate(
                    payload,
                    specs=an.to_specs_dict(),
                    validation_function=an.swag_validation_function,
                    validation_error_handler=an.swag_validation_error_handler,
                    require_data=an.swag_require_data
                    # handle openapiversion later
                )

            return f(*args, **kwargs, **{var: payload})
        return wrapper
    return decorator


def is_openapi3(openapi_version):
    """
    Returns True if openapi_version is 3
    """
    return openapi_version and str(openapi_version).split('.')[0] == '3'


def extract_schema(spec: dict) -> defaultdict:
    """
    Returns schema resources according to openapi version
    """
    openapi_version = spec.get('openapi', None)
    if is_openapi3(openapi_version):
        return spec.get('components', {}
                        ).get('schemas', defaultdict(dict))
    else:  # openapi2
        return spec.get('definitions', defaultdict(dict))
