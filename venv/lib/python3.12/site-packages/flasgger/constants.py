OPTIONAL_FIELDS = [
    'tags', 'consumes', 'produces', 'schemes', 'security',
    'deprecated', 'operationId', 'externalDocs'
]

OPTIONAL_OAS3_FIELDS = [
    'components', 'servers'
]

DEFAULT_FIELDS = {"tags": [], "consumes": ['application/json'],
                  "produces": ['application/json'], "schemes": [],
                  "security": [], "deprecated": False, "operationId": "",
                  "definitions": {}, "responses": {}, "summary": None,
                  "description": None, "parameters": []}
