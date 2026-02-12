# -*- coding: utf-8 -*-

"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience.
"""

import base64
import json
import os
import random
import time
import uuid
import argparse

from flask import (
    Flask,
    Response,
    request,
    render_template,
    redirect,
    jsonify as flask_jsonify,
    make_response,
    url_for,
    abort,
)
from werkzeug.datastructures import WWWAuthenticate, MultiDict
from werkzeug.http import http_date
try:
    from werkzeug.wrappers import Response
except ImportError:  # werkzeug < 2.1
    from werkzeug.wrappers import BaseResponse as Response

from flasgger import Swagger, NO_SANITIZER

from . import filters
from .helpers import (
    get_headers,
    status_code,
    get_dict,
    get_request_range,
    check_basic_auth,
    check_digest_auth,
    secure_cookie,
    H,
    ROBOT_TXT,
    ANGRY_ASCII,
    parse_authorization_header,
    parse_multi_value_header,
    next_stale_after_value,
    digest_challenge_response,
)
from .utils import weighted_choice
from .structures import CaseInsensitiveDict

try:
    from importlib.metadata import version as get_version
except ImportError:
    from importlib_metadata import version as get_version

version = get_version("httpbin")

ENV_COOKIES = (
    "_gauges_unique",
    "_gauges_unique_year",
    "_gauges_unique_month",
    "_gauges_unique_day",
    "_gauges_unique_hour",
    "__utmz",
    "__utma",
    "__utmb",
)


def jsonify(*args, **kwargs):
    response = flask_jsonify(*args, **kwargs)
    if not response.data.endswith(b"\n"):
        response.data += b"\n"
    return response


# Prevent WSGI from correcting the casing of the Location header
Response.autocorrect_location_header = False

# Find the correct template folder when running from a different location
tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

app = Flask(__name__, template_folder=tmpl_dir)
app.debug = bool(os.environ.get("DEBUG"))
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

app.add_template_global("HTTPBIN_TRACKING" in os.environ, name="tracking_enabled")

app.config["SWAGGER"] = {"title": "httpbin.org", "uiversion": 3}

template = {
    "swagger": "2.0",
    "info": {
        "title": "httpbin.org",
        "description": (
            "A simple HTTP Request & Response Service."
            "<br/> A <a href='http://kennethreitz.com/'>Kenneth Reitz</a> project."
            "<br/> <br/> <b>Run locally: </b> <br/> "
            "<code>$ docker pull ghcr.io/psf/httpbin</code> <br/>"
            "<code>$ docker run -p 80:8080 ghcr.io/psf/httpbin</code>"
        ),
        "contact": {
            "responsibleOrganization": "Python Software Foundation",
            "responsibleDeveloper": "Kenneth Reitz",
            "url": "https://github.com/psf/httpbin/",
        },
        # "termsOfService": "http://me.com/terms",
        "version": version,
    },
    "host": "httpbin.org",  # overrides localhost:5000
    "basePath": "/",  # base bash for blueprint registration
    "schemes": ["https"],
    "protocol": "https",
    "tags": [
        {
            "name": "HTTP Methods",
            "description": "Testing different HTTP verbs",
            # 'externalDocs': {'description': 'Learn more', 'url': 'https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html'}
        },
        {"name": "Auth", "description": "Auth methods"},
        {
            "name": "Status codes",
            "description": "Generates responses with given status code",
        },
        {"name": "Request inspection", "description": "Inspect the request data"},
        {
            "name": "Response inspection",
            "description": "Inspect the response data like caching and headers",
        },
        {
            "name": "Response formats",
            "description": "Returns responses in different data formats",
        },
        {"name": "Dynamic data", "description": "Generates random and dynamic data"},
        {"name": "Cookies", "description": "Creates, reads and deletes Cookies"},
        {"name": "Images", "description": "Returns different image formats"},
        {"name": "Redirects", "description": "Returns different redirect responses"},
        {
            "name": "Anything",
            "description": "Returns anything that is passed to request",
        },
    ],
}

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "spec",
            "route": "/spec.json",
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/flasgger_static",
    # "static_folder": "static",  # must be set by user
    "swagger_ui": True,
    "specs_route": "/",
}

swagger = Swagger(app, sanitizer=NO_SANITIZER, template=template, config=swagger_config)

# Set up Bugsnag exception tracking, if desired. To use Bugsnag, install the
# Bugsnag Python client with the command "pip install bugsnag", and set the
# environment variable BUGSNAG_API_KEY. You can also optionally set
# BUGSNAG_RELEASE_STAGE.
if os.environ.get("BUGSNAG_API_KEY") is not None:
    try:
        import bugsnag
        import bugsnag.flask

        release_stage = os.environ.get("BUGSNAG_RELEASE_STAGE") or "production"
        bugsnag.configure(
            api_key=os.environ.get("BUGSNAG_API_KEY"),
            project_root=os.path.dirname(os.path.abspath(__file__)),
            use_ssl=True,
            release_stage=release_stage,
            ignore_classes=["werkzeug.exceptions.NotFound"],
        )
        bugsnag.flask.handle_exceptions(app)
    except:
        app.logger.warning("Unable to initialize Bugsnag exception handling.")

# -----------
# Middlewares
# -----------
"""
https://github.com/kennethreitz/httpbin/issues/340
Adds a middleware to provide chunked request encoding support running under
gunicorn only.
Werkzeug required environ 'wsgi.input_terminated' to be set otherwise it
empties the input request stream.
- gunicorn seems to support input_terminated but does not add the environ,
  so we add it here.
- flask will hang and does not seem to properly terminate the request, so
  we explicitly deny chunked requests.
"""


@app.before_request
def before_request():
    if request.environ.get("HTTP_TRANSFER_ENCODING", "").lower() == "chunked":
        server = request.environ.get("SERVER_SOFTWARE", "")
        if server.lower().startswith("gunicorn/"):
            if "wsgi.input_terminated" in request.environ:
                app.logger.debug(
                    "environ wsgi.input_terminated already set, keeping: %s"
                    % request.environ["wsgi.input_terminated"]
                )
            else:
                request.environ["wsgi.input_terminated"] = 1
        else:
            abort(501, "Chunked requests are not supported for server %s" % server)


@app.after_request
def set_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"

    if request.method == "OPTIONS":
        # Both of these headers are only used for the "preflight request"
        # http://www.w3.org/TR/cors/#access-control-allow-methods-response-header
        response.headers[
            "Access-Control-Allow-Methods"
        ] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        response.headers["Access-Control-Max-Age"] = "3600"  # 1 hour cache
        if request.headers.get("Access-Control-Request-Headers") is not None:
            response.headers["Access-Control-Allow-Headers"] = request.headers[
                "Access-Control-Request-Headers"
            ]
    return response


# ------
# Routes
# ------


@app.route("/legacy")
def view_landing_page():
    """Generates Landing Page in legacy layout."""
    return render_template("index.html")


@app.route("/html")
def view_html_page():
    """Returns a simple HTML document.
    ---
    tags:
      - Response formats
    produces:
      - text/html
    responses:
      200:
        description: An HTML page.
    """

    return render_template("moby.html")


@app.route("/robots.txt")
def view_robots_page():
    """Returns some robots.txt rules.
    ---
    tags:
      - Response formats
    produces:
      - text/plain
    responses:
      200:
        description: Robots file
    """

    response = make_response()
    response.data = ROBOT_TXT
    response.content_type = "text/plain"
    return response


@app.route("/deny")
def view_deny_page():
    """Returns page denied by robots.txt rules.
    ---
    tags:
      - Response formats
    produces:
      - text/plain
    responses:
      200:
        description: Denied message
    """
    response = make_response()
    response.data = ANGRY_ASCII
    response.content_type = "text/plain"
    return response
    # return "YOU SHOULDN'T BE HERE"


@app.route("/ip")
def view_origin():
    """Returns the requester's IP Address.
    ---
    tags:
      - Request inspection
    produces:
      - application/json
    responses:
      200:
        description: The Requester's IP Address.
    """

    return jsonify(origin=request.headers.get("X-Forwarded-For", request.remote_addr))


@app.route("/uuid")
def view_uuid():
    """Return a UUID4.
    ---
    tags:
      - Dynamic data
    produces:
      - application/json
    responses:
      200:
        description: A UUID4.
    """

    return jsonify(uuid=str(uuid.uuid4()))


@app.route("/headers")
def view_headers():
    """Return the incoming request's HTTP headers.
    ---
    tags:
      - Request inspection
    produces:
      - application/json
    responses:
      200:
        description: The request's headers.
    """

    return jsonify(get_dict('headers'))


@app.route("/user-agent")
def view_user_agent():
    """Return the incoming requests's User-Agent header.
    ---
    tags:
      - Request inspection
    produces:
      - application/json
    responses:
      200:
        description: The request's User-Agent header.
    """

    headers = get_headers()

    return jsonify({"user-agent": headers["user-agent"]})


@app.route("/get", methods=("GET",))
def view_get():
    """The request's query parameters.
    ---
    tags:
      - HTTP Methods
    produces:
      - application/json
    responses:
      200:
        description: The request's query parameters.
    """

    return jsonify(get_dict("url", "args", "headers", "origin"))


@app.route("/anything", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"])
@app.route(
    "/anything/<path:anything>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"],
)
def view_anything(anything=None):
    """Returns anything passed in request data.
    ---
    tags:
      - Anything
    produces:
      - application/json
    responses:
      200:
        description: Anything passed in request
    """

    return jsonify(
        get_dict(
            "url",
            "args",
            "headers",
            "origin",
            "method",
            "form",
            "data",
            "files",
            "json",
        )
    )


@app.route("/post", methods=("POST",))
def view_post():
    """The request's POST parameters.
    ---
    tags:
      - HTTP Methods
    produces:
      - application/json
    responses:
      200:
        description: The request's POST parameters.
    """

    return jsonify(
        get_dict("url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.route("/put", methods=("PUT",))
def view_put():
    """The request's PUT parameters.
    ---
    tags:
      - HTTP Methods
    produces:
      - application/json
    responses:
      200:
        description: The request's PUT parameters.
    """

    return jsonify(
        get_dict("url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.route("/patch", methods=("PATCH",))
def view_patch():
    """The request's PATCH parameters.
    ---
    tags:
      - HTTP Methods
    produces:
      - application/json
    responses:
      200:
        description: The request's PATCH parameters.
    """

    return jsonify(
        get_dict("url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.route("/delete", methods=("DELETE",))
def view_delete():
    """The request's DELETE parameters.
    ---
    tags:
      - HTTP Methods
    produces:
      - application/json
    responses:
      200:
        description: The request's DELETE parameters.
    """

    return jsonify(
        get_dict("url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.route("/gzip")
@filters.gzip
def view_gzip_encoded_content():
    """Returns GZip-encoded data.
    ---
    tags:
      - Response formats
    produces:
      - application/json
    responses:
      200:
        description: GZip-encoded data.
    """

    return jsonify(get_dict("origin", "headers", method=request.method, gzipped=True))


@app.route("/deflate")
@filters.deflate
def view_deflate_encoded_content():
    """Returns Deflate-encoded data.
    ---
    tags:
      - Response formats
    produces:
      - application/json
    responses:
      200:
        description: Defalte-encoded data.
    """

    return jsonify(get_dict("origin", "headers", method=request.method, deflated=True))


@app.route("/brotli")
@filters.brotli
def view_brotli_encoded_content():
    """Returns Brotli-encoded data.
    ---
    tags:
      - Response formats
    produces:
      - application/json
    responses:
      200:
        description: Brotli-encoded data.
    """

    return jsonify(get_dict("origin", "headers", method=request.method, brotli=True))


@app.route("/redirect/<int:n>")
def redirect_n_times(n):
    """302 Redirects n times.
    ---
    tags:
      - Redirects
    parameters:
      - in: path
        name: n
        type: int
    produces:
      - text/html
    responses:
      302:
        description: A redirection.
    """
    assert n > 0

    absolute = request.args.get("absolute", "false").lower() == "true"

    if n == 1:
        return redirect(url_for("view_get", _external=absolute))

    if absolute:
        return _redirect("absolute", n, True)
    else:
        return _redirect("relative", n, False)


def _redirect(kind, n, external):
    return redirect(
        url_for("{0}_redirect_n_times".format(kind), n=n - 1, _external=external)
    )


@app.route("/redirect-to", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"])
def redirect_to():
    """302/3XX Redirects to the given URL.
    ---
    tags:
      - Redirects
    produces:
      - text/html
    get:
      parameters:
        - in: query
          name: url
          type: string
          required: true
        - in: query
          name: status_code
          type: int
    post:
      consumes:
        - application/x-www-form-urlencoded
      parameters:
        - in: formData
          name: url
          type: string
          required: true
        - in: formData
          name: status_code
          type: int
          required: false
    patch:
      consumes:
        - application/x-www-form-urlencoded
      parameters:
        - in: formData
          name: url
          type: string
          required: true
        - in: formData
          name: status_code
          type: int
          required: false
    put:
      consumes:
        - application/x-www-form-urlencoded
      parameters:
        - in: formData
          name: url
          type: string
          required: true
        - in: formData
          name: status_code
          type: int
          required: false
    responses:
      302:
        description: A redirection.
    """

    args_dict = request.args.items()
    args = CaseInsensitiveDict(args_dict)

    response = app.make_response("")
    response.status_code = 302
    if "status_code" in args:
        status_code = int(args["status_code"])
        if status_code >= 300 and status_code < 400:
            response.status_code = status_code
    response.headers["Location"] = args["url"]

    return response


@app.route("/relative-redirect/<int:n>")
def relative_redirect_n_times(n):
    """Relatively 302 Redirects n times.
    ---
    tags:
      - Redirects
    parameters:
      - in: path
        name: n
        type: int
    produces:
      - text/html
    responses:
      302:
        description: A redirection.
    """

    assert n > 0

    response = app.make_response("")
    response.status_code = 302

    if n == 1:
        response.headers["Location"] = url_for("view_get")
        return response

    response.headers["Location"] = url_for("relative_redirect_n_times", n=n - 1)
    return response


@app.route("/absolute-redirect/<int:n>")
def absolute_redirect_n_times(n):
    """Absolutely 302 Redirects n times.
    ---
    tags:
      - Redirects
    parameters:
      - in: path
        name: n
        type: int
    produces:
      - text/html
    responses:
      302:
        description: A redirection.
    """

    assert n > 0

    if n == 1:
        return redirect(url_for("view_get", _external=True))

    return _redirect("absolute", n, True)


@app.route("/stream/<int:n>")
def stream_n_messages(n):
    """Stream n JSON responses
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: n
        type: int
    produces:
      - application/json
    responses:
      200:
        description: Streamed JSON responses.
    """
    response = get_dict("url", "args", "headers", "origin")
    n = min(n, 100)

    def generate_stream():
        for i in range(n):
            response["id"] = i
            yield json.dumps(response) + "\n"

    return Response(generate_stream(), headers={"Content-Type": "application/json"})


@app.route(
    "/status/<codes>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"]
)
def view_status_code(codes):
    """Return status code or random status code if more than one are given
    ---
    tags:
      - Status codes
    parameters:
      - in: path
        name: codes
    produces:
      - text/plain
    responses:
      100:
        description: Informational responses
      200:
        description: Success
      300:
        description: Redirection
      400:
        description: Client Errors
      500:
        description: Server Errors
    """

    if "," not in codes:
        try:
            code = int(codes)
        except ValueError:
            return Response("Invalid status code", status=400)
        return status_code(code)

    choices = []
    for choice in codes.split(","):
        if ":" not in choice:
            code = choice
            weight = 1
        else:
            code, weight = choice.split(":")

        try:
            choices.append((int(code), float(weight)))
        except ValueError:
            return Response("Invalid status code", status=400)

    code = weighted_choice(choices)

    return status_code(code)


@app.route("/response-headers", methods=["GET", "POST"])
def response_headers():
    """Returns a set of response headers from the query string.
    ---
    tags:
      - Response inspection
    parameters:
      - in: query
        name: freeform
        explode: true
        allowEmptyValue: true
        schema:
          type: object
          additionalProperties:
            type: string
        style: form
    produces:
      - application/json
    responses:
      200:
        description: Response headers
    """
    # Pending swaggerUI update
    # https://github.com/swagger-api/swagger-ui/issues/3850
    headers = MultiDict(request.args.items(multi=True))
    response = jsonify(list(headers.lists()))

    while True:
        original_data = response.data
        d = {}
        for key in response.headers.keys():
            value = response.headers.get_all(key)
            if len(value) == 1:
                value = value[0]
            d[key] = value
        response = jsonify(d)
        for key, value in headers.items(multi=True):
            response.headers.add(key, value)
        response_has_changed = response.data != original_data
        if not response_has_changed:
            break
    return response


@app.route("/cookies")
def view_cookies(hide_env=True):
    """Returns cookie data.
    ---
    tags:
      - Cookies
    produces:
      - application/json
    responses:
      200:
        description: Set cookies.
    """

    cookies = dict(request.cookies.items())

    if hide_env and ("show_env" not in request.args):
        for key in ENV_COOKIES:
            try:
                del cookies[key]
            except KeyError:
                pass

    return jsonify(cookies=cookies)


@app.route("/forms/post")
def view_forms_post():
    """Simple HTML form."""

    return render_template("forms-post.html")


@app.route("/cookies/set/<name>/<value>")
def set_cookie(name, value):
    """Sets a cookie and redirects to cookie list.
    ---
    tags:
      - Cookies
    parameters:
      - in: path
        name: name
        type: string
      - in: path
        name: value
        type: string
    produces:
      - text/plain
    responses:
      200:
        description: Set cookies and redirects to cookie list.
    """

    r = app.make_response(redirect(url_for("view_cookies")))
    r.set_cookie(key=name, value=value, secure=secure_cookie())

    return r


@app.route("/cookies/set")
def set_cookies():
    """Sets cookie(s) as provided by the query string and redirects to cookie list.
    ---
    tags:
      - Cookies
    parameters:
      - in: query
        name: freeform
        explode: true
        allowEmptyValue: true
        schema:
          type: object
          additionalProperties:
            type: string
        style: form
    produces:
      - text/plain
    responses:
      200:
        description: Redirect to cookie list
    """

    cookies = dict(request.args.items())
    r = app.make_response(redirect(url_for("view_cookies")))
    for key, value in cookies.items():
        r.set_cookie(key=key, value=value, secure=secure_cookie())

    return r


@app.route("/cookies/delete")
def delete_cookies():
    """Deletes cookie(s) as provided by the query string and redirects to cookie list.
    ---
    tags:
      - Cookies
    parameters:
      - in: query
        name: freeform
        explode: true
        allowEmptyValue: true
        schema:
          type: object
          additionalProperties:
            type: string
        style: form
    produces:
      - text/plain
    responses:
      200:
        description: Redirect to cookie list
    """

    cookies = dict(request.args.items())
    r = app.make_response(redirect(url_for("view_cookies")))
    for key, value in cookies.items():
        r.delete_cookie(key=key)

    return r


@app.route("/basic-auth/<user>/<passwd>")
def basic_auth(user="user", passwd="passwd"):
    """Prompts the user for authorization using HTTP Basic Auth.
    ---
    tags:
      - Auth
    parameters:
      - in: path
        name: user
        type: string
      - in: path
        name: passwd
        type: string
    produces:
      - application/json
    responses:
      200:
        description: Sucessful authentication.
      401:
        description: Unsuccessful authentication.
    """

    if not check_basic_auth(user, passwd):
        return status_code(401)

    return jsonify(authenticated=True, user=user)


@app.route("/hidden-basic-auth/<user>/<passwd>")
def hidden_basic_auth(user="user", passwd="passwd"):
    """Prompts the user for authorization using HTTP Basic Auth.
    ---
    tags:
      - Auth
    parameters:
      - in: path
        name: user
        type: string
      - in: path
        name: passwd
        type: string
    produces:
      - application/json
    responses:
      200:
        description: Sucessful authentication.
      404:
        description: Unsuccessful authentication.
    """

    if not check_basic_auth(user, passwd):
        return status_code(404)
    return jsonify(authenticated=True, user=user)


@app.route("/bearer")
def bearer_auth():
    """Prompts the user for authorization using bearer authentication.
    ---
    tags:
      - Auth
    parameters:
      - in: header
        name: Authorization
        schema:
          type: string
    produces:
      - application/json
    responses:
      200:
        description: Sucessful authentication.
      401:
        description: Unsuccessful authentication.
    """
    authorization = request.headers.get("Authorization")
    if not (authorization and authorization.startswith("Bearer ")):
        response = app.make_response("")
        response.headers["WWW-Authenticate"] = "Bearer"
        response.status_code = 401
        return response
    slice_start = len("Bearer ")
    token = authorization[slice_start:]

    return jsonify(authenticated=True, token=token)


@app.route("/digest-auth/<qop>/<user>/<passwd>")
def digest_auth_md5(qop=None, user="user", passwd="passwd"):
    """Prompts the user for authorization using Digest Auth.
    ---
    tags:
      - Auth
    parameters:
      - in: path
        name: qop
        type: string
        description: auth or auth-int
      - in: path
        name: user
        type: string
      - in: path
        name: passwd
        type: string
    produces:
      - application/json
    responses:
      200:
        description: Sucessful authentication.
      401:
        description: Unsuccessful authentication.
    """
    return digest_auth(qop, user, passwd, "MD5", "never")


@app.route("/digest-auth/<qop>/<user>/<passwd>/<algorithm>")
def digest_auth_nostale(qop=None, user="user", passwd="passwd", algorithm="MD5"):
    """Prompts the user for authorization using Digest Auth + Algorithm.
    ---
    tags:
      - Auth
    parameters:
      - in: path
        name: qop
        type: string
        description: auth or auth-int
      - in: path
        name: user
        type: string
      - in: path
        name: passwd
        type: string
      - in: path
        name: algorithm
        type: string
        description: MD5, SHA-256, SHA-512
        default: MD5
    produces:
      - application/json
    responses:
      200:
        description: Sucessful authentication.
      401:
        description: Unsuccessful authentication.
    """
    return digest_auth(qop, user, passwd, algorithm, "never")


@app.route("/digest-auth/<qop>/<user>/<passwd>/<algorithm>/<stale_after>")
def digest_auth(
    qop=None, user="user", passwd="passwd", algorithm="MD5", stale_after="never"
):
    """Prompts the user for authorization using Digest Auth + Algorithm.
    allow settings the stale_after argument.
    ---
    tags:
      - Auth
    parameters:
      - in: path
        name: qop
        type: string
        description: auth or auth-int
      - in: path
        name: user
        type: string
      - in: path
        name: passwd
        type: string
      - in: path
        name: algorithm
        type: string
        description: MD5, SHA-256, SHA-512
        default: MD5
      - in: path
        name: stale_after
        type: string
        default: never
    produces:
      - application/json
    responses:
      200:
        description: Sucessful authentication.
      401:
        description: Unsuccessful authentication.
    """
    require_cookie_handling = request.args.get("require-cookie", "").lower() in (
        "1",
        "t",
        "true",
    )
    if algorithm not in ("MD5", "SHA-256", "SHA-512"):
        algorithm = "MD5"

    if qop not in ("auth", "auth-int"):
        qop = None

    authorization = request.headers.get("Authorization")
    credentials = None
    if authorization:
        credentials = parse_authorization_header(authorization)

    if (
        not authorization
        or not credentials
        or credentials.type.lower() != "digest"
        or (require_cookie_handling and "Cookie" not in request.headers)
    ):
        response = digest_challenge_response(app, qop, algorithm)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("fake", value="fake_value")
        return response

    if require_cookie_handling and request.cookies.get("fake") != "fake_value":
        response = jsonify({"errors": ["missing cookie set on challenge"]})
        response.set_cookie("fake", value="fake_value")
        response.status_code = 403
        return response

    current_nonce = credentials.get("nonce")

    stale_after_value = None
    if "stale_after" in request.cookies:
        stale_after_value = request.cookies.get("stale_after")

    if (
        "last_nonce" in request.cookies
        and current_nonce == request.cookies.get("last_nonce")
        or stale_after_value == "0"
    ):
        response = digest_challenge_response(app, qop, algorithm, True)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("last_nonce", value=current_nonce)
        response.set_cookie("fake", value="fake_value")
        return response

    if not check_digest_auth(user, passwd):
        response = digest_challenge_response(app, qop, algorithm, False)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("last_nonce", value=current_nonce)
        response.set_cookie("fake", value="fake_value")
        return response

    response = jsonify(authenticated=True, user=user)
    response.set_cookie("fake", value="fake_value")
    if stale_after_value:
        response.set_cookie(
            "stale_after", value=next_stale_after_value(stale_after_value)
        )

    return response


@app.route("/delay/<delay>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "TRACE"])
def delay_response(delay):
    """Returns a delayed response (max of 10 seconds).
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: delay
        type: int
    produces:
      - application/json
    responses:
      200:
        description: A delayed response.
    """
    delay = min(float(delay), 10)

    time.sleep(delay)

    return jsonify(
        get_dict("url", "args", "form", "data", "origin", "headers", "files")
    )


@app.route("/drip")
def drip():
    """Drips data over a duration after an optional initial delay.
    ---
    tags:
      - Dynamic data
    parameters:
      - in: query
        name: duration
        type: number
        description: The amount of time (in seconds) over which to drip each byte
        default: 2
        required: false
      - in: query
        name: numbytes
        type: integer
        description: The number of bytes to respond with
        default: 10
        required: false
      - in: query
        name: code
        type: integer
        description: The response code that will be returned
        default: 200
        required: false
      - in: query
        name: delay
        type: number
        description: The amount of time (in seconds) to delay before responding
        default: 2
        required: false
    produces:
      - application/octet-stream
    responses:
      200:
        description: A dripped response.
    """
    args = CaseInsensitiveDict(request.args.items())
    duration = float(args.get("duration", 2))
    numbytes = min(int(args.get("numbytes", 10)), (10 * 1024 * 1024))  # set 10MB limit
    code = int(args.get("code", 200))

    if numbytes <= 0:
        response = Response("number of bytes must be positive", status=400)
        return response

    delay = float(args.get("delay", 0))
    if delay > 0:
        time.sleep(delay)

    pause = duration / numbytes

    def generate_bytes():
        for i in range(numbytes):
            yield b"*"
            time.sleep(pause)

    response = Response(
        generate_bytes(),
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(numbytes),
        },
    )

    response.status_code = code

    return response


@app.route("/base64/<value>")
def decode_base64(value):
    """Decodes base64url-encoded string.
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: value
        type: string
        default: SFRUUEJJTiBpcyBhd2Vzb21l
    produces:
      - text/html
    responses:
      200:
        description: Decoded base64 content.
    """
    encoded = value.encode("utf-8")  # base64 expects binary string as input
    try:
        return base64.urlsafe_b64decode(encoded).decode("utf-8")
    except:
        return "Incorrect Base64 data try: SFRUUEJJTiBpcyBhd2Vzb21l"


@app.route("/cache", methods=("GET",))
def cache():
    """Returns a 304 if an If-Modified-Since header or If-None-Match is present. Returns the same as a GET otherwise.
    ---
    tags:
      - Response inspection
    parameters:
      - in: header
        name: If-Modified-Since
      - in: header
        name: If-None-Match
    produces:
      - application/json
    responses:
      200:
        description: Cached response
      304:
        description: Modified

    """
    is_conditional = request.headers.get("If-Modified-Since") or request.headers.get(
        "If-None-Match"
    )

    if is_conditional is None:
        response = view_get()
        response.headers["Last-Modified"] = http_date()
        response.headers["ETag"] = uuid.uuid4().hex
        return response
    else:
        return status_code(304)


@app.route("/etag/<etag>", methods=("GET",))
def etag(etag):
    """Assumes the resource has the given etag and responds to If-None-Match and If-Match headers appropriately.
    ---
    tags:
      - Response inspection
    parameters:
      - in: header
        name: If-None-Match
      - in: header
        name: If-Match
    produces:
      - application/json
    responses:
      200:
        description: Normal response
      412:
        description: match

    """
    if_none_match = parse_multi_value_header(request.headers.get("If-None-Match"))
    if_match = parse_multi_value_header(request.headers.get("If-Match"))

    if if_none_match:
        if etag in if_none_match or "*" in if_none_match:
            response = status_code(304)
            response.headers["ETag"] = etag
            return response
    elif if_match:
        if etag not in if_match and "*" not in if_match:
            return status_code(412)

    # Special cases don't apply, return normal response
    response = view_get()
    response.headers["ETag"] = etag
    return response


@app.route("/cache/<int:value>")
def cache_control(value):
    """Sets a Cache-Control header for n seconds.
    ---
    tags:
      - Response inspection
    parameters:
      - in: path
        name: value
        type: integer
    produces:
      - application/json
    responses:
      200:
        description: Cache control set
    """
    response = view_get()
    response.headers["Cache-Control"] = "public, max-age={0}".format(value)
    return response


@app.route("/encoding/utf8")
def encoding():
    """Returns a UTF-8 encoded body.
    ---
    tags:
      - Response formats
    produces:
      - text/html
    responses:
      200:
        description: Encoded UTF-8 content.
    """

    return render_template("UTF-8-demo.txt")


@app.route("/bytes/<int:n>")
def random_bytes(n):
    """Returns n random bytes generated with given seed
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: n
        type: int
    produces:
      - application/octet-stream
    responses:
      200:
        description: Bytes.
    """

    n = min(n, 100 * 1024)  # set 100KB limit

    params = CaseInsensitiveDict(request.args.items())
    if "seed" in params:
        random.seed(int(params["seed"]))

    response = make_response()

    # Note: can't just use os.urandom here because it ignores the seed
    response.data = bytearray(random.randint(0, 255) for i in range(n))
    response.content_type = "application/octet-stream"
    return response


@app.route("/stream-bytes/<int:n>")
def stream_random_bytes(n):
    """Streams n random bytes generated with given seed, at given chunk size per packet.
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: n
        type: int
    produces:
      - application/octet-stream
    responses:
      200:
        description: Bytes.
    """
    n = min(n, 100 * 1024)  # set 100KB limit

    params = CaseInsensitiveDict(request.args.items())
    if "seed" in params:
        random.seed(int(params["seed"]))

    if "chunk_size" in params:
        chunk_size = max(1, int(params["chunk_size"]))
    else:
        chunk_size = 10 * 1024

    def generate_bytes():
        chunks = bytearray()

        for i in range(n):
            chunks.append(random.randint(0, 255))
            if len(chunks) == chunk_size:
                yield (bytes(chunks))
                chunks = bytearray()

        if chunks:
            yield (bytes(chunks))

    headers = {"Content-Type": "application/octet-stream"}

    return Response(generate_bytes(), headers=headers)


@app.route("/range/<int:numbytes>")
def range_request(numbytes):
    """Streams n random bytes generated with given seed, at given chunk size per packet.
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: numbytes
        type: int
    produces:
      - application/octet-stream
    responses:
      200:
        description: Bytes.
    """

    if numbytes <= 0 or numbytes > (100 * 1024):
        response = Response(
            headers={"ETag": "range%d" % numbytes, "Accept-Ranges": "bytes"}
        )
        response.status_code = 404
        response.data = "number of bytes must be in the range (0, 102400]"
        return response

    params = CaseInsensitiveDict(request.args.items())
    if "chunk_size" in params:
        chunk_size = max(1, int(params["chunk_size"]))
    else:
        chunk_size = 10 * 1024

    duration = float(params.get("duration", 0))
    pause_per_byte = duration / numbytes

    request_headers = get_headers()
    first_byte_pos, last_byte_pos = get_request_range(request_headers, numbytes)
    range_length = (last_byte_pos + 1) - first_byte_pos

    if (
        first_byte_pos > last_byte_pos
        or first_byte_pos not in range(0, numbytes)
        or last_byte_pos not in range(0, numbytes)
    ):
        response = Response(
            headers={
                "ETag": "range%d" % numbytes,
                "Accept-Ranges": "bytes",
                "Content-Range": "bytes */%d" % numbytes,
                "Content-Length": "0",
            }
        )
        response.status_code = 416
        return response

    def generate_bytes():
        chunks = bytearray()

        for i in range(first_byte_pos, last_byte_pos + 1):

            # We don't want the resource to change across requests, so we need
            # to use a predictable data generation function
            chunks.append(ord("a") + (i % 26))
            if len(chunks) == chunk_size:
                yield (bytes(chunks))
                time.sleep(pause_per_byte * chunk_size)
                chunks = bytearray()

        if chunks:
            time.sleep(pause_per_byte * len(chunks))
            yield (bytes(chunks))

    content_range = "bytes %d-%d/%d" % (first_byte_pos, last_byte_pos, numbytes)
    response_headers = {
        "Content-Type": "application/octet-stream",
        "ETag": "range%d" % numbytes,
        "Accept-Ranges": "bytes",
        "Content-Length": str(range_length),
        "Content-Range": content_range,
    }

    response = Response(generate_bytes(), headers=response_headers)

    if (first_byte_pos == 0) and (last_byte_pos == (numbytes - 1)):
        response.status_code = 200
    else:
        response.status_code = 206

    return response


@app.route("/links/<int:n>/<int:offset>")
def link_page(n, offset):
    """Generate a page containing n links to other pages which do the same.
    ---
    tags:
      - Dynamic data
    parameters:
      - in: path
        name: n
        type: int
      - in: path
        name: offset
        type: int
    produces:
      - text/html
    responses:
      200:
        description: HTML links.
    """
    n = min(max(1, n), 200)  # limit to between 1 and 200 links

    link = "<a href='{0}'>{1}</a> "

    html = ["<html><head><title>Links</title></head><body>"]
    for i in range(n):
        if i == offset:
            html.append("{0} ".format(i))
        else:
            html.append(link.format(url_for("link_page", n=n, offset=i), i))
    html.append("</body></html>")

    return "".join(html)


@app.route("/links/<int:n>")
def links(n):
    """Redirect to first links page."""
    return redirect(url_for("link_page", n=n, offset=0))


@app.route("/image")
def image():
    """Returns a simple image of the type suggest by the Accept header.
    ---
    tags:
      - Images
    produces:
      - image/webp
      - image/svg+xml
      - image/jpeg
      - image/png
      - image/*
    responses:
      200:
        description: An image.
    """

    headers = get_headers()
    if "accept" not in headers:
        return image_png()  # Default media type to png

    accept = headers["accept"].lower()

    if "image/webp" in accept:
        return image_webp()
    elif "image/svg+xml" in accept:
        return image_svg()
    elif "image/jpeg" in accept:
        return image_jpeg()
    elif "image/png" in accept or "image/*" in accept:
        return image_png()
    else:
        return status_code(406)  # Unsupported media type


@app.route("/image/png")
def image_png():
    """Returns a simple PNG image.
    ---
    tags:
      - Images
    produces:
      - image/png
    responses:
      200:
        description: A PNG image.
    """
    data = resource("images/pig_icon.png")
    return Response(data, headers={"Content-Type": "image/png"})


@app.route("/image/jpeg")
def image_jpeg():
    """Returns a simple JPEG image.
    ---
    tags:
      - Images
    produces:
      - image/jpeg
    responses:
      200:
        description: A JPEG image.
    """
    data = resource("images/jackal.jpg")
    return Response(data, headers={"Content-Type": "image/jpeg"})


@app.route("/image/webp")
def image_webp():
    """Returns a simple WEBP image.
    ---
    tags:
      - Images
    produces:
      - image/webp
    responses:
      200:
        description: A WEBP image.
    """
    data = resource("images/wolf_1.webp")
    return Response(data, headers={"Content-Type": "image/webp"})


@app.route("/image/svg")
def image_svg():
    """Returns a simple SVG image.
    ---
    tags:
      - Images
    produces:
      - image/svg+xml
    responses:
      200:
        description: An SVG image.
    """
    data = resource("images/svg_logo.svg")
    return Response(data, headers={"Content-Type": "image/svg+xml"})


def resource(filename):
    path = os.path.join(tmpl_dir, filename)
    with open(path, "rb") as f:
      return f.read()


@app.route("/xml")
def xml():
    """Returns a simple XML document.
    ---
    tags:
      - Response formats
    produces:
      - application/xml
    responses:
      200:
        description: An XML document.
    """
    response = make_response(render_template("sample.xml"))
    response.headers["Content-Type"] = "application/xml"
    return response


@app.route("/json")
def a_json_endpoint():
    """Returns a simple JSON document.
    ---
    tags:
      - Response formats
    produces:
      - application/json
    responses:
      200:
        description: An JSON document.
    """
    return flask_jsonify(
        slideshow={
            "title": "Sample Slide Show",
            "date": "date of publication",
            "author": "Yours Truly",
            "slides": [
                {"type": "all", "title": "Wake up to WonderWidgets!"},
                {
                    "type": "all",
                    "title": "Overview",
                    "items": [
                        "Why <em>WonderWidgets</em> are great",
                        "Who <em>buys</em> WonderWidgets",
                    ],
                },
            ],
        }
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    app.run(port=args.port, host=args.host)
