from flask import Flask

"""Local patches for pytest-httpbin's bundled Flask application to test QUERY method."""

QUERY_ENDPOINTS_IN_TEST = {
    "view_anything",
    "redirect_n_times",
    "redirect_to"
}


def allow_query_method(app: Flask, endpoints: set[str] = QUERY_ENDPOINTS_IN_TEST):
    """Allow QUERY on selected httpbin endpoints.

    httpbin registers Flask routes at import time, so patching ``app.route``
    later will not affect existing rules. The registered URL rules are mutable,
    though, and pytest-httpbin serves this same app object.
    """
    for rule in app.url_map.iter_rules():
        if rule.endpoint in endpoints:
            if rule.methods is None:
                rule.methods = {"QUERY"}
            else:
                rule.methods.add("QUERY")