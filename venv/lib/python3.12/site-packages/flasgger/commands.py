import json

import click
from flask import current_app
from flask.cli import with_appcontext

from .utils import is_openapi3


@click.command()
@click.option("-f", "--file", type=click.File("w"), default="-")
@click.option("-e", "--endpoint", default=None)
@with_appcontext
def generate_api_schema(file, endpoint):
    """Generate the swagger schema for your api."""
    try:
        if endpoint is None:
            endpoint = current_app.swag.config["specs"][0]["endpoint"]

        spec = current_app.swag.get_apispecs(endpoint)
    except RuntimeError as e:
        click.echo(e, err=True)
        click.echo(
            "Possible values for endpoint are: {}".format(
                ", ".join(
                    [
                        spec["endpoint"]
                        for spec in current_app.swag.config["specs"]
                        if "endpoint" in spec
                    ]
                )
            ),
            err=True,
        )
        raise click.Abort

    # See also: https://github.com/flasgger/flasgger/issues/267
    if is_openapi3(spec.get("openapi")):
        if "definitions" in spec:
            del spec["definitions"]

    json.dump(spec, file, indent=4)

    return spec
