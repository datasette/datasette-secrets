import click
from cryptography.fernet import Fernet
from datasette import hookimpl


@hookimpl
def register_commands(cli):
    @cli.group()
    def secrets():
        "Commands for managing datasette-secrets"

    @secrets.command()
    def generate():
        "Generate a new secret key"
        key = Fernet.generate_key()
        click.echo(key.decode("utf-8"))
