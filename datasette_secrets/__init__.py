import click
from cryptography.fernet import Fernet
from datasette import hookimpl, Response

SCHEMA = """
create table if not exists datasette_secrets (
    id integer primary key,
    name text not null,
    note text,
    version integer not null default 1,
    encrypted blob,
    encryption_key_name text not null,
    redacted text,
    created_at text,
    created_by text,
    updated_at text,
    updated_by text,
    deleted_at text,
    deleted_by text,
    last_used_at text,
    last_used_by text
);
"""


def get_database(datasette):
    plugin_config = datasette.plugin_config("datasette-secrets") or {}
    database = plugin_config.get("database") or "_internal"
    if database == "_internal":
        return datasette.get_internal_database()
    return datasette.get_database(database)


def config(datasette):
    plugin_config = datasette.plugin_config("datasette-secrets") or {}
    encryption_key = plugin_config.get("encryption-key")
    database = plugin_config.get("database") or "_internal"
    if not encryption_key:
        return None
    return {
        "database": database,
        "encryption_key": encryption_key,
    }


@hookimpl
def register_commands(cli):
    @cli.group()
    def secrets():
        "Commands for managing datasette-secrets"

    @secrets.command()
    def generate_encryption_key():
        "Generate a new encryption key for encrypting and decrypting secrets"
        key = Fernet.generate_key()
        click.echo(key.decode("utf-8"))


@hookimpl
def startup(datasette):
    plugin_config = config(datasette)
    if not plugin_config:
        return
    db = get_database(datasette)

    async def create_table():
        await db.execute_write(SCHEMA)

    return create_table


async def secrets_index():
    return Response.html("Coming soon")


async def secrets_add(datasette, request):
    plugin_config = config(datasette)
    if not plugin_config:
        return Response.html("datasette-secrets has not been configured", status=400)
    if request.method == "POST":
        data = await request.post_vars()
        name = data.get("secret_name") or "".strip()
        secret = (data.get("secret") or "").strip()
        note = data.get("note") or ""
        if not (name and secret):
            return Response.html(
                await datasette.render_template(
                    "secrets_add.html",
                    {
                        "error": "Both name and secret are required",
                    },
                    request=request,
                ),
                status=400,
            )
        encryption_key = plugin_config["encryption_key"]
        key = Fernet(encryption_key.encode("utf-8"))
        encrypted = key.encrypt(secret.encode("utf-8"))
        encryption_key_name = "default"
        db = get_database(datasette)
        await db.execute_write(
            """
            insert into datasette_secrets (
                name, note, encrypted, encryption_key_name, created_at
            ) values (?, ?, ?, ?, datetime('now'))
            """,
            (name, note, encrypted, encryption_key_name),
        )
        datasette.add_message(request, "Secret {} added".format(name))
        return Response.redirect(request.path)

    return Response.html(
        await datasette.render_template("secrets_add.html", request=request)
    )


@hookimpl
def register_routes():
    return [
        (r"^/-/secrets$", secrets_index),
        (r"^/-/secrets/add$", secrets_add),
    ]
