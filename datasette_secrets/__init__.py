import click
from cryptography.fernet import Fernet
from datasette import hookimpl, Forbidden, Permission, Response
from datasette.plugins import pm
from datasette.utils import await_me_maybe
from . import hookspecs

pm.add_hookspecs(hookspecs)


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
def register_permissions(datasette):
    return [
        Permission(
            name="manage-secrets",
            abbr=None,
            description="Manage Datasette secrets",
            takes_database=False,
            takes_resource=False,
            default=False,
        )
    ]


async def get_secrets(datasette):
    secrets = []
    for result in pm.hook.register_secrets(datasette=datasette):
        result = await await_me_maybe(result)
        secrets.extend(result)
    return secrets


@hookimpl
def register_secrets():
    return [{"name": "EXAMPLE_SECRET"}]


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


async def secrets_index(datasette, request):
    if not await datasette.permission_allowed(request.actor, "manage-secrets"):
        raise Forbidden("Permission denied")
    secrets = await get_secrets(datasette)
    return Response.html(
        await datasette.render_template(
            "secrets_index.html",
            {
                "secrets": secrets,
            },
            request=request
        )
    )


async def secrets_update(datasette, request):
    if not await datasette.permission_allowed(request.actor, "manage-secrets"):
        raise Forbidden("Permission denied")
    plugin_config = config(datasette)
    if not plugin_config:
        return Response.html("datasette-secrets has not been configured", status=400)

    secret_name = request.url_vars["secret_name"]

    if request.method == "POST":
        data = await request.post_vars()
        secret = (data.get("secret") or "").strip()
        note = data.get("note") or ""
        if not secret:
            return Response.html(
                await datasette.render_template(
                    "secrets_update.html",
                    {
                        "error": "secret is required",
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
        actor_id = request.actor.get("id")
        await db.execute_write(
            """
            insert into datasette_secrets (
                name, version, note, encrypted, encryption_key_name,
                created_at, created_by, updated_at, updated_by
            ) values (
                ?,
                coalesce((select max(version) + 1 from datasette_secrets where name = ?), 1),
                ?,
                ?,
                ?,
                -- created_at, created_by
                datetime('now'), ?,
                -- updated_at, updated_by
                datetime('now'), ?
            )
            """,
            (
                secret_name,
                secret_name,
                note,
                encrypted,
                encryption_key_name,
                actor_id,
                actor_id,
            ),
        )
        datasette.add_message(request, "Secret {} updated".format(secret_name))
        return Response.redirect(datasette.urls.path("/-/secrets"))

    return Response.html(
        await datasette.render_template(
            "secrets_update.html", {"secret_name": secret_name}, request=request
        )
    )


@hookimpl
def register_routes():
    return [
        (r"^/-/secrets$", secrets_index),
        (r"^/-/secrets/(?P<secret_name>[^/]+)$", secrets_update),
    ]
