import click
from cryptography.fernet import Fernet
import dataclasses
from datasette import hookimpl, Forbidden, Permission, Response
from datasette.plugins import pm
from datasette.utils import await_me_maybe
import os
from typing import Optional
from . import hookspecs

MAX_NOTE_LENGTH = 100

pm.add_hookspecs(hookspecs)


@dataclasses.dataclass
class Secret:
    name: str
    description_html: Optional[str] = None
    is_environment: bool = False
    is_set_in_database: bool = False
    version: Optional[int] = None
    note: Optional[str] = None
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: Optional[str] = None
    created_by: Optional[str] = None
    deleted_at: Optional[str] = None
    deleted_by: Optional[str] = None
    last_used_at: Optional[str] = None
    last_used_by: Optional[str] = None


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
    # if not secrets:
    secrets.append(Secret("EXAMPLE_SECRET", "An example secret"))

    return secrets


@hookimpl
def register_secrets():
    return [
        Secret(
            "OPENAI_API_KEY",
            'An OpenAI API key. Get them from <a href="https://platform.openai.com/api-keys">here</a>.',
        ),
    ]


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
    all_secrets = await get_secrets(datasette)

    environment_secrets = []
    for secret in all_secrets:
        if os.environ.get("DATASETTE_SECRETS_{}".format(secret.name)):
            environment_secrets.append(secret)
    environment_secrets_names = {secret.name for secret in environment_secrets}

    db = get_database(datasette)
    existing_secrets_result = await db.execute(
        """
        select name, max(version) as version, updated_at, updated_by, note
        from datasette_secrets
        where name not in ({})
        group by name
        """.format(
            ", ".join("?" for _ in environment_secrets_names)
        ),
        list(environment_secrets_names),
    )
    existing_secrets = {row["name"]: dict(row) for row in existing_secrets_result.rows}
    unset_secrets = [
        secret
        for secret in all_secrets
        if secret.name not in existing_secrets
        and secret.name not in environment_secrets_names
    ]
    return Response.html(
        await datasette.render_template(
            "secrets_index.html",
            {
                "existing_secrets": existing_secrets.values(),
                "unset_secrets": unset_secrets,
                "environment_secrets": environment_secrets,
            },
            request=request,
        )
    )


async def secrets_update(datasette, request):
    if not await datasette.permission_allowed(request.actor, "manage-secrets"):
        raise Forbidden("Permission denied")
    plugin_config = config(datasette)
    if not plugin_config:
        return Response.html("datasette-secrets has not been configured", status=400)

    secret_name = request.url_vars["secret_name"]

    # Try and find a secret matching this name
    secret_details = None
    secrets = await get_secrets(datasette)
    for s in secrets:
        if s.name == secret_name:
            secret_details = s
            break

    db = get_database(datasette)

    current_secret = (
        await db.execute(
            """
        select * from datasette_secrets
        where name = ?
        order by version desc limit 1
        """,
            (secret_name,),
        )
    ).first()

    if request.method == "POST":
        data = await request.post_vars()
        secret = (data.get("secret") or "").strip()
        note = data.get("note") or ""
        if len(note) > MAX_NOTE_LENGTH:
            datasette.add_message(request, "Note is too long", datasette.ERROR)
            return Response.redirect(request.path)

        # Secret is required if adding
        if not secret:
            if current_secret:
                # Update the note
                await db.execute_write(
                    """
                    update datasette_secrets
                    set note = ?,
                        updated_at = datetime('now'),
                        updated_by = ?
                    where id = ?
                    """,
                    (note, request.actor.get("id"), current_secret["id"]),
                )
                if note and note != current_secret["note"]:
                    datasette.add_message(
                        request, "Note updated: {}".format(secret_name)
                    )
                return Response.redirect(datasette.urls.path("/-/secrets"))
            else:
                datasette.add_message(request, "Secret is required", datasette.ERROR)
                return Response.redirect(request.path)

        encryption_key = plugin_config["encryption_key"]
        key = Fernet(encryption_key.encode("utf-8"))
        encrypted = key.encrypt(secret.encode("utf-8"))
        encryption_key_name = "default"
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
            "secrets_update.html",
            {
                "secret_name": secret_name,
                "secret_details": secret_details,
                "current_secret": current_secret,
                "max_note_length": MAX_NOTE_LENGTH,
            },
            request=request,
        )
    )


@hookimpl
def register_routes():
    return [
        (r"^/-/secrets$", secrets_index),
        (r"^/-/secrets/(?P<secret_name>[^/]+)$", secrets_update),
    ]
