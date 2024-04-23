from click.testing import CliRunner
from cryptography.fernet import Fernet
from datasette.app import Datasette
from datasette.cli import cli
from datasette_secrets import get_secret
import pytest
from unittest.mock import ANY

TEST_ENCRYPTION_KEY = "-LujHtwFWGaBpznrV1zduoZBmCnMOW7J0H5hmeXgAVo="


def test_generate_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["secrets", "generate-encryption-key"])
    assert result.exit_code == 0
    key = result.output.strip()
    key_bytes = key.encode("utf-8")
    # This will throw an exception if key is invalid:
    key = Fernet(key_bytes)
    message = b"Secret message"
    assert key.decrypt(key.encrypt(message)) == message


@pytest.fixture
def ds():
    return Datasette(
        config={
            "plugins": {
                "datasette-secrets": {
                    "database": "_internal",
                    "encryption-key": TEST_ENCRYPTION_KEY,
                }
            },
            "permissions": {"manage-secrets": {"id": "admin"}},
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,verb,data",
    (
        ("/-/secrets", "GET", None),
        ("/-/secrets/EXAMPLE_SECRET", "GET", None),
    ),
)
@pytest.mark.parametrize("user", (None, "admin", "other"))
async def test_permissions(ds, path, verb, data, user):
    method = ds.client.get if verb == "GET" else ds.client.post
    kwargs = {}
    if user:
        kwargs["cookies"] = {
            "ds_actor": ds.client.actor_cookie({"id": user}),
        }
    if data:
        kwargs["data"] = data
    response = await method(path, **kwargs)
    if user == "admin":
        assert response.status_code != 403
        # And check they have the menu item too
        assert '<a href="/-/secrets">Manage secrets</a>' in response.text
    else:
        assert response.status_code == 403
        assert '<a href="/-/secrets">Manage secrets</a>' not in response.text


@pytest.mark.asyncio
async def test_set_secret(ds):
    cookies = {"ds_actor": ds.client.actor_cookie({"id": "admin"})}
    get_response = await ds.client.get("/-/secrets/EXAMPLE_SECRET", cookies=cookies)
    csrftoken = get_response.cookies["ds_csrftoken"]
    cookies["ds_csrftoken"] = csrftoken
    post_response = await ds.client.post(
        "/-/secrets/EXAMPLE_SECRET",
        cookies=cookies,
        data={"secret": "new-secret-value", "note": "new-note", "csrftoken": csrftoken},
    )
    assert post_response.status_code == 302
    assert post_response.headers["Location"] == "/-/secrets"
    internal_db = ds.get_internal_database()
    secrets = await internal_db.execute("select * from datasette_secrets")
    rows = [dict(r) for r in secrets.rows]
    assert rows == [
        {
            "id": 1,
            "name": "EXAMPLE_SECRET",
            "note": "new-note",
            "version": 1,
            "encrypted": ANY,
            "encryption_key_name": "default",
            "created_at": ANY,
            "created_by": "admin",
            "updated_at": ANY,
            "updated_by": "admin",
            "deleted_at": None,
            "deleted_by": None,
            "last_used_at": None,
            "last_used_by": None,
        }
    ]
    # Decrypt the secret
    key = Fernet(TEST_ENCRYPTION_KEY.encode("utf-8"))
    encrypted = rows[0]["encrypted"]
    decrypted = key.decrypt(encrypted)
    assert decrypted == b"new-secret-value"

    # Now let's edit it
    post_response2 = await ds.client.post(
        "/-/secrets/EXAMPLE_SECRET",
        cookies=cookies,
        data={"secret": "updated-secret-value", "note": "", "csrftoken": csrftoken},
    )
    assert post_response2.status_code == 302
    assert post_response2.headers["Location"] == "/-/secrets"
    secrets2 = await internal_db.execute("select * from datasette_secrets")
    rows2 = [dict(r) for r in secrets2.rows]
    assert len(rows2) == 2
    # Should be version 1 and version 2
    versions = {row["version"] for row in rows2}
    assert versions == {1, 2}
    # Version 2 should be the latest
    latest = [row for row in rows2 if row["version"] == 2][0]
    assert latest == {
        "id": 2,
        "name": "EXAMPLE_SECRET",
        "note": "",
        "version": 2,
        "encrypted": ANY,
        "encryption_key_name": "default",
        "created_at": ANY,
        "created_by": "admin",
        "updated_at": ANY,
        "updated_by": "admin",
        "deleted_at": None,
        "deleted_by": None,
        "last_used_at": None,
        "last_used_by": None,
    }


@pytest.mark.asyncio
async def test_get_secret(ds, monkeypatch):
    # First set it manually
    cookies = {"ds_actor": ds.client.actor_cookie({"id": "admin"})}
    get_response = await ds.client.get("/-/secrets/EXAMPLE_SECRET", cookies=cookies)
    csrftoken = get_response.cookies["ds_csrftoken"]
    cookies["ds_csrftoken"] = csrftoken
    db = ds.get_internal_database()
    # Reset state
    await db.execute_write(
        "update datasette_secrets set last_used_at = null, last_used_by = null"
    )
    post_response = await ds.client.post(
        "/-/secrets/EXAMPLE_SECRET",
        cookies=cookies,
        data={
            "secret": "manually-set-secret",
            "note": "new-note",
            "csrftoken": csrftoken,
        },
    )
    assert post_response.status_code == 302

    assert await get_secret(ds, "EXAMPLE_SECRET", "actor") == "manually-set-secret"

    # Should have updated last_used_at and last_used_by
    secret = (
        await db.execute(
            "select * from datasette_secrets where name = ? order by version desc limit 1",
            ["EXAMPLE_SECRET"],
        )
    ).first()
    assert secret["last_used_by"] == "actor"
    assert secret["last_used_at"] is not None

    # Calling again without actor ID should set that to null
    assert await get_secret(ds, "EXAMPLE_SECRET") == "manually-set-secret"
    secret2 = (
        await db.execute(
            "select * from datasette_secrets where name = ? order by version desc limit 1",
            ["EXAMPLE_SECRET"],
        )
    ).first()
    assert secret2["last_used_by"] is None

    # Now over-ride with an environment variable
    monkeypatch.setenv("DATASETTE_SECRETS_EXAMPLE_SECRET", "from env")

    assert await get_secret(ds, "EXAMPLE_SECRET") == "from env"
