from click.testing import CliRunner
from cryptography.fernet import Fernet
from datasette import hookimpl
from datasette.cli import cli
from datasette.plugins import pm
from datasette_test import Datasette, actor_cookie
from datasette_secrets import get_secret, Secret, startup, get_config
import pytest
from unittest.mock import ANY

TEST_ENCRYPTION_KEY = "-LujHtwFWGaBpznrV1zduoZBmCnMOW7J0H5hmeXgAVo="


def get_internal_database(ds):
    if hasattr(ds, "get_internal_database"):
        return ds.get_internal_database()
    else:
        return ds.get_database("_internal")


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
def use_actors_plugin():
    class ActorPlugin:
        __name__ = "ActorPlugin"

        @hookimpl
        def actors_from_ids(self, actor_ids):
            return {
                id: {
                    "id": id,
                    "username": id.upper(),
                }
                for id in actor_ids
            }

    pm.register(ActorPlugin(), name="ActorPlugin")
    yield
    pm.unregister(name="ActorPlugin")


@pytest.fixture
def register_multiple_secrets():
    class SecretOnePlugin:
        __name__ = "SecretOnePlugin"

        @hookimpl
        def register_secrets(self):
            return [
                Secret(
                    name="OPENAI_API_KEY",
                    obtain_url="https://platform.openai.com/api-keys",
                    obtain_label="Get an OpenAI API key",
                ),
                Secret(
                    name="ANTHROPIC_API_KEY", description="A key for Anthropic's API"
                ),
            ]

    class SecretTwoPlugin:
        __name__ = "SecretTwoPlugin"

        @hookimpl
        def register_secrets(self):
            return [
                Secret(
                    name="OPENAI_API_KEY",
                    description="Just a description but should be ignored",
                ),
                Secret(
                    name="OPENCAGE_API_KEY",
                    description="The OpenCage Geocoder",
                    obtain_url="https://opencagedata.com/dashboard",
                    obtain_label="Get an OpenCage API key",
                ),
            ]

    pm.register(SecretTwoPlugin(), name="SecretTwoPlugin")
    pm.register(SecretOnePlugin(), name="SecretOnePlugin")
    yield
    pm.unregister(name="SecretOnePlugin")
    pm.unregister(name="SecretTwoPlugin")


@pytest.fixture
def ds():
    return Datasette(
        plugin_config={
            "datasette-secrets": {
                "database": "_internal",
                "encryption-key": TEST_ENCRYPTION_KEY,
            }
        },
        permissions={"manage-secrets": {"id": "admin"}},
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
            "ds_actor": actor_cookie(ds, {"id": user}),
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
async def test_set_secret(ds, use_actors_plugin):
    cookies = {"ds_actor": actor_cookie(ds, {"id": "admin"})}
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
    internal_db = get_internal_database(ds)
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

    # Check that the listing is as expected, including showing the actor username
    response = await ds.client.get("/-/secrets", cookies=cookies)
    assert response.status_code == 200
    assert "EXAMPLE_SECRET" in response.text
    assert "new-note" in response.text

    if hasattr(ds, "actors_from_ids"):
        assert "<td>ADMIN</td>" in response.text
    else:
        # Pre 1.0, so can't use that mechanism
        assert "<td>admin</td>" in response.text

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
    cookies = {"ds_actor": actor_cookie(ds, {"id": "admin"})}
    get_response = await ds.client.get("/-/secrets/EXAMPLE_SECRET", cookies=cookies)
    csrftoken = get_response.cookies["ds_csrftoken"]
    cookies["ds_csrftoken"] = csrftoken
    db = get_internal_database(ds)
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

    # And check that it's shown that way on the /-/secrets page
    response = await ds.client.get("/-/secrets", cookies=cookies)
    assert response.status_code == 200
    expected_html = """
    <li><strong>EXAMPLE_SECRET</a></strong> - An example secret<br>
      <span style="font-size: 0.8 em">Set by <code>DATASETTE_SECRETS_EXAMPLE_SECRET</code></span></li>
    """
    assert remove_whitespace(expected_html) in remove_whitespace(response.text)

    # Finally it should still work even if the datasette_secrets table is missing
    await db.execute_write("drop table datasette_secrets")
    monkeypatch.delenv("DATASETTE_SECRETS_EXAMPLE_SECRET")
    assert await get_secret(ds, "EXAMPLE_SECRET") is None


@pytest.mark.asyncio
async def test_if_not_configured(register_multiple_secrets):
    ds = Datasette()
    config = get_config(ds)
    assert config is None
    assert await get_secret(ds, "OPENAI_API_KEY") is None


@pytest.mark.asyncio
async def test_secret_index_page(ds, register_multiple_secrets):
    response = await ds.client.get(
        "/-/secrets",
        cookies={
            "ds_actor": actor_cookie(ds, {"id": "admin"}),
        },
    )
    assert response.status_code == 200
    expected_html = """
    <p style="margin-top: 2em">The following secrets have not been set:</p>
    <ul>
        <li><strong><a href="/-/secrets/OPENAI_API_KEY">OPENAI_API_KEY</a></strong>
        -
        <a href="https://platform.openai.com/api-keys">Get an OpenAI API key</a>
        </li>
        <li><strong><a href="/-/secrets/ANTHROPIC_API_KEY">ANTHROPIC_API_KEY</a></strong>
        - A key for Anthropic&#39;s API
        </li>
        <li><strong><a href="/-/secrets/OPENCAGE_API_KEY">OPENCAGE_API_KEY</a></strong>
        - The OpenCage Geocoder,
        <a href="https://opencagedata.com/dashboard">Get an OpenCage API key</a>
        </li>
        <li><strong><a href="/-/secrets/EXAMPLE_SECRET">EXAMPLE_SECRET</a></strong>
        - An example secret
        </li>
    </ul>
    """
    assert remove_whitespace(expected_html) in remove_whitespace(response.text)


def remove_whitespace(s):
    return " ".join(s.split())
