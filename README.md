# datasette-secrets

[![PyPI](https://img.shields.io/pypi/v/datasette-secrets.svg)](https://pypi.org/project/datasette-secrets/)
[![Changelog](https://img.shields.io/github/v/release/datasette/datasette-secrets?include_prereleases&label=changelog)](https://github.com/datasette/datasette-secrets/releases)
[![Tests](https://github.com/datasette/datasette-secrets/actions/workflows/test.yml/badge.svg)](https://github.com/datasette/datasette-secrets/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/datasette/datasette-secrets/blob/main/LICENSE)

Manage secrets such as API keys for use with other Datasette plugins

## Installation

Install this plugin in the same environment as Datasette.
```bash
datasette install datasette-secrets
```
## Configuration

First you will need to generate an encryption key for this plugin to use. Run this command:

```bash
datasette secrets generate-encryption-key
```
Store this secret somewhere secure. It will be used to both encrypt and decrypt secrets stored by this plugin - if you lose it you will not be able to recover your secrets.

## Usage

TODO

## For plugin authors

Plugins can depend on this plugin if they want to implement secrets.

`datasette-secrets` to the `dependencies` list in `pyproject.toml`.

Then declare the name and description of any secrets you need using the `register_secrets()` plugin hook:

```python
from datasette import hookimpl
from datasette_secrets import Secret


@hookimpl
def register_secrets():
    return [
        Secret(
            "OPENAI_API_KEY",
            'An OpenAI API key. Get them from <a href="https://platform.openai.com/api-keys">here</a>.',
        ),
    ]
```
The hook can take an optional `datasette` argument. It can return a list or an `async def` function that, when awaited, returns a list.

The list should consist of `Secret()` instances, each with a name and an optional description. The description can contain HTML.

To obtain the current value of the secret, use the `await get_secret()` method:

```python
from datasette_secrets import get_secret


secret = await get_secret(datasette, "OPENAI_API_KEY")
```
If the Datasette administrator set a `DATASETTE_SECRETS_OPENAI_API_KEY` environment variable, that will be returned.

Otherwise the encrypted value in the database table will be decrypted and returned - or `None` if there is no configured secret.


## Development

To set up this plugin locally, first checkout the code. Then create a new virtual environment:
```bash
cd datasette-secrets
python3 -m venv venv
source venv/bin/activate
```
Now install the dependencies and test dependencies:
```bash
pip install -e '.[test]'
```
To run the tests:
```bash
pytest
```
