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
## Usage

Usage instructions go here.

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
