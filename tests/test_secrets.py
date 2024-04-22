from click.testing import CliRunner
from cryptography.fernet import Fernet
from datasette.cli import cli


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
