"""Smoke tests — verify the package imports and CLI is wired up."""

from typer.testing import CliRunner

from ioc_hunter import __version__
from ioc_hunter.cli import app

runner = CliRunner()


def test_version_constant() -> None:
    assert __version__ == "0.2.0"


def test_cli_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ioc-hunter" in result.stdout.lower()
