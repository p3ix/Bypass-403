from typer.testing import CliRunner

from bypass.cli import app

runner = CliRunner()


def test_list_command_works() -> None:
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "Path mutations" in result.stdout


def test_probe_help_shows_options() -> None:
    result = runner.invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--rate" in result.stdout
    assert "--top" in result.stdout
    assert "-k" in result.stdout
    assert "--method" in result.stdout
    assert "--host" in result.stdout


def test_batch_help_works() -> None:
    result = runner.invoke(app, ["batch", "--help"])
    assert result.exit_code == 0
    assert "--out-dir" in result.stdout


def test_replay_help_works() -> None:
    result = runner.invoke(app, ["replay", "--help"])
    assert result.exit_code == 0
    assert "--min-confidence" in result.stdout
    assert "--max-targets" in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "bypass" in result.stdout.lower() or "usage" in result.stdout.lower()
