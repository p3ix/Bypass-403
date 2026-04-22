from typer.testing import CliRunner

from bypass.cli import app

runner = CliRunner()


def test_list_command_works() -> None:
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "Mutaciones de ruta" in result.stdout


def test_probe_help_contains_profiles() -> None:
    result = runner.invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    assert "--profile" in result.stdout
    assert "all" in result.stdout
    assert "--host-fuzz" in result.stdout
    assert "--smuggling-lite" in result.stdout


def test_replay_help_contains_advanced_flags() -> None:
    result = runner.invoke(app, ["replay", "--help"])
    assert result.exit_code == 0
    assert "--min-confidence" in result.stdout
    assert "--replay-methods" in result.stdout
