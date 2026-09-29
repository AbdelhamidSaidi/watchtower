"""Secrets resolve from files first, and never silently from nowhere."""

import config


def test_file_wins_over_env(tmp_path, monkeypatch):
    secret = tmp_path / "s"
    secret.write_text("from-file\n")
    monkeypatch.setenv("TOKEN_FILE", str(secret))
    monkeypatch.setenv("TOKEN", "from-env")
    assert config.read_secret("TOKEN") == "from-file"


def test_env_is_a_last_resort_and_warns(monkeypatch, capsys):
    monkeypatch.delenv("TOKEN_FILE", raising=False)
    monkeypatch.setenv("TOKEN", "from-env")
    assert config.read_secret("TOKEN") == "from-env"
    assert "plain environment variable" in capsys.readouterr().err


def test_unreadable_file_degrades_to_default(monkeypatch):
    monkeypatch.setenv("TOKEN_FILE", "/nonexistent/secret")
    assert config.read_secret("TOKEN", default=None) is None


def test_secret_value_is_never_printed(tmp_path, monkeypatch, capsys):
    secret = tmp_path / "s"
    secret.write_text("sk-very-secret")
    monkeypatch.setenv("TOKEN_FILE", str(secret))
    config.read_secret("TOKEN")
    captured = capsys.readouterr()
    assert "sk-very-secret" not in captured.out + captured.err

