"""Tests for the styled console I/O (panda.system).

Styling must never change the substance: the banner still names the product and
help still lists every command, whether or not color/unicode are active. (Under
pytest, stdout isn't a tty, so these run with color off.)
"""
import builtins

from panda import system


def test_banner_names_the_product(capsys):
    system.banner()
    assert "P.A.N.D.A" in capsys.readouterr().out


def test_help_lists_every_command(capsys):
    system.help()
    out = capsys.readouterr().out
    for name in ("VAULT", "TDR", "CASES", "SET", "CHANGE", "HELP", "QUIT", "COMMANDS"):
        assert name in out


def test_takecommand_returns_the_input(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "hello world")
    assert system.takecommand() == "hello world"
