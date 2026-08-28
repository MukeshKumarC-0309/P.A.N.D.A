"""Tests for the [live] source availability logic.

These need no splunk-sdk and no Splunk: importing panda_tdr.live must not pull
in splunklib (it's imported lazily inside load_live), and live_available() is
pure env + import probing. Actually pulling from Splunk is out of scope here —
that needs the lab up; the bridge's live path is exercised with an injected
loader in test_bridge.py.
"""
from panda_tdr import live


def test_import_does_not_require_splunklib():
    # If importing the module required the SDK, collection would already fail.
    assert hasattr(live, "load_live") and hasattr(live, "live_available")


def test_unavailable_without_credentials(monkeypatch):
    monkeypatch.delenv("SPLUNK_USER", raising=False)
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    assert live.live_available() is False


def test_unavailable_when_sdk_missing_even_with_credentials(monkeypatch):
    # Credentials present but splunk-sdk not installed in this env -> still False
    # (the import probe fails), so a live request degrades to the snapshot.
    monkeypatch.setenv("SPLUNK_USER", "u")
    monkeypatch.setenv("SPLUNK_PASSWORD", "p")
    import importlib
    if importlib.util.find_spec("splunklib") is not None:
        import pytest
        pytest.skip("splunk-sdk installed; the SDK-missing branch can't be exercised here")
    assert live.live_available() is False
