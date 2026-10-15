"""Tests for the hermesvault plugin — real store, real SecretSource contract.

Covers the bundled plugin at ``plugins/hermesvault/``:

  * ``source.py``: ``hv:<item>[:field]`` ref parsing, ``secrets.hermesvault.env``
    mapping, fail-closed warnings, store dir resolution (never the login vault).
  * ``__init__.register``: wires the ``hermesvault`` secret source and the
    ``hvault`` CLI command.
  * Custody: wrong-key access fails closed, ``HERMES_VAULT_KEY`` is protected.

``hermes_vault`` resolves from the plugin's own vendored copy at
``plugins/hermesvault/vendor/`` — the same path the plugin uses at runtime.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[2] / "plugins" / "hermesvault"
_VENDOR = str(PLUGIN_DIR / "vendor")
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

import hermes_vault  # noqa: E402

from agent.secret_sources.base import (  # noqa: E402
    ErrorKind,
    FetchResult,
    is_valid_env_name,
)
import agent.secret_sources.base as secret_base  # noqa: E402


def _load_plugin_pkg():
    """Import the plugin package the way PluginManager names it."""
    if "hermes_plugins" not in sys.modules:
        ns = types.ModuleType("hermes_plugins")
        ns.__path__ = []
        sys.modules["hermes_plugins"] = ns
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.hermesvault",
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "hermes_plugins.hermesvault"
    mod.__path__ = [str(PLUGIN_DIR)]
    sys.modules["hermes_plugins.hermesvault"] = mod
    spec.loader.exec_module(mod)
    return mod


_load_plugin_pkg()
from hermes_plugins.hermesvault.source import (  # noqa: E402
    HermesVaultSource,
    parse_ref,
    resolve_base_dir,
)

KEY = "00" * 32


@pytest.fixture()
def vault_home(tmp_path, monkeypatch):
    """A hermes home with a populated agent-vault store (env-var key custody)."""
    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    store_dir = tmp_path / "agent-vault"
    store = hermes_vault.get_vault_store(store_dir, auto_migrate=False)
    store.add_item(kind="generic", label="openai key", secret={"value": "sk-test-123"},
                   item_id="vault_testopenai")
    store.add_item(kind="generic", label="two fields",
                   secret={"user": "u1", "token": "tok-abc"}, item_id="vault_multi")
    return tmp_path


def fetch(home, cfg=None):
    cfg = {"enabled": True, "env": {}, **(cfg or {})}
    return HermesVaultSource().fetch(cfg, home)


def test_ref_parsing():
    assert parse_ref("hv:vault_abc123") == ("vault_abc123", None)
    assert parse_ref("hv:vault_abc123:token") == ("vault_abc123", "token")
    assert parse_ref("op://x") == (None, None)
    assert parse_ref("hv:") == (None, None)
    assert parse_ref("hv:bad id!") == (None, None)
    assert parse_ref(42) == (None, None)


def test_fetch_resolves_single_field_and_value(vault_home):
    result = fetch(vault_home, {"env": {"OPENAI_API_KEY": "hv:vault_testopenai"}})
    assert result.ok and result.secrets == {"OPENAI_API_KEY": "sk-test-123"}


def test_fetch_named_field(vault_home):
    result = fetch(vault_home, {"env": {"TG_TOKEN": "hv:vault_multi:token",
                                        "TG_USER": "hv:vault_multi:user"}})
    assert result.secrets == {"TG_TOKEN": "tok-abc", "TG_USER": "u1"}


def test_fetch_multi_field_without_name_warns(vault_home):
    result = fetch(vault_home, {"env": {"X": "hv:vault_multi"}})
    assert result.secrets == {} and result.ok
    assert any("vault_multi" in w and "field" in w for w in result.warnings)


def test_fetch_missing_item_warns_and_keeps_others(vault_home):
    result = fetch(vault_home, {"env": {"GONE": "hv:vault_nope",
                                        "HERE": "hv:vault_testopenai"}})
    assert result.secrets == {"HERE": "sk-test-123"}
    assert any("GONE" in w for w in result.warnings)


def test_fetch_bad_env_name_and_bad_ref_warn(vault_home):
    result = fetch(vault_home, {"env": {"1BAD": "hv:vault_testopenai",
                                        "OK_NAME": "not-a-ref"}})
    assert result.secrets == {}
    assert len(result.warnings) == 2


def test_fetch_malformed_env_section_fails_closed(vault_home):
    result = fetch(vault_home, {"env": "OPENAI_API_KEY=hv:x"})
    assert not result.ok and result.error_kind == ErrorKind.NOT_CONFIGURED


def test_fetch_empty_or_disabled_is_noop(vault_home):
    assert fetch(vault_home).ok and fetch(vault_home).secrets == {}
    assert fetch(vault_home, {"env": {}}).secrets == {}


def test_store_never_uses_login_vault_dir(vault_home):
    # The agent-secret store defaults to <home>/agent-vault, NOT <home>/vault —
    # auto_migrate=False additionally guarantees legacy vault.json.enc files are
    # never adopted into this store.
    assert resolve_base_dir({}, vault_home) == vault_home / "agent-vault"
    assert resolve_base_dir({"dir": "custom/secrets"}, vault_home) == vault_home / "custom/secrets"
    assert resolve_base_dir({"dir": "/abs/path"}, vault_home) == Path("/abs/path")


def test_bootstrap_key_is_protected():
    source = HermesVaultSource()
    assert source.protected_env_vars({}) == frozenset({"HERMES_VAULT_KEY"})
    assert source.protected_env_vars({"token_env": "MY_KEY"}) == frozenset({"MY_KEY"})


def test_source_contract_surface():
    source = HermesVaultSource()
    assert source.name == "hermesvault" and source.scheme == "hv" and source.shape == "mapped"
    assert source.api_version == secret_base.SECRET_SOURCE_API_VERSION
    assert is_valid_env_name("HERMES_VAULT_KEY")
    assert isinstance(source.fetch({}, Path("/nonexistent-home")), FetchResult)


def test_register_wires_source_and_cli():
    pkg = _load_plugin_pkg()
    calls = []
    ctx = type("Ctx", (), {
        "register_secret_source": lambda self, s: calls.append(("source", s.name)),
        "register_cli_command": lambda self, **kw: calls.append(("cli", kw["name"])),
    })()
    pkg.register(ctx)
    assert calls == [("source", "hermesvault"), ("cli", "hvault")]


def test_wrong_key_fails_closed_not_silent(tmp_path, monkeypatch):
    """A vault sealed under one key must not open under another."""
    monkeypatch.setenv("HERMES_VAULT_KEY", KEY)
    store = hermes_vault.get_vault_store(tmp_path / "agent-vault", auto_migrate=False)
    store.add_item(kind="generic", label="k", secret={"value": "v"}, item_id="vault_a")
    monkeypatch.setenv("HERMES_VAULT_KEY", "ff" * 32)
    result = HermesVaultSource().fetch({"enabled": True, "env": {"X": "hv:vault_a"}}, tmp_path)
    assert result.ok and result.secrets == {}
    assert result.warnings, "ciphertext under a different key must not resolve"
