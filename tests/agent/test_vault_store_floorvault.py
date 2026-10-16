"""FloorVault store (``vault.store: floorvault``): same contract as the Fernet ``VaultStore``,
contextual binding, fail-closed key custody, and the Fernet -> FloorVault migration."""

import secrets
import sqlite3
from unittest.mock import patch

import pytest

pytest.importorskip("floorvault")

from floorvault import FloorVault

from agent.vault_store import VaultError, VaultItemMeta, VaultStore
from agent.vault_store_floorvault import (
    APP_INSTANCE_ID,
    FloorVaultStore,
    migrate_from_fernet,
)

LOGIN = {"identifier_type": "email", "identifier": "u@example.com", "password": "hunter2-pw",
         "otp_secret": "JBSWY3DPEHPK3PXP"}
CARD = {"card_number": "4111111111111111", "exp_month": "12", "exp_year": "2030", "cvc": "123"}


def _store(path, key=None) -> FloorVaultStore:
    crypto = FloorVault(key or secrets.token_bytes(32), app_instance_id=APP_INSTANCE_ID)
    return FloorVaultStore(path, crypto=crypto)


def test_crud_matches_fernet_contract(tmp_path):
    store = _store(tmp_path / "vault")
    login = store.add_item("login", "Example", dict(LOGIN), origin="https://example.com:443/login")
    card = store.add_item("payment", "Visa", dict(CARD))

    assert isinstance(login, VaultItemMeta) and login.id.startswith("vault_")
    assert login.origin == "https://example.com" and login.identifier == "u@example.com" and login.has_otp
    assert {m.id for m in store.list_items()} == {login.id, card.id}
    assert store.resolve_secret(login.id) == {"password": "hunter2-pw", "otp_secret": "JBSWY3DPEHPK3PXP"}
    assert store.resolve_secret(card.id) == CARD
    assert store.get_meta("vault_missing") is None
    assert store.remove_item(card.id) and not store.remove_item(card.id)
    assert store.has_items()


def test_nothing_sensitive_is_stored_in_plaintext(tmp_path):
    store = _store(tmp_path / "vault")
    store.add_item("login", "Example label", dict(LOGIN), origin="https://example.com")
    blob = (tmp_path / "vault" / "vault.db").read_bytes()
    for needle in (b"hunter2-pw", b"JBSWY3DPEHPK3PXP", b"u@example.com", b"example.com", b"Example label"):
        assert needle not in blob


def test_ciphertext_moved_to_another_record_fails_closed(tmp_path):
    store = _store(tmp_path / "vault")
    a = store.add_item("login", "A", dict(LOGIN), origin="https://a.example")
    b = store.add_item("login", "B", {**LOGIN, "password": "other"}, origin="https://b.example")
    with sqlite3.connect(tmp_path / "vault" / "vault.db") as conn:
        conn.execute("UPDATE vault_items SET payload_cipher = (SELECT payload_cipher FROM vault_items WHERE id = ?)"
                     " WHERE id = ?", (a.id, b.id))
    with pytest.raises(VaultError, match="failed authentication"):
        store.resolve_secret(b.id)


def test_wrong_key_cannot_read(tmp_path):
    item = _store(tmp_path / "vault").add_item("login", "A", dict(LOGIN), origin="https://a.example")
    with pytest.raises(VaultError):
        _store(tmp_path / "vault").resolve_secret(item.id)


def test_validation_errors_are_vault_errors(tmp_path):
    store = _store(tmp_path / "vault")
    with pytest.raises(VaultError):
        store.add_item("login", "No origin", dict(LOGIN))
    with pytest.raises(VaultError):
        store.add_item("payment", "Partial", {"card_number": "4111"})


def test_headless_without_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("FLOOR_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    with patch("floorvault.providers.adaptive.AdaptiveKeyProvider.resolve_key",
               side_effect=__import__("floorvault").KeyProviderError("no OS key store")):
        with pytest.raises(VaultError, match="master key unavailable"):
            FloorVaultStore(tmp_path / "vault")
    assert not list((tmp_path / "vault").glob("*.key"))


def test_env_key_override(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOOR_VAULT_KEY", secrets.token_hex(32))
    item = FloorVaultStore(tmp_path / "vault").add_item("login", "A", dict(LOGIN), origin="https://a.example")
    assert FloorVaultStore(tmp_path / "vault").resolve_secret(item.id)["password"] == "hunter2-pw"


def test_malformed_env_key_reports_the_real_cause(tmp_path, monkeypatch):
    # A set-but-malformed key must not read back as "is not set": the mapped
    # VaultError keeps floorvault's own message, which names the fix.
    monkeypatch.delenv("APPSTATE_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    monkeypatch.setenv("FLOOR_VAULT_KEY", "not-hex")
    with pytest.raises(VaultError, match="64 hexadecimal"):
        FloorVaultStore(tmp_path / "vault")


def test_generic_kind_is_rejected(tmp_path):
    # floorvault accepts a 4th kind ("generic") the Fernet store never writes;
    # letting it through would strand a ghost item if the user reverts.
    store = _store(tmp_path / "vault")
    with pytest.raises(VaultError, match="unknown vault kind"):
        store.add_item("generic", "G", {"anything": "goes"})


def test_has_items_swallows_failures_like_fernet(tmp_path, monkeypatch):
    store = _store(tmp_path / "vault")
    monkeypatch.setattr(store._store, "has_items",
                        lambda: (_ for _ in ()).throw(Exception("db gone")))
    assert store.has_items() is False


@pytest.mark.platforms("posix")
def test_vault_db_is_owner_only(tmp_path):
    _store(tmp_path / "vault")
    import stat
    assert stat.S_IMODE((tmp_path / "vault" / "vault.db").stat().st_mode) == 0o600


def test_vault_store_key_is_a_known_config_key():
    # Without the registry entry, `hermes config set/get vault.store` warns the
    # key is unrecognized even though the runtime reads it.
    from hermes_cli.config import _validate_config_key
    assert _validate_config_key("vault.store") == (True, None)


def test_config_selects_store(tmp_path, monkeypatch):
    import agent.vault_store as vs
    import agent.vault_store_floorvault as fv

    monkeypatch.setattr(vs, "get_hermes_home", lambda: str(tmp_path))
    monkeypatch.setattr(vs, "configured_store_name", lambda: "floorvault")
    sentinel = object()
    monkeypatch.setattr(fv, "get_floorvault_store", lambda base: sentinel if base == tmp_path / "vault" else None)
    assert vs.get_vault_store() is sentinel
    monkeypatch.setattr(vs, "configured_store_name", lambda: "fernet")
    assert isinstance(vs.get_vault_store(), VaultStore)


def test_unknown_store_name_is_rejected(monkeypatch):
    import agent.vault_store as vs

    monkeypatch.setattr("hermes_cli.config.load_config_readonly", lambda: {"vault": {"store": "plaintext"}})
    with pytest.raises(VaultError, match="unknown vault.store"):
        vs.configured_store_name()


def test_migration_keeps_handles_and_verifies(tmp_path):
    legacy = VaultStore(tmp_path / "vault")
    login = legacy.add_item("login", "Example", dict(LOGIN), origin="https://example.com")
    card = legacy.add_item("payment", "Visa", dict(CARD))
    target = _store(tmp_path / "vault")

    result = migrate_from_fernet(legacy, target)
    assert result == {"total": 2, "copied": 2, "skipped": 0, "verified": True}
    assert target.resolve_secret(login.id) == legacy.resolve_secret(login.id)
    assert target.resolve_secret(card.id) == CARD
    assert target.get_meta(login.id).identifier == "u@example.com"
    # Legacy files are untouched; a rerun is a no-op.
    assert legacy.resolve_secret(login.id)["password"] == "hunter2-pw"
    assert migrate_from_fernet(legacy, target) == {"total": 2, "copied": 0, "skipped": 2, "verified": True}


def test_migration_reports_mismatch(tmp_path):
    legacy = VaultStore(tmp_path / "vault")
    login = legacy.add_item("login", "Example", dict(LOGIN), origin="https://example.com")
    target = _store(tmp_path / "vault")
    target.add_item("login", "Example", {**LOGIN, "password": "different"}, origin="https://example.com",
                    item_id=login.id)
    assert migrate_from_fernet(legacy, target)["verified"] is False


def test_migration_detects_label_mismatch(tmp_path):
    legacy = VaultStore(tmp_path / "vault")
    login = legacy.add_item("login", "Example", dict(LOGIN), origin="https://example.com")
    target = _store(tmp_path / "vault")
    target.add_item("login", "Different label", dict(LOGIN), origin="https://example.com",
                    item_id=login.id)
    assert migrate_from_fernet(legacy, target)["verified"] is False
