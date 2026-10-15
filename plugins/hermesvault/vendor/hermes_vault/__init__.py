"""hermes-vault: Hardened, contextual, misuse-resistant credential vault for Hermes Agent."""

from __future__ import annotations

from .core import (
    AppStateCrypto,
    AppStateCryptoError,
    DecryptionVerificationError,
    FloorVault,
    FloorVaultError,
    HermesVault,
    HermesVaultError,
    NonceReuseError,
    associated_data,
)
from .key_recovery import recover_master_key, wrap_master_key
from .keyring import KeyRing, UnknownKeyIdError
from .memory import (
    HardenedMemoryKey,
    SecurityHardeningError,
    disable_core_dumps,
)
from .migration import LegacyRetiredError, LegacyVaultError, MigratingVaultStore
from .providers.adaptive import AdaptiveKeyProvider
from .providers.base import KeyProvider, KeyProviderError, MissingKeyError
from .sqlite_adapter import ContextualSQLite, ContextualTable, EncryptedSQLiteTable
from .sqlite_migration import migrate_plaintext_column, verify_encrypted_column
from .store import (
    HermesVaultStore,
    VaultError,
    VaultItemMeta,
    VaultStore,
    get_vault_store,
)
from .vault_rotation import rotate_vault_store

__version__ = "0.1.0"

__all__ = [
    # Hermes Vault First-Class Surface
    "HermesVault",
    "HermesVaultError",
    "HermesVaultStore",
    "VaultStore",
    "VaultItemMeta",
    "VaultError",
    "get_vault_store",
    # Core Cryptography
    "FloorVault",
    "FloorVaultError",
    "AppStateCrypto",
    "AppStateCryptoError",
    "DecryptionVerificationError",
    "NonceReuseError",
    "associated_data",
    # Hardware Memory Custody
    "HardenedMemoryKey",
    "SecurityHardeningError",
    "disable_core_dumps",
    # SQLite Helpers
    "ContextualSQLite",
    "ContextualTable",
    "EncryptedSQLiteTable",
    "migrate_plaintext_column",
    "verify_encrypted_column",
    "rotate_vault_store",
    # Key Providers
    "KeyProvider",
    "KeyProviderError",
    "MissingKeyError",
    "AdaptiveKeyProvider",
    # Lazy Migration
    "MigratingVaultStore",
    "LegacyVaultError",
    "LegacyRetiredError",
    # Multi-generation reads (rotation)
    "KeyRing",
    "UnknownKeyIdError",
    "wrap_master_key",
    "recover_master_key",
]
