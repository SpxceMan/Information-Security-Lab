"""
client/key_manager.py
---------------------
Key management with ephemeral query-key lifecycle.

EXISTING TECHNIQUES:
    - Master key generation using OS entropy (standard practice)
    - HMAC-based key derivation (standard, see crypto/prf.py)

OUR ARCHITECTURAL INTEGRATION:
    - Ephemeral query-key lifecycle: temporary keys are created per-query
      and explicitly cleared after use.
    - This demonstrates key-lifecycle hardening, NOT a guarantee of
      secure memory erasure or cold-boot attack prevention.
"""

import os
import time
from crypto.utils import secure_random_bytes
from crypto.prf import derive_key, generate_query_key, generate_index_key
from crypto.encryption import derive_document_key


class EphemeralKeyHandle:
    """
    Handle for an ephemeral query key with explicit lifecycle.

    The key material is created for a single query and must be
    cleared after use via the clear() method.

    NOTE: This demonstrates the concept of key-lifecycle hardening.
    Python's garbage collector may not immediately overwrite memory.
    In production, a lower-level language or secure memory allocator
    would be needed for true secure erasure.
    """

    def __init__(self, key_bytes: bytes, query_nonce: bytes):
        self._key = bytearray(key_bytes)
        self._nonce = query_nonce
        self._created_at = time.time()
        self._cleared = False

    @property
    def key(self) -> bytes:
        if self._cleared:
            raise RuntimeError("Ephemeral key has been cleared. Cannot access after lifecycle end.")
        return bytes(self._key)

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @property
    def is_cleared(self) -> bool:
        return self._cleared

    @property
    def lifetime_seconds(self) -> float:
        return time.time() - self._created_at

    def clear(self):
        """
        Clear key material from memory.

        Overwrites the key bytearray with zeros and marks as cleared.
        This is a best-effort approach in Python.
        """
        if not self._cleared:
            # Overwrite with zeros
            for i in range(len(self._key)):
                self._key[i] = 0
            self._cleared = True
            return True
        return False


class KeyManager:
    """
    Manages the master key and ephemeral query-key lifecycle.

    Architecture:
        MASTER KEY (long-term, client-only)
            |
            +--> derive_index_key()     -> for building encrypted index
            +--> derive_document_key()  -> for document encryption
            +--> create_query_key()     -> ephemeral, per-query
    """

    def __init__(self, master_key: bytes = None):
        """
        Initialize KeyManager with a master key.

        Args:
            master_key: 32-byte master key. If None, generates a new one.
        """
        if master_key is None:
            self._master_key = secure_random_bytes(32)
        else:
            if len(master_key) != 32:
                raise ValueError("Master key must be exactly 32 bytes")
            self._master_key = master_key

        self._active_handles = []
        self._query_count = 0
        self._total_keys_cleared = 0

    @property
    def master_key(self) -> bytes:
        """Access the master key. NEVER send this to the server."""
        return self._master_key

    @property
    def query_count(self) -> int:
        return self._query_count

    @property
    def total_keys_cleared(self) -> int:
        return self._total_keys_cleared

    @property
    def active_handle_count(self) -> int:
        return len([h for h in self._active_handles if not h.is_cleared])

    def get_index_key(self) -> bytes:
        """Derive the index key from the master key."""
        return generate_index_key(self._master_key)

    def get_document_key(self) -> bytes:
        """Derive the document encryption key from the master key."""
        return derive_document_key(self._master_key)

    def create_query_key(self) -> EphemeralKeyHandle:
        """
        Create an ephemeral query key for a single search operation.

        OUR ARCHITECTURAL INTEGRATION: Ephemeral query-key lifecycle.
        Each search gets a unique derived key with a fresh nonce.

        Returns:
            EphemeralKeyHandle with the query key material
        """
        query_nonce = secure_random_bytes(16)
        query_key = generate_query_key(self._master_key, query_nonce)

        handle = EphemeralKeyHandle(query_key, query_nonce)
        self._active_handles.append(handle)
        self._query_count += 1

        return handle

    def clear_query_key(self, handle: EphemeralKeyHandle) -> dict:
        """
        Clear an ephemeral query key after query completion.

        Args:
            handle: The EphemeralKeyHandle to clear

        Returns:
            Dict with lifecycle info for demonstration
        """
        lifetime = handle.lifetime_seconds
        cleared = handle.clear()

        if cleared:
            self._total_keys_cleared += 1

        return {
            'cleared': cleared,
            'lifetime_seconds': round(lifetime, 6),
            'total_cleared': self._total_keys_cleared,
            'active_handles': self.active_handle_count
        }

    def get_lifecycle_stats(self) -> dict:
        """Get statistics about the key lifecycle for demonstration."""
        return {
            'total_queries': self._query_count,
            'total_keys_cleared': self._total_keys_cleared,
            'active_handles': self.active_handle_count,
            'all_cleared': self.active_handle_count == 0
        }
