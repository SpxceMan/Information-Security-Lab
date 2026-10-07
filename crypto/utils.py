"""
crypto/utils.py
---------------
Utility functions for cryptographic operations.

Uses established primitives from PyCryptodome:
- Secure random byte generation
- Constant-time comparison

These are standard library wrappers, NOT custom cryptography.
"""

import os
import hmac
import hashlib
import re


def secure_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes using OS entropy source."""
    return os.urandom(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing side-channel attacks."""
    return hmac.compare_digest(a, b)


def normalize_keyword(keyword: str) -> str:
    """
    Normalize a keyword for consistent indexing and searching.
    Strips whitespace, lowercases, removes non-alphanumeric characters.
    """
    keyword = keyword.strip().lower()
    keyword = re.sub(r'[^a-z0-9]', '', keyword)
    return keyword


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for storage/display."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string back to bytes."""
    return bytes.fromhex(hex_str)


def compute_sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash of data. Standard hash function, not custom."""
    return hashlib.sha256(data).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(a) != len(b):
        raise ValueError("Byte strings must be of equal length for XOR")
    return bytes(x ^ y for x, y in zip(a, b))
