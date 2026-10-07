"""
crypto/prf.py
-------------
Pseudorandom Function (PRF) implementation using HMAC-SHA256.

EXISTING TECHNIQUE (from literature):
    HMAC-SHA256 is a standard PRF construction used widely in SSE schemes.
    Reference: Curtmola et al., "Searchable Symmetric Encryption: Improved
    Definitions and Efficient Constructions" (CCS 2006).

OUR USAGE:
    We use HMAC-SHA256 as the PRF for:
    1. Deriving temporary query keys from the master key
    2. Generating search tokens/trapdoors
    3. Computing encrypted index labels
    This is standard usage of PRFs in SSE, not a new construction.
"""

import hmac
import hashlib
from crypto.utils import secure_random_bytes


def prf(key: bytes, message: bytes) -> bytes:
    """
    PRF using HMAC-SHA256.

    EXISTING TECHNIQUE: HMAC-SHA256 as a PRF.
    Standard construction from cryptographic literature.

    Args:
        key: Secret key (should be at least 32 bytes)
        message: Input message

    Returns:
        32-byte pseudorandom output
    """
    return hmac.new(key, message, hashlib.sha256).digest()


def prf_hex(key: bytes, message: bytes) -> str:
    """PRF with hex-encoded output for index label usage."""
    return prf(key, message).hex()


def derive_key(master_key: bytes, context: bytes) -> bytes:
    """
    Derive a sub-key from the master key using HMAC-based key derivation.

    EXISTING TECHNIQUE: HMAC-based key derivation.
    Simplified version of HKDF-Expand (RFC 5869).

    Args:
        master_key: The long-term master key
        context: Context/label for domain separation

    Returns:
        32-byte derived key
    """
    return prf(master_key, context)


def generate_search_token(query_key: bytes, keyword: str) -> bytes:
    """
    Generate a search token (trapdoor) for a keyword.

    EXISTING TECHNIQUE: Token generation via PRF.
    Standard in SSE constructions (Curtmola et al., Song et al.).

    Args:
        query_key: Ephemeral query key derived from master key
        keyword: Normalized keyword string

    Returns:
        32-byte search token
    """
    return prf(query_key, keyword.encode('utf-8'))


def generate_index_key(master_key: bytes) -> bytes:
    """
    Derive the key used for building the encrypted index.

    OUR ARCHITECTURAL CHOICE: Separate derived key for index operations.
    Uses the same HMAC-SHA256 PRF but with index-specific context.

    Args:
        master_key: The long-term master key

    Returns:
        32-byte index key
    """
    return derive_key(master_key, b"INDEX_KEY_DERIVATION")


def generate_query_key(master_key: bytes, query_nonce: bytes) -> bytes:
    """
    Derive an ephemeral query key for a specific search operation.

    OUR ARCHITECTURAL INTEGRATION: Ephemeral query-key lifecycle.
    Each query gets a unique derived key that is cleared after use.
    The underlying primitive (HMAC-SHA256) is standard.

    Args:
        master_key: The long-term master key
        query_nonce: Unique random nonce for this query

    Returns:
        32-byte ephemeral query key
    """
    context = b"QUERY_KEY:" + query_nonce
    return derive_key(master_key, context)


def compute_index_label(index_key: bytes, keyword: str, counter: int) -> str:
    """
    Compute the label for an index entry: PRF(K_index, keyword || counter).

    EXISTING TECHNIQUE: Counter-based SSE index label computation.
    From Curtmola et al. SSE-2 construction.

    Args:
        index_key: Key for index operations
        keyword: Normalized keyword
        counter: Position counter for this keyword's document list

    Returns:
        Hex-encoded index label
    """
    message = f"{keyword}:{counter}".encode('utf-8')
    return prf_hex(index_key, message)


def compute_index_value(index_key: bytes, keyword: str, counter: int, doc_id: str) -> bytes:
    """
    Compute the encrypted value for an index entry.

    EXISTING TECHNIQUE: Encrypting document IDs in the index.
    The document ID is XORed with a PRF output to hide it.

    Args:
        index_key: Key for index operations
        keyword: Normalized keyword
        counter: Position counter
        doc_id: Document identifier to encrypt

    Returns:
        Encrypted document ID bytes
    """
    # Generate a mask from PRF
    mask_input = f"{keyword}:val:{counter}".encode('utf-8')
    mask = prf(index_key, mask_input)

    # Pad or truncate doc_id to 32 bytes
    doc_id_bytes = doc_id.encode('utf-8')
    if len(doc_id_bytes) < 32:
        doc_id_bytes = doc_id_bytes + b'\x00' * (32 - len(doc_id_bytes))
    else:
        doc_id_bytes = doc_id_bytes[:32]

    # XOR to encrypt
    encrypted = bytes(a ^ b for a, b in zip(doc_id_bytes, mask))
    return encrypted


def decrypt_index_value(index_key: bytes, keyword: str, counter: int, encrypted_value: bytes) -> str:
    """
    Decrypt a document ID from an index entry.

    Reverses compute_index_value by XORing with the same PRF mask.

    Args:
        index_key: Key for index operations
        keyword: Normalized keyword
        counter: Position counter
        encrypted_value: Encrypted document ID bytes

    Returns:
        Decrypted document ID string
    """
    mask_input = f"{keyword}:val:{counter}".encode('utf-8')
    mask = prf(index_key, mask_input)

    decrypted = bytes(a ^ b for a, b in zip(encrypted_value, mask))
    # Remove null padding
    return decrypted.rstrip(b'\x00').decode('utf-8')
