"""
crypto/encryption.py
--------------------
Document encryption/decryption using AES-256-GCM.

EXISTING TECHNIQUE (from literature):
    AES-256-GCM is a standard authenticated encryption scheme.
    Provides both confidentiality and integrity.
    Reference: NIST SP 800-38D.

OUR USAGE:
    We use AES-256-GCM for encrypting documents before uploading
    to the cloud server. Each document gets a unique nonce.
    This is standard usage, not a new construction.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crypto.prf import derive_key


# AES-256-GCM key size in bytes
AES_KEY_SIZE = 32
# Nonce size for GCM (96 bits recommended by NIST)
GCM_NONCE_SIZE = 12


def derive_document_key(master_key: bytes) -> bytes:
    """
    Derive the document encryption key from the master key.

    Args:
        master_key: The long-term master key

    Returns:
        32-byte AES-256 key for document encryption
    """
    return derive_key(master_key, b"DOCUMENT_ENCRYPTION_KEY")


def encrypt_document(doc_key: bytes, plaintext: str, associated_data: bytes = None) -> dict:
    """
    Encrypt a document using AES-256-GCM.

    EXISTING TECHNIQUE: AES-256-GCM authenticated encryption.
    Standard NIST-approved AEAD construction.

    Args:
        doc_key: 32-byte AES-256 key
        plaintext: Document plaintext string
        associated_data: Optional additional authenticated data (e.g., doc_id)

    Returns:
        Dictionary with 'ciphertext', 'nonce', and 'tag' (all bytes)
    """
    nonce = get_random_bytes(GCM_NONCE_SIZE)
    cipher = AES.new(doc_key, AES.MODE_GCM, nonce=nonce)

    if associated_data:
        cipher.update(associated_data)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'tag': tag
    }


def decrypt_document(doc_key: bytes, ciphertext: bytes, nonce: bytes,
                     tag: bytes, associated_data: bytes = None) -> str:
    """
    Decrypt a document using AES-256-GCM.

    Verifies the authentication tag to ensure integrity.

    Args:
        doc_key: 32-byte AES-256 key
        ciphertext: Encrypted document bytes
        nonce: Nonce used during encryption
        tag: Authentication tag
        associated_data: Optional AAD used during encryption

    Returns:
        Decrypted plaintext string

    Raises:
        ValueError: If authentication tag verification fails (tampered ciphertext)
    """
    cipher = AES.new(doc_key, AES.MODE_GCM, nonce=nonce)

    if associated_data:
        cipher.update(associated_data)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        raise ValueError(f"Decryption failed: authentication tag verification failed. "
                         f"Ciphertext may have been tampered with.") from e


def encrypt_result_record(doc_key: bytes, record_data: bytes, is_real: bool) -> dict:
    """
    Encrypt a result record (real or padding) so the server cannot distinguish them.

    OUR ARCHITECTURAL INTEGRATION: Indistinguishable result records.
    Both real and padding records are encrypted with AES-256-GCM.
    The 'is_real' flag is included INSIDE the encrypted payload,
    so the server cannot see it.

    Args:
        doc_key: 32-byte AES-256 key
        record_data: The record content bytes (doc_id for real, random for padding)
        is_real: Whether this is a real result or padding

    Returns:
        Dictionary with encrypted record
    """
    nonce = get_random_bytes(GCM_NONCE_SIZE)
    cipher = AES.new(doc_key, AES.MODE_GCM, nonce=nonce)

    # Pack the real/padding flag INSIDE the encrypted payload
    # Format: [1 byte flag][record_data]
    flag = b'\x01' if is_real else b'\x00'
    payload = flag + record_data

    ciphertext, tag = cipher.encrypt_and_digest(payload)

    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'tag': tag
    }


def decrypt_result_record(doc_key: bytes, ciphertext: bytes,
                          nonce: bytes, tag: bytes) -> tuple:
    """
    Decrypt a result record and determine if it's real or padding.

    Args:
        doc_key: 32-byte AES-256 key
        ciphertext: Encrypted record bytes
        nonce: Nonce
        tag: Authentication tag

    Returns:
        Tuple of (is_real: bool, record_data: bytes)
    """
    cipher = AES.new(doc_key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        is_real = (plaintext[0:1] == b'\x01')
        record_data = plaintext[1:]
        return is_real, record_data
    except (ValueError, KeyError) as e:
        raise ValueError(f"Result record decryption failed.") from e
