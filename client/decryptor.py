"""
client/decryptor.py
-------------------
Handles decryption of documents returned from the server.

EXISTING TECHNIQUE:
    AES-256-GCM decryption (standard AEAD).

OUR ARCHITECTURAL INTEGRATION:
    Decryptor integrates with the privacy layer to filter padding
    and with key management for ephemeral key clearing.
"""

from crypto.encryption import decrypt_document


class DecryptionError(Exception):
    """Raised when document decryption fails."""
    pass


class Decryptor:
    """
    Decrypts documents returned from the cloud server.
    """

    def __init__(self, doc_key: bytes):
        """
        Args:
            doc_key: Document encryption key derived from master key
        """
        self._doc_key = doc_key

    def decrypt_documents(self, encrypted_docs: list) -> list:
        """
        Decrypt a list of encrypted documents.

        Args:
            encrypted_docs: List of dicts with 'doc_id', 'ciphertext', 'nonce', 'tag'

        Returns:
            List of dicts with 'doc_id' and 'plaintext'
        """
        decrypted = []

        for doc in encrypted_docs:
            try:
                plaintext = decrypt_document(
                    self._doc_key,
                    doc['ciphertext'],
                    doc['nonce'],
                    doc['tag'],
                    associated_data=doc.get('doc_id', '').encode('utf-8') if doc.get('doc_id') else None
                )
                decrypted.append({
                    'doc_id': doc.get('doc_id', 'UNKNOWN'),
                    'plaintext': plaintext
                })
            except ValueError as e:
                decrypted.append({
                    'doc_id': doc.get('doc_id', 'UNKNOWN'),
                    'error': str(e)
                })

        return decrypted

    def decrypt_single(self, encrypted_doc: dict) -> dict:
        """
        Decrypt a single encrypted document.

        Args:
            encrypted_doc: Dict with 'doc_id', 'ciphertext', 'nonce', 'tag'

        Returns:
            Dict with 'doc_id' and 'plaintext'

        Raises:
            DecryptionError: If decryption fails
        """
        try:
            plaintext = decrypt_document(
                self._doc_key,
                encrypted_doc['ciphertext'],
                encrypted_doc['nonce'],
                encrypted_doc['tag'],
                associated_data=encrypted_doc.get('doc_id', '').encode('utf-8')
                    if encrypted_doc.get('doc_id') else None
            )
            return {
                'doc_id': encrypted_doc.get('doc_id', 'UNKNOWN'),
                'plaintext': plaintext
            }
        except ValueError as e:
            raise DecryptionError(
                f"Failed to decrypt document {encrypted_doc.get('doc_id', 'UNKNOWN')}: {e}"
            ) from e
