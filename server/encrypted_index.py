"""
server/encrypted_index.py
-------------------------
Encrypted inverted index for SSE.

EXISTING TECHNIQUE:
    Encrypted inverted index using PRF-based label/value pairs.
    Based on SSE-2 construction from Curtmola et al. (CCS 2006).

    Conceptual structure:
        PRF(K, keyword||counter) -> label
        Encrypted(doc_id) -> value

    The server stores (label, encrypted_value) pairs.
    The server NEVER sees plaintext keywords or document IDs.

OUR ARCHITECTURAL INTEGRATION:
    We use this index for both single-keyword and Boolean search paths.
    The index building uses the same PRF infrastructure.
"""

from crypto.prf import compute_index_label, compute_index_value, decrypt_index_value


class EncryptedIndex:
    """
    Server-side encrypted inverted index.

    The index is a dictionary mapping:
        encrypted_label (hex string) -> encrypted_value (bytes)

    The server cannot derive keywords or document IDs from the index.
    """

    def __init__(self):
        self._index = {}  # label -> encrypted_value
        self._keyword_counts = {}  # For the server to know iteration bounds
        self._total_entries = 0

    def store_entry(self, label: str, encrypted_value: bytes):
        """
        Store an encrypted index entry.

        Args:
            label: Hex-encoded PRF output (encrypted keyword+counter)
            encrypted_value: Encrypted document ID
        """
        self._index[label] = encrypted_value
        self._total_entries += 1

    def lookup(self, label: str) -> bytes:
        """
        Look up an entry by its encrypted label.

        Args:
            label: Hex-encoded label to look up

        Returns:
            Encrypted value if found, None otherwise
        """
        return self._index.get(label, None)

    def has_label(self, label: str) -> bool:
        """Check if a label exists in the index."""
        return label in self._index

    def set_keyword_count(self, token_label: str, count: int):
        """
        Store the document count for a keyword token.
        The token_label is already encrypted, so the server
        doesn't learn the actual keyword.

        Args:
            token_label: Encrypted label for the keyword
            count: Number of documents for this keyword
        """
        self._keyword_counts[token_label] = count

    def get_keyword_count(self, token_label: str) -> int:
        """Get stored count for a keyword token."""
        return self._keyword_counts.get(token_label, 0)

    @property
    def total_entries(self) -> int:
        return self._total_entries

    @property
    def index_size_bytes(self) -> int:
        """Approximate size of the index in bytes."""
        size = 0
        for label, value in self._index.items():
            size += len(label.encode('utf-8')) + len(value)
        return size

    def get_stats(self) -> dict:
        """Get index statistics (safe for server-side logging)."""
        return {
            'total_entries': self._total_entries,
            'total_keywords': len(self._keyword_counts),
            'index_size_bytes': self.index_size_bytes
        }


def build_encrypted_index(index_key: bytes, plaintext_index: dict) -> EncryptedIndex:
    """
    Build an encrypted index from a plaintext inverted index.

    THIS RUNS ON THE CLIENT before uploading to the server.

    EXISTING TECHNIQUE: SSE-2 index construction (Curtmola et al.).
    Each (keyword, doc_id) pair is stored as:
        label  = PRF(K, keyword || counter)
        value  = Encrypt(K, keyword, counter, doc_id)

    Args:
        index_key: Key for index operations (derived from master key)
        plaintext_index: Dict mapping keyword -> list of doc_ids

    Returns:
        EncryptedIndex ready for server storage
    """
    enc_index = EncryptedIndex()

    for keyword, doc_ids in plaintext_index.items():
        for counter, doc_id in enumerate(doc_ids):
            # Compute encrypted label
            label = compute_index_label(index_key, keyword, counter)
            # Compute encrypted value
            encrypted_value = compute_index_value(index_key, keyword, counter, doc_id)

            enc_index.store_entry(label, encrypted_value)

        # Store the count using an encrypted label
        count_label = compute_index_label(index_key, keyword + ":count", 0)
        enc_index.set_keyword_count(count_label, len(doc_ids))

    return enc_index
