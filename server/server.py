"""
server/server.py
----------------
Cloud server simulation.

TRUST MODEL:
    The server is honest-but-curious:
    - It correctly stores and retrieves encrypted data
    - It correctly executes search operations
    - It may try to infer information from observable patterns

    The server does NOT learn:
    - Plaintext documents
    - Plaintext keywords
    - Encryption master key

    The server CAN observe (acknowledged leakage):
    - Search tokens (encrypted)
    - Result sizes (mitigated by padding)
    - Access patterns (not addressed in this prototype)
    - Search patterns (not addressed in this prototype)
"""

from server.encrypted_index import EncryptedIndex, build_encrypted_index
from server.search_engine import SearchEngine
from server.result_handler import ResultHandler


class CloudServer:
    """
    Simulates the cloud server storing encrypted data and executing searches.
    """

    def __init__(self):
        self._encrypted_index = None
        self._document_store = {}
        self._search_engine = None
        self._result_handler = None
        self._search_log = []  # Server-side observable log

    def receive_encrypted_index(self, encrypted_index: EncryptedIndex, index_key: bytes):
        """
        Receive and store the encrypted index from the client.

        Args:
            encrypted_index: The encrypted inverted index
            index_key: Index key for search operations
        """
        self._encrypted_index = encrypted_index
        self._search_engine = SearchEngine(encrypted_index, index_key)
        self._result_handler = ResultHandler(self._document_store)

    def store_encrypted_document(self, doc_id: str, encrypted_doc: dict):
        """
        Store an encrypted document.

        The server receives only ciphertext, nonce, and tag.
        It NEVER receives plaintext.

        Args:
            doc_id: Document identifier
            encrypted_doc: Dict with 'ciphertext', 'nonce', 'tag'
        """
        self._document_store[doc_id] = encrypted_doc
        if self._result_handler is None:
            self._result_handler = ResultHandler(self._document_store)

    def execute_search(self, query_type: str, keywords: list) -> dict:
        """
        Execute a search on the encrypted index.

        Args:
            query_type: "SINGLE_KEYWORD" or "BOOLEAN_AND"
            keywords: List of normalized keywords

        Returns:
            Dict with search results and metadata
        """
        if self._search_engine is None:
            raise RuntimeError("No encrypted index loaded on server.")

        if query_type == "SINGLE_KEYWORD":
            search_result = self._search_engine.search_single_keyword(keywords[0])
        elif query_type == "BOOLEAN_AND":
            search_result = self._search_engine.search_boolean_and(keywords)
        else:
            raise ValueError(f"Unsupported query type: {query_type}")

        # Extract document IDs from search results
        doc_ids = [r.decode('utf-8') for r in search_result.encrypted_doc_ids]

        # Retrieve encrypted documents
        encrypted_docs = self._result_handler.prepare_results(doc_ids)

        # Log what the server observes (for demonstration)
        log_entry = {
            'query_type': query_type,
            'tokens_received': len(keywords),
            'candidates_found': search_result.actual_count,
            'mechanism': search_result.search_metadata.get('mechanism', 'Unknown')
        }
        self._search_log.append(log_entry)

        return {
            'doc_ids': doc_ids,
            'encrypted_docs': encrypted_docs,
            'search_metadata': search_result.search_metadata,
            'server_log_entry': log_entry
        }

    def get_server_observations(self) -> list:
        """
        Return what the server has observed across all searches.
        Used for the leakage demonstration.
        """
        return self._search_log.copy()

    def get_stats(self) -> dict:
        """Get server statistics."""
        stats = {
            'documents_stored': len(self._document_store),
            'searches_executed': len(self._search_log)
        }
        if self._encrypted_index:
            stats.update(self._encrypted_index.get_stats())
        if self._result_handler:
            stats.update(self._result_handler.get_server_stats())
        return stats
