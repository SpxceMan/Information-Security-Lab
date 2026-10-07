"""
server/result_handler.py
------------------------
Handles search results on the server side, including
preparation of encrypted result sets.

The result handler packages search results for transmission
back to the client. In the hybrid architecture, the privacy
layer (padding) is applied here before sending results.
"""


class ResultHandler:
    """
    Packages search results for client transmission.

    In the trust model, the server is honest-but-curious:
    it correctly executes the search but may observe metadata.
    """

    def __init__(self, document_store: dict):
        """
        Args:
            document_store: Dict mapping doc_id -> encrypted document dict
        """
        self._document_store = document_store

    def prepare_results(self, doc_ids: list) -> list:
        """
        Retrieve encrypted documents for the given document IDs.

        Args:
            doc_ids: List of document ID strings

        Returns:
            List of encrypted document dicts
        """
        results = []
        for doc_id in doc_ids:
            if doc_id in self._document_store:
                doc = self._document_store[doc_id].copy()
                doc['doc_id'] = doc_id
                results.append(doc)
        return results

    def get_document(self, doc_id: str) -> dict:
        """Retrieve a single encrypted document."""
        if doc_id in self._document_store:
            doc = self._document_store[doc_id].copy()
            doc['doc_id'] = doc_id
            return doc
        return None

    @property
    def document_count(self) -> int:
        return len(self._document_store)

    def get_server_stats(self) -> dict:
        """Get server-side statistics (safe to expose)."""
        total_size = 0
        for doc_id, doc in self._document_store.items():
            total_size += len(doc.get('ciphertext', b''))
        return {
            'total_documents': self.document_count,
            'total_encrypted_size_bytes': total_size
        }
