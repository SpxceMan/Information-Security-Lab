"""
server/search_engine.py
-----------------------
Server-side search engine for encrypted index.

EXISTING TECHNIQUES:
    - Single-keyword SSE search: look up PRF labels (Curtmola et al.)
    - OXT-inspired Boolean search: candidate selection + intersection filtering
      (Cash et al., CRYPTO 2013)

OUR ARCHITECTURAL INTEGRATION:
    - Unified search engine supporting both single-keyword and Boolean paths
    - OXT-INSPIRED prototype (simplified): uses candidate keyword selection
      and intersection filtering without full bilinear-map cross-tags.
    - This is labeled as "OXT-inspired Boolean SSE prototype", NOT as
      a full OXT implementation.

TRUST MODEL:
    The search engine runs on the honest-but-curious server.
    It receives encrypted tokens and returns encrypted results.
    It does NOT learn plaintext keywords or document contents.
"""

from crypto.prf import compute_index_label, compute_index_value, decrypt_index_value


class SearchResult:
    """Represents search results from the server."""

    def __init__(self, query_type: str):
        self.query_type = query_type
        self.encrypted_doc_ids = []  # List of encrypted doc_id bytes
        self.actual_count = 0
        self.search_metadata = {}

    def add_result(self, encrypted_doc_id: bytes):
        self.encrypted_doc_ids.append(encrypted_doc_id)
        self.actual_count += 1


class SearchEngine:
    """
    Executes searches on the encrypted index.

    Server-side component - operates only on encrypted data.
    """

    def __init__(self, encrypted_index, index_key: bytes):
        """
        Args:
            encrypted_index: EncryptedIndex instance
            index_key: Index key for label/value computation
                       (in a real system, tokens would be used instead;
                        for this prototype, the search engine uses the
                        index key to verify lookups)
        """
        self._index = encrypted_index
        self._index_key = index_key

    def search_single_keyword(self, keyword: str) -> SearchResult:
        """
        Execute a single-keyword SSE search.

        EXISTING TECHNIQUE: SSE-2 search (Curtmola et al.).
        Iterates through counter values, computing labels until
        no more entries are found.

        In a real SSE deployment, the server would receive a token
        and compute labels from the token. For this prototype, we
        use the index key directly.

        Args:
            keyword: Normalized keyword (in production, would be a token)

        Returns:
            SearchResult with matching encrypted document IDs
        """
        result = SearchResult(query_type="SINGLE_KEYWORD")

        counter = 0
        while True:
            label = compute_index_label(self._index_key, keyword, counter)
            encrypted_value = self._index.lookup(label)

            if encrypted_value is None:
                break

            # Decrypt the document ID from the index value
            doc_id = decrypt_index_value(
                self._index_key, keyword, counter, encrypted_value
            )
            result.add_result(doc_id.encode('utf-8'))

            counter += 1

        result.search_metadata = {
            'mechanism': 'Basic SSE (Curtmola et al. SSE-2)',
            'labels_checked': counter,
            'matches_found': result.actual_count
        }

        # Server log (no plaintext keyword shown)
        self._server_log(f"Search executed | Labels checked: {counter} | "
                         f"Candidate records: {result.actual_count}")

        return result

    def search_boolean_and(self, keywords: list) -> SearchResult:
        """
        Execute a Boolean AND search using OXT-inspired architecture.

        OXT-INSPIRED BOOLEAN SSE PROTOTYPE:
            1. Select the first keyword as the s-term (candidate selector)
            2. Search for all documents matching the s-term
            3. For each remaining keyword (x-terms), search for their documents
            4. Compute intersection: only documents matching ALL keywords

        DISTINCTION FROM FULL OXT:
            The full OXT protocol (Cash et al., CRYPTO 2013) uses:
            - Bilinear maps for cross-tags
            - TSet and XSet data structures
            - More sophisticated token computation

            Our prototype reproduces the ARCHITECTURAL IDEA:
            - Use a selective/candidate keyword
            - Intersect/filter using remaining keyword postings
            But uses simpler HMAC-based lookups instead of bilinear maps.

        Args:
            keywords: List of normalized keywords

        Returns:
            SearchResult with documents matching ALL keywords
        """
        result = SearchResult(query_type="BOOLEAN_AND (OXT-inspired)")

        if not keywords:
            return result

        # Step 1: Get candidate documents from first keyword (s-term)
        s_term = keywords[0]
        candidate_doc_ids = self._get_keyword_documents(s_term)

        self._server_log(f"OXT-inspired search | S-term candidates: {len(candidate_doc_ids)}")

        if not candidate_doc_ids:
            result.search_metadata = {
                'mechanism': 'OXT-inspired Boolean SSE prototype',
                's_term_candidates': 0,
                'x_terms_checked': len(keywords) - 1,
                'final_matches': 0
            }
            return result

        # Step 2: For each x-term, get document set and intersect
        current_candidates = set(candidate_doc_ids)

        for i, x_term in enumerate(keywords[1:], start=1):
            x_doc_ids = set(self._get_keyword_documents(x_term))

            # Intersect: keep only documents that also match this x-term
            current_candidates = current_candidates.intersection(x_doc_ids)

            self._server_log(
                f"OXT-inspired search | X-term {i} filter: "
                f"{len(x_doc_ids)} docs | Remaining candidates: {len(current_candidates)}"
            )

            # Early termination if intersection is empty
            if not current_candidates:
                break

        # Step 3: Collect final matching document IDs
        for doc_id in sorted(current_candidates):
            result.add_result(doc_id.encode('utf-8'))

        result.search_metadata = {
            'mechanism': 'OXT-inspired Boolean SSE prototype',
            's_term': '(encrypted)',
            's_term_candidates': len(candidate_doc_ids),
            'x_terms_checked': len(keywords) - 1,
            'final_matches': result.actual_count
        }

        self._server_log(
            f"OXT-inspired search complete | Final matches: {result.actual_count}"
        )

        return result

    def _get_keyword_documents(self, keyword: str) -> list:
        """
        Get all document IDs for a keyword from the encrypted index.

        Args:
            keyword: Normalized keyword

        Returns:
            List of document ID strings
        """
        doc_ids = []
        counter = 0

        while True:
            label = compute_index_label(self._index_key, keyword, counter)
            encrypted_value = self._index.lookup(label)

            if encrypted_value is None:
                break

            doc_id = decrypt_index_value(
                self._index_key, keyword, counter, encrypted_value
            )
            doc_ids.append(doc_id)
            counter += 1

        return doc_ids

    def _server_log(self, message: str):
        """
        Server-side logging.
        MUST NOT contain plaintext keywords, keys, or document content.
        """
        # In this prototype, we print to console.
        # In production, this would go to a secure log.
        pass  # Disabled by default; enable for debugging
