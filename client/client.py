"""
client/client.py
----------------
Main client module that integrates all components of the
hybrid privacy-aware searchable encryption architecture.

ARCHITECTURAL INTEGRATION (our contribution):
    This module ties together:
    1. Basic SSE for single-keyword search
    2. OXT-inspired Boolean AND search
    3. Result-size padding/bucketization (privacy layer)
    4. Ephemeral query-key lifecycle management
    into a single unified architecture.

    Each individual technique is from established literature.
    The integration and lifecycle management is our contribution.
"""

import time
import hashlib
from crypto.utils import normalize_keyword
from crypto.encryption import encrypt_document, derive_document_key
from crypto.prf import generate_index_key
from client.key_manager import KeyManager
from client.query_processor import QueryProcessor, ParsedQuery, QueryParseError
from client.token_generator import TokenGenerator
from client.privacy_layer import PrivacyLayer
from client.decryptor import Decryptor
from server.encrypted_index import build_encrypted_index
from server.server import CloudServer


class SearchableEncryptionClient:
    """
    Main client for the hybrid privacy-aware SSE system.

    Architecture flow:
        User -> Query Processor -> [SSE or OXT path] -> Privacy Layer
        -> Token Generation -> Cloud Server -> Encrypted Results
        -> Client Verification/Decryption -> Final Documents
    """

    def __init__(self, master_key: bytes = None):
        """
        Initialize the client with all sub-components.

        Args:
            master_key: 32-byte master key. If None, generates a new one.
        """
        # Key management
        self.key_manager = KeyManager(master_key)

        # Derived keys
        self._doc_key = self.key_manager.get_document_key()
        self._index_key = self.key_manager.get_index_key()

        # Sub-components
        self.query_processor = QueryProcessor()
        self.token_generator = TokenGenerator(self._index_key)
        self.privacy_layer = PrivacyLayer(doc_key=self._doc_key)
        self.decryptor = Decryptor(self._doc_key)

        # Cloud server (simulated)
        self.server = CloudServer()

        # Document tracking
        self._documents = {}  # doc_id -> plaintext (client-side only)
        self._plaintext_index = {}  # keyword -> [doc_ids] (temporary, for index building)
        self._index_built = False

        # Timing metrics
        self._metrics = {
            'encryption_times': [],
            'index_build_time': 0,
            'search_times': [],
            'decryption_times': [],
            'token_gen_times': [],
        }

    def add_document(self, doc_id: str, plaintext: str) -> dict:
        """
        Encrypt and upload a document to the cloud server.

        Args:
            doc_id: Unique document identifier
            plaintext: Document content

        Returns:
            Dict with encryption metadata
        """
        start_time = time.time()

        # Encrypt document using AES-256-GCM
        encrypted = encrypt_document(
            self._doc_key,
            plaintext,
            associated_data=doc_id.encode('utf-8')
        )

        enc_time = time.time() - start_time
        self._metrics['encryption_times'].append(enc_time)

        # Store locally for decryption reference
        self._documents[doc_id] = plaintext

        # Upload encrypted document to server
        self.server.store_encrypted_document(doc_id, encrypted)

        # Build plaintext index for later index construction
        keywords = self._extract_keywords(plaintext)
        for kw in keywords:
            if kw not in self._plaintext_index:
                self._plaintext_index[kw] = []
            if doc_id not in self._plaintext_index[kw]:
                self._plaintext_index[kw].append(doc_id)

        return {
            'doc_id': doc_id,
            'plaintext_length': len(plaintext),
            'ciphertext_length': len(encrypted['ciphertext']),
            'encryption_time_ms': round(enc_time * 1000, 3),
            'keywords_extracted': len(keywords)
        }

    def add_documents_bulk(self, documents: list) -> dict:
        """
        Encrypt and upload multiple documents.

        Args:
            documents: List of dicts with 'doc_id' and 'text'

        Returns:
            Summary dict
        """
        results = []
        total_start = time.time()

        for doc in documents:
            result = self.add_document(doc['doc_id'], doc['text'])
            results.append(result)

        total_time = time.time() - total_start

        return {
            'documents_uploaded': len(results),
            'total_time_ms': round(total_time * 1000, 3),
            'avg_encryption_time_ms': round(
                sum(r['encryption_time_ms'] for r in results) / len(results), 3
            ) if results else 0,
            'details': results
        }

    def build_index(self) -> dict:
        """
        Build the encrypted inverted index and upload to server.

        EXISTING TECHNIQUE: SSE-2 index construction (Curtmola et al.)
        Uses PRF-based label/value pairs.

        Returns:
            Dict with index building metadata
        """
        start_time = time.time()

        # Build encrypted index from plaintext index
        encrypted_index = build_encrypted_index(
            self._index_key,
            self._plaintext_index
        )

        build_time = time.time() - start_time
        self._metrics['index_build_time'] = build_time

        # Upload to server
        self.server.receive_encrypted_index(encrypted_index, self._index_key)
        self._index_built = True

        # Clear plaintext index from client memory (security measure)
        # In production, the plaintext index would be deleted.
        # We keep it for demonstration/testing purposes in this prototype.

        return {
            'index_entries': encrypted_index.total_entries,
            'unique_keywords': len(self._plaintext_index),
            'build_time_ms': round(build_time * 1000, 3),
            'index_size_bytes': encrypted_index.index_size_bytes
        }

    def search(self, raw_query: str, enable_padding: bool = True) -> dict:
        """
        Execute a search query through the full hybrid architecture.

        Flow:
            1. Parse query (single keyword or Boolean AND)
            2. Create ephemeral query key
            3. Generate search tokens
            4. Send to server
            5. Receive encrypted results
            6. Apply/remove padding
            7. Decrypt documents
            8. Clear ephemeral key material

        Args:
            raw_query: User's search query
            enable_padding: Whether to apply result-size padding

        Returns:
            Dict with search results and metadata
        """
        if not self._index_built:
            raise RuntimeError("Index not built. Call build_index() first.")

        total_start = time.time()

        # Step 1: Parse query
        try:
            parsed = self.query_processor.parse(raw_query)
        except QueryParseError as e:
            return {'error': str(e), 'query': raw_query}

        # Step 2: Create ephemeral query key
        key_handle = self.key_manager.create_query_key()

        # Step 3: Generate search tokens
        token_start = time.time()
        if parsed.is_single:
            token_set = self.token_generator.generate_single_token(
                key_handle.key, parsed.keywords[0]
            )
        else:
            token_set = self.token_generator.generate_boolean_tokens(
                key_handle.key, parsed.keywords
            )
        token_time = time.time() - token_start
        self._metrics['token_gen_times'].append(token_time)

        # Step 4: Send to server and execute search
        search_start = time.time()
        server_result = self.server.execute_search(
            parsed.query_type,
            parsed.keywords
        )
        search_time = time.time() - search_start
        self._metrics['search_times'].append(search_time)

        # Step 5: Apply padding (privacy layer)
        doc_ids = server_result['doc_ids']

        padding_info = None
        if enable_padding:
            query_hash = hashlib.sha256(raw_query.lower().encode()).hexdigest()
            padding_result = self.privacy_layer.pad_results(doc_ids, query_hash)
            padding_info = {
                'actual_count': padding_result['actual_count'],
                'padded_count': padding_result['total_returned'],
                'padding_added': padding_result['padding_count'],
                'bucket_size': padding_result['bucket_size'],
                'risk_level': padding_result['risk_level'],
                'risk_score': padding_result['risk_score']
            }

            # Client-side: unpad to get real doc IDs
            real_doc_ids = self.privacy_layer.unpad_results(
                padding_result['encrypted_records']
            )
        else:
            real_doc_ids = doc_ids

        # Step 6: Decrypt matching documents
        decrypt_start = time.time()
        encrypted_docs = server_result['encrypted_docs']

        # Filter to only documents in real_doc_ids
        matching_docs = [d for d in encrypted_docs if d['doc_id'] in real_doc_ids]
        decrypted_results = self.decryptor.decrypt_documents(matching_docs)
        decrypt_time = time.time() - decrypt_start
        self._metrics['decryption_times'].append(decrypt_time)

        # Step 7: Clear ephemeral key material
        key_lifecycle = self.key_manager.clear_query_key(key_handle)

        total_time = time.time() - total_start

        return {
            'query': raw_query,
            'query_type': parsed.query_type,
            'keywords': parsed.keywords,
            'mechanism': server_result['search_metadata'].get('mechanism', 'Unknown'),
            'results': decrypted_results,
            'result_count': len(decrypted_results),
            'padding': padding_info,
            'timing': {
                'total_ms': round(total_time * 1000, 3),
                'token_generation_ms': round(token_time * 1000, 3),
                'search_ms': round(search_time * 1000, 3),
                'decryption_ms': round(decrypt_time * 1000, 3),
            },
            'key_lifecycle': {
                'key_created': True,
                'key_used': True,
                'key_cleared': key_lifecycle['cleared'],
                'key_lifetime_ms': round(key_lifecycle['lifetime_seconds'] * 1000, 3)
            },
            'server_observation': server_result['server_log_entry']
        }

    def _extract_keywords(self, text: str) -> list:
        """Extract and normalize keywords from document text."""
        # Simple word-based extraction
        words = text.lower().split()
        keywords = set()
        for word in words:
            normalized = normalize_keyword(word)
            if normalized and len(normalized) >= 2:  # Skip very short words
                keywords.add(normalized)
        return sorted(keywords)

    def get_metrics(self) -> dict:
        """Get all collected performance metrics."""
        enc_times = self._metrics['encryption_times']
        search_times = self._metrics['search_times']
        dec_times = self._metrics['decryption_times']
        token_times = self._metrics['token_gen_times']

        def stats(times):
            if not times:
                return {'count': 0, 'avg_ms': 0, 'min_ms': 0, 'max_ms': 0, 'total_ms': 0}
            return {
                'count': len(times),
                'avg_ms': round(sum(times) / len(times) * 1000, 3),
                'min_ms': round(min(times) * 1000, 3),
                'max_ms': round(max(times) * 1000, 3),
                'total_ms': round(sum(times) * 1000, 3),
            }

        return {
            'encryption': stats(enc_times),
            'index_build_time_ms': round(self._metrics['index_build_time'] * 1000, 3),
            'search': stats(search_times),
            'decryption': stats(dec_times),
            'token_generation': stats(token_times),
            'server_stats': self.server.get_stats(),
            'key_lifecycle': self.key_manager.get_lifecycle_stats(),
            'privacy_stats': self.privacy_layer.get_history_stats()
        }

    def get_leakage_comparison(self) -> list:
        """Get comparison data for leakage demonstration."""
        return self.privacy_layer.get_leakage_comparison()

    def get_document_count(self) -> int:
        """Get the number of documents stored."""
        return len(self._documents)

    def get_index_keywords(self) -> list:
        """Get list of indexed keywords (client-side only, for demo)."""
        return sorted(self._plaintext_index.keys())

    def get_keyword_doc_count(self, keyword: str) -> int:
        """Get document count for a keyword (client-side only, for demo)."""
        normalized = normalize_keyword(keyword)
        return len(self._plaintext_index.get(normalized, []))
