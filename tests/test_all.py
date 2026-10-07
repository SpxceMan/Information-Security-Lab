"""
tests/test_all.py
-----------------
Comprehensive test suite for the hybrid SSE architecture.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.utils import secure_random_bytes, normalize_keyword, constant_time_compare
from crypto.encryption import (encrypt_document, decrypt_document,
                               encrypt_result_record, decrypt_result_record,
                               derive_document_key)
from crypto.prf import (prf, derive_key, generate_search_token,
                        generate_index_key, generate_query_key,
                        compute_index_label, compute_index_value,
                        decrypt_index_value)
from client.key_manager import KeyManager
from client.query_processor import QueryProcessor, QueryParseError
from client.privacy_layer import PrivacyLayer
from client.client import SearchableEncryptionClient
from data.loader import load_dataset


class TestAESEncryptionDecryption(unittest.TestCase):
    """Test AES-256-GCM encryption and decryption."""

    def setUp(self):
        self.master_key = secure_random_bytes(32)
        self.doc_key = derive_document_key(self.master_key)

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption followed by decryption returns original plaintext."""
        plaintext = "This is a test document about diabetes treatment."
        encrypted = encrypt_document(self.doc_key, plaintext)
        decrypted = decrypt_document(
            self.doc_key, encrypted['ciphertext'],
            encrypted['nonce'], encrypted['tag']
        )
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_with_aad(self):
        """Test encryption/decryption with associated authenticated data."""
        plaintext = "Document with AAD."
        aad = b"D001"
        encrypted = encrypt_document(self.doc_key, plaintext, associated_data=aad)
        decrypted = decrypt_document(
            self.doc_key, encrypted['ciphertext'],
            encrypted['nonce'], encrypted['tag'],
            associated_data=aad
        )
        self.assertEqual(plaintext, decrypted)

    def test_tampered_ciphertext_detection(self):
        """Test that tampered ciphertext is detected."""
        plaintext = "Sensitive medical data."
        encrypted = encrypt_document(self.doc_key, plaintext)

        # Tamper with ciphertext
        tampered = bytearray(encrypted['ciphertext'])
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with self.assertRaises(ValueError):
            decrypt_document(self.doc_key, tampered,
                             encrypted['nonce'], encrypted['tag'])

    def test_tampered_tag_detection(self):
        """Test that a tampered authentication tag is detected."""
        plaintext = "Another test document."
        encrypted = encrypt_document(self.doc_key, plaintext)

        tampered_tag = bytearray(encrypted['tag'])
        tampered_tag[0] ^= 0xFF
        tampered_tag = bytes(tampered_tag)

        with self.assertRaises(ValueError):
            decrypt_document(self.doc_key, encrypted['ciphertext'],
                             encrypted['nonce'], tampered_tag)

    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        plaintext = "Secret document."
        encrypted = encrypt_document(self.doc_key, plaintext)

        wrong_key = secure_random_bytes(32)
        with self.assertRaises(ValueError):
            decrypt_document(wrong_key, encrypted['ciphertext'],
                             encrypted['nonce'], encrypted['tag'])

    def test_unique_nonces(self):
        """Test that each encryption uses a unique nonce."""
        plaintext = "Same plaintext twice."
        enc1 = encrypt_document(self.doc_key, plaintext)
        enc2 = encrypt_document(self.doc_key, plaintext)
        self.assertNotEqual(enc1['nonce'], enc2['nonce'])
        self.assertNotEqual(enc1['ciphertext'], enc2['ciphertext'])

    def test_empty_plaintext(self):
        """Test encryption of empty string."""
        encrypted = encrypt_document(self.doc_key, "")
        decrypted = decrypt_document(
            self.doc_key, encrypted['ciphertext'],
            encrypted['nonce'], encrypted['tag']
        )
        self.assertEqual("", decrypted)


class TestPRF(unittest.TestCase):
    """Test PRF (HMAC-SHA256) operations."""

    def setUp(self):
        self.key = secure_random_bytes(32)

    def test_prf_deterministic(self):
        """PRF with same key and message produces same output."""
        result1 = prf(self.key, b"test")
        result2 = prf(self.key, b"test")
        self.assertEqual(result1, result2)

    def test_prf_different_messages(self):
        """PRF with different messages produces different outputs."""
        result1 = prf(self.key, b"test1")
        result2 = prf(self.key, b"test2")
        self.assertNotEqual(result1, result2)

    def test_prf_different_keys(self):
        """PRF with different keys produces different outputs."""
        key2 = secure_random_bytes(32)
        result1 = prf(self.key, b"test")
        result2 = prf(key2, b"test")
        self.assertNotEqual(result1, result2)

    def test_prf_output_length(self):
        """PRF output should be 32 bytes (SHA-256)."""
        result = prf(self.key, b"test")
        self.assertEqual(len(result), 32)


class TestIndexGeneration(unittest.TestCase):
    """Test encrypted index generation."""

    def setUp(self):
        self.master_key = secure_random_bytes(32)
        self.index_key = generate_index_key(self.master_key)

    def test_index_label_deterministic(self):
        """Same keyword and counter produce same label."""
        label1 = compute_index_label(self.index_key, "diabetes", 0)
        label2 = compute_index_label(self.index_key, "diabetes", 0)
        self.assertEqual(label1, label2)

    def test_index_label_different_keywords(self):
        """Different keywords produce different labels."""
        label1 = compute_index_label(self.index_key, "diabetes", 0)
        label2 = compute_index_label(self.index_key, "cancer", 0)
        self.assertNotEqual(label1, label2)

    def test_index_label_different_counters(self):
        """Different counters produce different labels."""
        label1 = compute_index_label(self.index_key, "diabetes", 0)
        label2 = compute_index_label(self.index_key, "diabetes", 1)
        self.assertNotEqual(label1, label2)

    def test_index_value_encrypt_decrypt(self):
        """Test that index values can be encrypted and decrypted."""
        doc_id = "D001"
        encrypted = compute_index_value(self.index_key, "diabetes", 0, doc_id)
        decrypted = decrypt_index_value(self.index_key, "diabetes", 0, encrypted)
        self.assertEqual(doc_id, decrypted)

    def test_plaintext_not_in_label(self):
        """Ensure plaintext keyword is not visible in the index label."""
        label = compute_index_label(self.index_key, "diabetes", 0)
        self.assertNotIn("diabetes", label.lower())


class TestSingleKeywordSearch(unittest.TestCase):
    """Test single-keyword SSE search."""

    def setUp(self):
        self.client = SearchableEncryptionClient()
        documents = [
            {"doc_id": "D001", "text": "Diabetes treatment by hospital doctors"},
            {"doc_id": "D002", "text": "Heart disease prevention"},
            {"doc_id": "D003", "text": "Cancer research at the hospital"},
            {"doc_id": "D004", "text": "Diabetes patients and doctor visits"},
            {"doc_id": "D005", "text": "Mental health awareness programs"},
        ]
        self.client.add_documents_bulk(documents)
        self.client.build_index()

    def test_single_keyword_match(self):
        """Search for a keyword that exists."""
        result = self.client.search("diabetes", enable_padding=False)
        self.assertGreater(result['result_count'], 0)
        self.assertEqual(result['query_type'], 'SINGLE_KEYWORD')

    def test_single_keyword_no_match(self):
        """Search for a keyword that doesn't exist."""
        result = self.client.search("xyznonexistent", enable_padding=False)
        self.assertEqual(result['result_count'], 0)

    def test_keyword_normalization(self):
        """Search should be case-insensitive."""
        result1 = self.client.search("diabetes", enable_padding=False)
        result2 = self.client.search("DIABETES", enable_padding=False)
        self.assertEqual(result1['result_count'], result2['result_count'])


class TestBooleanANDSearch(unittest.TestCase):
    """Test Boolean AND (OXT-inspired) search."""

    def setUp(self):
        self.client = SearchableEncryptionClient()
        documents = [
            {"doc_id": "D001", "text": "Diabetes treatment by hospital doctors"},
            {"doc_id": "D002", "text": "Heart disease prevention by specialist doctors"},
            {"doc_id": "D003", "text": "Cancer research at the hospital"},
            {"doc_id": "D004", "text": "Diabetes patients and doctor visits at hospital"},
            {"doc_id": "D005", "text": "Mental health programs"},
        ]
        self.client.add_documents_bulk(documents)
        self.client.build_index()

    def test_boolean_two_keywords(self):
        """Boolean AND with two keywords."""
        result = self.client.search("diabetes AND doctor", enable_padding=False)
        self.assertGreater(result['result_count'], 0)
        self.assertEqual(result['query_type'], 'BOOLEAN_AND')

    def test_boolean_three_keywords(self):
        """Boolean AND with three keywords."""
        result = self.client.search("diabetes AND doctor AND hospital", enable_padding=False)
        self.assertEqual(result['query_type'], 'BOOLEAN_AND')
        # Results should only include docs with ALL three keywords
        for doc in result['results']:
            text = doc['plaintext'].lower()
            self.assertIn('diabetes', text)
            self.assertIn('doctor', text)
            self.assertIn('hospital', text)

    def test_boolean_no_intersection(self):
        """Boolean AND where no document has all keywords."""
        result = self.client.search("diabetes AND mental", enable_padding=False)
        self.assertEqual(result['result_count'], 0)

    def test_boolean_mechanism_label(self):
        """Verify the search mechanism is labeled as OXT-inspired."""
        result = self.client.search("diabetes AND doctor", enable_padding=False)
        self.assertIn("OXT", result['mechanism'])


class TestResultPadding(unittest.TestCase):
    """Test result-size padding/bucketization."""

    def setUp(self):
        self.doc_key = secure_random_bytes(32)
        self.privacy = PrivacyLayer(doc_key=self.doc_key)

    def test_bucket_sizes(self):
        """Test that results are padded to correct bucket sizes."""
        self.assertEqual(self.privacy.compute_bucket_size(0), 4)
        self.assertEqual(self.privacy.compute_bucket_size(1), 4)
        self.assertEqual(self.privacy.compute_bucket_size(3), 4)
        self.assertEqual(self.privacy.compute_bucket_size(4), 4)
        self.assertEqual(self.privacy.compute_bucket_size(5), 8)
        self.assertEqual(self.privacy.compute_bucket_size(6), 8)
        self.assertEqual(self.privacy.compute_bucket_size(8), 8)
        self.assertEqual(self.privacy.compute_bucket_size(9), 16)
        self.assertEqual(self.privacy.compute_bucket_size(13), 16)
        self.assertEqual(self.privacy.compute_bucket_size(16), 16)

    def test_padding_count(self):
        """Test that padding adds the right number of dummy records."""
        doc_ids = ["D001", "D002", "D003"]
        result = self.privacy.pad_results(doc_ids)
        self.assertEqual(result['total_returned'], 4)
        self.assertEqual(result['padding_count'], 1)
        self.assertEqual(len(result['encrypted_records']), 4)

    def test_unpad_recovers_real_ids(self):
        """Test that unpadding correctly recovers real document IDs."""
        doc_ids = ["D001", "D002", "D003"]
        result = self.privacy.pad_results(doc_ids)
        recovered = self.privacy.unpad_results(result['encrypted_records'])
        self.assertEqual(sorted(recovered), sorted(doc_ids))

    def test_encrypted_records_indistinguishable(self):
        """Test that all encrypted records have similar structure."""
        doc_ids = ["D001"]
        result = self.privacy.pad_results(doc_ids)
        records = result['encrypted_records']

        # All records should have ciphertext, nonce, tag
        for rec in records:
            self.assertIn('ciphertext', rec)
            self.assertIn('nonce', rec)
            self.assertIn('tag', rec)
            # All nonces same length
            self.assertEqual(len(rec['nonce']), 12)


class TestQueryParsing(unittest.TestCase):
    """Test query parsing and validation."""

    def setUp(self):
        self.qp = QueryProcessor()

    def test_single_keyword(self):
        """Parse single keyword."""
        parsed = self.qp.parse("diabetes")
        self.assertTrue(parsed.is_single)
        self.assertEqual(parsed.keywords, ["diabetes"])

    def test_boolean_and(self):
        """Parse Boolean AND query."""
        parsed = self.qp.parse("diabetes AND doctor")
        self.assertTrue(parsed.is_boolean)
        self.assertEqual(parsed.keywords, ["diabetes", "doctor"])

    def test_three_keyword_boolean(self):
        """Parse three-keyword Boolean AND."""
        parsed = self.qp.parse("diabetes AND doctor AND hospital")
        self.assertTrue(parsed.is_boolean)
        self.assertEqual(len(parsed.keywords), 3)

    def test_case_insensitive_and(self):
        """AND operator should be case-insensitive."""
        parsed = self.qp.parse("diabetes and doctor")
        self.assertTrue(parsed.is_boolean)

    def test_empty_query_rejected(self):
        """Empty query should raise error."""
        with self.assertRaises(QueryParseError):
            self.qp.parse("")

    def test_or_query_rejected(self):
        """OR queries should be rejected."""
        with self.assertRaises(QueryParseError):
            self.qp.parse("diabetes OR doctor")

    def test_not_query_rejected(self):
        """NOT queries should be rejected."""
        with self.assertRaises(QueryParseError):
            self.qp.parse("NOT diabetes")

    def test_nested_query_rejected(self):
        """Nested queries should be rejected."""
        with self.assertRaises(QueryParseError):
            self.qp.parse("diabetes AND (doctor OR nurse)")

    def test_duplicate_keywords_rejected(self):
        """Duplicate keywords in Boolean query should be rejected."""
        with self.assertRaises(QueryParseError):
            self.qp.parse("diabetes AND diabetes")

    def test_multiple_words_without_and(self):
        """Multiple words without AND should be rejected."""
        with self.assertRaises(QueryParseError):
            self.qp.parse("diabetes doctor")


class TestKeyLifecycle(unittest.TestCase):
    """Test ephemeral query-key lifecycle."""

    def setUp(self):
        self.km = KeyManager()

    def test_create_query_key(self):
        """Test creation of ephemeral query key."""
        handle = self.km.create_query_key()
        self.assertFalse(handle.is_cleared)
        self.assertEqual(len(handle.key), 32)

    def test_clear_query_key(self):
        """Test that clearing a key marks it as cleared."""
        handle = self.km.create_query_key()
        self.km.clear_query_key(handle)
        self.assertTrue(handle.is_cleared)

    def test_cleared_key_inaccessible(self):
        """Test that a cleared key cannot be accessed."""
        handle = self.km.create_query_key()
        self.km.clear_query_key(handle)
        with self.assertRaises(RuntimeError):
            _ = handle.key

    def test_key_lifecycle_stats(self):
        """Test key lifecycle statistics."""
        for _ in range(3):
            handle = self.km.create_query_key()
            self.km.clear_query_key(handle)

        stats = self.km.get_lifecycle_stats()
        self.assertEqual(stats['total_queries'], 3)
        self.assertEqual(stats['total_keys_cleared'], 3)
        self.assertTrue(stats['all_cleared'])

    def test_master_key_never_changes(self):
        """Master key should remain constant."""
        key1 = self.km.master_key
        self.km.create_query_key()
        key2 = self.km.master_key
        self.assertEqual(key1, key2)


class TestNoPlaintextLeakage(unittest.TestCase):
    """Test that plaintext keywords are not stored in server-side structures."""

    def setUp(self):
        self.client = SearchableEncryptionClient()
        documents = [
            {"doc_id": "D001", "text": "Diabetes treatment by hospital doctors"},
        ]
        self.client.add_documents_bulk(documents)
        self.client.build_index()

    def test_keywords_not_in_server_index(self):
        """Plaintext keywords should not appear in the encrypted index."""
        index = self.client.server._encrypted_index
        for label in index._index.keys():
            self.assertNotIn("diabetes", label.lower())
            self.assertNotIn("hospital", label.lower())
            self.assertNotIn("doctor", label.lower())

    def test_master_key_stays_on_client(self):
        """Master key should not be accessible from server."""
        # Server should not have any reference to the master key
        server = self.client.server
        # Check that server doesn't store the master key
        self.assertFalse(hasattr(server, '_master_key'))
        self.assertFalse(hasattr(server, 'master_key'))


class TestInvalidInputs(unittest.TestCase):
    """Test error handling for invalid inputs."""

    def setUp(self):
        self.client = SearchableEncryptionClient()
        documents = load_dataset()[:10]
        self.client.add_documents_bulk(documents)
        self.client.build_index()

    def test_invalid_boolean_operator(self):
        """Unsupported Boolean operator should return error."""
        result = self.client.search("diabetes OR doctor")
        self.assertIn('error', result)

    def test_empty_query(self):
        """Empty query should return error."""
        result = self.client.search("")
        self.assertIn('error', result)

    def test_whitespace_query(self):
        """Whitespace-only query should return error."""
        result = self.client.search("   ")
        self.assertIn('error', result)

    def test_search_before_index(self):
        """Searching before building index should raise error."""
        client2 = SearchableEncryptionClient()
        client2.add_document("D001", "Test document")
        with self.assertRaises(RuntimeError):
            client2.search("test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
