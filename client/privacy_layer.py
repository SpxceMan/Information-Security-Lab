"""
client/privacy_layer.py
-----------------------
Lightweight privacy layer for result-size leakage mitigation.

EXISTING TECHNIQUE:
    Result-set padding / bucketization to hide exact result counts.
    Concept from volume-hiding encrypted multi-maps and padded SSE literature.

OUR ARCHITECTURAL INTEGRATION:
    - Modular privacy layer that can be swapped with stronger mechanisms
    - Adaptive risk scoring based on query history
    - Indistinguishable padding records via AES-256-GCM encryption

EXPLICIT LIMITATION:
    This layer reduces EXACT RESULT-COUNT leakage only.
    It does NOT eliminate:
    - search-pattern leakage
    - access-pattern leakage
    - frequency leakage
    - query equality leakage
    - all forms of SSE leakage
"""

import time
import math
from collections import defaultdict
from crypto.utils import secure_random_bytes
from crypto.encryption import encrypt_result_record, decrypt_result_record


# Bucket sizes for padding
DEFAULT_BUCKET_SIZES = [4, 8, 16, 32, 64, 128, 256]

# Fixed padding size for high-risk queries
HIGH_RISK_FIXED_SIZE = 64

# Risk thresholds
LOW_RISK_THRESHOLD = 0.3
MEDIUM_RISK_THRESHOLD = 0.6


class QueryHistoryEntry:
    """Records a single query for risk assessment."""

    def __init__(self, query_hash: str, result_count: int, padded_count: int):
        self.query_hash = query_hash
        self.result_count = result_count
        self.padded_count = padded_count
        self.timestamp = time.time()


class PrivacyLayer:
    """
    Manages result-size padding and adaptive risk scoring.

    Padding mechanism:
        Real result count -> next bucket size
        Example: 3 results -> 4-result bucket
                 6 results -> 8-result bucket
                 13 results -> 16-result bucket

    Risk scoring:
        Tracks query repetitions and result-size patterns
        to decide whether stronger padding is needed.
    """

    def __init__(self, bucket_sizes: list = None, doc_key: bytes = None):
        """
        Args:
            bucket_sizes: List of bucket sizes (must be sorted ascending)
            doc_key: Document key for encrypting padding records
        """
        self.bucket_sizes = sorted(bucket_sizes or DEFAULT_BUCKET_SIZES)
        self._doc_key = doc_key
        self._query_history = []
        self._query_frequency = defaultdict(int)
        self._result_size_frequency = defaultdict(int)

    def compute_bucket_size(self, actual_count: int, risk_level: str = "LOW") -> int:
        """
        Determine the padded bucket size for a given actual result count.

        Args:
            actual_count: Number of real results
            risk_level: "LOW", "MEDIUM", or "HIGH"

        Returns:
            Bucket size to pad to
        """
        if risk_level == "HIGH":
            return HIGH_RISK_FIXED_SIZE

        if actual_count == 0:
            return self.bucket_sizes[0]

        for size in self.bucket_sizes:
            if actual_count <= size:
                return size

        # If larger than all buckets, round up to next power of 2
        return 2 ** math.ceil(math.log2(actual_count))

    def pad_results(self, real_doc_ids: list, query_hash: str = None) -> dict:
        """
        Pad real results with indistinguishable dummy records.

        OUR ARCHITECTURAL INTEGRATION:
            Both real and padding records are encrypted identically
            using AES-256-GCM. The real/padding flag is INSIDE the
            encrypted payload, invisible to the server.

        Args:
            real_doc_ids: List of actual matching document IDs
            query_hash: Hash of the query for risk tracking

        Returns:
            Dictionary with padded encrypted records and metadata
        """
        actual_count = len(real_doc_ids)

        # Assess risk if query hash provided
        risk_level = "LOW"
        risk_score = 0.0
        if query_hash:
            risk_score = self.compute_risk_score(query_hash, actual_count)
            risk_level = self._risk_level_from_score(risk_score)

        bucket_size = self.compute_bucket_size(actual_count, risk_level)
        padding_count = bucket_size - actual_count

        # Create encrypted result records
        encrypted_records = []

        # Real records
        for doc_id in real_doc_ids:
            doc_id_bytes = doc_id.encode('utf-8')
            # Pad doc_id to fixed length to prevent length-based distinction
            doc_id_padded = doc_id_bytes.ljust(64, b'\x00')
            record = encrypt_result_record(self._doc_key, doc_id_padded, is_real=True)
            encrypted_records.append(record)

        # Padding records (indistinguishable from real when encrypted)
        for _ in range(padding_count):
            dummy_data = secure_random_bytes(64)  # Same length as padded doc_id
            record = encrypt_result_record(self._doc_key, dummy_data, is_real=False)
            encrypted_records.append(record)

        # Track query history
        if query_hash:
            self._record_query(query_hash, actual_count, bucket_size)

        return {
            'encrypted_records': encrypted_records,
            'total_returned': bucket_size,
            'actual_count': actual_count,
            'padding_count': padding_count,
            'risk_level': risk_level,
            'risk_score': round(risk_score, 4),
            'bucket_size': bucket_size
        }

    def unpad_results(self, encrypted_records: list) -> list:
        """
        Decrypt and filter out padding records, returning only real doc IDs.

        Args:
            encrypted_records: List of encrypted record dicts

        Returns:
            List of real document ID strings
        """
        real_doc_ids = []

        for record in encrypted_records:
            try:
                is_real, record_data = decrypt_result_record(
                    self._doc_key,
                    record['ciphertext'],
                    record['nonce'],
                    record['tag']
                )
                if is_real:
                    # Remove null padding from doc_id
                    doc_id = record_data.rstrip(b'\x00').decode('utf-8')
                    real_doc_ids.append(doc_id)
            except ValueError:
                # Skip corrupted records
                continue

        return real_doc_ids

    def compute_risk_score(self, query_hash: str, result_count: int) -> float:
        """
        Compute a simple risk score based on query repetition and result patterns.

        Risk factors:
            1. Query repetition frequency (weight: 0.6)
            2. Result-size repetition (weight: 0.4)

        Args:
            query_hash: Hash of the current query
            result_count: Number of actual results

        Returns:
            Risk score between 0.0 and 1.0
        """
        # Query repetition factor
        query_freq = self._query_frequency.get(query_hash, 0)
        repetition_factor = min(query_freq / 10.0, 1.0)  # Caps at 10 repeats

        # Result-size repetition factor
        size_freq = self._result_size_frequency.get(result_count, 0)
        size_factor = min(size_freq / 15.0, 1.0)  # Caps at 15 occurrences

        # Weighted combination
        risk_score = 0.6 * repetition_factor + 0.4 * size_factor

        return min(risk_score, 1.0)

    def _risk_level_from_score(self, score: float) -> str:
        """Convert numeric risk score to categorical level."""
        if score >= MEDIUM_RISK_THRESHOLD:
            return "HIGH"
        elif score >= LOW_RISK_THRESHOLD:
            return "MEDIUM"
        return "LOW"

    def _record_query(self, query_hash: str, result_count: int, padded_count: int):
        """Record a query in history for risk tracking."""
        entry = QueryHistoryEntry(query_hash, result_count, padded_count)
        self._query_history.append(entry)
        self._query_frequency[query_hash] += 1
        self._result_size_frequency[result_count] += 1

    def get_history_stats(self) -> dict:
        """Get query history statistics."""
        return {
            'total_queries': len(self._query_history),
            'unique_queries': len(self._query_frequency),
            'query_frequencies': dict(self._query_frequency),
            'result_size_frequencies': dict(self._result_size_frequency)
        }

    def get_leakage_comparison(self) -> list:
        """
        Generate a comparison of actual vs padded result sizes
        for all queries in history.

        Used for the leakage demonstration.
        """
        comparisons = []
        for entry in self._query_history:
            comparisons.append({
                'query_hash': entry.query_hash[:16] + "...",
                'actual_count': entry.result_count,
                'padded_count': entry.padded_count,
                'padding_added': entry.padded_count - entry.result_count,
                'timestamp': entry.timestamp
            })
        return comparisons
