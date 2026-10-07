"""
experiments/benchmark.py
------------------------
Performance benchmarking for the hybrid SSE architecture.

Measures:
1. Document encryption time
2. Index generation time
3. Index size
4. Single-keyword search latency
5. Boolean search latency
6. Token generation time
7. Communication/result size
8. Padding overhead
9. Decryption time
10. Memory usage

Compares baseline SSE vs proposed hybrid architecture.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import SearchableEncryptionClient
from data.loader import load_dataset


def run_benchmark(num_documents=None):
    """Run comprehensive performance benchmarks."""

    print("=" * 70)
    print("  PERFORMANCE BENCHMARK")
    print("  Hybrid Privacy-Aware SSE Architecture")
    print("=" * 70)
    print()

    documents = load_dataset()
    if num_documents:
        documents = documents[:num_documents]

    print(f"  Dataset: {len(documents)} documents")
    print()

    # ============ PHASE 1: Document Encryption ============
    print("-" * 70)
    print("  PHASE 1: Document Encryption (AES-256-GCM)")
    print("-" * 70)

    client = SearchableEncryptionClient()

    enc_start = time.time()
    upload_result = client.add_documents_bulk(documents)
    enc_total = time.time() - enc_start

    print(f"  Documents encrypted: {upload_result['documents_uploaded']}")
    print(f"  Total time: {upload_result['total_time_ms']:.3f} ms")
    print(f"  Avg per document: {upload_result['avg_encryption_time_ms']:.3f} ms")
    print()

    # ============ PHASE 2: Index Building ============
    print("-" * 70)
    print("  PHASE 2: Encrypted Index Building")
    print("-" * 70)

    idx_result = client.build_index()
    print(f"  Index entries: {idx_result['index_entries']}")
    print(f"  Unique keywords: {idx_result['unique_keywords']}")
    print(f"  Build time: {idx_result['build_time_ms']:.3f} ms")
    print(f"  Index size: {idx_result['index_size_bytes']} bytes")
    print()

    # ============ PHASE 3: Single-Keyword Search ============
    print("-" * 70)
    print("  PHASE 3: Single-Keyword Search Latency")
    print("-" * 70)

    single_queries = ["diabetes", "doctor", "hospital", "cancer", "surgery",
                      "treatment", "patient", "blood", "xyznotexist"]

    single_results = []
    for query in single_queries:
        times = []
        for _ in range(5):  # 5 runs each
            start = time.time()
            result = client.search(query, enable_padding=False)
            elapsed = time.time() - start
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        result_count = result.get('result_count', 0)
        single_results.append({
            'query': query,
            'avg_ms': round(avg_time * 1000, 3),
            'results': result_count
        })
        print(f"  Query: {query:20s} | Avg: {avg_time*1000:8.3f} ms | Results: {result_count}")

    print()

    # ============ PHASE 4: Boolean AND Search ============
    print("-" * 70)
    print("  PHASE 4: Boolean AND Search Latency (OXT-inspired)")
    print("-" * 70)

    boolean_queries = [
        "diabetes AND doctor",
        "diabetes AND hospital",
        "doctor AND hospital",
        "diabetes AND doctor AND hospital",
        "cancer AND treatment",
        "surgery AND hospital",
    ]

    boolean_results = []
    for query in boolean_queries:
        times = []
        for _ in range(5):
            start = time.time()
            result = client.search(query, enable_padding=False)
            elapsed = time.time() - start
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        result_count = result.get('result_count', 0)
        boolean_results.append({
            'query': query,
            'avg_ms': round(avg_time * 1000, 3),
            'results': result_count
        })
        print(f"  Query: {query:40s} | Avg: {avg_time*1000:8.3f} ms | Results: {result_count}")

    print()

    # ============ PHASE 5: Padding Overhead ============
    print("-" * 70)
    print("  PHASE 5: Padding Overhead")
    print("-" * 70)

    padding_queries = ["diabetes", "doctor", "hospital",
                       "diabetes AND doctor", "diabetes AND doctor AND hospital"]

    for query in padding_queries:
        # Without padding
        start1 = time.time()
        r_no_pad = client.search(query, enable_padding=False)
        time_no_pad = time.time() - start1

        # With padding
        start2 = time.time()
        r_with_pad = client.search(query, enable_padding=True)
        time_with_pad = time.time() - start2

        padding_info = r_with_pad.get('padding', {})
        actual = padding_info.get('actual_count', r_no_pad.get('result_count', 0))
        padded = padding_info.get('padded_count', actual)
        overhead_ms = (time_with_pad - time_no_pad) * 1000

        print(f"  Query: {query:40s}")
        print(f"    Without padding: {time_no_pad*1000:8.3f} ms | {actual} results")
        print(f"    With padding:    {time_with_pad*1000:8.3f} ms | {padded} records (actual: {actual})")
        print(f"    Overhead:        {overhead_ms:8.3f} ms")
        print()

    # ============ PHASE 6: Overall Metrics ============
    print("-" * 70)
    print("  PHASE 6: Overall Metrics Summary")
    print("-" * 70)

    metrics = client.get_metrics()
    print(f"  Encryption:")
    print(f"    Count: {metrics['encryption']['count']}")
    print(f"    Avg: {metrics['encryption']['avg_ms']:.3f} ms")
    print(f"    Total: {metrics['encryption']['total_ms']:.3f} ms")
    print()
    print(f"  Index Build: {metrics['index_build_time_ms']:.3f} ms")
    print()
    print(f"  Search:")
    print(f"    Count: {metrics['search']['count']}")
    print(f"    Avg: {metrics['search']['avg_ms']:.3f} ms")
    print(f"    Min: {metrics['search']['min_ms']:.3f} ms")
    print(f"    Max: {metrics['search']['max_ms']:.3f} ms")
    print()
    print(f"  Token Generation:")
    print(f"    Count: {metrics['token_generation']['count']}")
    print(f"    Avg: {metrics['token_generation']['avg_ms']:.3f} ms")
    print()
    print(f"  Decryption:")
    print(f"    Count: {metrics['decryption']['count']}")
    print(f"    Avg: {metrics['decryption']['avg_ms']:.3f} ms")
    print()
    print(f"  Key Lifecycle:")
    kl = metrics['key_lifecycle']
    print(f"    Total queries: {kl['total_queries']}")
    print(f"    Keys cleared: {kl['total_keys_cleared']}")
    print(f"    All cleared: {kl['all_cleared']}")
    print()

    # ============ PHASE 7: Baseline vs Hybrid Comparison ============
    print("-" * 70)
    print("  PHASE 7: Baseline SSE vs Hybrid Architecture Comparison")
    print("-" * 70)
    print()

    # Baseline: SSE only (no padding, no Boolean)
    baseline_client = SearchableEncryptionClient()
    baseline_client.add_documents_bulk(documents)
    baseline_client.build_index()

    comparison_queries = ["diabetes", "doctor", "hospital"]
    baseline_times = []
    hybrid_times = []

    for query in comparison_queries:
        # Baseline: single keyword, no padding
        times_b = []
        for _ in range(10):
            start = time.time()
            baseline_client.search(query, enable_padding=False)
            times_b.append(time.time() - start)
        baseline_times.append(sum(times_b) / len(times_b))

        # Hybrid: single keyword, with padding
        times_h = []
        for _ in range(10):
            start = time.time()
            client.search(query, enable_padding=True)
            times_h.append(time.time() - start)
        hybrid_times.append(sum(times_h) / len(times_h))

    print(f"  {'Query':<20} {'Baseline (ms)':>15} {'Hybrid (ms)':>15} {'Overhead (ms)':>15}")
    print("  " + "-" * 65)
    for i, query in enumerate(comparison_queries):
        b = baseline_times[i] * 1000
        h = hybrid_times[i] * 1000
        print(f"  {query:<20} {b:>15.3f} {h:>15.3f} {h-b:>15.3f}")

    print()
    print("  Baseline: AES encryption + Basic SSE + Single keyword search")
    print("  Hybrid:   Baseline + Boolean search + Padding + Ephemeral keys")
    print()

    return {
        'single_results': single_results,
        'boolean_results': boolean_results,
        'metrics': metrics
    }


if __name__ == "__main__":
    run_benchmark()
