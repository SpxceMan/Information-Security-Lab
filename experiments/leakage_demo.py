"""
experiments/leakage_demo.py
---------------------------
Demonstrates what the cloud server can observe with and without
the privacy layer (result-size padding).

This is the main security demonstration for the project.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import SearchableEncryptionClient
from data.loader import load_dataset


def run_leakage_demo():
    """
    DEMO: Comparison of server observations with and without padding.

    Shows:
    1. What the server sees WITHOUT privacy layer (exact result counts)
    2. What the server sees WITH privacy layer (bucketed/padded counts)
    3. Side-by-side comparison
    """
    print("=" * 70)
    print("  LEAKAGE DEMONSTRATION")
    print("  What the Cloud Server Can Observe")
    print("=" * 70)
    print()

    # Initialize system
    client = SearchableEncryptionClient()
    documents = load_dataset()

    print(f"[SETUP] Encrypting and uploading {len(documents)} documents...")
    client.add_documents_bulk(documents)
    client.build_index()
    print(f"[SETUP] Index built successfully.\n")

    # Test queries
    test_queries = [
        "diabetes",
        "doctor",
        "hospital",
        "diabetes AND doctor",
        "diabetes AND hospital",
        "diabetes AND doctor AND hospital",
        "cancer",
        "surgery",
        "xyznotexist",
    ]

    print("-" * 70)
    print("  WITHOUT PRIVACY LAYER (Server sees exact counts)")
    print("-" * 70)

    no_padding_results = []
    for query in test_queries:
        result = client.search(query, enable_padding=False)
        count = result.get('result_count', 0)
        no_padding_results.append({
            'query': query,
            'actual_count': count,
            'type': result.get('query_type', 'N/A')
        })
        print(f"  Query: {query:40s} -> {count} results")

    print()
    print("-" * 70)
    print("  WITH PRIVACY LAYER (Server sees padded counts)")
    print("-" * 70)

    # Reset privacy layer for clean demo
    client2 = SearchableEncryptionClient(master_key=client.key_manager.master_key)
    client2.add_documents_bulk(documents)
    client2.build_index()

    with_padding_results = []
    for query in test_queries:
        result = client2.search(query, enable_padding=True)
        padding = result.get('padding', {})
        actual = padding.get('actual_count', result.get('result_count', 0))
        padded = padding.get('padded_count', actual)
        with_padding_results.append({
            'query': query,
            'actual_count': actual,
            'padded_count': padded,
            'padding_added': padding.get('padding_added', 0),
            'bucket': padding.get('bucket_size', 0),
            'risk': padding.get('risk_level', 'N/A')
        })
        print(f"  Query: {query:40s} -> {padded} records (actual: {actual})")

    # Comparison table
    print()
    print("=" * 70)
    print("  COMPARISON: Exact vs Padded Result Counts")
    print("=" * 70)
    print(f"  {'Query':<35} {'Exact':>8} {'Padded':>8} {'Padding':>8}")
    print("  " + "-" * 65)

    for no_pad, with_pad in zip(no_padding_results, with_padding_results):
        q = no_pad['query']
        exact = no_pad['actual_count']
        padded = with_pad['padded_count']
        padding = with_pad['padding_added']
        print(f"  {q:<35} {exact:>8} {padded:>8} {'+' + str(padding):>8}")

    print()
    print("=" * 70)
    print("  ANALYSIS")
    print("=" * 70)
    print()
    print("  Without the privacy layer, the server sees EXACT result counts.")
    print("  This can reveal information about the data distribution.")
    print()
    print("  With result-size padding (bucketization), the server only sees")
    print("  the padded bucket size, making it harder to determine exact counts.")
    print()
    print("  LIMITATION: This does NOT prevent search-pattern, access-pattern,")
    print("  frequency, or query-equality leakage. It only reduces exact")
    print("  result-count leakage.")
    print()

    # Repeated query demonstration
    print("=" * 70)
    print("  REPEATED QUERY DEMONSTRATION")
    print("=" * 70)
    print()

    repeated_query = "diabetes"
    print(f"  Repeating query '{repeated_query}' 5 times:")
    print()

    for i in range(5):
        result = client2.search(repeated_query, enable_padding=True)
        padding = result.get('padding', {})
        print(f"  Run {i+1}: actual={padding.get('actual_count', '?')}, "
              f"padded={padding.get('padded_count', '?')}, "
              f"risk={padding.get('risk_level', '?')} "
              f"(score={padding.get('risk_score', '?')})")

    print()
    print("  As queries repeat, the risk score may increase,")
    print("  triggering stronger padding for privacy protection.")
    print()


def run_key_lifecycle_demo():
    """
    DEMO 7: Ephemeral query-key lifecycle demonstration.

    Shows:
    1. Key created for query
    2. Token generated
    3. Search completed
    4. Temporary key cleared
    """
    print("=" * 70)
    print("  EPHEMERAL QUERY-KEY LIFECYCLE DEMONSTRATION")
    print("=" * 70)
    print()

    client = SearchableEncryptionClient()
    documents = load_dataset()
    client.add_documents_bulk(documents)
    client.build_index()

    queries = ["diabetes", "diabetes AND doctor", "hospital AND surgery"]

    for query in queries:
        print(f"  Query: '{query}'")
        result = client.search(query, enable_padding=True)
        kl = result.get('key_lifecycle', {})

        print(f"    [1] Ephemeral key CREATED: {kl.get('key_created', False)}")
        print(f"    [2] Token GENERATED and used: {kl.get('key_used', False)}")
        print(f"    [3] Search completed: {result.get('result_count', 0)} results")
        print(f"    [4] Ephemeral key CLEARED: {kl.get('key_cleared', False)}")
        print(f"    [5] Key lifetime: {kl.get('key_lifetime_ms', 0):.3f} ms")
        print()

    stats = client.key_manager.get_lifecycle_stats()
    print(f"  Key Lifecycle Summary:")
    print(f"    Total queries: {stats['total_queries']}")
    print(f"    Total keys cleared: {stats['total_keys_cleared']}")
    print(f"    Active handles remaining: {stats['active_handles']}")
    print(f"    All cleared: {stats['all_cleared']}")
    print()


if __name__ == "__main__":
    run_leakage_demo()
    print("\n")
    run_key_lifecycle_demo()
