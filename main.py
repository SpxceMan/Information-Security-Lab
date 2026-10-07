"""
main.py
-------
CLI entry point for the Hybrid Privacy-Aware Searchable Encryption System.

ARCHITECTURAL CONTRIBUTION:
    This prototype integrates:
    1. Efficient single-keyword SSE (Curtmola et al.)
    2. OXT-inspired Boolean conjunctive search (Cash et al.)
    3. Lightweight result-size leakage mitigation (bucketization)
    4. Ephemeral query-key lifecycle management

    Each technique is from established literature.
    The integration into a single hybrid architecture is our contribution.
"""

import sys
import os
import json
import time

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client.client import SearchableEncryptionClient
from data.loader import load_dataset


def print_banner():
    print()
    print("=" * 70)
    print("  HYBRID PRIVACY-AWARE SEARCHABLE ENCRYPTION")
    print("  For Secure Cloud Data Retrieval")
    print("=" * 70)
    print("  Architecture: SSE + OXT-inspired Boolean + Padding + Ephemeral Keys")
    print("  Crypto: AES-256-GCM, HMAC-SHA256 (PyCryptodome)")
    print("  Trust Model: Client = trusted, Server = honest-but-curious")
    print("=" * 70)
    print()


def print_menu():
    print("-" * 50)
    print("  MENU")
    print("-" * 50)
    print("  1. Upload/encrypt documents")
    print("  2. Build encrypted index")
    print("  3. Search (single keyword)")
    print("  4. Search (Boolean AND query)")
    print("  5. Run all demonstrations")
    print("  6. Run privacy comparison")
    print("  7. Run benchmark")
    print("  8. Run security comparison")
    print("  9. Run tests")
    print("  10. View system stats")
    print("  0. Exit")
    print("-" * 50)


def display_search_result(result):
    """Display a search result in a user-friendly format."""
    if 'error' in result:
        print(f"\n  [ERROR] {result['error']}\n")
        return

    print(f"\n  {'='*60}")
    print(f"  Query: {result['query']}")
    print(f"  Query Type: {result['query_type']}")
    print(f"  Search Mechanism: {result['mechanism']}")
    print(f"  Keywords: {', '.join(result['keywords'])}")
    print(f"  {'='*60}")

    # Padding info
    padding = result.get('padding')
    if padding:
        print(f"\n  Privacy Mode: Bucket Padding")
        print(f"  Actual matching documents: {padding['actual_count']}")
        print(f"  Encrypted records returned: {padding['padded_count']} (bucket size: {padding['bucket_size']})")
        print(f"  Padding added: {padding['padding_added']}")
        print(f"  Risk level: {padding['risk_level']} (score: {padding['risk_score']})")
    else:
        print(f"\n  Privacy Mode: Disabled")
        print(f"  Results: {result['result_count']} documents")

    # Timing
    timing = result.get('timing', {})
    print(f"\n  Timing:")
    print(f"    Total: {timing.get('total_ms', 0):.3f} ms")
    print(f"    Token generation: {timing.get('token_generation_ms', 0):.3f} ms")
    print(f"    Search: {timing.get('search_ms', 0):.3f} ms")
    print(f"    Decryption: {timing.get('decryption_ms', 0):.3f} ms")

    # Key lifecycle
    kl = result.get('key_lifecycle', {})
    print(f"\n  Key Lifecycle:")
    print(f"    Ephemeral key created: {kl.get('key_created', False)}")
    print(f"    Token generated: {kl.get('key_used', False)}")
    print(f"    Key cleared after query: {kl.get('key_cleared', False)}")
    print(f"    Key lifetime: {kl.get('key_lifetime_ms', 0):.3f} ms")

    # Results
    results = result.get('results', [])
    if results:
        print(f"\n  Matching Documents ({len(results)}):")
        print(f"  {'-'*60}")
        for doc in results:
            if 'error' in doc:
                print(f"  [{doc['doc_id']}] ERROR: {doc['error']}")
            else:
                text = doc['plaintext']
                if len(text) > 100:
                    text = text[:100] + "..."
                print(f"  [{doc['doc_id']}] {text}")
    else:
        print(f"\n  No matching documents found.")

    print()


def run_all_demos(client):
    """Run all required demonstrations."""

    print("\n" + "=" * 70)
    print("  RUNNING ALL DEMONSTRATIONS")
    print("=" * 70)

    # DEMO 1: Single keyword search
    print("\n" + "=" * 60)
    print("  DEMO 1: Single Keyword Search")
    print("=" * 60)
    display_search_result(client.search("diabetes"))

    # DEMO 2: Boolean two-keyword search
    print("=" * 60)
    print("  DEMO 2: Boolean Multi-Keyword Search (2 keywords)")
    print("=" * 60)
    display_search_result(client.search("diabetes AND doctor"))

    # DEMO 3: Three-keyword query
    print("=" * 60)
    print("  DEMO 3: Three-Keyword Boolean AND Query")
    print("=" * 60)
    display_search_result(client.search("diabetes AND doctor AND hospital"))

    # DEMO 4: No-match query
    print("=" * 60)
    print("  DEMO 4: No-Match Query")
    print("=" * 60)
    display_search_result(client.search("xyznonexistent"))

    # DEMO 5: Result-size padding
    print("=" * 60)
    print("  DEMO 5: Result-Size Padding Comparison")
    print("=" * 60)
    print("\n  WITHOUT PADDING:")
    r_no = client.search("diabetes", enable_padding=False)
    print(f"    Results returned: {r_no['result_count']}")
    print("\n  WITH PADDING:")
    r_yes = client.search("diabetes", enable_padding=True)
    p = r_yes.get('padding', {})
    print(f"    Actual matches: {p.get('actual_count', '?')}")
    print(f"    Records returned: {p.get('padded_count', '?')}")
    print(f"    Bucket size: {p.get('bucket_size', '?')}")
    print()

    # DEMO 6: Repeated query
    print("=" * 60)
    print("  DEMO 6: Repeated Query Behavior")
    print("=" * 60)
    print()
    for i in range(5):
        r = client.search("diabetes", enable_padding=True)
        p = r.get('padding', {})
        print(f"    Run {i+1}: actual={p.get('actual_count', '?')}, "
              f"padded={p.get('padded_count', '?')}, "
              f"risk={p.get('risk_level', '?')} "
              f"(score={p.get('risk_score', '?')})")
    print()

    # DEMO 7: Ephemeral key lifecycle
    print("=" * 60)
    print("  DEMO 7: Ephemeral Query-Key Lifecycle")
    print("=" * 60)
    print()
    test_queries = ["diabetes", "diabetes AND doctor", "hospital AND surgery"]
    for q in test_queries:
        r = client.search(q)
        kl = r.get('key_lifecycle', {})
        print(f"    Query: '{q}'")
        print(f"      [1] Key CREATED:  {kl.get('key_created', False)}")
        print(f"      [2] Token USED:   {kl.get('key_used', False)}")
        print(f"      [3] Results:      {r.get('result_count', 0)} documents")
        print(f"      [4] Key CLEARED:  {kl.get('key_cleared', False)}")
        print(f"      [5] Lifetime:     {kl.get('key_lifetime_ms', 0):.3f} ms")
        print()

    stats = client.key_manager.get_lifecycle_stats()
    print(f"    Summary: {stats['total_queries']} queries, "
          f"{stats['total_keys_cleared']} keys cleared, "
          f"all cleared: {stats['all_cleared']}")
    print()


def main():
    print_banner()

    client = None
    documents_loaded = False
    index_built = False

    while True:
        print_menu()
        try:
            choice = input("\n  Enter choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting...")
            break

        if choice == '0':
            print("\n  Exiting. Goodbye!")
            break

        elif choice == '1':
            print("\n  Loading and encrypting documents...")
            if client is None:
                client = SearchableEncryptionClient()

            documents = load_dataset()
            result = client.add_documents_bulk(documents)

            print(f"  Documents uploaded: {result['documents_uploaded']}")
            print(f"  Total encryption time: {result['total_time_ms']:.3f} ms")
            print(f"  Avg per document: {result['avg_encryption_time_ms']:.3f} ms")
            documents_loaded = True
            print()

        elif choice == '2':
            if not documents_loaded:
                print("\n  [ERROR] Upload documents first (option 1).\n")
                continue

            print("\n  Building encrypted index...")
            result = client.build_index()
            print(f"  Index entries: {result['index_entries']}")
            print(f"  Unique keywords: {result['unique_keywords']}")
            print(f"  Build time: {result['build_time_ms']:.3f} ms")
            print(f"  Index size: {result['index_size_bytes']} bytes")
            index_built = True
            print()

        elif choice == '3':
            if not index_built:
                print("\n  [ERROR] Build index first (options 1 then 2).\n")
                continue

            query = input("  Enter keyword: ").strip()
            if query:
                result = client.search(query)
                display_search_result(result)

        elif choice == '4':
            if not index_built:
                print("\n  [ERROR] Build index first (options 1 then 2).\n")
                continue

            query = input("  Enter Boolean AND query (e.g., diabetes AND doctor): ").strip()
            if query:
                result = client.search(query)
                display_search_result(result)

        elif choice == '5':
            if not index_built:
                print("\n  Auto-initializing system...")
                client = SearchableEncryptionClient()
                documents = load_dataset()
                client.add_documents_bulk(documents)
                client.build_index()
                documents_loaded = True
                index_built = True

            run_all_demos(client)

        elif choice == '6':
            print("\n  Running privacy comparison...")
            from experiments.leakage_demo import run_leakage_demo
            run_leakage_demo()

        elif choice == '7':
            print("\n  Running benchmark...")
            from experiments.benchmark import run_benchmark
            run_benchmark()

        elif choice == '8':
            print("\n  Generating security comparison...")
            from experiments.results import generate_security_comparison
            generate_security_comparison()

        elif choice == '9':
            print("\n  Running tests...")
            import unittest
            loader = unittest.TestLoader()
            suite = loader.discover('tests', pattern='test_*.py')
            runner = unittest.TextTestRunner(verbosity=2)
            runner.run(suite)
            print()

        elif choice == '10':
            if client is None:
                print("\n  [INFO] No system initialized yet.\n")
                continue

            print("\n  System Statistics:")
            print(f"  Documents: {client.get_document_count()}")
            if index_built:
                metrics = client.get_metrics()
                print(f"  Index build time: {metrics['index_build_time_ms']:.3f} ms")
                print(f"  Server stats: {json.dumps(metrics['server_stats'], indent=4)}")
                print(f"  Key lifecycle: {json.dumps(metrics['key_lifecycle'], indent=4)}")
            print()

        else:
            print("\n  [ERROR] Invalid choice. Try again.\n")


if __name__ == "__main__":
    main()
