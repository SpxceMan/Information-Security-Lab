"""
experiments/results.py
----------------------
Generate graphs and tables for the research report.
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import SearchableEncryptionClient
from data.loader import load_dataset


def generate_security_comparison():
    """
    Generate the security comparison table.

    Compares:
        Plain encrypted storage vs Basic SSE vs Boolean SSE vs Proposed system
    """
    print("=" * 80)
    print("  SECURITY COMPARISON TABLE")
    print("=" * 80)
    print()

    headers = ["Feature", "Plain Encrypted", "Basic SSE", "Boolean SSE", "Proposed Hybrid"]
    rows = [
        ["Searchability", "No", "Yes", "Yes", "Yes"],
        ["Single keyword", "No", "Yes", "Yes", "Yes"],
        ["Boolean AND queries", "No", "No", "Yes", "Yes"],
        ["Result-size hiding", "N/A", "No", "No", "Partial (bucketed)"],
        ["Query-key lifetime", "N/A", "Persistent", "Persistent", "Ephemeral"],
        ["Search efficiency", "N/A", "O(matches)", "O(s-term + intersect)", "O(s-term + intersect)"],
        ["Storage overhead", "Low", "Medium", "Medium", "Medium + padding"],
        ["Leakage level", "None (no search)", "High", "Medium", "Reduced (partial)"],
    ]

    # Calculate column widths
    widths = [max(len(h), max(len(r[i]) for r in rows)) + 2 for i, h in enumerate(headers)]

    # Print header
    header_line = "  " + "".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print("  " + "-" * sum(widths))

    for row in rows:
        line = "  " + "".join(cell.ljust(w) for cell, w in zip(row, widths))
        print(line)

    print()
    print("  NOTE: 'Proposed Hybrid' does NOT claim to eliminate all leakage.")
    print("  It only reduces exact result-count leakage via bucketization.")
    print()


def generate_performance_graphs():
    """Generate performance data and save results for graphing."""

    print("=" * 80)
    print("  GENERATING PERFORMANCE DATA FOR GRAPHS")
    print("=" * 80)
    print()

    documents = load_dataset()

    # Test with increasing dataset sizes
    sizes = [10, 25, 50, 75, 100]
    enc_times = []
    idx_times = []
    idx_sizes = []
    search_single_times = []
    search_boolean_times = []

    for size in sizes:
        subset = documents[:size]
        client = SearchableEncryptionClient()

        # Encryption
        start = time.time()
        client.add_documents_bulk(subset)
        enc_time = time.time() - start
        enc_times.append(round(enc_time * 1000, 3))

        # Index
        start = time.time()
        idx_result = client.build_index()
        idx_time = time.time() - start
        idx_times.append(round(idx_time * 1000, 3))
        idx_sizes.append(idx_result['index_size_bytes'])

        # Single keyword search
        start = time.time()
        client.search("diabetes", enable_padding=False)
        s_time = time.time() - start
        search_single_times.append(round(s_time * 1000, 3))

        # Boolean search
        start = time.time()
        client.search("diabetes AND doctor", enable_padding=False)
        b_time = time.time() - start
        search_boolean_times.append(round(b_time * 1000, 3))

        print(f"  Size {size:>4}: enc={enc_time*1000:.1f}ms, "
              f"idx={idx_time*1000:.1f}ms, "
              f"single={s_time*1000:.1f}ms, "
              f"boolean={b_time*1000:.1f}ms")

    # Save data for external graphing
    data = {
        'sizes': sizes,
        'encryption_times_ms': enc_times,
        'index_build_times_ms': idx_times,
        'index_sizes_bytes': idx_sizes,
        'single_search_times_ms': search_single_times,
        'boolean_search_times_ms': search_boolean_times,
    }

    results_dir = os.path.dirname(os.path.abspath(__file__))
    results_file = os.path.join(results_dir, 'performance_data.json')
    with open(results_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n  Performance data saved to: {results_file}")
    print()

    # Try to generate matplotlib graphs
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Performance Metrics - Hybrid SSE Architecture', fontsize=14, fontweight='bold')

        # 1. Encryption time vs dataset size
        axes[0, 0].plot(sizes, enc_times, 'b-o', linewidth=2, markersize=6)
        axes[0, 0].set_xlabel('Number of Documents')
        axes[0, 0].set_ylabel('Time (ms)')
        axes[0, 0].set_title('Document Encryption Time')
        axes[0, 0].grid(True, alpha=0.3)

        # 2. Index build time vs dataset size
        axes[0, 1].plot(sizes, idx_times, 'r-s', linewidth=2, markersize=6)
        axes[0, 1].set_xlabel('Number of Documents')
        axes[0, 1].set_ylabel('Time (ms)')
        axes[0, 1].set_title('Index Build Time')
        axes[0, 1].grid(True, alpha=0.3)

        # 3. Search latency comparison
        axes[1, 0].plot(sizes, search_single_times, 'g-o', linewidth=2, markersize=6, label='Single Keyword')
        axes[1, 0].plot(sizes, search_boolean_times, 'm-s', linewidth=2, markersize=6, label='Boolean AND')
        axes[1, 0].set_xlabel('Number of Documents')
        axes[1, 0].set_ylabel('Time (ms)')
        axes[1, 0].set_title('Search Latency Comparison')
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)

        # 4. Index size vs dataset size
        idx_sizes_kb = [s / 1024 for s in idx_sizes]
        axes[1, 1].bar(range(len(sizes)), idx_sizes_kb, tick_label=[str(s) for s in sizes], color='teal', alpha=0.7)
        axes[1, 1].set_xlabel('Number of Documents')
        axes[1, 1].set_ylabel('Size (KB)')
        axes[1, 1].set_title('Encrypted Index Size')
        axes[1, 1].grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        graph_file = os.path.join(results_dir, 'performance_graphs.png')
        plt.savefig(graph_file, dpi=150)
        print(f"  Graphs saved to: {graph_file}")
        plt.close()

        # Padding overhead graph
        fig2, ax2 = plt.subplots(figsize=(10, 6))
        client = SearchableEncryptionClient()
        client.add_documents_bulk(documents)
        client.build_index()

        queries = ["diabetes", "doctor", "hospital", "cancer", "surgery",
                   "treatment", "patient", "blood"]
        actuals = []
        paddeds = []
        query_labels = []

        for q in queries:
            r = client.search(q, enable_padding=True)
            p = r.get('padding', {})
            actuals.append(p.get('actual_count', r.get('result_count', 0)))
            paddeds.append(p.get('padded_count', actuals[-1]))
            query_labels.append(q)

        x = range(len(queries))
        width = 0.35
        ax2.bar([i - width/2 for i in x], actuals, width, label='Actual Results', color='steelblue', alpha=0.8)
        ax2.bar([i + width/2 for i in x], paddeds, width, label='Padded Results', color='coral', alpha=0.8)
        ax2.set_xlabel('Query')
        ax2.set_ylabel('Result Count')
        ax2.set_title('Actual vs Padded Result Counts (Leakage Comparison)')
        ax2.set_xticks(list(x))
        ax2.set_xticklabels(query_labels, rotation=45, ha='right')
        ax2.legend()
        ax2.grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        leakage_graph = os.path.join(results_dir, 'leakage_comparison.png')
        plt.savefig(leakage_graph, dpi=150)
        print(f"  Leakage graph saved to: {leakage_graph}")
        plt.close()

    except ImportError:
        print("  matplotlib not available. Skipping graph generation.")
        print("  Install with: pip install matplotlib")
    print()


def generate_all():
    """Generate all results for the report."""
    generate_security_comparison()
    generate_performance_graphs()


if __name__ == "__main__":
    generate_all()
