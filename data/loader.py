"""
data/loader.py
--------------
Dataset loader utility.
"""

import json
import os


def load_dataset(filepath: str = None) -> list:
    """
    Load the document dataset from JSON.

    Args:
        filepath: Path to dataset JSON file. Defaults to data/dataset.json.

    Returns:
        List of document dicts with 'doc_id' and 'text' fields.
    """
    if filepath is None:
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'data', 'dataset.json'
        )

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        documents = json.load(f)

    # Validate
    for doc in documents:
        if 'doc_id' not in doc or 'text' not in doc:
            raise ValueError(f"Invalid document format: {doc}")

    return documents


def generate_scaled_dataset(base_documents: list, target_size: int) -> list:
    """
    Generate a larger dataset by duplicating and modifying base documents.

    Args:
        base_documents: Original document list
        target_size: Desired number of documents

    Returns:
        Scaled document list
    """
    scaled = []
    base_count = len(base_documents)

    for i in range(target_size):
        base_idx = i % base_count
        base_doc = base_documents[base_idx]

        if i < base_count:
            scaled.append(base_doc.copy())
        else:
            # Create a variant
            variant = {
                'doc_id': f"D{i+1:04d}",
                'text': f"[Variant {i // base_count}] {base_doc['text']}"
            }
            scaled.append(variant)

    return scaled
