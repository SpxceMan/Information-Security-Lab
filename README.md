# Hybrid Privacy-Aware Searchable Encryption for Secure Cloud Data Retrieval

## Overview

A research prototype demonstrating how multiple searchable symmetric encryption (SSE) techniques can be combined into one practical architecture for secure cloud data retrieval.

**This is a college Information Security project prototype.**

### What This Project Integrates (from existing literature)

| Component | Based On |
|---|---|
| Single-keyword SSE | Curtmola et al., "Searchable Symmetric Encryption" (CCS 2006) |
| Boolean AND search | OXT-inspired architecture from Cash et al. (CRYPTO 2013) |
| Document encryption | AES-256-GCM (NIST SP 800-38D) |
| PRF for tokens/index | HMAC-SHA256 (RFC 2104) |
| Result-size padding | Concept from volume-hiding / padded SSE literature |

### Our Architectural Contribution

The integration of efficient single-keyword search, Boolean conjunctive search, lightweight result-size leakage mitigation, and ephemeral query-key management into a single hybrid architecture.

**We do NOT claim to have invented any cryptographic primitive or SSE scheme.**

---

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

### CLI Menu

| Option | Description |
|--------|-------------|
| 1 | Upload/encrypt documents (AES-256-GCM) |
| 2 | Build encrypted inverted index |
| 3 | Single keyword search |
| 4 | Boolean AND query |
| 5 | Run all 7 demonstrations |
| 6 | Run privacy/leakage comparison |
| 7 | Run performance benchmark |
| 8 | Security feature comparison table |
| 9 | Run unit tests (48 tests) |
| 10 | View system statistics |

### Query Examples

```
Single:   diabetes
Boolean:  diabetes AND doctor AND hospital
```

## Running Tests

```bash
python -m unittest tests.test_all -v
```

## Running Benchmarks

```bash
python experiments/benchmark.py
```

## Running Leakage Demo

```bash
python experiments/leakage_demo.py
```

## Generating Graphs/Tables

```bash
python experiments/results.py
```

---

## Project Structure

```
searchable-encryption/
├── client/
│   ├── client.py           # Main client (integrates all components)
│   ├── query_processor.py  # Parses single-keyword & Boolean AND queries
│   ├── key_manager.py      # Master key + ephemeral query-key lifecycle
│   ├── token_generator.py  # Search token/trapdoor generation
│   ├── privacy_layer.py    # Result-size padding/bucketization
│   └── decryptor.py        # Document decryption
├── server/
│   ├── server.py           # Cloud server simulation (honest-but-curious)
│   ├── encrypted_index.py  # Encrypted inverted index (SSE-2)
│   ├── search_engine.py    # Single-keyword + OXT-inspired Boolean search
│   └── result_handler.py   # Result packaging
├── crypto/
│   ├── encryption.py       # AES-256-GCM encryption/decryption
│   ├── prf.py              # HMAC-SHA256 PRF, key derivation, token generation
│   └── utils.py            # Utilities (secure random, normalization)
├── data/
│   ├── dataset.json        # 100 medical documents
│   └── loader.py           # Dataset loader
├── experiments/
│   ├── benchmark.py        # Performance benchmarking
│   ├── leakage_demo.py     # Leakage comparison demonstration
│   └── results.py          # Graph/table generation
├── tests/
│   └── test_all.py         # 48 unit tests
├── main.py                 # CLI entry point
├── requirements.txt
└── README.md
```

## Trust Model

- **Client**: Trusted
- **Cloud Server**: Honest-but-curious

## Security Limitations (explicitly acknowledged)

Result-size padding reduces **exact result-count leakage only**.

It does **NOT** eliminate:
- Search-pattern leakage
- Access-pattern leakage
- Frequency leakage
- Query equality leakage

Ephemeral key clearing is **best-effort in Python** and does not guarantee secure memory erasure.

## Cryptographic Libraries

- **PyCryptodome** for AES-256-GCM and secure random generation
- **Python hmac + hashlib** for HMAC-SHA256

No custom cryptographic primitives are implemented.
