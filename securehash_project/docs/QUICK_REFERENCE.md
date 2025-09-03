# Quick Reference Guide

## CLI Commands

### Basic Usage
```bash
# Compute signature
python scripts/collatz_sig.py compute file.txt

# Verify signature
python scripts/collatz_sig.py verify file.txt <signature>

# Check for collisions
python scripts/collatz_sig.py demo-collision file1.txt file2.txt
```

### Options
```bash
# Verbose output
python scripts/collatz_sig.py -v compute file.txt

# Help
python scripts/collatz_sig.py --help
```

## Python API

### High-Level API
```python
from storage.utils.api import collatz_sha1_signature_of_data

# Generate signature
signature = collatz_sha1_signature_of_data(b"data")

# With custom block count
signature = collatz_sha1_signature_of_data(b"data", num_blocks=8)
```

### Low-Level Components
```python
from storage.utils.hash_utils import compute_sha1
from storage.utils.collatz_utils import collatz_sequence
from storage.utils.merkle import build_merkle_root

# Hash computation
hash_bytes = compute_sha1(b"data")

# Collatz sequence
sequence = collatz_sequence(42)

# Merkle tree
root = build_merkle_root([hash1, hash2, hash3])
```

## Common Development Tasks

### Testing
```bash
# All tests
pytest

# Specific test
pytest storage/tests/test_merkle_tree.py

# With coverage
pytest --cov=storage
```

### Django Development
```bash
# Run server
python manage.py runserver

# Migrations
python manage.py makemigrations
python manage.py migrate
```

## Error Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | Verification failed |
| 2 | File error |
| 3 | System error |

## Project Structure
```
securehash_project/
├── storage/utils/          # Core implementation
│   ├── api.py             # High-level API
│   ├── hash_utils.py      # SHA-1 operations
│   ├── collatz_utils.py   # Sequence handling
│   ├── merkle.py         # Tree operations
│   └── file_utils.py     # File handling
├── scripts/               # CLI tools
└── tests/                # Test suites
```

## Type Hints

```python
from typing import List, Tuple, Iterator

def example(data: bytes) -> str: ...
def sequence(n: int) -> List[int]: ...
def proof(hashes: List[bytes]) -> List[Tuple[bool, bytes]]: ...
def stream(path: str) -> Iterator[bytes]: ...
```

## Common Patterns

### File Processing
```python
from storage.utils.file_utils import stream_file_in_chunks

for chunk in stream_file_in_chunks(file_path):
    process(chunk)
```

### Error Handling
```python
try:
    signature = compute_signature(file_path)
except IOError as e:
    print(f"File error: {e}")
except Exception as e:
    print(f"System error: {e}")
```

### Logging
```python
import logging

logging.debug("Processing started")
logging.info("Signature: %s", signature)
logging.error("Failed: %s", error)
```
