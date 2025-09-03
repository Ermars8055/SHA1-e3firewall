# Collatz-SHA1 Composite Hash System

A Django-based implementation of a composite hash system that combines Collatz sequences, SHA-1 hashing, and Merkle trees to create unique file signatures.

## Overview

This system implements a novel approach to file signatures by:
1. Using SHA-1 as the base hash function
2. Applying Collatz sequence transformations to influence the hash blocks
3. Building a Merkle tree from the transformed blocks
4. Producing a final hex signature

### Key Features

- Composite hash system combining multiple cryptographic primitives
- Stream-based file processing for handling large files
- CLI tool for easy signature computation and verification
- Django integration for web service capabilities
- Comprehensive test suite

## Installation

1. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python manage.py migrate
```

## CLI Tool Usage

The `collatz_sig.py` script provides three main commands:

1. Computing a file signature:
```bash
python scripts/collatz_sig.py compute path/to/file.txt
```

2. Verifying a file against a signature:
```bash
python scripts/collatz_sig.py verify path/to/file.txt <signature>
```

3. Testing for collisions between two files:
```bash
python scripts/collatz_sig.py demo-collision file1.txt file2.txt
```

For detailed help:
```bash
python scripts/collatz_sig.py --help
```

Enable verbose output with the `-v` flag:
```bash
python scripts/collatz_sig.py -v compute file.txt
```

## Development

### Project Structure

```
securehash_project/
├── manage.py                # Django management script
├── requirements.txt         # Python dependencies
├── pytest.ini              # pytest configuration
├── scripts/
│   └── collatz_sig.py      # CLI tool
├── securehash_project/     # Django project settings
└── storage/               # Main application
    ├── utils/
    │   ├── api.py         # High-level signature API
    │   ├── collatz_utils.py
    │   ├── file_utils.py
    │   ├── hash_utils.py
    │   └── merkle.py
    └── tests/
        ├── test_collatz_sequence.py
        ├── test_leaf_hash.py
        ├── test_merkle_tree.py
        └── test_signature_consistency.py
```

### Running Tests

Run the full test suite:
```bash
pytest
```

Run specific test files:
```bash
pytest storage/tests/test_merkle_tree.py
```

Run tests with verbose output:
```bash
pytest -v
```

### Implementation Details

The signature generation process involves several steps:

1. Initial SHA-1 hash computation
2. Block splitting and Collatz-based shuffling
3. Leaf hash computation with Collatz sequence influence
4. Merkle tree construction
5. Final signature generation

Key components:

- `hash_utils.py`: Core SHA-1 operations
- `collatz_utils.py`: Collatz sequence generation and block processing
- `merkle.py`: Merkle tree operations with proof generation/verification
- `file_utils.py`: Efficient file streaming
- `api.py`: High-level signature generation API

## Running the Server

Start the Django development server:
```bash
python manage.py runserver
```

The server will be available at http://localhost:8000/

## Security Considerations

- This is a demonstration system combining various cryptographic primitives
- The security properties are derived from:
  - SHA-1 hash function properties
  - Collatz sequence unpredictability
  - Merkle tree structure
- Not recommended for production cryptographic use without further analysis

## License

This project is available under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
