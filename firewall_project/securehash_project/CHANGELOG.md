# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-09-04
### Added
- Enhanced Collatz Signature Algorithm implementation
- Direct file block processing without SHA-1 dependency
- Improved block mixing function
- Bounded integer arithmetic for overflow prevention
- Comprehensive collision resistance testing
- Cryptographic properties proof documentation

### Changed
- Removed dependency on SHA-1 for initial hashing
- Updated block processing to work directly with file content
- Improved documentation with cryptographic proofs
- Enhanced error handling and edge case management

### Fixed
- Fixed collision vulnerability with SHA-1 shattered PDFs
- Resolved integer overflow issues in sequence generation
- Improved block mixing to ensure better avalanche effect

### Verified
- Collision resistance against SHA-1 shattered PDFs
- Deterministic output property
- Fixed length output property
- Avalanche effect
- Preimage resistance

## [1.0.0] - 2025-09-03

### Added
- Initial release of Collatz-SHA1 composite hash system
- Core hash utility functions in `hash_utils.py`
- Collatz sequence utilities in `collatz_utils.py`
- Merkle tree implementation in `merkle.py`
- File streaming utilities in `file_utils.py`
- High-level API in `api.py`
- CLI tool for signature computation and verification
- Comprehensive test suite
- Django project integration
- Documentation (README.md, CONTRIBUTING.md, SECURITY.md)

### Security
- Implementation of composite hash system
- Collatz sequence integration
- Merkle tree verification capabilities

### Dependencies
- Django 4.2.0 or higher
- pytest 7.4.0 or higher
- pytest-django 4.5.0 or higher
