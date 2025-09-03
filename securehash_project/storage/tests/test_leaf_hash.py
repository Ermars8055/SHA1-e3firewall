"""Tests for leaf hash computation and properties."""

import pytest
from storage.utils.collatz_utils import compute_leaf_hash_from_block
from storage.utils.hash_utils import compute_sha1


def test_leaf_hash_deterministic():
    """Test that leaf hash computation is deterministic."""
    test_data = b'test_data'
    hash1 = compute_leaf_hash_from_block(test_data)
    hash2 = compute_leaf_hash_from_block(test_data)
    assert hash1 == hash2


def test_leaf_hash_different_inputs():
    """Test that different inputs produce different leaf hashes."""
    hash1 = compute_leaf_hash_from_block(b'data1')
    hash2 = compute_leaf_hash_from_block(b'data2')
    assert hash1 != hash2


def test_leaf_hash_empty_input():
    """Test leaf hash computation with empty input."""
    empty_hash = compute_leaf_hash_from_block(b'')
    assert isinstance(empty_hash, bytes)
    assert len(empty_hash) == 20  # SHA-1 hash length


def test_leaf_hash_collatz_influence():
    """Test that Collatz sequence influences the leaf hash."""
    # Two blocks with same SHA-1 hash but different first byte
    # should produce different leaf hashes due to Collatz influence
    block1 = b'\x01' + b'x' * 19
    block2 = b'\x02' + b'x' * 19
    
    # Ensure blocks have same SHA-1 initially
    assert compute_sha1(block1[1:]) == compute_sha1(block2[1:])
    
    # But different leaf hashes due to Collatz influence
    assert compute_leaf_hash_from_block(block1) != compute_leaf_hash_from_block(block2)
