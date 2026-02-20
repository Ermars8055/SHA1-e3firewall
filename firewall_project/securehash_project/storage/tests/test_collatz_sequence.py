"""Tests for Collatz sequence generation and related utilities."""

import pytest
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
from storage.utils.collatz_utils import (
    collatz_sequence,
    serialize_seq,
    split_and_shuffle,
    compute_leaf_hash_from_block
)


def test_collatz_sequence_terminates():
    """Test that Collatz sequence always reaches 1."""
    test_cases = [5, 7, 10, 15, 20]
    for n in test_cases:
        logging.info(f"Testing Collatz sequence for n={n}")
        seq = collatz_sequence(n)
        assert seq[-1] == 1
        assert all(isinstance(x, int) for x in seq)
        logging.info(f"Sequence length: {len(seq)}")


def test_collatz_sequence_correctness():
    """Test known Collatz sequences."""
    # Test case: starting with 6
    # 6 → 3 → 10 → 5 → 16 → 8 → 4 → 2 → 1
    assert collatz_sequence(6) == [6, 3, 10, 5, 16, 8, 4, 2, 1]


def test_serialize_seq():
    """Test sequence serialization."""
    seq = [1, 2, 3, 4]
    serialized = serialize_seq(seq)
    assert isinstance(serialized, bytes)
    assert len(serialized) == len(seq) * 8  # 8 bytes per number


def test_split_and_shuffle():
    """Test hash splitting and shuffling."""
    test_hash = b'0123456789abcdef'  # 16 bytes
    num_blocks = 4
    
    blocks = split_and_shuffle(test_hash, num_blocks)
    
    assert len(blocks) == num_blocks
    assert all(len(block) == len(test_hash) // num_blocks for block in blocks)
    # All original bytes should be present, just rearranged
    assert sorted(b''.join(blocks)) == sorted(test_hash)


def test_compute_leaf_hash():
    """Test leaf hash computation."""
    test_block = b'test_block'
    leaf_hash = compute_leaf_hash_from_block(test_block)
    
    assert isinstance(leaf_hash, bytes)
    assert len(leaf_hash) == 20  # SHA-1 hash length
    
    # Same input should produce same hash
    assert compute_leaf_hash_from_block(test_block) == leaf_hash
