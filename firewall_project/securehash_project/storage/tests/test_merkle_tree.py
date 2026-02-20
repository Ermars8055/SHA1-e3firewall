"""Tests for Merkle tree operations."""

import pytest
from storage.utils.merkle import build_merkle_root, build_proof, verify_proof


def test_merkle_root_empty():
    """Test Merkle root computation with empty input."""
    root = build_merkle_root([])
    assert isinstance(root, bytes)
    assert len(root) == 20  # SHA-1 hash length


def test_merkle_root_single_leaf():
    """Test Merkle root computation with single leaf."""
    leaf = b'test_leaf'
    root = build_merkle_root([leaf])
    assert isinstance(root, bytes)
    assert len(root) == 20


def test_merkle_root_multiple_leaves():
    """Test Merkle root computation with multiple leaves."""
    leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4']
    root = build_merkle_root(leaves)
    assert isinstance(root, bytes)
    assert len(root) == 20


def test_merkle_proof_generation():
    """Test Merkle proof generation and verification."""
    leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4']
    root = build_merkle_root(leaves)
    
    # Test proof for each leaf
    for i, leaf in enumerate(leaves):
        proof = build_proof(leaves, i)
        assert verify_proof(leaf, proof, root)


def test_merkle_proof_invalid():
    """Test that invalid proofs are rejected."""
    leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4']
    root = build_merkle_root(leaves)
    
    # Get valid proof for first leaf
    proof = build_proof(leaves, 0)
    
    # Modify the proof to make it invalid
    if proof:
        proof[0] = (proof[0][0], b'invalid_hash')
    
    assert not verify_proof(leaves[0], proof, root)


def test_merkle_tree_deterministic():
    """Test that Merkle tree construction is deterministic."""
    leaves = [b'leaf1', b'leaf2', b'leaf3']
    root1 = build_merkle_root(leaves)
    root2 = build_merkle_root(leaves)
    assert root1 == root2


def test_merkle_proof_ordering():
    """Test that proof order matters in verification."""
    leaves = [b'leaf1', b'leaf2', b'leaf3', b'leaf4']
    root = build_merkle_root(leaves)
    proof = build_proof(leaves, 0)
    
    # Reverse proof order should fail verification
    reversed_proof = [(is_left, hash_) for is_left, hash_ in reversed(proof)]
    assert not verify_proof(leaves[0], reversed_proof, root)
