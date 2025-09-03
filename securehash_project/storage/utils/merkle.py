"""Merkle tree implementation for hash combination."""

from typing import List, Optional, Tuple
from .hash_utils import compute_sha1


def build_merkle_root(leaf_hashes: List[bytes]) -> bytes:
    """
    Build a Merkle tree from leaf hashes and return the root hash.
    
    Args:
        leaf_hashes: List of leaf node hashes
        
    Returns:
        bytes: Merkle root hash
    """
    if not leaf_hashes:
        return compute_sha1(b'')
    
    # First hash all leaf values to ensure fixed length
    current_level = [compute_sha1(leaf) for leaf in leaf_hashes]
    
    while len(current_level) > 1:
        next_level = []
        # Process pairs of hashes
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # If odd number of hashes, duplicate the last one
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = compute_sha1(left + right)
            next_level.append(combined)
        current_level = next_level
    
    return current_level[0]


def build_proof(leaf_hashes: List[bytes], index: int) -> List[Tuple[bool, bytes]]:
    """
    Build a Merkle proof for the leaf at the given index.
    
    Args:
        leaf_hashes: List of all leaf hashes
        index: Index of the target leaf
        
    Returns:
        List[Tuple[bool, bytes]]: List of (is_left, hash) pairs forming the proof
    """
    if not leaf_hashes or index >= len(leaf_hashes):
        return []
    
    # First hash all leaf values
    current_level = [compute_sha1(leaf) for leaf in leaf_hashes]
    target_index = index
    proof = []
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i == target_index or i + 1 == target_index:
                # Add sibling to proof
                if target_index % 2 == 0:
                    if i + 1 < len(current_level):
                        proof.append((False, current_level[i + 1]))
                else:
                    proof.append((True, current_level[i]))
            
            # Calculate parent hash
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            next_level.append(compute_sha1(left + right))
        
        current_level = next_level
        target_index //= 2
    
    return proof


def verify_proof(leaf: bytes, proof: List[Tuple[bool, bytes]], root: bytes) -> bool:
    """
    Verify a Merkle proof against a root hash.
    
    Args:
        leaf: The target leaf value (not hashed)
        proof: List of (is_left, hash) pairs forming the proof
        root: Expected Merkle root
        
    Returns:
        bool: True if proof is valid, False otherwise
    """
    # Start with the leaf hash
    current = compute_sha1(leaf)
    
    for is_left, sibling in proof:
        if is_left:
            current = compute_sha1(sibling + current)
        else:
            current = compute_sha1(current + sibling)
    
    return current == root
