"""Utility functions for SHA-1 hashing and signature generation."""

import hashlib


def compute_sha1(data: bytes) -> bytes:
    """
    Compute SHA-1 hash of input data.
    
    Args:
        data: Bytes to hash
        
    Returns:
        bytes: The SHA-1 hash of the input data
    """
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.digest()


def final_signature_from_root(root: bytes) -> str:
    """
    Convert a Merkle root hash into its final hexadecimal signature.
    
    Args:
        root: The Merkle root hash bytes
        
    Returns:
        str: Hexadecimal representation of the hash
    """
    return root.hex()
