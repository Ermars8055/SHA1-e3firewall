"""High-level API for the Collatz-SHA1 composite hash system."""

import logging
from typing import List

from .hash_utils import compute_sha1, final_signature_from_root
from .collatz_utils import split_and_shuffle, compute_leaf_hash_from_block
from .merkle import build_merkle_root


def collatz_sha1_signature_of_data(data: bytes, num_blocks: int = 4) -> str:
    """
    Generate a composite signature for input data using Collatz-SHA1 system.
    
    The process involves:
    1. Computing initial SHA-1 hash
    2. Splitting and shuffling using Collatz sequences
    3. Computing leaf hashes with Collatz influence
    4. Building Merkle tree and getting root
    5. Converting to final signature format
    
    Args:
        data: Input bytes to generate signature for
        num_blocks: Number of blocks to split hash into
        
    Returns:
        str: Hexadecimal signature string
    """
    logging.debug("Computing initial SHA-1 hash")
    initial_hash = compute_sha1(data)
    
    logging.debug(f"Splitting hash into {num_blocks} blocks and shuffling")
    blocks = split_and_shuffle(initial_hash, num_blocks)
    
    logging.debug("Computing leaf hashes with Collatz influence")
    leaf_hashes: List[bytes] = [compute_leaf_hash_from_block(block) for block in blocks]
    
    logging.debug("Building Merkle tree and getting root")
    root = build_merkle_root(leaf_hashes)
    
    logging.debug("Converting to final signature format")
    return final_signature_from_root(root)
