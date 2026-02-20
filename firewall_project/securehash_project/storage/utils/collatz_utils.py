"""Utility functions for Collatz sequence generation and block processing."""

import logging
import struct
from typing import List, Iterator


def collatz_sequence(n: int) -> List[int]:
    """
    Generate Collatz sequence starting from n until reaching 1.
    
    Args:
        n: Starting number for the sequence
        
    Returns:
        List[int]: The complete Collatz sequence
        
    Raises:
        RuntimeError: If number becomes too large
    """
    sequence = [n]
    iterations = 0
    current = n
    
    logging.info(f"Starting Collatz sequence with n={n}")
    
    while current != 1:
        if iterations % 100 == 0:  # Log progress every 100 iterations
            logging.info(f"  Progress: iteration {iterations}, current value = {current}")
            
        if current % 2 == 0:
            current = current // 2
            logging.debug(f"  Even: {current * 2} -> {current}")
        else:
            # Prevent potential integer overflow
            if current > (2**60):  # Safe limit for multiplication by 3
                msg = f"Number too large in Collatz sequence: {current}"
                logging.error(msg)
                raise RuntimeError(msg)
            current = 3 * current + 1
            logging.debug(f"  Odd: {(current-1)//3} -> {current}")
            
        sequence.append(current)
        iterations += 1
        
    if current != 1:
        msg = f"Sequence did not reach 1 after {iterations} iterations with value {current}"
        logging.warning(msg)
        return sequence  # Return the sequence as is
    
    logging.info(f"Sequence completed: length={len(sequence)}, final value={current}")
    return sequence


def serialize_seq(seq: List[int]) -> bytes:
    """
    Serialize a sequence of integers into bytes.
    
    Args:
        seq: List of integers to serialize
        
    Returns:
        bytes: Serialized representation of the sequence
    """
    # Pack each number as a 64-bit integer
    return b''.join(struct.pack('>Q', num) for num in seq)


def split_and_shuffle(hash_bytes: bytes, num_blocks: int = 4) -> List[bytes]:
    """
    Split input hash into blocks and apply Collatz-based shuffling.
    
    Args:
        hash_bytes: Input hash to split and shuffle
        num_blocks: Number of blocks to split into
        
    Returns:
        List[bytes]: List of shuffled blocks
    """
    logging.info(f"Splitting hash into {num_blocks} blocks")
    logging.info(f"Input hash length: {len(hash_bytes)} bytes")
    
    block_size = len(hash_bytes) // num_blocks
    logging.info(f"Block size: {block_size} bytes")
    
    if len(hash_bytes) % num_blocks != 0:
        logging.warning("Hash length not divisible by num_blocks, some data may be truncated")
    
    # Split into blocks
    blocks = [hash_bytes[i:i + block_size] for i in range(0, len(hash_bytes), block_size)][:num_blocks]
    logging.info(f"Created {len(blocks)} blocks")
    
    # Use first byte of each block to generate Collatz sequence for shuffling
    seeds = [blocks[i][0] if blocks[i] else 0 for i in range(num_blocks)]
    logging.info(f"Block seeds: {[hex(seed) for seed in seeds]}")
    
    sequences = []
    for i, seed in enumerate(seeds):
        logging.info(f"Generating Collatz sequence for block {i}, seed={seed}")
        seq_len = len(collatz_sequence(seed))
        sequences.append(seq_len)
        logging.info(f"Block {i} sequence length: {seq_len}")
    
    # Sort blocks based on sequence lengths
    sorted_blocks = [block for _, block in sorted(zip(sequences, blocks), reverse=True)]
    logging.info("Blocks shuffled based on sequence lengths")
    return sorted_blocks


def compute_leaf_hash_from_block(block: bytes) -> bytes:
    """
    Compute leaf hash for a block by combining it with its Collatz sequence.
    
    Args:
        block: Input block to process
        
    Returns:
        bytes: Computed leaf hash
    """
    # Use first byte as seed for Collatz sequence
    seed = block[0] if block else 0
    sequence = collatz_sequence(seed)
    
    # Combine block with serialized sequence
    combined = block + serialize_seq(sequence)
    
    # Use hash_utils to compute final hash
    from .hash_utils import compute_sha1
    return compute_sha1(combined)
