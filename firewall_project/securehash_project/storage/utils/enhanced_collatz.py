"""Enhanced Collatz-based signature system that uses full block content."""

import logging
import struct
from typing import List, Tuple
from .collatz_utils import collatz_sequence

def block_to_seed(block: bytes) -> int:
    """
    Convert a block of bytes into a seed integer using all bytes.
    Uses multiplication-based mixing for better distribution.
    
    Args:
        block: Input bytes to convert
        
    Returns:
        int: Mixed seed value
    """
    # Convert bytes to integer and scale down to prevent overflow
    seed = int.from_bytes(block, 'big')
    seed = seed % 1000000  # Keep initial seed manageable
    
    # Apply mixing function with smaller multiplier
    mixed = (seed ^ (seed >> 8)) * 0x45d
    mixed = (mixed ^ (mixed >> 8)) * 0x45d
    mixed = mixed ^ (mixed >> 8)
    
    # Scale to safe range for Collatz (1-999999)
    return (mixed % 999999) + 1

def compute_sequence_pattern(sequence: List[int]) -> bytes:
    """
    Compute a pattern signature from a Collatz sequence.
    Captures mathematical properties of the sequence.
    
    Args:
        sequence: List of numbers in Collatz sequence
        
    Returns:
        bytes: Pattern signature
    """
    if not sequence:
        return b'\x00' * 16
    
    # Count even/odd transitions
    transitions = 0
    for i in range(1, len(sequence)):
        if (sequence[i-1] % 2) != (sequence[i] % 2):
            transitions += 1
            
    # Calculate maximum value reached
    max_value = max(sequence)
    
    # Calculate average step size
    steps = [abs(sequence[i] - sequence[i-1]) for i in range(1, len(sequence))]
    avg_step = sum(steps) // len(steps) if steps else 0
    
    # Pack characteristics into bytes
    pattern = struct.pack('>QQQQ', 
        len(sequence),      # Sequence length
        transitions,        # Number of even/odd transitions
        max_value,         # Maximum value reached
        avg_step           # Average step size
    )
    
    return pattern

def generate_block_sequences(block: bytes, window_size: int = 4) -> List[List[int]]:
    """
    Generate multiple Collatz sequences from different parts of the block.
    
    Args:
        block: Input bytes to process
        window_size: Size of sliding window for seed generation
        
    Returns:
        List[List[int]]: List of Collatz sequences
    """
    sequences = []
    
    # Use sliding window to generate multiple seeds
    for i in range(max(1, len(block) - window_size + 1)):
        window = block[i:i+window_size]
        if len(window) < window_size:
            window = window + b'\x00' * (window_size - len(window))
            
        seed = block_to_seed(window)
        sequences.append(collatz_sequence(seed))
        
    return sequences

def compute_block_signature(block: bytes) -> bytes:
    """
    Compute a comprehensive signature for a block incorporating
    multiple Collatz sequences and their patterns.
    
    Args:
        block: Input bytes to process
        
    Returns:
        bytes: Block signature
    """
    sequences = generate_block_sequences(block)
    
    # Initialize signature with block length
    signature = len(block).to_bytes(4, 'big')
    
    # Add pattern information for each sequence
    for seq in sequences:
        pattern = compute_sequence_pattern(seq)
        signature += pattern
    
    return signature

def enhanced_split_and_shuffle(data: bytes, num_blocks: int = 4) -> List[bytes]:
    """
    Split input data into blocks and shuffle based on enhanced
    Collatz sequence characteristics.
    
    Args:
        data: Input data to split and shuffle
        num_blocks: Number of blocks to split into
        
    Returns:
        List[bytes]: Shuffled blocks
    """
    block_size = len(data) // num_blocks
    if block_size == 0:
        block_size = 1
        
    # Split into blocks
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if block:  # Only add non-empty blocks
            blocks.append(block)
    
    # Compute signatures and sequence characteristics for each block
    block_info = []
    for i, block in enumerate(blocks):
        signature = compute_block_signature(block)
        sequences = generate_block_sequences(block)
        
        # Compute block weight based on sequence properties
        total_length = sum(len(seq) for seq in sequences)
        max_value = max(max(seq) for seq in sequences)
        unique_values = len(set(val for seq in sequences for val in seq))
        
        weight = (total_length * unique_values) / max_value if max_value else 0
        block_info.append((block, signature, weight))
    
    # Sort blocks based on their weights
    sorted_blocks = [b[0] for b in sorted(block_info, key=lambda x: x[2], reverse=True)]
    
    return sorted_blocks

def compute_enhanced_signature(data: bytes) -> bytes:
    """
    Compute enhanced Collatz-based signature for input data.
    
    Args:
        data: Input bytes to process
        
    Returns:
        bytes: Final signature
    """
    # Split data into blocks and shuffle
    blocks = enhanced_split_and_shuffle(data)
    
    # Compute and combine block signatures
    combined = b''
    for block in blocks:
        sig = compute_block_signature(block)
        combined += sig
    
    # Ensure fixed-length output by using SHA-256
    import hashlib
    return hashlib.sha256(combined).digest()
