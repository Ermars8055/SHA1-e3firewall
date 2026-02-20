"""
Enhanced SHA-1 v3 with Improved Content Sensitivity
Specifically designed to detect subtle differences in similar files
"""

import hashlib
from typing import List, Tuple
import struct

def collatz_sequence(n: int, max_steps: int = 100) -> List[int]:
    """Generate bounded Collatz sequence for a given number."""
    sequence = [n]
    steps = 0
    while n != 1 and steps < max_steps:
        if n % 2 == 0:
            n = n // 2
        else:
            n = 3 * n + 1
        sequence.append(n)
        steps += 1
    return sequence

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings with length preservation."""
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b'\x00')
    b_padded = b.ljust(max_len, b'\x00')
    return bytes(x ^ y for x, y in zip(a_padded, b_padded))

def create_content_features(block: bytes, position: int) -> bytes:
    """Create detailed content features for a block."""
    features = bytearray()
    
    # 1. Basic block hash (2 bytes)
    block_hash = hashlib.sha1(block).digest()[:2]
    features.extend(block_hash)
    
    # 2. Statistical features (4 bytes)
    features.append(max(block))  # Max byte
    features.append(min(block))  # Min byte
    features.append(sum(block) % 256)  # Sum of bytes mod 256
    features.append(len(set(block)))  # Unique byte count
    
    # 3. Position features (4 bytes)
    pos_bytes = position.to_bytes(4, 'big')
    features.extend(pos_bytes)
    
    # 4. Byte frequency features
    freq = [0] * 4  # Track frequency of byte ranges
    for b in block:
        freq[b % 4] += 1
    features.extend(bytes(freq))
    
    return bytes(features)

def mix_with_position(block: bytes, position: int, prev_blocks: List[bytes] = None) -> bytes:
    """Advanced position-sensitive mixing."""
    if not prev_blocks:
        prev_blocks = []
    
    # Initial position mixing
    pos_bytes = position.to_bytes(4, 'big')
    mixed = xor_bytes(block, pos_bytes * (len(block) // 4 + 1))
    
    # Mix with previous blocks using rolling XOR
    for prev in prev_blocks:
        mixed = xor_bytes(mixed, prev)
        # Rotate mixed bytes to create avalanche effect
        mixed = mixed[1:] + mixed[:1]
    
    return mixed

def enhanced_sha1_with_content(data: bytes) -> str:
    """
    Compute enhanced signature with improved content sensitivity.
    """
    # 1. Initial SHA-1 hash with smaller block size
    sha1_hash = hashlib.sha1(data).digest()
    sha1_blocks = [sha1_hash[i:i+4] for i in range(0, 20, 4)]  # 4-byte blocks
    
    # 2. Process file content with overlapping windows
    content_blocks = []
    window_size = 6  # Smaller window for more sensitivity
    overlap = 2  # Overlapping bytes between windows
    
    for i in range(0, len(data), window_size - overlap):
        # Get current window
        window = data[i:i + window_size]
        if not window:  # Skip empty windows
            continue
            
        # Create detailed features for this window
        features = create_content_features(window, i)
        content_blocks.append(features)
    
    # 3. Advanced mixing of SHA-1 and content blocks
    mixed_blocks = []
    for i in range(5):  # Process 5 blocks for more granularity
        # Get SHA-1 block
        sha1_block = sha1_blocks[i % len(sha1_blocks)]
        
        # Get content blocks for this region
        start_idx = (i * len(content_blocks)) // 5
        end_idx = ((i + 1) * len(content_blocks)) // 5
        region_blocks = content_blocks[start_idx:end_idx]
        
        if not region_blocks:  # Handle empty regions
            region_blocks = [b'\x00' * len(sha1_block)]
        
        # Mix all blocks in the region
        mixed = sha1_block
        for j, content_block in enumerate(region_blocks):
            # Position-sensitive mixing
            block_mixed = mix_with_position(content_block, i * 1000 + j, mixed_blocks)
            mixed = xor_bytes(mixed, block_mixed)
            
            # Rotate mixed bytes for better diffusion
            mixed = mixed[1:] + mixed[:1]
        
        mixed_blocks.append(mixed)
    
    # 4. Generate and analyze Collatz sequences
    signatures = []
    for i, block in enumerate(mixed_blocks):
        # Convert block to integer with position influence
        seed = int.from_bytes(block, 'big')
        seed = ((seed + i) % 999999) + 1  # Ensure valid range
        
        # Generate bounded Collatz sequence
        sequence = collatz_sequence(seed, max_steps=50)
        
        # Extract detailed sequence properties and handle large numbers
        length = len(sequence)
        max_val = min(max(sequence), 4294967295)  # Cap at 32-bit max
        min_val = min(sequence)
        steps_to_one = min(length - 1, 4294967295)  # Cap at 32-bit max
        
        # Pack properties with position information
        block_sig = struct.pack('>IIIII', length % 4294967295, max_val, min_val % 4294967295, steps_to_one, i)
        signatures.append(block_sig)
    
    # 5. Create final signature with double hashing
    combined = b''.join(signatures + mixed_blocks)  # Include mixed blocks
    intermediate_hash = hashlib.sha256(combined).digest()
    final_hash = hashlib.sha256(intermediate_hash).hexdigest()
    
    return final_hash

def verify_signature(data: bytes, signature: str) -> bool:
    """Verify if a signature matches the data."""
    computed = enhanced_sha1_with_content(data)
    return computed.lower() == signature.lower()
