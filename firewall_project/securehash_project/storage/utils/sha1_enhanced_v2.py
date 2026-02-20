"""
Enhanced SHA-1 with Collatz Sequences and Direct Content Processing
Combines SHA-1, file content, and Collatz sequences for unique signatures
"""

import hashlib
from typing import List, Tuple
import struct

def collatz_sequence(n: int) -> List[int]:
    """Generate Collatz sequence for a given number."""
    sequence = [n]
    while n != 1:
        if n % 2 == 0:
            n = n // 2
        else:
            n = 3 * n + 1
        sequence.append(n)
    return sequence

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    # Ensure equal length by padding shorter one
    max_len = max(len(a), len(b))
    a_padded = a.ljust(max_len, b'\x00')
    b_padded = b.ljust(max_len, b'\x00')
    return bytes(x ^ y for x, y in zip(a_padded, b_padded))

def create_content_block(data: bytes, start: int, size: int) -> bytes:
    """Create a block from file content with padding if needed."""
    block = data[start:start + size]
    return block.ljust(size, b'\x00')

def mix_with_position(block: bytes, position: int) -> bytes:
    """Mix block with its position information."""
    pos_bytes = position.to_bytes(4, 'big')
    return xor_bytes(block, pos_bytes * (len(block) // 4 + 1))

def enhanced_sha1_with_content(data: bytes) -> str:
    """
    Compute enhanced signature using both SHA-1 and file content.
    
    Process:
    1. Get SHA-1 hash and split into blocks
    2. Get corresponding file content blocks
    3. Mix SHA-1 blocks with content blocks
    4. Generate Collatz sequences from mixed blocks
    5. Create final signature incorporating all elements
    """
    # 1. Get SHA-1 hash and split into blocks (5 bytes each)
    sha1_hash = hashlib.sha1(data).digest()
    sha1_blocks = [sha1_hash[i:i+5] for i in range(0, 20, 5)]
    
    # 2. Process file content in detail
    content_blocks = []
    content_size = 8  # Smaller blocks for more sensitivity
    
    # Get detailed content information
    for i in range(0, len(data), content_size):
        # Get current block
        block = create_content_block(data, i, content_size)
        
        # Create block features
        block_features = bytearray()
        
        # Add block hash
        block_hash = hashlib.sha1(block).digest()[:2]
        block_features.extend(block_hash)
        
        # Add statistical features
        block_features.append(max(block))  # Max byte value
        block_features.append(min(block))  # Min byte value
        
        # Add position sensitivity
        pos_byte = (i % 256).to_bytes(1, 'big')[0]
        block_features.append(pos_byte)
        
        content_blocks.append(bytes(block_features))
    
    # 3. Mix SHA-1 blocks with content blocks
    mixed_blocks = []
    for i in range(4):  # Process 4 blocks
        # Mix SHA-1 block with content and position
        sha1_block = sha1_blocks[i]
        content_block = content_blocks[i % len(content_blocks)]
        
        # First level mixing
        mixed = xor_bytes(sha1_block, content_block)
        
        # Position-sensitive mixing
        mixed = mix_with_position(mixed, i)
        
        # Additional mixing with previous blocks
        for j in range(i):
            mixed = xor_bytes(mixed, mixed_blocks[j])
        
        mixed_blocks.append(mixed)
    
    # 4. Generate Collatz sequences from mixed blocks
    signatures = []
    for i, block in enumerate(mixed_blocks):
        # Convert block to integer (seeds for Collatz)
        seed = int.from_bytes(block, 'big')
        seed = (seed % 999999) + 1  # Ensure valid range
        
        # Generate and analyze Collatz sequence
        sequence = collatz_sequence(seed)
        
        # Extract sequence properties
        length = len(sequence)
        max_val = max(sequence)
        steps_to_one = length - 1
        
        # Create block signature incorporating position
        block_sig = struct.pack('>IIII', length, max_val, steps_to_one, i)
        signatures.append(block_sig)
    
    # 5. Combine everything into final signature
    combined = b''.join(signatures)
    final_hash = hashlib.sha256(combined).hexdigest()
    
    return final_hash

def verify_signature(data: bytes, signature: str) -> bool:
    """Verify if a signature matches the data."""
    computed = enhanced_sha1_with_content(data)
    return computed.lower() == signature.lower()
