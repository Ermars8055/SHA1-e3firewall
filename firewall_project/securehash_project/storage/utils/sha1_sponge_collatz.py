"""
Enhanced SHA-1 using sponge construction and Collatz sequences.
Combines SHA-1's initial security with sponge-like mixing and Collatz complexity.
"""

import hashlib
from typing import List, Tuple

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
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def count_transitions(sequence: List[int]) -> int:
    """Count even-odd transitions in sequence."""
    transitions = 0
    for i in range(1, len(sequence)):
        if (sequence[i-1] % 2) != (sequence[i] % 2):
            transitions += 1
    return transitions

def get_sequence_properties(sequence: List[int]) -> Tuple[int, int, int]:
    """Extract key properties from a Collatz sequence."""
    length = len(sequence)
    max_val = max(sequence)
    transitions = count_transitions(sequence)
    return length, max_val, transitions

def sponge_mix_blocks(blocks: List[bytes], rate: int = 3, capacity: int = 2) -> List[bytes]:
    """
    Apply sponge-like mixing to blocks with position-sensitive mixing.
    Rate: bytes used for mixing
    Capacity: bytes preserved for state
    """
    mixed_blocks = []
    state = blocks[0]  # Initial state

    for i in range(len(blocks)):
        # Position-sensitive mixing
        position_mask = bytes([((b + i + 1) % 256) for b in blocks[i]])
        current_block = xor_bytes(blocks[i], position_mask)
        
        # Split current state into rate and capacity parts
        rate_part = state[:rate]
        capacity_part = state[rate:]

        # Mix with modified block
        mixed_rate = xor_bytes(rate_part, current_block[:rate])
        
        # Rotate capacity based on position
        rotated_capacity = capacity_part[i % capacity:] + capacity_part[:i % capacity]
        
        # Create new state with additional mixing
        new_state = mixed_rate + rotated_capacity
        
        # Additional mixing with previous blocks
        for j in range(i):
            mixed_rate = xor_bytes(new_state[:rate], 
                                 xor_bytes(blocks[j][:rate], 
                                         bytes([(x + j) % 256 for x in range(rate)])))
            new_state = mixed_rate + new_state[rate:]
        
        mixed_blocks.append(new_state)
        state = new_state

    return mixed_blocks

def enhanced_sha1_signature(data: bytes) -> str:
    """
    Compute enhanced SHA-1 signature using sponge construction and Collatz sequences.
    """
    # 1. Initial SHA-1 hash
    initial_hash = hashlib.sha1(data).digest()
    
    # 2. Split into blocks (5 bytes each)
    blocks = [initial_hash[i:i+5] for i in range(0, 20, 5)]
    
    # 3. Apply sponge-like mixing
    mixed_blocks = sponge_mix_blocks(blocks)
    
    # 4. Generate Collatz sequences from mixed blocks
    signatures = []
    for block in mixed_blocks:
        # Use mixed block as seed for Collatz
        seed = int.from_bytes(block, 'big') % 1000000
        if seed == 0:  # Avoid invalid seed
            seed = 1
        sequence = collatz_sequence(seed)
        
        # Get sequence properties
        length, max_val, transitions = get_sequence_properties(sequence)
        
        # Create block signature (hex format)
        block_sig = f"{length:04x}{max_val:08x}{transitions:04x}"
        signatures.append(block_sig)
    
    # 5. Combine block signatures
    final_sig = "".join(signatures)
    
    return final_sig

def verify_signature(data: bytes, signature: str) -> bool:
    """Verify if a signature matches the data."""
    computed = enhanced_sha1_signature(data)
    return computed.lower() == signature.lower()
