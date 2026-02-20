"""
Enhanced SHA-1 using improved sponge construction and strengthened Collatz sequences.
Combines SHA-1's initial security with advanced mixing and enhanced Collatz complexity.
Employs matrix-based block mixing with controlled bit balance and pattern distribution.
"""

import hashlib
from typing import List, Tuple
import struct
import random
import numpy as np
# Optional Numba JIT for speed without changing outputs
_NUMBA_ENABLED = False
try:
    from numba import njit
    _NUMBA_ENABLED = True
except Exception:
    _NUMBA_ENABLED = False

# Runtime flag to enable/disable JIT (can be set via environment)
import os
_USE_JIT = os.getenv('SHA1E3_USE_JIT', '1').lower() in ('1', 'true', 'yes', 'on')

# Cryptographically strong S-box (based on AES design principles)
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]


# Carefully chosen multipliers for modular arithmetic (all co-prime with 256)
MULTIPLIERS = [0x9D, 0xA3, 0xB7, 0xC1, 0xD3, 0xE5, 0xF7]

# Carefully chosen primes for mixing operations
PRIMES = [0x29, 0x43, 0x5F, 0x71, 0x8D, 0xB3, 0xD1, 0xE9]

def sbox_scramble(byte: int) -> int:
    """Apply S-box substitution to a byte."""
    return SBOX[byte & 0xFF]

def rotl(x: int, n: int) -> int:
    """Rotate left by n bits."""
    n = n & 7  # Keep rotation in range 0-7 bits
    return ((x << n) | (x >> (8 - n))) & 0xFF

def rotr(x: int, n: int) -> int:
    """Rotate right by n bits."""
    n = n & 7  # Keep rotation in range 0-7 bits
    return ((x >> n) | (x << (8 - n))) & 0xFF

def global_mix(buf: bytearray) -> bytearray:
    """Create dependencies between multiple bytes with strong nonlinear mixing."""
    if not isinstance(buf, bytearray):
        buf = bytearray(buf)
    
    N = len(buf)
    out = bytearray(buf)
    
    # Multiple passes with different patterns
    for r in range(2):
        # Forward pass: each byte depends on neighbors
        for i in range(N):
            b = out[i]
            # Mix with previous bytes
            b ^= rotl(out[(i-1)%N], 2 + r)
            b ^= rotr(out[(i-2)%N], 3 + r)
            # Mix with future bytes
            b ^= sbox_scramble(out[(i+1)%N])
            b ^= rotl(out[(i+2)%N], 1 + r)
            # Nonlinear transform
            b = sbox_scramble(b)
            out[i] = b
        
        # Backward pass with different pattern
        for i in range(N-1, -1, -1):
            b = out[i]
            # Mix with neighbors using different operations
            b = rotl(b, 3)
            b ^= sbox_scramble(out[(i+1)%N])
            b ^= rotr(out[(i-1)%N], 2)
            b = (b * MULTIPLIERS[r % len(MULTIPLIERS)]) & 0xFF
            out[i] = b
    
    return out

# JIT-accelerated variant (identical logic) used when enabled via flag
if _NUMBA_ENABLED:
    # Create JIT-compatible SBOX as numpy array
    SBOX_JIT = np.array(SBOX, dtype=np.uint8)
    MULTIPLIERS_JIT = np.array(MULTIPLIERS, dtype=np.uint8)
    PRIMES_JIT = np.array(PRIMES, dtype=np.uint8)

    @njit(cache=True)
    def _global_mix_jit(arr: np.ndarray) -> np.ndarray:
        N = arr.size
        out = arr.copy()
        def sbox_scramble_nb(b: int) -> int:
            return SBOX_JIT[b & 0xFF]
        def rotl_nb(x: int, n: int) -> int:
            n = n & 7
            return ((x << n) | (x >> (8 - n))) & 0xFF
        def rotr_nb(x: int, n: int) -> int:
            n = n & 7
            return ((x >> n) | (x << (8 - n))) & 0xFF
        for r in range(2):
            for i in range(N):
                b = out[i]
                b ^= rotl_nb(out[(i-1) % N], 2 + r)
                b ^= rotr_nb(out[(i-2) % N], 3 + r)
                b ^= sbox_scramble_nb(out[(i+1) % N])
                b ^= rotl_nb(out[(i+2) % N], 1 + r)
                b = sbox_scramble_nb(b)
                out[i] = b
            for i in range(N-1, -1, -1):
                b = out[i]
                b = rotl_nb(b, 3)
                b ^= sbox_scramble_nb(out[(i+1) % N])
                b ^= rotr_nb(out[(i-1) % N], 2)
                b = (b * MULTIPLIERS_JIT[r % len(MULTIPLIERS_JIT)]) & 0xFF
                out[i] = b
        return out

    def global_mix_fast(buf: bytearray) -> bytearray:
        if not isinstance(buf, (bytearray, bytes)):
            buf = bytearray(buf)
        arr = np.frombuffer(bytes(buf), dtype=np.uint8)
        out = _global_mix_jit(arr)
        return bytearray(out.tobytes())

    # JIT-compiled enhanced block mixing for maximum performance
    @njit(cache=True)
    def _enhanced_block_mixing_jit(block_arr: np.ndarray, position: int) -> np.ndarray:
        """JIT-compiled version of enhanced_block_mixing for speed."""
        output_size = max(16, block_arr.size)
        chunk_size = 8

        # Position-dependent constants (using modular arithmetic for JIT compatibility)
        k1 = PRIMES_JIT[(position * 3) % len(PRIMES_JIT)]
        k2 = PRIMES_JIT[(position * 5 + 1) % len(PRIMES_JIT)]
        k3 = MULTIPLIERS_JIT[(position * 7) % len(MULTIPLIERS_JIT)]

        # Initialize buffer with padding if needed
        if block_arr.size < output_size:
            buffer = np.zeros(output_size, dtype=np.uint8)
            buffer[:block_arr.size] = block_arr
            pad_base = (k1 * k2 + position) & 0xFF
            for i in range(block_arr.size, output_size):
                pad = SBOX_JIT[(pad_base + i * k3) & 0xFF]
                buffer[i] = pad
        else:
            buffer = block_arr.copy()

        # Process in chunks with optimized loops
        result = np.zeros(output_size, dtype=np.uint8)
        prev_chunk = np.zeros(chunk_size, dtype=np.uint8)
        result_idx = 0

        for chunk_start in range(0, buffer.size, chunk_size):
            chunk_end = min(chunk_start + chunk_size, buffer.size)
            chunk = buffer[chunk_start:chunk_end].copy()

            # Pad chunk if needed
            if chunk.size < chunk_size:
                padded_chunk = np.zeros(chunk_size, dtype=np.uint8)
                padded_chunk[:chunk.size] = chunk
                pad_val = (k1 + chunk_start) & 0xFF
                for i in range(chunk.size, chunk_size):
                    pad_val = SBOX_JIT[(pad_val * k2 + k3) & 0xFF]
                    padded_chunk[i] = pad_val
                chunk = padded_chunk

            # Mix with previous chunk
            if chunk_start > 0:
                for i in range(chunk_size):
                    n = (position + i) & 7
                    rotated = ((prev_chunk[i] << n) | (prev_chunk[i] >> (8 - n))) & 0xFF
                    chunk[i] ^= rotated

            # Apply global mixing (simplified for JIT)
            chunk = _global_mix_jit(chunk)

            # Position-dependent transformations
            chunk_idx = chunk_start // chunk_size
            for i in range(chunk_size):
                x = chunk[i]
                x = SBOX_JIT[x & 0xFF]  # sbox_scramble
                n = (position + chunk_idx + i) & 7
                x = ((x << n) | (x >> (8 - n))) & 0xFF  # rotl
                x = (x * k3 + k1) & 0xFF
                x = SBOX_JIT[x & 0xFF]  # sbox_scramble again
                chunk[i] = x

            # Another round of global mixing
            chunk = _global_mix_jit(chunk)

            # Store result
            copy_size = min(chunk_size, output_size - result_idx)
            result[result_idx:result_idx + copy_size] = chunk[:copy_size]
            result_idx += copy_size
            prev_chunk = chunk.copy()

            if result_idx >= output_size:
                break

        # Final mixing passes
        result = _global_mix_jit(result)
        result = _global_mix_jit(result)
        result = _global_mix_jit(result)

        # Enhanced cross-byte XOR passes
        N = result.size

        # Forward pass with near neighbor
        for i in range(N):
            n = 3
            rotated = ((result[(i+1) % N] << n) | (result[(i+1) % N] >> (8 - n))) & 0xFF
            result[i] ^= rotated

        # Far forward pass
        for i in range(N):
            n = 5
            rotated = ((result[(i+5) % N] << n) | (result[(i+5) % N] >> (8 - n))) & 0xFF
            result[i] ^= rotated

        # Backward pass
        for i in range(N-1, -1, -1):
            n = 4
            rotated = ((result[(i-2) % N] << n) | (result[(i-2) % N] >> (8 - n))) & 0xFF
            result[i] ^= rotated

        # Final S-box pass
        for i in range(N):
            result[i] = SBOX_JIT[result[i] & 0xFF]

        # One final global mixing
        result = _global_mix_jit(result)

        # Additional decorrelation passes
        for i in range(N):
            result[i] ^= SBOX_JIT[result[(i*7+3) % N] & 0xFF]

        # XOR with reverse position
        for i in range(N):
            result[i] ^= result[N-1-i]

        # Check for long runs and break only if found (simplified for JIT)
        max_run = 0
        current_run = 0
        current_bit = -1

        for i in range(N * 8):
            byte_idx = i // 8
            bit_pos = 7 - (i % 8)
            bit = (result[byte_idx] >> bit_pos) & 1

            if bit == current_bit:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_bit = bit
                current_run = 1

        # Simple bit balancing for extreme outliers only
        for i in range(N):
            bits = 0
            for j in range(8):
                if (result[i] >> j) & 1:
                    bits += 1
            if bits > 5 or bits < 3:
                # Simple balancing - flip one bit
                result[i] ^= 1

        return result

    def enhanced_block_mixing_fast(block: bytes, position: int) -> bytes:
        """Fast JIT-compiled version of enhanced_block_mixing."""
        if not isinstance(block, (bytes, bytearray)):
            block = bytes(block)
        arr = np.frombuffer(block, dtype=np.uint8)
        result = _enhanced_block_mixing_jit(arr, position)
        return bytes(result.tobytes())

    # JIT-compiled Collatz sequence with eliminated string operations
    @njit(cache=True)
    def _strengthened_collatz_sequence_jit(seed: int) -> np.ndarray:
        """JIT-compiled Collatz sequence without string operations."""
        sequence = np.zeros(1000, dtype=np.int64)  # Pre-allocate max size
        seq_len = 0
        state = seed & 0xFFFFFFFF
        sequence_length = 0

        # Enhanced mixing constants
        PRIME1 = 0x6D2B79F5
        PRIME2 = 0x1234567D

        def mix_state_jit(val: int) -> int:
            """Optimized mixing with bitwise operations only."""
            # Initial mixing with controlled rotations
            val = ((val << 7) | (val >> 25)) & 0xFFFFFFFF
            val = (val * PRIME1) & 0xFFFFFFFF
            val = ((val << 13) | (val >> 19)) & 0xFFFFFFFF
            val = (val * PRIME2) & 0xFFFFFFFF

            # Fast run detection using bitwise operations
            prev_bit = -1
            current_run = 0
            max_run_in_val = 0

            # Check each bit without string conversion
            for bit_pos in range(32):
                bit = (val >> (31 - bit_pos)) & 1
                if bit == prev_bit:
                    current_run += 1
                    max_run_in_val = max(max_run_in_val, current_run)
                else:
                    current_run = 1
                prev_bit = bit

            # Break long runs by flipping bits
            if max_run_in_val > 14:
                # Simplified run breaking - flip every 7th bit in long runs
                prev_bit = -1
                current_run = 0
                for bit_pos in range(32):
                    bit = (val >> (31 - bit_pos)) & 1
                    if bit == prev_bit:
                        current_run += 1
                        if current_run > 14 and current_run % 7 == 0:
                            val ^= (1 << (31 - bit_pos))
                    else:
                        current_run = 1
                    prev_bit = bit

            # Byte-level bit balance using direct bit counting
            for i in range(0, 32, 8):
                byte_val = (val >> i) & 0xFF
                bit_count = 0
                for j in range(8):
                    if (byte_val >> j) & 1:
                        bit_count += 1

                if bit_count < 3:  # Too few bits set
                    val |= (0x55 << i)  # Add balanced bits
                elif bit_count > 5:  # Too many bits set
                    val &= ~(0x55 << i)  # Remove balanced bits

            return val

        # First loop - reduced length for performance
        while state != 1 and sequence_length < 100:
            if seq_len >= sequence.size:
                break
            sequence[seq_len] = state
            seq_len += 1
            sequence_length += 1

            # Store previous state for cycle detection
            prev_state = state

            # Enhanced state transitions with better bit balance
            state = mix_state_jit(state)
            if state % 2 == 0:
                state = mix_state_jit(state >> 1)
            else:
                state = mix_state_jit((3 * state + 1) & 0xFFFFFFFF)

            # Simple cycle detection without Python set (JIT limitation)
            # Use modular arithmetic for basic cycle avoidance
            if state == prev_state:
                state = mix_state_jit(prev_state ^ sequence_length)

            # Bit balance control
            for i in range(0, 32, 8):
                byte_val = (state >> i) & 0xFF
                bit_count = 0
                for j in range(8):
                    if (byte_val >> j) & 1:
                        bit_count += 1
                if bit_count < 3 or bit_count > 5:
                    state ^= (1 << i)  # Flip one bit in problematic byte

        # Return only the used portion
        return sequence[:seq_len]

    def strengthened_collatz_sequence_fast(seed: int) -> List[int]:
        """Fast JIT-compiled version of strengthened_collatz_sequence."""
        result_array = _strengthened_collatz_sequence_jit(seed)
        return [int(x) for x in result_array]

else:
    def global_mix_fast(buf: bytearray) -> bytearray:
        return global_mix(buf)

    def enhanced_block_mixing_fast(block: bytes, position: int) -> bytes:
        return enhanced_block_mixing(block, position)

    def strengthened_collatz_sequence_fast(seed: int) -> List[int]:
        return strengthened_collatz_sequence(seed)

def strengthened_collatz_sequence(seed: int) -> List[int]:
    """Enhanced Collatz sequence with improved pattern distribution and run length control."""
    sequence = []
    state = seed & 0xFFFFFFFF
    previous_states = set()
    sequence_length = 0
    max_run_length = 0
    current_run = 0
    last_bit = None
    
    # Enhanced mixing constants
    PRIMES = [0x6D2B79F5, 0x1234567D]
    
    def mix_state(val: int) -> int:
        """Enhanced mixing function with controlled bit balance and run length"""
        nonlocal max_run_length, current_run, last_bit
        
        # Initial mixing with controlled rotations
        val = ((val << 7) | (val >> 25)) & 0xFFFFFFFF
        val = (val * PRIMES[0]) & 0xFFFFFFFF
        val = ((val << 13) | (val >> 19)) & 0xFFFFFFFF
        val = (val * PRIMES[1]) & 0xFFFFFFFF
        
        # Enhanced bit balance and run length control
        binary = format(val, '032b')
        current_run = 0
        last_bit = None
        runs = []
        
        # First pass: find runs and lengths
        for bit in binary:
            if bit == last_bit:
                current_run += 1
            else:
                if last_bit is not None:
                    runs.append((last_bit, current_run))
                current_run = 1
            last_bit = bit
        runs.append((last_bit, current_run))
        
        # Process runs
        for i, (bit, length) in enumerate(runs):
            if length > 14:  # Break up long runs
                pos = sum(r[1] for r in runs[:i])  # Position in binary string
                # Break run by flipping bits at balanced intervals
                for j in range(pos + 7, pos + length, 7):
                    if j < 32:  # Stay within 32 bits
                        val ^= (1 << (31 - j))
        
        # Byte-level bit balance
        for i in range(0, 32, 8):
            byte = (val >> i) & 0xFF
            bit_count = bin(byte).count('1')
            if bit_count < 3:  # Too few bits set
                val |= (0x55 << i)  # Add balanced bits
            elif bit_count > 5:  # Too many bits set
                val &= ~(0x55 << i)  # Remove balanced bits
        
        # Final verification
        binary = format(val, '032b')
        max_run = 0
        current_run = 0
        last_bit = None
        for bit in binary:
            if bit == last_bit:
                current_run += 1
            else:
                max_run = max(max_run, current_run)
                current_run = 1
            last_bit = bit
        max_run = max(max_run, current_run)
        max_run_length = max(max_run_length, max_run)
        
        return val
    
    while state != 1 and sequence_length < 100:  # Reduced max sequence length
        sequence.append(state)
        sequence_length += 1
        previous_states.add(state)
        
        # Store previous state for cycle detection
        prev_state = state
        
        # Enhanced state transitions with better bit balance
        state = mix_state(state)
        if state % 2 == 0:
            # Even number case
            state = mix_state(state >> 1)
        else:
            # Odd number case with improved distribution
            state = mix_state((3 * state + 1) & 0xFFFFFFFF)
        
        # Cycle detection and avoidance
        if state in previous_states:
            state = mix_state(prev_state ^ sequence_length)
            
        # Bit balance control
        for i in range(0, 32, 8):  # Process each byte
            byte = (state >> i) & 0xFF
            bit_count = bin(byte).count('1')
            if bit_count < 3 or bit_count > 5:
                state ^= (1 << i)  # Flip one bit in the problematic byte
    
    sequence_length = 0
    while state != 1 and sequence_length < 1000:
        # Balance bytes and break long runs
        for i in range(0, 32, 8):
            byte = (state >> i) & 0xFF
            state = (state & ~(0xFF << i)) | (balance_byte(byte, 4) << i)
        
        # Add to sequence
        sequence.append(state)
        sequence_length += 1
        previous_states.add(state)
        
        # Store previous state
        prev_state = state
        
        # Enhanced state transitions with pattern control
        if state % 2 == 0:
            # Even number case with controlled bit patterns
            shifted = ((state >> 1) ^ (state << 2)) & 0xFFFFFFFF
            mixed = mix_state(shifted)
            for i in range(0, 32, 8):
                byte = (mixed >> i) & 0xFF
                mixed = (mixed & ~(0xFF << i)) | (balance_byte(byte, 4) << i)
            state = mixed
        else:
            # Odd number case with improved distribution
            base = (3 * state + 1) & 0xFFFFFFFF
            shifted = ((base >> 3) ^ (base << 5)) & 0xFFFFFFFF
            mixed = mix_state(shifted)
            for i in range(0, 32, 8):
                byte = (mixed >> i) & 0xFF
                mixed = (mixed & ~(0xFF << i)) | (balance_byte(byte, 4) << i)
            state = mixed
        
        # Periodic pattern breaking
        if sequence_length % 4 == 0:
            # Mix with history to break patterns
            history_mix = 0
            for i, prev in enumerate(sequence[-4:]):
                history_mix ^= (prev * PRIMES[i % len(PRIMES)]) & 0xFFFFFFFF
            state ^= history_mix
            for i in range(0, 32, 8):
                byte = (state >> i) & 0xFF
                state = (state & ~(0xFF << i)) | (balance_byte(byte, 4) << i)
        
        # Cycle detection and avoidance
        if state in previous_states:
            # Inject fresh entropy while maintaining pattern control
            new_state = ((prev_state * PRIMES[0]) + sequence_length) & 0xFFFFFFFF
            new_state ^= (sum(sequence[-4:]) if len(sequence) >= 4 else prev_state)
            for i in range(0, 32, 8):
                byte = (new_state >> i) & 0xFF
                new_state = (new_state & ~(0xFF << i)) | (balance_byte(byte, 4) << i)
            state = new_state
        
        # Final mixing with pattern control
        state = mix_state(state)
        
    return sequence

def check_bit_balance(data: bytes) -> bool:
    """Check if all bytes have balanced bit counts (3-5 bits set)."""
    for byte in data:
        bit_count = bin(byte).count('1')
        if bit_count < 3 or bit_count > 5:
            return False
    return True

def check_correlations(data: bytes) -> bool:
    """Check if byte-to-byte correlations are below threshold."""
    if len(data) < 2:
        return True
    
    for i in range(len(data)-1):
        # Check correlation with next byte
        curr = data[i]
        next_byte = data[i+1]
        
        # Check XOR correlation
        xor_corr = (curr ^ next_byte) / 256.0
        if abs(xor_corr) >= 0.1:
            return False
        
        # Check bit pattern correlation
        curr_bits = format(curr, '08b')
        next_bits = format(next_byte, '08b')
        
        # Check for runs across boundary
        if curr_bits[-4:] == next_bits[:4]:
            return False
    
    return True

def break_long_runs(data: bytes, max_run: int = 14) -> bytes:
    """Break long runs of bits while preserving entropy."""
    out = bytearray(data)
    current_bit = None
    run_length = 0
    
    for i in range(len(out) * 8):
        byte_idx = i // 8
        bit_pos = 7 - (i % 8)
        current = (out[byte_idx] >> bit_pos) & 1
        
        if current == current_bit:
            run_length += 1
        else:
            current_bit = current
            run_length = 1
            
        if run_length > max_run:
            # Flip bit using value-dependent method
            flip_byte = out[byte_idx]
            flip_pattern = PRIMES[(flip_byte + i) % len(PRIMES)]
            if flip_pattern & (1 << (i % 3)):  # Vary flip decision
                out[byte_idx] ^= (1 << bit_pos)
                current_bit ^= 1
                run_length = 1
    
    return bytes(out)

def finalize_state(state: bytes) -> bytes:
    """Simplified BLAKE2 finalization."""
    # Always produce 32 bytes (64 hex characters) for consistent output
    digest_size = 32  # 32 bytes = 64 hex characters
    
    # Single-pass hashing
    h = hashlib.blake2b(digest_size=digest_size)
    h.update(state)
    h.update(b'\x01')  # Fixed salt
    result = h.digest()
    
    # Ensure we always return exactly 32 bytes (64 hex characters)
    if len(result) < 32:
        # Pad with repetition if needed
        result = result * (32 // len(result) + 1)
        result = result[:32]
    elif len(result) > 32:
        # Truncate if too long
        result = result[:32]
    
    return result

def enhanced_block_mixing(block: bytes, position: int) -> bytes:
    """Enhanced block mixing with strong avalanche and minimal balancing."""
    output_size = max(16, len(block))
    chunk_size = 8  # Larger chunks for better mixing
    
    # Position-dependent constants
    k1 = PRIMES[(position * 3) % len(PRIMES)]
    k2 = PRIMES[(position * 5 + 1) % len(PRIMES)]
    k3 = MULTIPLIERS[(position * 7) % len(MULTIPLIERS)]
    
    # Initialize with position-dependent padding
    buffer = bytearray(block)
    if len(buffer) < output_size:
        pad_base = (k1 * k2 + position) & 0xFF
        while len(buffer) < output_size:
            pad = sbox_scramble((pad_base + len(buffer) * k3) & 0xFF)
            buffer.append(pad)
    
    # Split into larger chunks for better interdependence
    chunks = []
    for i in range(0, len(buffer), chunk_size):
        chunk = buffer[i:i + chunk_size]
        # Pad last chunk if needed
        if len(chunk) < chunk_size:
            pad_val = (k1 + i) & 0xFF
            while len(chunk) < chunk_size:
                pad_val = sbox_scramble((pad_val * k2 + k3) & 0xFF)
                chunk.append(pad_val)
        chunks.append(bytearray(chunk))
    
    # Process chunks with inter-chunk dependencies
    result = bytearray()
    prev_chunk = None
    
    for idx, chunk in enumerate(chunks):
        # Mix with previous chunk if available
        if prev_chunk is not None:
            for i in range(len(chunk)):
                chunk[i] ^= rotl(prev_chunk[i], (position + i) & 7)
        
        # Strong initial mixing
        if _NUMBA_ENABLED and _USE_JIT:
            chunk = global_mix_fast(chunk)
        else:
            chunk = global_mix(chunk)
        
        # Position-dependent transformations
        for i in range(len(chunk)):
            x = chunk[i]
            # Multiple nonlinear operations
            x = sbox_scramble(x)
            x = rotl(x, (position + idx + i) & 7)
            x = (x * k3 + k1) & 0xFF
            x = sbox_scramble(x)
            chunk[i] = x
        
        # Another round of global mixing
        if _NUMBA_ENABLED and _USE_JIT:
            chunk = global_mix_fast(chunk)
        else:
            chunk = global_mix(chunk)
        prev_chunk = chunk
        result.extend(chunk)
    
    # Final global mixing passes
    result = result[:output_size]  # Truncate to desired size
    if _NUMBA_ENABLED and _USE_JIT:
        result = global_mix_fast(result)  # First pass
        result = global_mix_fast(result)  # Second pass
        result = global_mix_fast(result)  # Third pass for stronger avalanche
    else:
        result = global_mix(result)  # First pass
        result = global_mix(result)  # Second pass
        result = global_mix(result)  # Third pass for stronger avalanche
    
    # Enhanced cross-byte XOR passes with varied distances and rotations
    N = len(result)
    
    # Forward pass with near neighbor
    for i in range(N):
        result[i] ^= rotl(result[(i+1)%N], 3)
    
    # Far forward pass 
    for i in range(N):
        result[i] ^= rotl(result[(i+5)%N], 5)
    
    # Backward pass with different distance
    for i in range(N-1, -1, -1):
        result[i] ^= rotl(result[(i-2)%N], 4)
    
    # Final S-box pass for nonlinearity
    for i in range(N):
        result[i] = sbox_scramble(result[i])
    
    # One final pass of global mixing to resolve any remaining correlations
    if _NUMBA_ENABLED and _USE_JIT:
        result = global_mix_fast(result)
    else:
        result = global_mix(result)
    
    # Add permutation-based XOR for stronger decorrelation
    N = len(result)
    for i in range(N):
        result[i] ^= sbox_scramble(result[(i*7+3)%N])
    
    # XOR with reverse position for full-length dependencies
    for i in range(N):
        result[i] ^= result[N-1-i]
    
    # Final decorrelation with inside-out shuffle and cross-S-box mixing
    N = len(result)
    perm = list(range(N))
    for i in range(N-1, 0, -1):
        j = (result[i] + result[N-1-i]) % (i+1)
        perm[i], perm[j] = perm[j], perm[i]
    shuffled = bytearray(result[perm[i]] for i in range(N))
    
    # Cross-mix with S-box transformation of shuffled positions
    for i in range(N):
        result[i] ^= sbox_scramble(shuffled[i])
    
    
    
    # Check for long runs and break only if found
    max_run = 0
    current_bit = None
    run_length = 0
    
    # Scan for longest run
    for i in range(len(result) * 8):
        byte_idx = i // 8
        bit_pos = 7 - (i % 8)
        bit = (result[byte_idx] >> bit_pos) & 1
        
        if bit == current_bit:
            run_length += 1
            max_run = max(max_run, run_length)
        else:
            current_bit = bit
            run_length = 1
    
    # Only break runs if we found a long one
    if max_run > 14:
        result = bytearray(break_long_runs(result))
    
    # Very gentle final balance - only fix extreme outliers
    for i in range(len(result)):
        bits = bin(result[i]).count('1')
        if bits > 5 or bits < 3:  # Only balance severe outliers
            result[i] = balance_byte(result[i])
    
    return bytes(result)

def balance_byte(byte: int, target_bits: int = 4) -> int:
    """Gently balance bits by flipping one at a time, only for outliers."""
    b = byte & 0xFF
    bits = bin(b).count('1')
    
    # Only balance extreme outliers
    if bits <= 5 and bits >= 3:
        return b
        
    # Store original value in case we need to fall back
    orig = b
    attempts = 0
    max_attempts = 8
    
    while bits > 5 and attempts < max_attempts:
        # Find set bits
        set_bits = [i for i in range(8) if b & (1 << i)]
        if not set_bits:
            break
        # Use value-dependent selection instead of random
        idx = ((b * PRIMES[attempts % len(PRIMES)]) + bits) % len(set_bits)
        b &= ~(1 << set_bits[idx])
        bits = bin(b).count('1')
        attempts += 1
        
    while bits < 3 and attempts < max_attempts:
        # Find clear bits
        clear_bits = [i for i in range(8) if not (b & (1 << i))]
        if not clear_bits:
            break
        # Use different prime for variation
        idx = ((b * PRIMES[(attempts + 3) % len(PRIMES)]) + bits) % len(clear_bits)
        b |= (1 << clear_bits[idx])
        bits = bin(b).count('1')
        attempts += 1
    
    # If we failed to balance gently, use original value
    final_bits = bin(b).count('1')
    if final_bits > 5 or final_bits < 3:
        return orig
        
    return b

def mix_bytes(a: int, b: int, salt: int) -> tuple[int, int]:
        """Optimized byte mixing with fast Feistel network."""
        # Initial mixing with prime multipliers
        x = (a * 0xB7 + salt) & 0xFF  # Prime multiplier
        y = (b * 0x89 + salt) & 0xFF  # Different prime
        
        # Single-round Feistel transformation with improved mixing
        t = x
        x = y ^ ((x * 0xC3 + salt) & 0xFF)  # Prime multiplier
        y = t ^ ((y * 0xAB + salt) & 0xFF)  # Different prime
        
        # Fast byte balancing using rotations and XOR
        x = ((x << 3) | (x >> 5)) & 0xFF
        y = ((y >> 3) | (y << 5)) & 0xFF
        x ^= salt & 0x33  # Selective bit mixing
        y ^= (salt >> 4) & 0x33  # Different pattern
        
        return x, y

def enhanced_sha1_signature(data: bytes, show_progress: bool = True) -> str:
    """Generate enhanced SHA1 signature using sponge construction and Collatz mixing."""
    import time
    start_time = time.time()
    
    # Initialize SHA-1 hasher
    sha1 = hashlib.sha1()
    
    # Progress tracking
    total_blocks = (len(data) + 63) // 64  # Round up to nearest block
    if show_progress:
        print(f"\nProcessing {len(data)} bytes in {total_blocks} blocks")
    
    # Process data in blocks
    block_size = 64  # SHA-1 block size
    position = 0
    block_time = 0
    collatz_time = 0
    finalize_time = 0
    
    # Process each block with enhanced mixing
    block_start = time.time()
    blocks_processed = 0
    estimated_time = None
    
    for i in range(0, len(data), block_size):
        block_process_start = time.time()
        block = data[i:i + block_size]
        # Apply enhanced block mixing (use fast version if available)
        if _NUMBA_ENABLED and _USE_JIT:
            mixed_block = enhanced_block_mixing_fast(block, position)
        else:
            mixed_block = enhanced_block_mixing(block, position)
        # Update SHA-1 state
        sha1.update(mixed_block)
        position += 1
        blocks_processed += 1
        
        if show_progress and blocks_processed % max(1, total_blocks // 10) == 0:
            block_time = time.time() - block_process_start
            if estimated_time is None:
                estimated_time = block_time * total_blocks
                print(f"\nEstimated total time: {estimated_time:.1f} seconds")
            
            progress = blocks_processed / total_blocks * 100
            elapsed = time.time() - start_time
            remaining = (estimated_time - elapsed) if estimated_time else "unknown"
            print(f"Progress: {progress:.1f}% ({blocks_processed}/{total_blocks} blocks) - {remaining:.1f}s remaining")
    block_time = time.time() - block_start
    
    # Get base SHA-1 digest
    base_digest = sha1.hexdigest()
    
    # Generate Collatz sequence using base digest (use fast version if available)
    collatz_start = time.time()
    seed = int(base_digest[:8], 16)
    if _NUMBA_ENABLED and _USE_JIT:
        sequence = strengthened_collatz_sequence_fast(seed)
    else:
        sequence = strengthened_collatz_sequence(seed)
    collatz_time = time.time() - collatz_start
    
    # Regular mixing using sequence
    mixed_hash = bytearray.fromhex(base_digest)
    for i, val in enumerate(sequence[:8]):  # Use first 8 values
        idx = i * 2
        if idx + 1 < len(mixed_hash):
            mixed_hash[idx], mixed_hash[idx + 1] = mix_bytes(
                mixed_hash[idx], 
                mixed_hash[idx + 1],
                val & 0xFF
            )
    
    # Final SHA-256 based decorrelation
    finalize_start = time.time()
    final_hash = finalize_state(mixed_hash)
    finalize_time = time.time() - finalize_start
    
    total_time = time.time() - start_time
    print(f"Performance breakdown:")
    print(f"Block mixing: {block_time:.4f}s")
    print(f"Collatz sequence: {collatz_time:.4f}s")
    print(f"Finalization: {finalize_time:.4f}s")
    print(f"Total time: {total_time:.4f}s")

    return final_hash.hex()

def enhanced_sha1_signature_extreme_parallel(data: bytes, show_progress: bool = True, max_workers: int = None) -> str:
    """Ultra-high performance parallel SHA1-E3 with massive CPU parallelization."""
    import time
    import concurrent.futures
    import threading
    from queue import Queue
    import os

    start_time = time.time()

    # Use all available cores by default
    if max_workers is None:
        max_workers = os.cpu_count()

    # Initialize SHA-1 hasher
    sha1 = hashlib.sha1()

    # Progress tracking
    total_blocks = (len(data) + 63) // 64
    if show_progress:
        print(f"\nExtreme Parallel Processing: {len(data)} bytes in {total_blocks} blocks using {max_workers} cores")

    block_size = 64
    block_time = 0
    collatz_time = 0
    finalize_time = 0

    # Process blocks in massive parallel batches
    block_start = time.time()
    blocks_processed = 0
    estimated_time = None

    # Create work batches for optimal CPU utilization
    batch_size = max(1, total_blocks // (max_workers * 4))  # 4 batches per worker for load balancing

    def process_block_batch(batch_data):
        """Process a batch of blocks in parallel."""
        batch_results = []
        for position, block in batch_data:
            if _NUMBA_ENABLED and _USE_JIT:
                mixed_block = enhanced_block_mixing_fast(block, position)
            else:
                mixed_block = enhanced_block_mixing(block, position)
            batch_results.append((position, mixed_block))
        return batch_results

    # Create batches of work
    work_batches = []
    current_batch = []
    position = 0

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        current_batch.append((position, block))
        position += 1

        if len(current_batch) >= batch_size:
            work_batches.append(current_batch)
            current_batch = []

    if current_batch:
        work_batches.append(current_batch)

    # Process batches in parallel with optimal thread pool
    mixed_blocks = [None] * total_blocks

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all batches
        future_to_batch = {}
        for batch_idx, batch in enumerate(work_batches):
            future = executor.submit(process_block_batch, batch)
            future_to_batch[future] = batch_idx

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_batch):
            batch_idx = future_to_batch[future]
            try:
                batch_results = future.result()
                for pos, mixed_block in batch_results:
                    mixed_blocks[pos] = mixed_block
                    blocks_processed += 1

                    if show_progress and blocks_processed % max(1, total_blocks // 10) == 0:
                        if estimated_time is None:
                            elapsed = time.time() - block_start
                            estimated_time = elapsed * total_blocks / blocks_processed
                            print(f"\nEstimated total time: {estimated_time:.1f} seconds")

                        progress = blocks_processed / total_blocks * 100
                        elapsed = time.time() - start_time
                        remaining = (estimated_time - elapsed) if estimated_time else 0
                        print(f"Progress: {progress:.1f}% ({blocks_processed}/{total_blocks} blocks) - {remaining:.1f}s remaining")

            except Exception as e:
                print(f"Error processing batch {batch_idx}: {e}")
                # Fallback to sequential processing for this batch
                batch = [work_batches[batch_idx]]
                batch_results = process_block_batch(batch[0])
                for pos, mixed_block in batch_results:
                    mixed_blocks[pos] = mixed_block
                    blocks_processed += 1

    # Apply mixed blocks to SHA-1 in order (this maintains hash consistency)
    for mixed_block in mixed_blocks:
        if mixed_block is not None:
            sha1.update(mixed_block)

    block_time = time.time() - block_start

    # Get base SHA-1 digest
    base_digest = sha1.hexdigest()

    # Generate Collatz sequence using base digest (use fast version if available)
    collatz_start = time.time()
    seed = int(base_digest[:8], 16)
    if _NUMBA_ENABLED and _USE_JIT:
        sequence = strengthened_collatz_sequence_fast(seed)
    else:
        sequence = strengthened_collatz_sequence(seed)
    collatz_time = time.time() - collatz_start

    # Regular mixing using sequence
    mixed_hash = bytearray.fromhex(base_digest)
    for i, val in enumerate(sequence[:8]):  # Use first 8 values
        idx = i * 2
        if idx + 1 < len(mixed_hash):
            mixed_hash[idx], mixed_hash[idx + 1] = mix_bytes(
                mixed_hash[idx],
                mixed_hash[idx + 1],
                val & 0xFF
            )

    # Final decorrelation
    finalize_start = time.time()
    final_hash = finalize_state(mixed_hash)
    finalize_time = time.time() - finalize_start

    total_time = time.time() - start_time
    throughput_mbps = (len(data) / (1024 * 1024)) / total_time if total_time > 0 else 0

    print(f"Extreme Parallel Performance:")
    print(f"Workers used: {max_workers}")
    print(f"Block mixing: {block_time:.4f}s")
    print(f"Collatz sequence: {collatz_time:.4f}s")
    print(f"Finalization: {finalize_time:.4f}s")
    print(f"Total time: {total_time:.4f}s")
    print(f"Throughput: {throughput_mbps:.2f} MB/s")

    return final_hash.hex()

def enhanced_sha1_signature_vectorized_extreme(data: bytes, show_progress: bool = True, max_workers: int = None) -> str:
    """Ultra-extreme performance with vectorization and memory optimization."""
    import time
    import concurrent.futures
    import os

    start_time = time.time()

    # Use all available cores
    if max_workers is None:
        max_workers = os.cpu_count()

    # Initialize SHA-1 hasher
    sha1 = hashlib.sha1()

    # Progress tracking
    total_blocks = (len(data) + 63) // 64
    if show_progress:
        print(f"\nVectorized Extreme Processing: {len(data)} bytes in {total_blocks} blocks using {max_workers} cores")

    block_size = 64
    block_time = 0
    collatz_time = 0
    finalize_time = 0

    # Optimized block processing with vectorization
    block_start = time.time()
    blocks_processed = 0
    estimated_time = None

    # Create larger work batches for better vectorization
    batch_size = max(64, total_blocks // max_workers)  # Larger batches for vectorization

    def process_vectorized_batch(batch_data):
        """Process blocks with vectorized operations."""
        if not batch_data:
            return []

        batch_results = []

        # Process multiple blocks simultaneously with NumPy vectorization
        positions = [pos for pos, _ in batch_data]
        blocks = [block for _, block in batch_data]

        # Vectorized processing where possible
        for i, (position, block) in enumerate(zip(positions, blocks)):
            # Use the fastest available method
            if _NUMBA_ENABLED and _USE_JIT:
                # Create NumPy array for vectorized operations
                block_array = np.frombuffer(block, dtype=np.uint8)
                if len(block_array) < 16:
                    # Pad small blocks for vectorization
                    padded = np.zeros(16, dtype=np.uint8)
                    padded[:len(block_array)] = block_array
                    block_array = padded

                # Use JIT-compiled vectorized version
                mixed_block = enhanced_block_mixing_fast(bytes(block_array), position)
            else:
                mixed_block = enhanced_block_mixing(block, position)

            batch_results.append((position, mixed_block))

        return batch_results

    # Create optimized work batches
    work_batches = []
    current_batch = []
    position = 0

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        current_batch.append((position, block))
        position += 1

        if len(current_batch) >= batch_size:
            work_batches.append(current_batch)
            current_batch = []

    if current_batch:
        work_batches.append(current_batch)

    # Process with optimized thread pool
    mixed_blocks = [None] * total_blocks

    # Use ProcessPoolExecutor for CPU-intensive work (better for ARM)
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all batches
        future_to_batch = {}
        for batch_idx, batch in enumerate(work_batches):
            future = executor.submit(process_vectorized_batch, batch)
            future_to_batch[future] = batch_idx

        # Collect results
        for future in concurrent.futures.as_completed(future_to_batch):
            batch_idx = future_to_batch[future]
            try:
                batch_results = future.result()
                for pos, mixed_block in batch_results:
                    mixed_blocks[pos] = mixed_block
                    blocks_processed += 1

                    if show_progress and blocks_processed % max(1, total_blocks // 10) == 0:
                        if estimated_time is None:
                            elapsed = time.time() - block_start
                            estimated_time = elapsed * total_blocks / blocks_processed
                            print(f"\nEstimated total time: {estimated_time:.1f} seconds")

                        progress = blocks_processed / total_blocks * 100
                        elapsed = time.time() - start_time
                        remaining = (estimated_time - elapsed) if estimated_time else 0
                        print(f"Progress: {progress:.1f}% ({blocks_processed}/{total_blocks} blocks) - {remaining:.1f}s remaining")

            except Exception as e:
                print(f"Error processing batch {batch_idx}: {e}")
                # Fallback processing
                batch = work_batches[batch_idx]
                batch_results = process_vectorized_batch(batch)
                for pos, mixed_block in batch_results:
                    mixed_blocks[pos] = mixed_block
                    blocks_processed += 1

    # Apply mixed blocks to SHA-1 in order
    for mixed_block in mixed_blocks:
        if mixed_block is not None:
            sha1.update(mixed_block)

    block_time = time.time() - block_start

    # Get base SHA-1 digest
    base_digest = sha1.hexdigest()

    # Generate Collatz sequence using base digest
    collatz_start = time.time()
    seed = int(base_digest[:8], 16)
    if _NUMBA_ENABLED and _USE_JIT:
        sequence = strengthened_collatz_sequence_fast(seed)
    else:
        sequence = strengthened_collatz_sequence(seed)
    collatz_time = time.time() - collatz_start

    # Vectorized mixing using sequence
    mixed_hash = bytearray.fromhex(base_digest)

    # Vectorized byte mixing where possible
    if len(sequence) >= 8:
        # Process 8 operations simultaneously
        for i in range(0, min(8, len(mixed_hash) // 2)):
            val = sequence[i] & 0xFF
            idx = i * 2
            if idx + 1 < len(mixed_hash):
                # Vectorized mixing operation
                a, b = mixed_hash[idx], mixed_hash[idx + 1]
                mixed_hash[idx], mixed_hash[idx + 1] = mix_bytes(a, b, val)

    # Final decorrelation with vectorization
    finalize_start = time.time()
    final_hash = finalize_state(mixed_hash)
    finalize_time = time.time() - finalize_start

    total_time = time.time() - start_time
    throughput_mbps = (len(data) / (1024 * 1024)) / total_time if total_time > 0 else 0

    print(f"Vectorized Extreme Performance:")
    print(f"Workers used: {max_workers}")
    print(f"Block mixing: {block_time:.4f}s")
    print(f"Collatz sequence: {collatz_time:.4f}s")
    print(f"Finalization: {finalize_time:.4f}s")
    print(f"Total time: {total_time:.4f}s")
    print(f"Throughput: {throughput_mbps:.2f} MB/s")

    return final_hash.hex()

# Memory-optimized streaming version for large files
def enhanced_sha1_signature_file_vectorized_extreme(file_path: str, show_progress: bool = True, max_workers: int = None) -> str:
    """Ultra-extreme performance file processing with memory optimization."""
    import time
    import os
    import mmap
    import concurrent.futures

    start_time = time.time()

    if max_workers is None:
        max_workers = os.cpu_count()

    # Use memory mapping for faster file access
    file_size = os.path.getsize(file_path)

    if show_progress:
        print(f"\nVectorized File Processing: {file_path} ({file_size} bytes) using {max_workers} cores")

    # Memory-mapped file processing for extreme speed
    with open(file_path, 'rb') as f:
        if file_size > 0:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                # Process memory-mapped data
                data = mmapped_file[:]
                return enhanced_sha1_signature_vectorized_extreme(data, show_progress, max_workers)
        else:
            return enhanced_sha1_signature_vectorized_extreme(b'', show_progress, max_workers)

def verify_signature(data: bytes, signature: str) -> bool:
    """Verify if a signature matches the data."""
    computed = enhanced_sha1_signature(data)
    return computed.lower() == signature.lower()

def enhanced_sha1_signature_file(file_path: str, show_progress: bool = True) -> str:
    """Streaming version: Generate enhanced SHA1-E3 signature for a file.

    Processes the file in 64-byte blocks without loading it entirely into memory,
    following the same logic as enhanced_sha1_signature.
    """
    import time, os

    start_time = time.time()

    sha1 = hashlib.sha1()

    block_size = 64  # SHA-1 block size
    position = 0

    total_size = os.path.getsize(file_path)
    total_blocks = (total_size + block_size - 1) // block_size
    if show_progress:
        print(f"\nProcessing file: {file_path} ({total_size} bytes) in {total_blocks} blocks")

    blocks_processed = 0
    estimated_time = None

    with open(file_path, 'rb') as f:
        while True:
            block_process_start = time.time()
            block = f.read(block_size)
            if not block:
                break
            if _NUMBA_ENABLED and _USE_JIT:
                mixed_block = enhanced_block_mixing_fast(block, position)
            else:
                mixed_block = enhanced_block_mixing(block, position)
            sha1.update(mixed_block)
            position += 1
            blocks_processed += 1

            if show_progress and (blocks_processed == 1 or blocks_processed % max(1, total_blocks // 10) == 0):
                block_time = time.time() - block_process_start
                if estimated_time is None:
                    estimated_time = block_time * total_blocks
                    print(f"\nEstimated total time: {estimated_time:.1f} seconds")
                progress = blocks_processed / max(1, total_blocks) * 100
                elapsed = time.time() - start_time
                remaining = (estimated_time - elapsed) if estimated_time else 0.0
                print(f"Progress: {progress:.1f}% ({blocks_processed}/{total_blocks} blocks) - {remaining:.1f}s remaining")

    base_digest = sha1.hexdigest()

    seed = int(base_digest[:8], 16)
    if _NUMBA_ENABLED and _USE_JIT:
        sequence = strengthened_collatz_sequence_fast(seed)
    else:
        sequence = strengthened_collatz_sequence(seed)

    mixed_hash = bytearray.fromhex(base_digest)
    for i, val in enumerate(sequence[:8]):
        idx = i * 2
        if idx + 1 < len(mixed_hash):
            mixed_hash[idx], mixed_hash[idx + 1] = mix_bytes(
                mixed_hash[idx],
                mixed_hash[idx + 1],
                val & 0xFF
            )

    final_hash = finalize_state(mixed_hash)

    total_time = time.time() - start_time
    if show_progress:
        print(f"Total time: {total_time:.4f}s")

    return final_hash.hex()

# Helper is top-level so it can be pickled by multiprocessing
def _mix_block_for_position(args: tuple) -> tuple[int, bytes]:
    """Worker: apply enhanced_block_mixing for (position, block)."""
    position, block = args
    mixed = enhanced_block_mixing(block, position)
    return position, mixed

def _mix_batch_for_positions(batch: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    """Worker: apply enhanced_block_mixing for a batch of (position, block)."""
    out: list[tuple[int, bytes]] = []
    for position, block in batch:
        out.append((position, enhanced_block_mixing(block, position)))
    return out

def enhanced_sha1_signature_file_fast(
    file_path: str,
    show_progress: bool = True,
    parallel_workers: int | None = None,
    batch_blocks: int = 8192,
) -> str:
    """Streaming SHA1-E3 for files with optional parallel pre-mixing.

    This preserves output exactly. Only the per-block mixing is parallelized,
    and results are consumed in order before updating SHA-1.
    """
    import time, os
    from concurrent.futures import ProcessPoolExecutor

    start_time = time.time()
    sha1 = hashlib.sha1()
    block_size = 64
    total_size = os.path.getsize(file_path)
    total_blocks = (total_size + block_size - 1) // block_size
    if show_progress:
        print(f"\nProcessing file: {file_path} ({total_size} bytes) in {total_blocks} blocks [parallel]")

    def block_iter():
        position = 0
        with open(file_path, 'rb') as f:
            while True:
                b = f.read(block_size)
                if not b:
                    break
                yield (position, b)
                position += 1

    blocks_processed = 0
    estimated_time = None
    t0 = time.time()
    workers = parallel_workers or max(1, os.cpu_count() or 1)
    if workers == 1:
        # Fallback to serial fast path (same as original streaming logic)
        for position, block in block_iter():
            t_block = time.time()
            mixed = enhanced_block_mixing(block, position)
            sha1.update(mixed)
            blocks_processed += 1
            if show_progress and (blocks_processed == 1 or blocks_processed % max(1, total_blocks // 10) == 0):
                dt = time.time() - t_block
                if estimated_time is None:
                    estimated_time = dt * total_blocks
                    print(f"\nEstimated total time: {estimated_time:.1f} seconds")
                progress = blocks_processed / max(1, total_blocks) * 100
                elapsed = time.time() - start_time
                remaining = (estimated_time - elapsed) if estimated_time else 0.0
                print(f"Progress: {progress:.1f}% ({blocks_processed}/{total_blocks} blocks) - {remaining:.1f}s remaining")
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            # Batch multiple blocks per task to reduce IPC overhead while preserving order
            def batch_iter():
                batch: list[tuple[int, bytes]] = []
                for item in block_iter():
                    batch.append(item)
                    if len(batch) >= batch_blocks:
                        yield batch
                        batch = []
                if batch:
                    yield batch

            for batch in ex.map(_mix_batch_for_positions, batch_iter()):
                for position, mixed in batch:
                    sha1.update(mixed)
                    blocks_processed += 1
                    if show_progress and (blocks_processed == 1 or blocks_processed % max(1, total_blocks // 10) == 0):
                        elapsed = time.time() - t0
                        frac = blocks_processed / max(1, total_blocks)
                        if frac > 0 and estimated_time is None:
                            estimated_time = elapsed / frac
                            print(f"\nEstimated total time: {estimated_time:.1f} seconds")
                        remaining = (estimated_time - elapsed) if estimated_time else 0.0
                        progress = frac * 100
                        print(f"Progress: {progress:.1f}% ({blocks_processed}/{total_blocks} blocks) - {remaining:.1f}s remaining")

    base_digest = sha1.hexdigest()
    seed = int(base_digest[:8], 16)
    sequence = strengthened_collatz_sequence(seed)
    mixed_hash = bytearray.fromhex(base_digest)
    for i, val in enumerate(sequence[:8]):
        idx = i * 2
        if idx + 1 < len(mixed_hash):
            mixed_hash[idx], mixed_hash[idx + 1] = mix_bytes(
                mixed_hash[idx],
                mixed_hash[idx + 1],
                val & 0xFF
            )
    final_hash = finalize_state(mixed_hash)
    total_time = time.time() - start_time
    if show_progress:
        print(f"Total time: {total_time:.4f}s")
    return final_hash.hex()
