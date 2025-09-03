# Collatz-SHA1 Technical Documentation

## System Overview

The Collatz-SHA1 is a novel cryptographic hashing system that combines the mathematical properties of the Collatz conjecture with SHA-1 to create a unique hashing mechanism. This document explains the complete working of the system.

## Core Components

### 1. Input Processing
- System accepts any digital input (file, text, binary data)
- Input is first hashed using standard SHA-1 to get initial 20-byte hash
- This initial hash becomes the seed for the Collatz sequence generation

### 2. Block Splitting
```
Input SHA-1 Hash (20 bytes)
         ↓
┌─────┬─────┬─────┬─────┐
│ B1  │ B2  │ B3  │ B4  │
└─────┴─────┴─────┴─────┘
   5b    5b    5b    5b
```
- The 20-byte SHA-1 hash is split into 4 equal blocks
- Each block is 5 bytes long
- Each block acts as a seed for a separate Collatz sequence

### 3. Collatz Sequence Generation

For each block:
1. Convert block bytes to integer (seed value)
2. Apply Collatz rules iteratively:
   ```python
   If n is even: n = n / 2
   If n is odd:  n = 3n + 1
   ```
3. Continue until reaching 1
4. Store the sequence length

Example Sequence:
```
Start: n = 27
27 → 82 → 41 → 124 → 62 → 31 → 94 → 47 → 142 → 71 → 214 → 107 → 322 → 161 → 484 → 242 → 121 → 364 → 182 → 91 → 274 → 137 → 412 → 206 → 103 → 310 → 155 → 466 → 233 → 700 → 350 → 175 → 526 → 263 → 790 → 395 → 1186 → 593 → 1780 → 890 → 445 → 1336 → 668 → 334 → 167 → 502 → 251 → 754 → 377 → 1132 → 566 → 283 → 850 → 425 → 1276 → 638 → 319 → 958 → 479 → 1438 → 719 → 2158 → 1079 → 3238 → 1619 → 4858 → 2429 → 7288 → 3644 → 1822 → 911 → 2734 → 1367 → 4102 → 2051 → 6154 → 3077 → 9232 → 4616 → 2308 → 1154 → 577 → 1732 → 866 → 433 → 1300 → 650 → 325 → 976 → 488 → 244 → 122 → 61 → 184 → 92 → 46 → 23 → 70 → 35 → 106 → 53 → 160 → 80 → 40 → 20 → 10 → 5 → 16 → 8 → 4 → 2 → 1
Length: 112 steps
```

### 4. Block Shuffling Mechanism

1. Blocks are reordered based on their Collatz sequence lengths
2. Order: Longest sequence first, shortest sequence last
3. Example:
   ```
   Block 1: length 48  → Position 2
   Block 2: length 31  → Position 3
   Block 3: length 125 → Position 1
   Block 4: length 26  → Position 4
   ```

### 5. Final Hash Generation

1. Each block undergoes another Collatz sequence based on its position
2. Results are combined in the new order
3. Final output is formatted as a 40-character hexadecimal string

## Security Features

### 1. Avalanche Effect
- Small changes in input create large changes in output
- Achieved through:
  - Initial SHA-1 processing
  - Block splitting
  - Sequence length-based shuffling

### 2. Collision Resistance
- Inherited from SHA-1's collision resistance
- Enhanced by:
  - Block splitting
  - Position-based reprocessing
  - Length-based shuffling

### 3. Pattern Resistance
- Multiple transformation stages
- Non-linear Collatz sequences
- Block shuffling based on sequence lengths

## Implementation Details

### 1. Block Processing
```python
def process_block(block: bytes) -> int:
    # Convert block to integer seed
    seed = int.from_bytes(block, 'big')
    # Generate Collatz sequence
    sequence_length = generate_collatz_sequence(seed)
    return sequence_length
```

### 2. Shuffling Algorithm
```python
def shuffle_blocks(blocks: List[tuple]) -> List[bytes]:
    # Sort blocks by sequence length
    sorted_blocks = sorted(blocks, 
                         key=lambda x: x[1], 
                         reverse=True)
    # Return blocks in new order
    return [block[0] for block in sorted_blocks]
```

### 3. Final Processing
```python
def generate_final_hash(shuffled_blocks: List[bytes]) -> str:
    # Process each block in new position
    final_sequences = []
    for position, block in enumerate(shuffled_blocks):
        sequence = process_block_with_position(block, position)
        final_sequences.append(sequence)
    # Combine and format result
    return format_final_hash(final_sequences)
```

## Performance Characteristics

### Time Complexity
- Block Processing: O(n) where n is max sequence length
- Shuffling: O(1) (fixed 4 blocks)
- Overall: O(n) linear complexity

### Space Complexity
- Fixed memory usage regardless of input size
- Only stores:
  - Current block being processed
  - Sequence lengths
  - Final hash value

## Usage Examples

### 1. File Hashing
```python
from storage.utils.api import collatz_sha1_signature_of_file

hash_value = collatz_sha1_signature_of_file('document.txt')
print(f"File hash: {hash_value}")
```

### 2. Data Hashing
```python
from storage.utils.api import collatz_sha1_signature_of_data

data = b"Hello, World!"
hash_value = collatz_sha1_signature_of_data(data)
print(f"Data hash: {hash_value}")
```

## Best Practices

1. Input Handling
   - Always use binary data for consistency
   - Handle file reading in chunks for large files
   - Validate input data integrity

2. Hash Storage
   - Store complete 40-character hash
   - Use case-sensitive comparison
   - Validate hash format before use

3. Performance
   - Process large files in chunks
   - Implement parallel processing for multiple files
   - Cache frequently used hashes

## Error Handling

The system includes robust error handling for:
- Invalid input data
- File system errors
- Memory constraints
- Buffer overflows
- Invalid block values

Each error case is logged with appropriate context for debugging.

## Testing Framework

The system includes comprehensive tests:
1. Unit tests for each component
2. Integration tests for the complete pipeline
3. Performance benchmarks
4. Collision tests
5. Pattern resistance tests

For detailed benchmark results, refer to `benchmark_report.md`.
