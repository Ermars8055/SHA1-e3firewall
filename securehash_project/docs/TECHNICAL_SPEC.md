# Technical Specification: Collatz-SHA1 Composite Hash System

## System Architecture

### Components Overview

```
Input Data → SHA-1 → Block Split → Collatz Transform → Merkle Tree → Final Signature
```

### 1. Initial Hashing (hash_utils.py)

The system begins with a SHA-1 hash of the input data:

```python
def compute_sha1(data: bytes) -> bytes:
    """Initial SHA-1 hash computation."""
```

Properties:
- Fixed output size: 160 bits (20 bytes)
- Deterministic output
- Avalanche effect from SHA-1

### 2. Block Processing (collatz_utils.py)

The SHA-1 hash is split and transformed:

1. **Block Splitting:**
   - Input: 20-byte SHA-1 hash
   - Default: Split into 4 blocks of 5 bytes each
   - Configurable number of blocks

2. **Collatz Transform:**
   - Each block influences its own transformation
   - First byte used as Collatz sequence seed
   - Sequence length affects block ordering

```python
def split_and_shuffle(hash_bytes: bytes, num_blocks: int = 4) -> List[bytes]
def collatz_sequence(n: int) -> List[int]
```

### 3. Merkle Tree Construction (merkle.py)

Processes transformed blocks into a Merkle tree:

1. **Leaf Generation:**
   - Each block produces a leaf hash
   - Collatz sequence incorporated into leaf computation

2. **Tree Building:**
   - Binary tree structure
   - Parent nodes: Hash of concatenated children
   - Root becomes basis for final signature

```python
def build_merkle_root(leaf_hashes: List[bytes]) -> bytes
def build_proof(leaf_hashes: List[bytes], index: int) -> List[Tuple[bool, bytes]]
```

### 4. API Layer (api.py)

High-level interface combining all components:

```python
def collatz_sha1_signature_of_data(data: bytes, num_blocks: int = 4) -> str
```

## Performance Characteristics

### Time Complexity

1. **SHA-1 Computation:** O(n) where n is input size
2. **Block Processing:** O(b * c) where:
   - b = number of blocks
   - c = average Collatz sequence length
3. **Merkle Tree:** O(b * log(b)) where b is number of blocks

### Space Complexity

1. **Stream Processing:** O(1) for input reading
2. **Block Storage:** O(b) where b is number of blocks
3. **Merkle Tree:** O(b) for storage

### Optimization Opportunities

1. **Parallel Processing:**
   - Block transformations are independent
   - Leaf hash computations can be parallelized
   - Tree level computations can be parallelized

2. **Memory Management:**
   - Stream-based input processing
   - Incremental tree construction
   - Proof generation without full tree storage

## Security Properties

### Collision Resistance

Derived from multiple factors:
1. SHA-1 base collision resistance
2. Collatz sequence unpredictability
3. Block ordering permutations
4. Merkle tree structure

### Theoretical Bounds

1. **Output Space:**
   - 160-bit final hash space
   - 40 character hex representation

2. **Collatz Impact:**
   - Variable sequence lengths
   - Influences block ordering
   - Affects leaf hash computation

### Attack Surface Analysis

1. **Known SHA-1 Vulnerabilities:**
   - Mitigated by additional transformations
   - Block shuffling reduces impact
   - Collatz sequence adds complexity

2. **Collatz Sequence Properties:**
   - Unpredictable sequence lengths
   - No known mathematical shortcuts
   - Conjecture remains unproven

3. **Merkle Tree Security:**
   - Tamper-evident structure
   - Proof verification capability
   - Branch independence

## Implementation Guidelines

### Error Handling

1. **Input Validation:**
   ```python
   if not isinstance(data, bytes):
       raise TypeError("Input must be bytes")
   ```

2. **Resource Limits:**
   ```python
   if len(data) > MAX_INPUT_SIZE:
       raise ValueError("Input exceeds size limit")
   ```

3. **Collatz Safety:**
   ```python
   if iterations > MAX_ITERATIONS:
       raise RuntimeError("Excessive iterations")
   ```

### Testing Strategy

1. **Unit Tests:**
   - Individual component testing
   - Edge case verification
   - Error handling validation

2. **Integration Tests:**
   - Component interaction testing
   - End-to-end workflow
   - Performance benchmarks

3. **Property Tests:**
   - Deterministic output
   - Size constraints
   - Format verification

## Future Enhancements

1. **Potential Improvements:**
   - Parallelization support
   - Alternative hash functions
   - Configurable security parameters

2. **Research Areas:**
   - Collision probability analysis
   - Performance optimization
   - Security proofs
