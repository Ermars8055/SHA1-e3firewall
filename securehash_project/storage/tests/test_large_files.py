"""Tests for large file handling and collision detection."""
import os
import random
import string
import tempfile
from pathlib import Path
import pytest
from storage.utils.api import collatz_sha1_signature_of_data
from storage.utils.hash_store import HashStore
from storage.utils.file_utils import stream_file_in_chunks


def generate_random_content(size_mb: int) -> bytes:
    """Generate random file content of specified size in MB."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(size_mb * 1024 * 1024)).encode()


def create_test_file(directory: Path, size_mb: int, pattern: str = None) -> Path:
    """Create a test file of specified size."""
    file_path = directory / f"test_file_{size_mb}mb.txt"
    with open(file_path, "wb") as f:
        if pattern:
            # Write repeating pattern
            pattern_bytes = pattern.encode()
            needed_repeats = (size_mb * 1024 * 1024) // len(pattern_bytes)
            f.write(pattern_bytes * needed_repeats)
        else:
            # Write random content
            f.write(generate_random_content(size_mb))
    return file_path


@pytest.fixture
def hash_store(tmp_path):
    """Create a temporary hash store for testing."""
    store_path = tmp_path / "test_hash_store.json"
    return HashStore(store_path)


def test_large_file_signatures(tmp_path, hash_store):
    """Test signature generation for files of different sizes."""
    sizes = [1, 5, 10]  # Different file sizes in MB
    signatures = set()
    
    for size in sizes:
        file_path = create_test_file(tmp_path, size)
        
        # Process file in chunks
        chunks = []
        for chunk in stream_file_in_chunks(str(file_path)):
            chunks.append(chunk)
        
        data = b''.join(chunks)
        signature = collatz_sha1_signature_of_data(data)
        signatures.add(signature)
        
        # Store hash and check for collisions
        collision = hash_store.add_hash(
            signature, 
            str(file_path),
            {'size_mb': size, 'timestamp': os.path.getmtime(file_path)}
        )
        assert not collision, f"Unexpected collision for {size}MB file"
    
    # Verify all signatures are different
    assert len(signatures) == len(sizes), "Duplicate signatures detected"


def test_potential_collisions(tmp_path, hash_store):
    """Test for potential hash collisions with similar content."""
    base_content = "A" * 1024  # 1KB base content
    variations = []
    
    # Create variations by changing single characters
    for i in range(1000):
        pos = random.randint(0, len(base_content) - 1)
        variation = list(base_content)
        variation[pos] = random.choice(string.ascii_letters)
        variations.append(''.join(variation))
    
    # Generate and store hashes for all variations
    hashes = set()
    for i, content in enumerate(variations):
        file_path = tmp_path / f"variation_{i}.txt"
        with open(file_path, "w") as f:
            f.write(content)
        
        signature = collatz_sha1_signature_of_data(content.encode())
        hashes.add(signature)
        
        collision = hash_store.add_hash(signature, str(file_path))
        assert not collision, f"Unexpected collision for variation {i}"
    
    # Verify no collisions
    assert len(hashes) == len(variations), "Hash collision detected"


def test_streaming_consistency(tmp_path, hash_store):
    """Test that streaming produces same results as direct processing."""
    # Create a large test file (5MB)
    file_path = create_test_file(tmp_path, 5, pattern="Test pattern with some variation ")
    
    # Get signature through streaming
    chunks = []
    for chunk in stream_file_in_chunks(str(file_path)):
        chunks.append(chunk)
    streamed_data = b''.join(chunks)
    stream_signature = collatz_sha1_signature_of_data(streamed_data)
    
    # Get signature directly
    with open(file_path, "rb") as f:
        direct_data = f.read()
    direct_signature = collatz_sha1_signature_of_data(direct_data)
    
    # Verify signatures match
    assert stream_signature == direct_signature, "Streaming and direct signatures differ"


def test_repeating_content(tmp_path, hash_store):
    """Test that repeating content produces different signatures with position changes."""
    # Create files with same content but different positions of repeating pattern
    pattern = "ABC" * 1000  # 3KB repeating pattern
    variations = []
    
    # Create variations by rotating the pattern
    for i in range(10):
        rotated = pattern[i:] + pattern[:i]
        file_path = tmp_path / f"rotated_{i}.txt"
        with open(file_path, "w") as f:
            f.write(rotated)
        variations.append(file_path)
    
    # Generate signatures for all variations
    signatures = set()
    for file_path in variations:
        with open(file_path, "rb") as f:
            data = f.read()
            signature = collatz_sha1_signature_of_data(data)
            signatures.add(signature)
            
            collision = hash_store.add_hash(signature, str(file_path))
            assert not collision, "Unexpected collision for rotated pattern"
    
    # Verify that position changes result in different signatures
    assert len(signatures) == len(variations), "Pattern position not affecting signature"
