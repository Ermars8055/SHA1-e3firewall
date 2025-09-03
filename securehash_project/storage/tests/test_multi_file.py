"""Test multi-file processing and collision detection."""
import os
import time
from pathlib import Path
import pytest
from storage.utils.api import collatz_sha1_signature_of_data
from storage.utils.hash_store import HashStore

@pytest.fixture
def hash_store(tmp_path):
    """Create a temporary hash store for testing."""
    store_path = tmp_path / "test_hash_store.json"
    return HashStore(store_path)

def create_test_files(directory, contents):
    """Create test files with given contents."""
    files = []
    for i, content in enumerate(contents):
        file_path = directory / f"test_file_{i}.txt"
        with open(file_path, "w") as f:
            f.write(content)
        files.append(file_path)
    return files

def test_multi_file_processing(tmp_path, hash_store):
    """Test processing multiple files and storing their hashes."""
    # Create test files
    contents = [
        "Hello, World!",
        "Different content",
        "Another unique file",
        "Some other content",
        "Yet another file"
    ]
    test_files = create_test_files(tmp_path, contents)
    
    # Process each file and store hashes
    hashes = []
    for file_path in test_files:
        with open(file_path, "rb") as f:
            data = f.read()
            file_hash = collatz_sha1_signature_of_data(data)
            hashes.append(file_hash)
            
            metadata = {
                'timestamp': time.time(),
                'file_size': len(data)
            }
            
            # Store hash and check for collisions
            collision = hash_store.add_hash(file_hash, str(file_path), metadata)
            assert not collision, f"Unexpected collision for {file_path}"

    # Verify all hashes are different
    assert len(set(h.hex() for h in hashes)) == len(test_files), "Hash collision detected"

def test_intentional_collision(tmp_path, hash_store):
    """Test collision detection with identical content."""
    content = "Same content"
    file1 = tmp_path / "file1.txt"
    file2 = tmp_path / "file2.txt"
    
    # Create two files with same content
    for file_path in [file1, file2]:
        with open(file_path, "w") as f:
            f.write(content)
    
    # Process files
    with open(file1, "rb") as f:
        data = f.read()
        hash1 = collatz_sha1_signature_of_data(data)
        hash_store.add_hash(hash1, str(file1))
        
    with open(file2, "rb") as f:
        data = f.read()
        hash2 = collatz_sha1_signature_of_data(data)
        collision = hash_store.add_hash(hash2, str(file2))
        assert collision, "Collision should be detected for identical content"

def test_large_file_processing(tmp_path, hash_store):
    """Test processing larger files without iteration limits."""
    # Create a larger test file with repeating pattern
    large_file = tmp_path / "large_file.txt"
    pattern = "This is a test pattern that will be repeated many times.\n"
    
    # Write about 1MB of data
    with open(large_file, "w") as f:
        for _ in range(20000):  # ~1MB
            f.write(pattern)
    
    # Process the large file
    with open(large_file, "rb") as f:
        data = f.read()
        file_hash = collatz_sha1_signature_of_data(data)
        
        metadata = {
            'timestamp': time.time(),
            'file_size': len(data)
        }
        
        collision = hash_store.add_hash(file_hash, str(large_file), metadata)
        assert not collision, "Unexpected collision for large file"

def test_hash_distribution(tmp_path, hash_store):
    """Test hash distribution across many small variations."""
    base_content = "Base content with small variation: "
    hashes = set()
    
    # Create many files with small variations
    for i in range(100):
        file_path = tmp_path / f"variation_{i}.txt"
        content = base_content + str(i)
        
        with open(file_path, "w") as f:
            f.write(content)
        
        with open(file_path, "rb") as f:
            data = f.read()
            file_hash = collatz_sha1_signature_of_data(data)
            hashes.add(file_hash)
            
            collision = hash_store.add_hash(file_hash, str(file_path))
            assert not collision, f"Unexpected collision for variation {i}"
    
    # Verify hash distribution
    assert len(hashes) == 100, "Hash function not producing unique hashes for different inputs"
