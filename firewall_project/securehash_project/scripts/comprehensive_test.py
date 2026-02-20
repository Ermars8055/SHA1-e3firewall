"""
Comprehensive Test Suite for SHA1-E3
Tests various cryptographic properties and performance characteristics
"""

import sys
import os
import time
import random
from collections import defaultdict
import matplotlib.pyplot as plt
from typing import List, Tuple
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

def test_avalanche_effect(base_content: bytes, num_tests: int = 100) -> float:
    """Test the avalanche effect by changing single bits and comparing hashes."""
    original_hash = enhanced_sha1_with_content(base_content)
    differences = []
    
    for _ in range(num_tests):
        # Change a random bit in the content
        pos = random.randint(0, len(base_content) - 1)
        bit_pos = random.randint(0, 7)
        modified_content = bytearray(base_content)
        modified_content[pos] ^= (1 << bit_pos)
        
        # Get new hash and compare
        new_hash = enhanced_sha1_with_content(bytes(modified_content))
        
        # Calculate bit difference percentage
        diff_bits = sum(bin(int(a, 16) ^ int(b, 16)).count('1') 
                       for a, b in zip(original_hash, new_hash))
        diff_percentage = (diff_bits / (len(original_hash) * 4)) * 100
        differences.append(diff_percentage)
    
    return sum(differences) / len(differences)

def test_performance(file_paths: List[str]) -> List[Tuple[str, float, float]]:
    """Test performance on different file sizes."""
    results = []
    
    for path in file_paths:
        with open(path, 'rb') as f:
            content = f.read()
            size_mb = len(content) / (1024 * 1024)
            
            # Time the hashing
            start_time = time.time()
            enhanced_sha1_with_content(content)
            duration = time.time() - start_time
            
            speed = size_mb / duration if duration > 0 else float('inf')
            results.append((os.path.basename(path), duration, speed))
    
    return results

def test_collision_resistance(file_paths: List[str]) -> bool:
    """Test collision resistance by hashing multiple files."""
    hashes = set()
    for path in file_paths:
        with open(path, 'rb') as f:
            content = f.read()
            hash_val = enhanced_sha1_with_content(content)
            if hash_val in hashes:
                return False
            hashes.add(hash_val)
    return True

def test_hash_distribution(test_data: List[bytes]) -> dict:
    """Test the distribution of hash values."""
    distribution = defaultdict(int)
    total_hashes = len(test_data)
    
    for data in test_data:
        hash_val = enhanced_sha1_with_content(data)
        # Use first byte of hash for distribution analysis
        first_byte = int(hash_val[:2], 16)
        distribution[first_byte] += 1
    
    # Convert to percentages
    distribution = {k: (v/total_hashes)*100 for k, v in distribution.items()}
    return dict(distribution)

def create_similar_files(base_content: bytes, num_files: int = 10) -> List[bytes]:
    """Create slightly modified versions of a base file."""
    similar_files = []
    for _ in range(num_files):
        modified = bytearray(base_content)
        # Make small modifications
        num_changes = random.randint(1, 5)
        for _ in range(num_changes):
            pos = random.randint(0, len(modified) - 1)
            modified[pos] = random.randint(0, 255)
        similar_files.append(bytes(modified))
    return similar_files

def plot_distribution(distribution: dict, title: str):
    """Plot the hash distribution."""
    plt.figure(figsize=(12, 6))
    plt.bar(distribution.keys(), distribution.values())
    plt.title(title)
    plt.xlabel('First Byte Value')
    plt.ylabel('Percentage')
    plt.savefig(f'hash_distribution_{title.lower().replace(" ", "_")}.png')
    plt.close()

def main():
    print("Starting Comprehensive SHA1-E3 Tests...")
    
    # 1. Test Avalanche Effect
    print("\n1. Testing Avalanche Effect...")
    base_content = b"This is a test string for avalanche effect analysis."
    avg_change = test_avalanche_effect(base_content)
    print(f"Average bit change: {avg_change:.2f}%")
    print(f"Avalanche Effect {'GOOD' if avg_change > 45 else 'POOR'}")
    
    # 2. Test Performance
    print("\n2. Testing Performance...")
    test_files = [
        "../benchmark_data/test_files/test_1kb_sequential.txt",
        "../benchmark_data/test_files/test_100kb_sequential.txt",
        "../benchmark_data/test_files/test_1000kb_sequential.txt",
        "../benchmark_data/test_files/test_10000kb_sequential.txt"
    ]
    perf_results = test_performance(test_files)
    print("\nPerformance Results:")
    for name, duration, speed in perf_results:
        print(f"{name}: {duration:.3f}s ({speed:.2f} MB/s)")
    
    # 3. Test Collision Resistance with Similar Files
    print("\n3. Testing Collision Resistance...")
    with open(test_files[1], 'rb') as f:  # Use 100KB file as base
        base_content = f.read()
    similar_files = create_similar_files(base_content)
    collision_free = test_collision_resistance([test_files[0], test_files[1]])
    print(f"Collision Test: {'PASSED' if collision_free else 'FAILED'}")
    
    # 4. Test Hash Distribution
    print("\n4. Testing Hash Distribution...")
    distribution = test_hash_distribution(similar_files + [base_content])
    plot_distribution(distribution, "Hash Distribution")
    
    # Calculate distribution statistics
    values = list(distribution.values())
    std_dev = np.std(values)
    print(f"Distribution Standard Deviation: {std_dev:.2f}")
    print(f"Distribution Test: {'GOOD' if std_dev < 5 else 'POOR'}")

if __name__ == "__main__":
    main()
