"""
SHA1-E3 Evaluation Test Suite
Tests various properties required for cryptographic hash functions
"""

import sys
import os
import binascii
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

def compare_hashes(hash1: str, hash2: str) -> float:
    """Calculate the percentage of differing bits between two hashes."""
    if len(hash1) != len(hash2):
        raise ValueError("Hash lengths must be equal")
    
    # Convert hashes to binary
    bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
    bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
    
    # Count differing bits
    diff_bits = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
    return (diff_bits / len(bin1)) * 100

def test_determinism():
    """Test Set 1: Determinism Test"""
    print("\n✅ Test Set 1: Determinism")
    print("=" * 50)
    
    input_str = b"hello world"
    hashes = []
    
    print("Input: 'hello world'")
    for i in range(3):
        hash_result = enhanced_sha1_with_content(input_str)
        hashes.append(hash_result)
        print(f"Run {i+1}: {hash_result}")
    
    are_identical = len(set(hashes)) == 1
    print(f"\nDeterminism Test: {'PASSED ✅' if are_identical else 'FAILED ❌'}")

def test_avalanche():
    """Test Set 2: Avalanche Effect"""
    print("\n🔁 Test Set 2: Avalanche Effect")
    print("=" * 50)
    
    input_a = b"The quick brown fox jumps over the lazy dog"
    input_b = b"The quick brown fox jumps over the lazy dot"
    
    hash_a = enhanced_sha1_with_content(input_a)
    hash_b = enhanced_sha1_with_content(input_b)
    
    print(f"Input A Hash: {hash_a}")
    print(f"Input B Hash: {hash_b}")
    
    diff_percentage = compare_hashes(hash_a, hash_b)
    print(f"\nBit Difference: {diff_percentage:.2f}%")
    print(f"Avalanche Test: {'PASSED ✅' if diff_percentage >= 45 else 'FAILED ❌'}")

def test_sha1_collision():
    """Test Set 3: SHA-1 Collision Test"""
    print("\n🔐 Test Set 3: SHA-1 Collision Test")
    print("=" * 50)
    
    try:
        with open('../ShatteredPDF/shattered-1.pdf', 'rb') as f1, \
             open('../ShatteredPDF/shattered-2.pdf', 'rb') as f2:
            pdf1_content = f1.read()
            pdf2_content = f2.read()
            
            hash1 = enhanced_sha1_with_content(pdf1_content)
            hash2 = enhanced_sha1_with_content(pdf2_content)
            
            print(f"Shattered-1 Hash: {hash1}")
            print(f"Shattered-2 Hash: {hash2}")
            
            diff_percentage = compare_hashes(hash1, hash2)
            print(f"\nBit Difference: {diff_percentage:.2f}%")
            print(f"Collision Test: {'PASSED ✅' if hash1 != hash2 else 'FAILED ❌'}")
    except FileNotFoundError:
        print("Error: Shattered PDF files not found!")

def test_padding_attacks():
    """Test Set 4: Padding and Structure Attacks"""
    print("\n🌀 Test Set 4: Padding and Structure Attacks")
    print("=" * 50)
    
    input_a = b"abc"
    input_b = b"abc\x00\x00\x00\x00"
    
    hash_a = enhanced_sha1_with_content(input_a)
    hash_b = enhanced_sha1_with_content(input_b)
    
    print(f"Input A Hash: {hash_a}")
    print(f"Input B Hash: {hash_b}")
    
    diff_percentage = compare_hashes(hash_a, hash_b)
    print(f"\nBit Difference: {diff_percentage:.2f}%")
    print(f"Padding Test: {'PASSED ✅' if hash_a != hash_b else 'FAILED ❌'}")

def test_collatz_entropy():
    """Test Set 5: Collatz Entropy Test"""
    print("\n🔢 Test Set 5: Collatz Entropy Test")
    print("=" * 50)
    
    input_a = b"abcdef"
    input_b = b"abcfed"
    
    hash_a = enhanced_sha1_with_content(input_a)
    hash_b = enhanced_sha1_with_content(input_b)
    
    print(f"Input A Hash: {hash_a}")
    print(f"Input B Hash: {hash_b}")
    
    diff_percentage = compare_hashes(hash_a, hash_b)
    print(f"\nBit Difference: {diff_percentage:.2f}%")
    print(f"Position Sensitivity Test: {'PASSED ✅' if diff_percentage >= 45 else 'FAILED ❌'}")

def main():
    print("SHA1-E3 Evaluation Test Suite")
    print("=" * 50)
    
    # Run all tests
    test_determinism()
    test_avalanche()
    test_sha1_collision()
    test_padding_attacks()
    test_collatz_entropy()

if __name__ == "__main__":
    main()
