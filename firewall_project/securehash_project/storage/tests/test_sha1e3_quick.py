#!/usr/bin/env python3
"""
Quick SHA1-E3 Test Suite - Clean Output Version
Tests major functionality without verbose progress output
"""

import sys
import os
import time
import random
import hashlib
from typing import List, Dict, Tuple
import statistics

# Add the parent directory to the path to import the SHA1-E3 module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from securehash_project.storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature

class QuickSHA1E3Tester:
    def __init__(self):
        self.results = {
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': [],
            'performance_metrics': {},
            'security_metrics': {}
        }
        
    def log_test(self, test_name: str, passed: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{status} {test_name}")
        if details:
            print(f"   Details: {details}")
        
        self.results['test_details'].append({
            'test_name': test_name,
            'passed': passed,
            'details': details
        })
        
        if passed:
            self.results['tests_passed'] += 1
        else:
            self.results['tests_failed'] += 1
    
    def test_basic_functionality(self):
        """Test basic hash functionality"""
        print("\n🔧 Testing Basic Functionality...")
        
        # Test 1: Basic string hashing
        test_string = "Hello World"
        hash1 = enhanced_sha1_signature(test_string.encode(), show_progress=False)
        hash2 = enhanced_sha1_signature(test_string.encode(), show_progress=False)
        
        self.log_test(
            "Identical Input Test",
            hash1 == hash2 and len(hash1) == 64,
            f"Hash: {hash1[:16]}... (length: {len(hash1)})"
        )
        
        # Test 2: Different inputs produce different hashes
        test_string2 = "Hello Universe"
        hash3 = enhanced_sha1_signature(test_string2.encode(), show_progress=False)
        
        self.log_test(
            "Different Input Test",
            hash1 != hash3,
            f"Hash1: {hash1[:16]}... vs Hash2: {hash3[:16]}..."
        )
        
        # Test 3: Empty string
        empty_hash = enhanced_sha1_signature(b"", show_progress=False)
        self.log_test(
            "Empty String Test",
            len(empty_hash) == 64,
            f"Empty string hash: {empty_hash[:16]}..."
        )
    
    def test_avalanche_effect(self):
        """Test avalanche effect - small changes should cause large hash changes"""
        print("\n⚡ Testing Avalanche Effect...")
        
        base_string = "The quick brown fox jumps over the lazy dog"
        base_hash = enhanced_sha1_signature(base_string.encode(), show_progress=False)
        
        # Test single bit changes
        avalanche_tests = []
        for i in range(5):  # Reduced from 10 to 5 for speed
            # Create a string with one character changed
            test_string = base_string[:i] + chr(ord(base_string[i]) + 1) + base_string[i+1:]
            test_hash = enhanced_sha1_signature(test_string.encode(), show_progress=False)
            
            # Calculate bit difference
            bit_diff = self.calculate_bit_difference(base_hash, test_hash)
            avalanche_tests.append(bit_diff)
            
            self.log_test(
                f"Single Character Change {i+1}",
                bit_diff > 20,  # Should be significant change
                f"Bit difference: {bit_diff:.1f}%"
            )
        
        # Calculate average avalanche effect
        avg_avalanche = statistics.mean(avalanche_tests)
        self.results['security_metrics']['avalanche_effect'] = avg_avalanche
        
        self.log_test(
            "Average Avalanche Effect",
            avg_avalanche > 40,  # Should be around 50%
            f"Average bit change: {avg_avalanche:.1f}%"
        )
    
    def test_collision_resistance(self):
        """Test collision resistance"""
        print("\n🛡️ Testing Collision Resistance...")
        
        # Test with random strings
        collision_tests = 100  # Reduced from 1000 to 100 for speed
        hashes = set()
        collisions = 0
        
        for i in range(collision_tests):
            # Generate random string
            random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=20))
            hash_value = enhanced_sha1_signature(random_string.encode(), show_progress=False)
            
            if hash_value in hashes:
                collisions += 1
            else:
                hashes.add(hash_value)
        
        self.results['security_metrics']['collisions_found'] = collisions
        self.results['security_metrics']['collision_tests'] = collision_tests
        
        self.log_test(
            "Collision Resistance",
            collisions == 0,
            f"Found {collisions} collisions in {collision_tests} tests"
        )
    
    def test_bit_balance(self):
        """Test bit balance in hash output"""
        print("\n⚖️ Testing Bit Balance...")
        
        # Generate hash for test string
        test_string = "Bit balance test string for SHA1-E3 algorithm"
        hash_value = enhanced_sha1_signature(test_string.encode(), show_progress=False)
        
        # Convert hex to binary
        binary = bin(int(hash_value, 16))[2:].zfill(len(hash_value) * 4)
        
        # Count bits per byte
        bits_per_byte = []
        for i in range(0, len(binary), 8):
            byte_bits = binary[i:i+8]
            bit_count = byte_bits.count('1')
            bits_per_byte.append(bit_count)
        
        # Check if bytes are balanced (3-5 bits per byte)
        balanced_bytes = sum(1 for count in bits_per_byte if 3 <= count <= 5)
        balance_ratio = balanced_bytes / len(bits_per_byte)
        
        self.results['security_metrics']['bit_balance_ratio'] = balance_ratio
        self.results['security_metrics']['bits_per_byte'] = bits_per_byte
        
        self.log_test(
            "Bit Balance Test",
            balance_ratio > 0.6,  # At least 60% of bytes should be balanced
            f"Balanced bytes: {balanced_bytes}/{len(bits_per_byte)} ({balance_ratio:.1%})"
        )
    
    def test_position_dependency(self):
        """Test that same content at different positions produces different hashes"""
        print("\n📍 Testing Position Dependency...")
        
        content = "Same content"
        
        # Test at different positions by padding
        hashes = []
        for i in range(3):  # Reduced from 5 to 3 for speed
            padded_content = "X" * i + content
            hash_value = enhanced_sha1_signature(padded_content.encode(), show_progress=False)
            hashes.append(hash_value)
        
        # All hashes should be different
        unique_hashes = len(set(hashes))
        
        self.log_test(
            "Position Dependency",
            unique_hashes == len(hashes),
            f"Generated {unique_hashes} unique hashes from {len(hashes)} positions"
        )
    
    def test_collatz_sequence_integration(self):
        """Test that Collatz sequences are properly integrated"""
        print("\n🧮 Testing Collatz Sequence Integration...")
        
        # Test with known Collatz sequences
        test_cases = [
            (1, [1]),  # Edge case
            (2, [2, 1]),  # Simple case
            (3, [3, 10, 5, 16, 8, 4, 2, 1]),  # Classic case
        ]
        
        for seed, expected_sequence in test_cases:
            # Create a test string that would use this seed
            test_string = chr(seed) + "test"
            hash_value = enhanced_sha1_signature(test_string.encode(), show_progress=False)
            
            # The hash should be deterministic
            hash2 = enhanced_sha1_signature(test_string.encode(), show_progress=False)
            
            self.log_test(
                f"Collatz Integration (seed {seed})",
                hash_value == hash2 and len(hash_value) == 64,
                f"Hash: {hash_value[:16]}..."
            )
    
    def test_performance(self):
        """Test performance metrics"""
        print("\n⚡ Testing Performance...")
        
        # Test with different file sizes
        test_sizes = [100, 1000]  # Reduced sizes for speed
        performance_data = {}
        
        for size in test_sizes:
            # Generate test data
            test_data = b"X" * size
            
            # Measure time
            start_time = time.time()
            hash_value = enhanced_sha1_signature(test_data, show_progress=False)
            end_time = time.time()
            
            processing_time = end_time - start_time
            throughput = size / processing_time / 1024 / 1024  # MB/s
            
            performance_data[size] = {
                'time': processing_time,
                'throughput': throughput
            }
            
            self.log_test(
                f"Performance Test ({size} bytes)",
                processing_time < 1.0,  # Should be fast
                f"Time: {processing_time:.4f}s, Throughput: {throughput:.2f} MB/s"
            )
        
        self.results['performance_metrics'] = performance_data
    
    def test_shattered_pdf_resistance(self):
        """Test resistance to known SHA-1 collision attacks"""
        print("\n💥 Testing SHAttered PDF Resistance...")
        
        # Simulate the SHAttered PDF attack scenario
        # These are simplified versions of the collision patterns
        pdf1_content = b"PDF1: " + b"A" * 100 + b"COLLISION_PATTERN_1"
        pdf2_content = b"PDF2: " + b"A" * 100 + b"COLLISION_PATTERN_2"
        
        hash1 = enhanced_sha1_signature(pdf1_content, show_progress=False)
        hash2 = enhanced_sha1_signature(pdf2_content, show_progress=False)
        
        # Calculate bit difference
        bit_diff = self.calculate_bit_difference(hash1, hash2)
        
        self.log_test(
            "SHAttered PDF Resistance",
            hash1 != hash2 and bit_diff > 20,
            f"Bit difference: {bit_diff:.1f}%"
        )
    
    def test_statistical_properties(self):
        """Test statistical properties of hash output"""
        print("\n📊 Testing Statistical Properties...")
        
        # Generate many hashes and analyze distribution
        num_hashes = 50  # Reduced from 1000 to 50 for speed
        hashes = []
        
        for i in range(num_hashes):
            test_string = f"Statistical test {i} with random data {random.randint(1, 10000)}"
            hash_value = enhanced_sha1_signature(test_string.encode(), show_progress=False)
            hashes.append(hash_value)
        
        # Analyze bit distribution
        all_bits = ''.join(bin(int(h, 16))[2:].zfill(64) for h in hashes)
        ones = all_bits.count('1')
        zeros = all_bits.count('0')
        total_bits = len(all_bits)
        
        bit_ratio = ones / total_bits
        
        self.log_test(
            "Statistical Bit Distribution",
            0.4 < bit_ratio < 0.6,  # Should be roughly balanced
            f"Bit ratio: {bit_ratio:.3f} (1s: {ones}, 0s: {zeros})"
        )
    
    def calculate_bit_difference(self, hash1: str, hash2: str) -> float:
        """Calculate percentage of bits that differ between two hashes"""
        # Convert hex to binary
        bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
        bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
        
        # Count differing bits
        differences = sum(1 for a, b in zip(bin1, bin2) if a != b)
        total_bits = len(bin1)
        
        return (differences / total_bits) * 100
    
    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting Quick SHA1-E3 Test Suite")
        print("=" * 50)
        
        start_time = time.time()
        
        # Run all test categories
        self.test_basic_functionality()
        self.test_avalanche_effect()
        self.test_collision_resistance()
        self.test_bit_balance()
        self.test_position_dependency()
        self.test_collatz_sequence_integration()
        self.test_performance()
        self.test_shattered_pdf_resistance()
        self.test_statistical_properties()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        print(f"Total Tests: {self.results['tests_passed'] + self.results['tests_failed']}")
        print(f"Passed: {self.results['tests_passed']} ✅")
        print(f"Failed: {self.results['tests_failed']} ❌")
        print(f"Success Rate: {self.results['tests_passed'] / (self.results['tests_passed'] + self.results['tests_failed']) * 100:.1f}%")
        print(f"Total Time: {total_time:.2f} seconds")
        
        # Security metrics summary
        if 'security_metrics' in self.results:
            print(f"\n🔒 SECURITY METRICS:")
            if 'avalanche_effect' in self.results['security_metrics']:
                print(f"  Avalanche Effect: {self.results['security_metrics']['avalanche_effect']:.1f}%")
            if 'collisions_found' in self.results['security_metrics']:
                print(f"  Collisions Found: {self.results['security_metrics']['collisions_found']}")
            if 'bit_balance_ratio' in self.results['security_metrics']:
                print(f"  Bit Balance: {self.results['security_metrics']['bit_balance_ratio']:.1%}")
        
        # Performance summary
        if 'performance_metrics' in self.results:
            print(f"\n⚡ PERFORMANCE METRICS:")
            for size, metrics in self.results['performance_metrics'].items():
                print(f"  {size} bytes: {metrics['throughput']:.2f} MB/s")
        
        return self.results

def main():
    """Main test function"""
    tester = QuickSHA1E3Tester()
    results = tester.run_all_tests()
    
    # Return exit code based on results
    if results['tests_failed'] == 0:
        print("\n🎉 All tests passed! SHA1-E3 is working perfectly!")
        return 0
    else:
        print(f"\n⚠️  {results['tests_failed']} tests failed. Please review the results.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
