"""
Comprehensive Security Test Suite for SHA1-E3
Including fuzz testing, collision analysis, entropy testing, and cryptanalysis simulation
"""

import sys
import os
import random
import string
import time
import hashlib
from typing import List, Dict, Tuple
import struct
from collections import defaultdict
import itertools
from math import log2

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

class SHA1E3Tester:
    def __init__(self):
        self.results = []
        self.test_files = {
            'shattered1': '../ShatteredPDF/shattered-1.pdf',
            'shattered2': '../ShatteredPDF/shattered-2.pdf',
            'seq1kb': '../benchmark_data/test_files/test_1kb_sequential.txt',
            'rand1kb': '../benchmark_data/test_files/test_1kb_random.txt',
            'seq1000kb': '../benchmark_data/test_files/test_1000kb_sequential.txt',
            'rand1000kb': '../benchmark_data/test_files/test_1000kb_random.txt'
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte string."""
        freq = defaultdict(int)
        data_len = len(data)
        
        for byte in data:
            freq[byte] += 1
            
        entropy = 0
        for count in freq.values():
            prob = count / data_len
            entropy -= prob * (log2(prob) if prob > 0 else 0)
            
        return entropy

    def fuzz_test(self, num_tests: int = 1000000) -> Dict:
        """Perform extensive fuzz testing."""
        results = {
            'total_tests': num_tests,
            'unique_hashes': set(),
            'collisions': 0,
            'min_diff_percentage': 100,
            'avg_diff_percentage': 0
        }
        
        print(f"Running {num_tests} fuzz tests...")
        base_content = b"base_content_for_testing"
        base_hash = enhanced_sha1_with_content(base_content)
        
        for i in range(num_tests):
            if i % 100000 == 0:
                print(f"Completed {i} tests...")
                
            # Generate different types of modifications
            test_type = i % 4
            if test_type == 0:
                # Random bytes
                content = bytes(random.randint(0, 255) for _ in range(random.randint(1, 1000)))
            elif test_type == 1:
                # Null padding
                content = base_content + b'\x00' * random.randint(0, 100)
            elif test_type == 2:
                # Single byte modification
                content = bytearray(base_content)
                pos = random.randint(0, len(content) - 1)
                content[pos] = random.randint(0, 255)
                content = bytes(content)
            else:
                # Structured modification
                content = base_content + bytes([i % 256 for _ in range(10)])
            
            hash_result = enhanced_sha1_with_content(content)
            results['unique_hashes'].add(hash_result)
            
            # Calculate bit difference percentage
            if content != base_content:
                diff_percentage = self.calculate_bit_difference(base_hash, hash_result)
                results['min_diff_percentage'] = min(results['min_diff_percentage'], diff_percentage)
                results['avg_diff_percentage'] += diff_percentage
        
        results['avg_diff_percentage'] /= num_tests
        results['collisions'] = num_tests - len(results['unique_hashes'])
        return results

    def collision_injection_test(self) -> Dict:
        """Test collision resistance with known problematic cases."""
        results = {'shattered_pdf_test': {}, 'similar_content_test': {}}
        
        # Test shattered PDFs
        with open(self.test_files['shattered1'], 'rb') as f1, \
             open(self.test_files['shattered2'], 'rb') as f2:
            pdf1 = f1.read()
            pdf2 = f2.read()
            
            hash1 = enhanced_sha1_with_content(pdf1)
            hash2 = enhanced_sha1_with_content(pdf2)
            
            results['shattered_pdf_test'] = {
                'hash1': hash1,
                'hash2': hash2,
                'difference': self.calculate_bit_difference(hash1, hash2),
                'collision_free': hash1 != hash2
            }
        
        # Test similar content files
        with open(self.test_files['seq1kb'], 'rb') as f1, \
             open(self.test_files['rand1kb'], 'rb') as f2:
            content1 = f1.read()
            content2 = f2.read()
            
            hash1 = enhanced_sha1_with_content(content1)
            hash2 = enhanced_sha1_with_content(content2)
            
            results['similar_content_test'] = {
                'hash1': hash1,
                'hash2': hash2,
                'difference': self.calculate_bit_difference(hash1, hash2),
                'collision_free': hash1 != hash2
            }
            
        return results

    def entropy_analysis(self, num_samples: int = 1000) -> Dict:
        """Perform entropy analysis on hash outputs."""
        results = {
            'entropy_scores': [],
            'byte_distribution': defaultdict(int),
            'avg_entropy': 0,
            'uniform_distribution_chi_square': 0
        }
        
        print(f"Performing entropy analysis with {num_samples} samples...")
        
        for i in range(num_samples):
            # Generate random input
            input_data = bytes(random.randint(0, 255) for _ in range(random.randint(100, 1000)))
            hash_result = enhanced_sha1_with_content(input_data)
            
            # Convert hash to bytes
            hash_bytes = bytes.fromhex(hash_result)
            
            # Calculate entropy
            entropy = self.calculate_entropy(hash_bytes)
            results['entropy_scores'].append(entropy)
            
            # Track byte distribution
            for byte in hash_bytes:
                results['byte_distribution'][byte] += 1
        
        # Calculate average entropy
        results['avg_entropy'] = sum(results['entropy_scores']) / len(results['entropy_scores'])
        
        # Calculate chi-square for uniform distribution
        expected_freq = num_samples * len(hash_bytes) / 256
        chi_square = sum((freq - expected_freq) ** 2 / expected_freq 
                        for freq in results['byte_distribution'].values())
        results['uniform_distribution_chi_square'] = chi_square
        
        return results

    def preimage_resistance_test(self, num_attempts: int = 1000000) -> Dict:
        """Simulate preimage attack attempts."""
        results = {
            'attempts': num_attempts,
            'successful_preimage': 0,
            'closest_match_bits': 0,
            'time_taken': 0
        }
        
        # Generate target hash
        target_input = b"target_message_for_preimage_test"
        target_hash = enhanced_sha1_with_content(target_input)
        
        start_time = time.time()
        print(f"Running {num_attempts} preimage attack attempts...")
        
        for i in range(num_attempts):
            if i % 100000 == 0:
                print(f"Completed {i} attempts...")
                
            # Try different input generation strategies
            if i % 3 == 0:
                # Random input
                test_input = bytes(random.randint(0, 255) for _ in range(len(target_input)))
            elif i % 3 == 1:
                # Modify target input slightly
                test_input = bytearray(target_input)
                pos = random.randint(0, len(test_input) - 1)
                test_input[pos] = random.randint(0, 255)
                test_input = bytes(test_input)
            else:
                # Append random data
                test_input = target_input + bytes([random.randint(0, 255) for _ in range(10)])
            
            test_hash = enhanced_sha1_with_content(test_input)
            
            # Check for preimage
            if test_hash == target_hash:
                results['successful_preimage'] += 1
            
            # Track closest match
            match_bits = self.count_matching_bits(target_hash, test_hash)
            results['closest_match_bits'] = max(results['closest_match_bits'], match_bits)
        
        results['time_taken'] = time.time() - start_time
        return results

    def statistical_collision_test(self) -> Dict:
        """Test resistance to statistical collision attacks."""
        results = {'reordering_tests': [], 'frequency_tests': []}
        
        # Test 1: Reordering blocks
        base_content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 10
        base_hash = enhanced_sha1_with_content(base_content)
        
        # Try different block arrangements
        block_size = 26
        blocks = [base_content[i:i+block_size] for i in range(0, len(base_content), block_size)]
        
        for i in range(10):
            random.shuffle(blocks)
            modified = b''.join(blocks)
            mod_hash = enhanced_sha1_with_content(modified)
            
            results['reordering_tests'].append({
                'difference': self.calculate_bit_difference(base_hash, mod_hash),
                'collision': base_hash == mod_hash
            })
        
        # Test 2: Same frequency, different order
        base_content = bytes([i % 256 for i in range(1000)])
        base_hash = enhanced_sha1_with_content(base_content)
        
        for i in range(10):
            # Shuffle while maintaining same byte frequency
            modified = bytearray(base_content)
            random.shuffle(modified)
            mod_hash = enhanced_sha1_with_content(bytes(modified))
            
            results['frequency_tests'].append({
                'difference': self.calculate_bit_difference(base_hash, mod_hash),
                'collision': base_hash == mod_hash
            })
        
        return results

    def calculate_bit_difference(self, hash1: str, hash2: str) -> float:
        """Calculate percentage of differing bits between two hashes."""
        bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
        bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
        diff_bits = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
        return (diff_bits / len(bin1)) * 100

    def count_matching_bits(self, hash1: str, hash2: str) -> int:
        """Count number of matching bits between two hashes."""
        bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
        bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
        return sum(b1 == b2 for b1, b2 in zip(bin1, bin2))

    def run_all_tests(self):
        """Run all tests and generate comprehensive results."""
        print("Starting comprehensive SHA1-E3 security testing...")
        
        # Phase 1: Local Real-Time Testing
        print("\nPhase 1: Local Real-Time Testing")
        
        print("\n1. Fuzz Testing...")
        fuzz_results = self.fuzz_test(num_tests=1000000)
        self.results.append(('Fuzz Testing', fuzz_results))
        
        print("\n2. Collision Injection Tests...")
        collision_results = self.collision_injection_test()
        self.results.append(('Collision Injection', collision_results))
        
        print("\n3. Entropy Analysis...")
        entropy_results = self.entropy_analysis(num_samples=1000)
        self.results.append(('Entropy Analysis', entropy_results))
        
        # Phase 2: Security Testing & Cryptanalysis
        print("\nPhase 2: Security Testing & Cryptanalysis")
        
        print("\n4. Preimage Resistance Testing...")
        preimage_results = self.preimage_resistance_test(num_attempts=1000000)
        self.results.append(('Preimage Resistance', preimage_results))
        
        print("\n5. Statistical Collision Testing...")
        stat_collision_results = self.statistical_collision_test()
        self.results.append(('Statistical Collision', stat_collision_results))
        
        return self.results

def main():
    tester = SHA1E3Tester()
    results = tester.run_all_tests()
    
    # Generate markdown report
    report = """# SHA1-E3 Comprehensive Security Analysis Results

## Overview
This document contains the results of extensive security testing performed on the SHA1-E3 hash function implementation.

## Test Results

"""
    
    for test_name, test_results in results:
        report += f"### {test_name}\n\n"
        report += f"```python\n{test_results}\n```\n\n"
    
    # Save report
    with open('../docs/Overallresults.md', 'w') as f:
        f.write(report)
    
    print("\nTesting complete! Results saved to docs/Overallresults.md")

if __name__ == "__main__":
    main()
