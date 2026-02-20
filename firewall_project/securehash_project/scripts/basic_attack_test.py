"""
Basic Attack Test Suite for SHA1-E3
Tests fundamental security properties and common attack vectors
"""

import sys
import os
import time
import random
import hashlib
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

class BasicAttackTester:
    def __init__(self):
        self.results = []
        self.start_time = datetime.now()
        
    def test_identical_files(self):
        """Test 1: Verify same input produces same hash"""
        print("\nRunning Test 1: Identical Input Test...")
        content = b"This is a test message"
        hash1 = enhanced_sha1_with_content(content)
        hash2 = enhanced_sha1_with_content(content)
        
        result = {
            "test": "Identical Input Test",
            "input1": content.decode(),
            "hash1": hash1,
            "input2": content.decode(),
            "hash2": hash2,
            "passed": hash1 == hash2,
            "details": "Same input should produce same hash"
        }
        self.results.append(result)
        
    def test_single_bit_change(self):
        """Test 2: Verify single bit change produces different hash"""
        print("\nRunning Test 2: Single Bit Change Test...")
        content1 = b"Test Message A"
        content2 = b"Test Message B"  # Single character change
        
        hash1 = enhanced_sha1_with_content(content1)
        hash2 = enhanced_sha1_with_content(content2)
        
        # Calculate bit difference percentage
        bit_diff = self.calculate_bit_difference(hash1, hash2)
        
        result = {
            "test": "Single Bit Change Test",
            "input1": content1.decode(),
            "hash1": hash1,
            "input2": content2.decode(),
            "hash2": hash2,
            "bit_difference": f"{bit_diff:.2f}%",
            "passed": bit_diff > 45,  # Good hash functions should show ~50% difference
            "details": "Single bit change should cause avalanche effect"
        }
        self.results.append(result)
        
    def test_length_extension(self):
        """Test 3: Test for length extension vulnerability"""
        print("\nRunning Test 3: Length Extension Test...")
        original = b"Original Message"
        extension = b"Extended Content"
        
        # Get hash of original
        orig_hash = enhanced_sha1_with_content(original)
        
        # Try length extension
        combined = original + extension
        combined_hash = enhanced_sha1_with_content(combined)
        
        # Try to predict combined hash using only original hash
        try:
            predicted = enhanced_sha1_with_content(orig_hash.encode() + extension)
            vulnerable = predicted == combined_hash
        except:
            vulnerable = False
            
        result = {
            "test": "Length Extension Test",
            "original": original.decode(),
            "extension": extension.decode(),
            "original_hash": orig_hash,
            "combined_hash": combined_hash,
            "passed": not vulnerable,
            "details": "Hash function should be resistant to length extension attacks"
        }
        self.results.append(result)
        
    def test_collision_resistance(self):
        """Test 4: Basic collision resistance test"""
        print("\nRunning Test 4: Collision Resistance Test...")
        num_tests = 10000
        hashes = set()
        collisions = 0
        
        for i in range(num_tests):
            content = f"Test content {i} {random.randint(1, 1000000)}".encode()
            hash_val = enhanced_sha1_with_content(content)
            if hash_val in hashes:
                collisions += 1
            hashes.add(hash_val)
            
        result = {
            "test": "Collision Resistance Test",
            "samples": num_tests,
            "collisions": collisions,
            "passed": collisions == 0,
            "details": f"Tested {num_tests} random inputs for collisions"
        }
        self.results.append(result)
        
    def test_shattered_pdfs(self):
        """Test 5: Test with known SHA-1 collision PDFs"""
        print("\nRunning Test 5: SHAttered PDF Test...")
        try:
            with open('../ShatteredPDF/shattered-1.pdf', 'rb') as f1, \
                 open('../ShatteredPDF/shattered-2.pdf', 'rb') as f2:
                content1 = f1.read()
                content2 = f2.read()
                
                hash1 = enhanced_sha1_with_content(content1)
                hash2 = enhanced_sha1_with_content(content2)
                
                # Calculate bit difference
                bit_diff = self.calculate_bit_difference(hash1, hash2)
                
                result = {
                    "test": "SHAttered PDF Test",
                    "hash1": hash1,
                    "hash2": hash2,
                    "bit_difference": f"{bit_diff:.2f}%",
                    "passed": hash1 != hash2,
                    "details": "Known SHA-1 colliding PDFs should produce different hashes"
                }
        except FileNotFoundError:
            result = {
                "test": "SHAttered PDF Test",
                "error": "PDF files not found",
                "passed": None,
                "details": "Could not perform test - PDF files missing"
            }
        
        self.results.append(result)
    
    def calculate_bit_difference(self, hash1: str, hash2: str) -> float:
        """Calculate percentage of differing bits between two hashes."""
        bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
        bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
        diff_bits = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
        return (diff_bits / len(bin1)) * 100
    
    def run_all_tests(self):
        """Run all attack tests"""
        self.test_identical_files()
        self.test_single_bit_change()
        self.test_length_extension()
        self.test_collision_resistance()
        self.test_shattered_pdfs()
        self.save_results()
        
    def save_results(self):
        """Save test results to markdown file"""
        with open('../docs/attack_results.md', 'w') as f:
            f.write("# SHA1-E3 Basic Attack Test Results\n\n")
            f.write(f"Test Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            passed = sum(1 for r in self.results if r.get('passed'))
            total = len(self.results)
            f.write(f"## Summary\n")
            f.write(f"- Tests Run: {total}\n")
            f.write(f"- Tests Passed: {passed}\n")
            f.write(f"- Success Rate: {(passed/total)*100:.2f}%\n\n")
            
            # Detailed Results
            f.write("## Detailed Results\n\n")
            for result in self.results:
                f.write(f"### {result['test']}\n")
                f.write(f"- Status: {'✅ PASSED' if result.get('passed') else '❌ FAILED' if result.get('passed') is not None else '⚠️ ERROR'}\n")
                for key, value in result.items():
                    if key not in ['test', 'passed']:
                        f.write(f"- {key}: {value}\n")
                f.write("\n")

def main():
    print("Starting Basic Attack Test Suite for SHA1-E3...")
    tester = BasicAttackTester()
    tester.run_all_tests()
    print("\nTesting complete! Results saved to docs/attack_results.md")

if __name__ == "__main__":
    main()
