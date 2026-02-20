"""
Reverse Engineering Test Suite for SHA1-E3
Attempts to break the one-way property of the hash function
"""

import sys
import os
import time
import random
import string
from datetime import datetime
from typing import Dict, Tuple, List
import multiprocessing as mp
from itertools import product

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

class ReverseEngineeringTester:
    def __init__(self):
        self.results = []
        self.start_time = datetime.now()
        self.attempts_per_test = 1_000_000
        
    def generate_random_content(self, length: int) -> bytes:
        """Generate random content of specified length"""
        return ''.join(random.choices(string.printable, k=length)).encode()
    
    def try_match_hash(self, target_hash: str, attempt_range: Tuple[int, int]) -> Dict:
        """Try to find content that produces the target hash"""
        start_time = time.time()
        best_match = {
            'input': None,
            'hash': None,
            'matching_bits': 0,
            'attempts': 0
        }
        
        for i in range(attempt_range[0], attempt_range[1]):
            # Try different input lengths
            test_input = self.generate_random_content(random.randint(4, 32))
            test_hash = enhanced_sha1_with_content(test_input)
            
            # Count matching bits
            matching_bits = sum(1 for a, b in zip(bin(int(test_hash, 16))[2:].zfill(256),
                                                bin(int(target_hash, 16))[2:].zfill(256))
                              if a == b)
            
            if matching_bits > best_match['matching_bits']:
                best_match = {
                    'input': test_input,
                    'hash': test_hash,
                    'matching_bits': matching_bits,
                    'attempts': i - attempt_range[0] + 1
                }
                
            if test_hash == target_hash:
                best_match['found_match'] = True
                break
                
        best_match['time_taken'] = time.time() - start_time
        return best_match
    
    def parallel_hash_attack(self, target_hash: str) -> Dict:
        """Attempt to reverse engineer hash using parallel processing"""
        cpu_count = mp.cpu_count()
        chunk_size = self.attempts_per_test // cpu_count
        
        ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(cpu_count)]
        
        with mp.Pool(cpu_count) as pool:
            results = pool.starmap(self.try_match_hash,
                                 [(target_hash, range_) for range_ in ranges])
            
        # Find best result across all processes
        best_result = max(results, key=lambda x: x['matching_bits'])
        return best_result
    
    def test_known_input_reversal(self) -> Dict:
        """Test attempting to reverse hash of known input"""
        known_input = b"This is a test message for SHA1-E3"
        target_hash = enhanced_sha1_with_content(known_input)
        
        result = self.parallel_hash_attack(target_hash)
        result['original_input'] = known_input
        result['target_hash'] = target_hash
        return result
    
    def test_random_input_reversal(self) -> Dict:
        """Test attempting to reverse hash of random input"""
        random_input = self.generate_random_content(16)
        target_hash = enhanced_sha1_with_content(random_input)
        
        result = self.parallel_hash_attack(target_hash)
        result['original_input'] = random_input
        result['target_hash'] = target_hash
        return result
    
    def test_similar_input_reversal(self) -> Dict:
        """Test with slightly modified inputs"""
        base_input = b"Base input string"
        modified_input = b"Base input string!"  # One character difference
        
        base_hash = enhanced_sha1_with_content(base_input)
        mod_hash = enhanced_sha1_with_content(modified_input)
        
        # Try to find either hash
        result = self.parallel_hash_attack(base_hash)
        result['original_input'] = base_input
        result['modified_input'] = modified_input
        result['base_hash'] = base_hash
        result['modified_hash'] = mod_hash
        return result
    
    def run_all_tests(self):
        """Run comprehensive reverse engineering tests"""
        print("\nStarting SHA1-E3 Reverse Engineering Tests...")
        
        print("\n1. Testing Known Input Reversal...")
        known_result = self.test_known_input_reversal()
        
        print("\n2. Testing Random Input Reversal...")
        random_result = self.test_random_input_reversal()
        
        print("\n3. Testing Similar Input Reversal...")
        similar_result = self.test_similar_input_reversal()
        
        self.save_results({
            'known_input': known_result,
            'random_input': random_result,
            'similar_input': similar_result
        })
        
    def save_results(self, all_results: Dict):
        """Save test results to markdown file"""
        with open('../docs/reverse_engineering_results.md', 'w') as f:
            f.write("# SHA1-E3 Reverse Engineering Test Results\n\n")
            f.write(f"Test Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Test Configuration\n")
            f.write(f"- Attempts per test: {self.attempts_per_test:,}\n")
            f.write(f"- CPU cores used: {mp.cpu_count()}\n")
            f.write(f"- Total attempts: {self.attempts_per_test * 3:,}\n\n")
            
            # Known Input Test
            f.write("## 1. Known Input Reversal Test\n")
            kr = all_results['known_input']
            f.write(f"- Original Input: {kr['original_input']}\n")
            f.write(f"- Target Hash: {kr['target_hash']}\n")
            f.write(f"- Best Match Bits: {kr['matching_bits']}/256\n")
            f.write(f"- Success Rate: {(kr['matching_bits']/256)*100:.2f}%\n")
            f.write(f"- Time Taken: {kr['time_taken']:.2f} seconds\n\n")
            
            # Random Input Test
            f.write("## 2. Random Input Reversal Test\n")
            rr = all_results['random_input']
            f.write(f"- Original Input: {rr['original_input']}\n")
            f.write(f"- Target Hash: {rr['target_hash']}\n")
            f.write(f"- Best Match Bits: {rr['matching_bits']}/256\n")
            f.write(f"- Success Rate: {(rr['matching_bits']/256)*100:.2f}%\n")
            f.write(f"- Time Taken: {rr['time_taken']:.2f} seconds\n\n")
            
            # Similar Input Test
            f.write("## 3. Similar Input Test\n")
            sr = all_results['similar_input']
            f.write(f"- Base Input: {sr['original_input']}\n")
            f.write(f"- Modified Input: {sr['modified_input']}\n")
            f.write(f"- Base Hash: {sr['base_hash']}\n")
            f.write(f"- Modified Hash: {sr['modified_hash']}\n")
            f.write(f"- Best Match Bits: {sr['matching_bits']}/256\n")
            f.write(f"- Success Rate: {(sr['matching_bits']/256)*100:.2f}%\n")
            f.write(f"- Time Taken: {sr['time_taken']:.2f} seconds\n\n")
            
            # Overall Analysis
            f.write("## Overall Analysis\n")
            avg_success = (kr['matching_bits'] + rr['matching_bits'] + sr['matching_bits']) / (3 * 256)
            total_time = kr['time_taken'] + rr['time_taken'] + sr['time_taken']
            
            f.write(f"- Average Success Rate: {avg_success*100:.2f}%\n")
            f.write(f"- Total Time Taken: {total_time:.2f} seconds\n")
            f.write("- Reverse Engineering Status: ")
            if avg_success < 0.55:  # Less than 55% match is good
                f.write("✅ SECURE - No successful reverse engineering\n")
            else:
                f.write("❌ VULNERABLE - Possible patterns detected\n")

def main():
    tester = ReverseEngineeringTester()
    tester.run_all_tests()
    print("\nReverse engineering tests completed! Results saved to docs/reverse_engineering_results.md")

if __name__ == "__main__":
    main()
