#!/usr/bin/env python3
"""
Comprehensive Hash Analysis Suite
Including statistical tests, adversarial analysis, and detailed bit-level testing
"""

import sys
import time
import random
import signal
import numpy as np
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from typing import Dict, List, Tuple, Set
from itertools import combinations
import scipy.stats as stats
import json
import platform
import os
import multiprocessing
from collections import defaultdict

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))
from storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature

class TimeoutException(Exception):
    pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Test timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

class ComprehensiveHashAnalyzer:
    def __init__(self, sample_sizes=[10_000, 50_000, 100_000]):
        self.sample_sizes = sample_sizes
        self.results_dir = Path(__file__).parent.parent / "docs" / "comprehensive_analysis"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.environment_info = self._get_environment_info()
        
    def _get_environment_info(self) -> Dict:
        """Collect environment information for reproducibility."""
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "python_version": sys.version,
            "cpu_count": multiprocessing.cpu_count(),
            "platform": platform.platform(),
            "timestamp": datetime.now().isoformat()
        }
    
    def hash_to_binary(self, hash_str: str) -> str:
        """Convert hash to binary string."""
        return ''.join(format(int(c, 16), '04b') for c in hash_str)
    
    def compute_partial_matches(self, hashes: List[str], bits: int) -> float:
        """Correctly compute partial matches for first N bits."""
        total_pairs = 0
        matching_pairs = 0
        prefix_len = bits // 4  # Convert bits to hex characters
        
        # Calculate total number of combinations
        total_combinations = len(hashes) * (len(hashes) - 1) // 2
        progress_interval = max(1, total_combinations // 100)
        print(f"\nComputing {bits}-bit partial matches...")
        print("[" + " " * 50 + "] 0%", end="\r")
        
        # Use combinations to get all unique pairs
        for idx, (hash1, hash2) in enumerate(combinations(hashes, 2)):
            if idx % progress_interval == 0:
                progress = (idx / total_combinations) * 100
                blocks = int(progress / 2)
                print(f"[{'=' * blocks}{' ' * (50-blocks)}] {progress:.1f}%", end="\r")
            
            total_pairs += 1
            if hash1[:prefix_len] == hash2[:prefix_len]:
                matching_pairs += 1
        
        return (matching_pairs / total_pairs) * 100 if total_pairs > 0 else 0
    
    def chi_square_test(self, bit_sequences: List[str]) -> List[float]:
        """Perform chi-square test for bit uniformity at all positions."""
        print("\nPerforming chi-square tests...")
        print("[" + " " * 50 + "] 0%", end="\r")
        
        p_values = []
        for i, sequence in enumerate(bit_sequences):
            if i % (len(bit_sequences) // 50) == 0:
                progress = (i / len(bit_sequences)) * 100
                blocks = int(progress / 2)
                print(f"[{'=' * blocks}{' ' * (50-blocks)}] {progress:.1f}%", end="\r")
            
            observed = [sequence.count('0'), sequence.count('1')]
            expected = [len(sequence)/2, len(sequence)/2]
            chi2, p_value = stats.chisquare(observed, expected)
            p_values.append(p_value)
        
        print("\nChi-square tests completed!")
        return p_values
    
    def generate_avalanche_heatmap(self, input_size: int = 32) -> np.ndarray:
        """Generate avalanche effect heatmap."""
        print("\nGenerating avalanche heatmap...")
        print("[" + " " * 50 + "] 0%", end="\r")
        
        base_input = bytes([0] * input_size)
        base_hash = self.hash_to_binary(enhanced_sha1_signature(base_input))
        heatmap = np.zeros((input_size * 8, 256))  # Input bits × Output bits
        
        total_bits = input_size * 8
        for bit_num in range(total_bits):
            byte_idx = bit_num // 8
            bit_idx = bit_num % 8
            
            progress = (bit_num / total_bits) * 100
            blocks = int(progress / 2)
            print(f"[{'=' * blocks}{' ' * (50-blocks)}] {progress:.1f}%", end="\r")
            
            modified = bytearray(base_input)
            modified[byte_idx] ^= (1 << bit_idx)
            mod_hash = self.hash_to_binary(enhanced_sha1_signature(bytes(modified)))
            
            for out_idx in range(256):
                heatmap[byte_idx * 8 + bit_idx][out_idx] = (base_hash[out_idx] != mod_hash[out_idx])
        
        return heatmap
    
    def small_domain_analysis(self, max_size: int = 16) -> Dict:
        """Analyze hash behavior for small input domains."""
        print("\nPerforming small domain analysis...")
        results = {}
        seen_hashes = set()
        collisions = []
        
        # Calculate total operations
        total_ops = sum(min(2**(size*8), 1000) for size in range(1, max_size + 1))
        current_ops = 0
        
        # Test all possible inputs up to max_size bytes
        for size in range(1, max_size + 1):
            print(f"\nAnalyzing {size}-byte inputs...")
            size_results = {
                "total_inputs": 0,
                "unique_hashes": 0,
                "collisions": 0,
                "collision_pairs": []
            }
            
            seen_hashes.clear()
            max_inputs = min(2**(size*8), 1000)  # Limit for larger sizes
            
            for i in range(max_inputs):
                input_data = i.to_bytes(size, byteorder='big')
                hash_value = enhanced_sha1_signature(input_data)
                
                size_results["total_inputs"] += 1
                if hash_value in seen_hashes:
                    size_results["collisions"] += 1
                    collisions.append((input_data.hex(), hash_value))
                seen_hashes.add(hash_value)
            
            size_results["unique_hashes"] = len(seen_hashes)
            results[size] = size_results
        
        return results
    
    def run_comprehensive_analysis(self):
        """Run comprehensive analysis with multiple sample sizes."""
        results = {
            "environment": self.environment_info,
            "sample_sizes": {}
        }
        
        for sample_size in self.sample_sizes:
            print(f"\nRunning analysis with sample size: {sample_size:,}")
            size_results = {}
            
            # Generate hash samples
            print("Generating hash samples...")
            hashes = []
            binary_hashes = []
            
            for i in range(sample_size):
                if i % (sample_size // 10) == 0:
                    print(f"Progress: {(i/sample_size)*100:.1f}%")
                input_data = bytes(random.randint(0, 255) for _ in range(random.randint(8, 64)))
                hash_value = enhanced_sha1_signature(input_data)
                hashes.append(hash_value)
                binary_hashes.append(self.hash_to_binary(hash_value))
            
            # 1. Correct Partial Match Analysis
            print("Computing partial matches...")
            partial_matches = {}
            for bits in [8, 16, 32, 64]:
                partial_matches[bits] = self.compute_partial_matches(hashes, bits)
            size_results["partial_matches"] = partial_matches
            
            # 2. Chi-square tests for each bit position
            bit_sequences = [''.join(hash_bin[i] for hash_bin in binary_hashes) 
                           for i in range(256)]
            p_values = self.chi_square_test(bit_sequences)
            size_results["chi_square"] = {
                "min_p_value": min(p_values),
                "max_p_value": max(p_values),
                "mean_p_value": np.mean(p_values),
                "suspicious_positions": [i for i, p in enumerate(p_values) if p < 0.001]
            }
            
            # 3. Avalanche Analysis
            print("Generating avalanche heatmap...")
            heatmap = self.generate_avalanche_heatmap()
            size_results["avalanche"] = {
                "mean_change_rate": float(np.mean(heatmap)),
                "min_change_rate": float(np.min(heatmap)),
                "max_change_rate": float(np.max(heatmap)),
                "std_dev": float(np.std(heatmap))
            }
            
            # 4. Small Domain Analysis
            print("Performing small domain analysis...")
            size_results["small_domain"] = self.small_domain_analysis()
            
            results["sample_sizes"][sample_size] = size_results
        
        # Save results
        self.save_results(results)
        return results
    
    def save_results(self, results: Dict):
        """Save comprehensive results and generate detailed report."""
        # Save raw results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_file = self.results_dir / f"raw_results_{timestamp}.json"
        with open(raw_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate markdown report
        report_file = self.results_dir / f"comprehensive_analysis_{timestamp}.md"
        with open(report_file, 'w') as f:
            f.write("# Comprehensive Hash Algorithm Analysis\n\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Environment Information
            f.write("## Environment\n")
            for key, value in results["environment"].items():
                f.write(f"- {key}: {value}\n")
            f.write("\n")
            
            # Results for each sample size
            for sample_size, size_results in results["sample_sizes"].items():
                f.write(f"## Sample Size: {sample_size:,}\n\n")
                
                # Partial Matches
                f.write("### Partial Match Analysis\n")
                f.write("| Bits | Actual % | Expected % | Difference |\n")
                f.write("|------|----------|------------|------------|\n")
                expected = {
                    8: 0.39,
                    16: 0.0015,
                    32: 2.3e-8,
                    64: 5.4e-18
                }
                for bits, rate in size_results["partial_matches"].items():
                    diff = rate - expected[bits]
                    f.write(f"| {bits:4d} | {rate:.4f}% | {expected[bits]:.4f}% | {diff:+.4f}% |\n")
                f.write("\n")
                
                # Chi-square Results
                f.write("### Bit Uniformity Analysis\n")
                chi = size_results["chi_square"]
                f.write(f"- Minimum p-value: {chi['min_p_value']:.6f}\n")
                f.write(f"- Mean p-value: {chi['mean_p_value']:.6f}\n")
                if chi['suspicious_positions']:
                    f.write("- Suspicious bit positions: " + 
                           ", ".join(map(str, chi['suspicious_positions'])) + "\n")
                f.write("\n")
                
                # Avalanche Effect
                f.write("### Avalanche Effect Analysis\n")
                av = size_results["avalanche"]
                f.write(f"- Mean bit change rate: {av['mean_change_rate']*100:.2f}%\n")
                f.write(f"- Change rate range: {av['min_change_rate']*100:.2f}% - {av['max_change_rate']*100:.2f}%\n")
                f.write(f"- Standard deviation: {av['std_dev']*100:.2f}%\n")
                f.write("\n")
                
                # Small Domain Analysis
                f.write("### Small Domain Analysis\n")
                for size, data in size_results["small_domain"].items():
                    f.write(f"\nInput size: {size} byte(s)\n")
                    f.write(f"- Total inputs tested: {data['total_inputs']:,}\n")
                    f.write(f"- Unique hashes: {data['unique_hashes']:,}\n")
                    f.write(f"- Collisions found: {data['collisions']:,}\n")
                f.write("\n")
            
            # Overall Assessment
            f.write("## Overall Assessment\n\n")
            all_partial_matches = [
                results["sample_sizes"][size]["partial_matches"]
                for size in results["sample_sizes"]
            ]
            all_chi_square = [
                results["sample_sizes"][size]["chi_square"]
                for size in results["sample_sizes"]
            ]
            
            # Check for concerning patterns
            concerns = []
            for matches in all_partial_matches:
                if matches[8] > 0.5:  # 8-bit partial matches
                    concerns.append("High 8-bit collision rate")
            for chi in all_chi_square:
                if chi["min_p_value"] < 0.001:
                    concerns.append("Some bit positions show non-uniform distribution")
            
            if concerns:
                f.write("### Areas Needing Attention\n")
                for concern in concerns:
                    f.write(f"- {concern}\n")
            else:
                f.write("No significant concerns identified.\n")
            
        print(f"\nComprehensive analysis saved to {report_file}")
        print(f"Raw results saved to {raw_file}")

def main():
    analyzer = ComprehensiveHashAnalyzer()
    analyzer.run_comprehensive_analysis()

if __name__ == "__main__":
    main()
