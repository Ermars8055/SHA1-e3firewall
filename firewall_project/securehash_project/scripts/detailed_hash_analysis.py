#!/usr/bin/env python3
import sys
import time
import random
import signal
import numpy as np
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
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

class HashAnalyzer:
    def __init__(self, samples=10000):
        self.samples = samples
        self.results_dir = Path(__file__).parent.parent / "docs" / "analysis_results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
    def hash_to_binary(self, hash_str: str) -> str:
        """Convert hash to binary string."""
        return ''.join(format(int(c, 16), '04b') for c in hash_str)
    
    def calculate_bit_difference(self, hash1: str, hash2: str) -> Tuple[int, float]:
        """Calculate number and percentage of differing bits."""
        bin1 = self.hash_to_binary(hash1)
        bin2 = self.hash_to_binary(hash2)
        diff_count = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
        return diff_count, (diff_count / len(bin1)) * 100
    
    def test_bit_distribution(self) -> Dict:
        """Analyze bit distribution in hash outputs."""
        print("\n1. Testing Bit Distribution...")
        total_bits = defaultdict(int)
        bit_positions = defaultdict(lambda: defaultdict(int))
        
        for i in range(self.samples):
            if i % (self.samples // 10) == 0:
                print(f"Progress: {(i/self.samples)*100:.1f}%")
            
            input_data = bytes(random.randint(0, 255) for _ in range(random.randint(8, 64)))
            hash_value = enhanced_sha1_signature(input_data)
            binary = self.hash_to_binary(hash_value)
            
            # Count total 1s and 0s
            total_bits['0'] += binary.count('0')
            total_bits['1'] += binary.count('1')
            
            # Count bits at each position
            for pos, bit in enumerate(binary):
                bit_positions[pos][bit] += 1
        
        # Calculate bias
        total = sum(total_bits.values())
        distribution = {bit: count/total for bit, count in total_bits.items()}
        position_bias = {}
        for pos in bit_positions:
            pos_total = sum(bit_positions[pos].values())
            position_bias[pos] = abs(0.5 - (bit_positions[pos]['1'] / pos_total))
        
        return {
            "distribution": distribution,
            "position_bias": position_bias,
            "max_bias": max(position_bias.values()),
            "avg_bias": sum(position_bias.values()) / len(position_bias)
        }
    
    def test_avalanche_effect(self) -> Dict:
        """Test how small input changes affect the output."""
        print("\n2. Testing Avalanche Effect...")
        results = defaultdict(list)
        
        for i in range(self.samples):
            if i % (self.samples // 10) == 0:
                print(f"Progress: {(i/self.samples)*100:.1f}%")
            
            # Generate random input
            input_len = random.randint(8, 64)
            input_data = bytes(random.randint(0, 255) for _ in range(input_len))
            original_hash = enhanced_sha1_signature(input_data)
            
            # Modify one random bit
            mod_data = bytearray(input_data)
            bit_pos = random.randint(0, len(mod_data) * 8 - 1)
            byte_pos = bit_pos // 8
            bit_in_byte = bit_pos % 8
            mod_data[byte_pos] ^= (1 << bit_in_byte)
            
            modified_hash = enhanced_sha1_signature(bytes(mod_data))
            diff_count, diff_percent = self.calculate_bit_difference(original_hash, modified_hash)
            results["bit_differences"].append(diff_count)
            results["diff_percentages"].append(diff_percent)
        
        return {
            "avg_bit_difference": np.mean(results["bit_differences"]),
            "min_bit_difference": min(results["bit_differences"]),
            "max_bit_difference": max(results["bit_differences"]),
            "std_dev": np.std(results["diff_percentages"]),
            "histogram": np.histogram(results["diff_percentages"], bins=20)
        }
    
    def test_collision_resistance(self) -> Dict:
        """Test for hash collisions with similar inputs."""
        print("\n3. Testing Collision Resistance...")
        collisions = 0
        partial_matches = defaultdict(int)
        hashes_seen = set()
        
        for i in range(self.samples):
            if i % (self.samples // 10) == 0:
                print(f"Progress: {(i/self.samples)*100:.1f}%")
            
            input_data = bytes(random.randint(0, 255) for _ in range(random.randint(8, 64)))
            hash_value = enhanced_sha1_signature(input_data)
            
            if hash_value in hashes_seen:
                collisions += 1
            
            # Check partial matches (first N bits)
            for n in [8, 16, 32, 64]:
                partial = hash_value[:n//4]  # n//4 because each hex char is 4 bits
                partial_matches[n] += 1 if partial in {h[:n//4] for h in hashes_seen} else 0
            
            hashes_seen.add(hash_value)
        
        return {
            "total_collisions": collisions,
            "collision_rate": collisions / self.samples,
            "partial_matches": {k: v/self.samples for k, v in partial_matches.items()}
        }
    
    def test_input_output_correlation(self) -> Dict:
        """Test correlation between input and output patterns."""
        print("\n4. Testing Input-Output Correlation...")
        correlations = defaultdict(list)
        
        # Test different input patterns
        patterns = [
            ("zeros", bytes([0] * 32)),
            ("ones", bytes([255] * 32)),
            ("alternating", bytes([0x55] * 32)),
            ("incremental", bytes(range(32))),
        ]
        
        for pattern_name, base_input in patterns:
            base_hash = enhanced_sha1_signature(base_input)
            
            # Test small modifications
            for i in range(32):
                modified = bytearray(base_input)
                modified[i] ^= 1
                mod_hash = enhanced_sha1_signature(bytes(modified))
                _, diff_percent = self.calculate_bit_difference(base_hash, mod_hash)
                correlations[pattern_name].append(diff_percent)
        
        return {
            "pattern_correlations": {
                pattern: {
                    "mean": np.mean(diffs),
                    "std": np.std(diffs),
                    "min": min(diffs),
                    "max": max(diffs)
                }
                for pattern, diffs in correlations.items()
            }
        }
    
    def analyze_and_save_results(self):
        """Run all tests and save detailed results."""
        start_time = time.time()
        results = {}
        
        try:
            with time_limit(300):  # 5-minute total timeout
                results["bit_distribution"] = self.test_bit_distribution()
                results["avalanche_effect"] = self.test_avalanche_effect()
                results["collision_resistance"] = self.test_collision_resistance()
                results["input_output_correlation"] = self.test_input_output_correlation()
        except TimeoutException:
            print("\nAnalysis timed out! Saving partial results...")
        
        # Save detailed results
        output_file = self.results_dir / "detailed_analysis.md"
        with open(output_file, "w") as f:
            f.write("# Detailed Hash Algorithm Analysis\n\n")
            f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Samples per test: {self.samples:,}\n\n")
            
            if "bit_distribution" in results:
                f.write("## 1. Bit Distribution Analysis\n")
                dist = results["bit_distribution"]
                f.write(f"- 0s: {dist['distribution']['0']:.2%}\n")
                f.write(f"- 1s: {dist['distribution']['1']:.2%}\n")
                f.write(f"- Maximum position bias: {dist['max_bias']:.4f}\n")
                f.write(f"- Average position bias: {dist['avg_bias']:.4f}\n")
                f.write("\nBias Analysis:\n")
                f.write("- Ideal: 0.5000 for each bit position\n")
                f.write("- Warning threshold: > 0.0100\n")
                f.write("- Critical threshold: > 0.0200\n\n")
            
            if "avalanche_effect" in results:
                f.write("## 2. Avalanche Effect Analysis\n")
                av = results["avalanche_effect"]
                f.write(f"- Average bit changes: {av['avg_bit_difference']:.2f} bits\n")
                f.write(f"- Minimum bit changes: {av['min_bit_difference']} bits\n")
                f.write(f"- Maximum bit changes: {av['max_bit_difference']} bits\n")
                f.write(f"- Standard deviation: {av['std_dev']:.2f}%\n")
                f.write("\nAvalanche Quality:\n")
                f.write("- Ideal: 50% of bits change\n")
                f.write("- Good: 45-55% range\n")
                f.write("- Warning: < 45% or > 55%\n")
                f.write("- Critical: < 40% or > 60%\n\n")
            
            if "collision_resistance" in results:
                f.write("## 3. Collision Resistance Analysis\n")
                col = results["collision_resistance"]
                f.write(f"- Total collisions: {col['total_collisions']}\n")
                f.write(f"- Collision rate: {col['collision_rate']:.6%}\n")
                f.write("\nPartial matches (first N bits):\n")
                for bits, rate in col['partial_matches'].items():
                    f.write(f"- {bits} bits: {rate:.6%}\n")
                f.write("\nQuality Metrics:\n")
                f.write("- Ideal collision rate: < 0.0001%\n")
                f.write("- Warning threshold: > 0.001%\n")
                f.write("- Critical threshold: > 0.01%\n\n")
            
            if "input_output_correlation" in results:
                f.write("## 4. Input-Output Correlation Analysis\n")
                corr = results["input_output_correlation"]["pattern_correlations"]
                for pattern, stats in corr.items():
                    f.write(f"\n### {pattern.title()} Pattern:\n")
                    f.write(f"- Mean difference: {stats['mean']:.2f}%\n")
                    f.write(f"- Std deviation: {stats['std']:.2f}%\n")
                    f.write(f"- Range: {stats['min']:.2f}% - {stats['max']:.2f}%\n")
                f.write("\nCorrelation Quality:\n")
                f.write("- Ideal: No detectable correlation\n")
                f.write("- Warning: Consistent patterns in differences\n")
                f.write("- Critical: Strong correlation between input and output\n\n")
            
            f.write(f"\nTotal analysis time: {time.time() - start_time:.2f} seconds\n")
            
            # Add recommendations
            f.write("\n## Recommendations\n")
            if "bit_distribution" in results:
                if results["bit_distribution"]["max_bias"] > 0.02:
                    f.write("- Critical: Improve bit distribution balance\n")
                elif results["bit_distribution"]["max_bias"] > 0.01:
                    f.write("- Warning: Consider enhancing bit mixing\n")
            
            if "avalanche_effect" in results:
                av = results["avalanche_effect"]
                if av["avg_bit_difference"] < 128 - 25 or av["avg_bit_difference"] > 128 + 25:
                    f.write("- Critical: Strengthen avalanche effect\n")
                elif av["avg_bit_difference"] < 128 - 15 or av["avg_bit_difference"] > 128 + 15:
                    f.write("- Warning: Consider improving bit propagation\n")
            
            if "collision_resistance" in results:
                if results["collision_resistance"]["collision_rate"] > 0.0001:
                    f.write("- Critical: Improve collision resistance\n")
            
        print(f"\nDetailed analysis saved to {output_file}")
        return results

def main():
    analyzer = HashAnalyzer(samples=10000)
    analyzer.analyze_and_save_results()

if __name__ == "__main__":
    main()
