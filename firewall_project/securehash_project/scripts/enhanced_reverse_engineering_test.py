#!/usr/bin/env python3
"""
Enhanced reverse engineering test suite for SHA1-E3
"""

import sys
import time
import random
import string
import hashlib
import multiprocessing
import signal
from datetime import datetime
from pathlib import Path
from typing import Tuple, List
import statistics
from contextlib import contextmanager

class TimeoutError(Exception):
    pass

@contextmanager
def timeout(seconds):
    def signal_handler(signum, frame):
        raise TimeoutError(f"Test timed out after {seconds} seconds")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))
from storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature

def generate_random_input(length: int) -> bytes:
    """Generate random input of specified length."""
    return ''.join(random.choices(string.printable, k=length)).encode()

def bit_similarity(hash1: str, hash2: str) -> Tuple[int, float]:
    """Calculate bit-level similarity between two hashes."""
    # Convert hashes to binary
    bin1 = ''.join(format(int(c, 16), '04b') for c in hash1)
    bin2 = ''.join(format(int(c, 16), '04b') for c in hash2)
    
    # Count matching bits
    matches = sum(1 for a, b in zip(bin1, bin2) if a == b)
    total_bits = len(bin1)
    
    return matches, (matches / total_bits) * 100

def test_known_input_reversal(attempts: int = 100_000) -> dict:
    """Test attempting to reverse engineer from known input."""
    print("\nTest 1: Known Input Reversal")
    
    try:
        with timeout(30):  # 30 second timeout
            original = b"This is an enhanced test message for SHA1-E3"
            target_hash = enhanced_sha1_signature(original)
            
            start_time = time.time()
            best_match = 0
            best_match_input = None
            match_rates = []
            
            for i in range(attempts):
                if i % (attempts // 100) == 0:
                    progress = i / attempts * 100
                    bars = int(progress / 2)
                    print(f"[{'=' * bars}{' ' * (50-bars)}] {progress:.1f}%", end='\r')
                    
                # Save intermediate results every 5 seconds
                current_time = time.time()
                if current_time - start_time > 5:
                    print(f"\nIntermediate result - Best match so far: {best_match/256:.2%}")
                    start_time = current_time
                    
                test_input = generate_random_input(len(original))
                test_hash = enhanced_sha1_signature(test_input)
                matches, match_rate = bit_similarity(target_hash, test_hash)
                
                match_rates.append(match_rate)
                if matches > best_match:
                    best_match = matches
                    best_match_input = test_input
                    
        return {
            "original_input": original,
            "target_hash": target_hash,
            "best_match_bits": best_match,
            "best_match_input": best_match_input,
            "avg_match_rate": statistics.mean(match_rates),
            "std_dev": statistics.stdev(match_rates),
            "time_taken": time.time() - start_time
        }
                    
    except TimeoutError as e:
        print(f"\n{str(e)}")
        return {
            "error": "Test timed out",
            "best_match_bits": best_match if 'best_match' in locals() else 0,
            "time_taken": 30.0
        }
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        return {
            "error": str(e),
            "time_taken": time.time() - start_time
        }
    
    for _ in range(attempts):
        test_input = generate_random_input(len(original))
        test_hash = enhanced_sha1_signature(test_input)
        matches, match_rate = bit_similarity(target_hash, test_hash)
        
        match_rates.append(match_rate)
        if matches > best_match:
            best_match = matches
            best_match_input = test_input
    
    return {
        "original_input": original,
        "target_hash": target_hash,
        "best_match_bits": best_match,
        "best_match_input": best_match_input,
        "avg_match_rate": statistics.mean(match_rates),
        "std_dev": statistics.stdev(match_rates),
        "time_taken": time.time() - start_time
    }

def test_random_input_reversal(attempts: int = 100_000) -> dict:
    """Test attempting to reverse random inputs."""
    print("\nTest 2: Random Input Reversal")
    lengths = [8, 16, 32, 64]
    results = []
    
    for i, length in enumerate(lengths):
        print(f"\nTesting length {length} bytes [{i+1}/{len(lengths)}]")
        print("[" + " " * 50 + "] 0%", end="\r")
        
        try:
            with time_limit(30):  # 30 second timeout per length
                original = generate_random_input(length)
                target_hash = enhanced_sha1_signature(original)
                
                start_time = time.time()
                best_match = 0
                match_rates = []
        
        for _ in range(attempts // len(lengths)):
            test_input = generate_random_input(length)
            test_hash = enhanced_sha1_signature(test_input)
            matches, match_rate = bit_similarity(target_hash, test_hash)
            
            match_rates.append(match_rate)
            best_match = max(best_match, matches)
        
        results.append({
            "length": length,
            "best_match_bits": best_match,
            "avg_match_rate": statistics.mean(match_rates),
            "std_dev": statistics.stdev(match_rates),
            "time_taken": time.time() - start_time
        })
    
    return results

def test_avalanche_effect() -> dict:
    """Test the avalanche effect - how small input changes affect output."""
    results = []
    base_input = b"base input string"
    base_hash = enhanced_sha1_signature(base_input)
    
    modifications = [
        b"Base input string",  # Case change
        b"base input string!",  # Added character
        b"base input strin",   # Removed character
        b"base input strinh",  # Changed character
    ]
    
    for mod_input in modifications:
        mod_hash = enhanced_sha1_signature(mod_input)
        matches, match_rate = bit_similarity(base_hash, mod_hash)
        
        results.append({
            "original": base_input,
            "modified": mod_input,
            "bit_differences": len(base_hash) * 4 - matches,
            "difference_rate": 100 - match_rate
        })
    
    return results

def test_pattern_analysis(attempts: int = 1_000_000) -> dict:
    """Analyze for patterns in hash outputs."""
    hashes = []
    start_time = time.time()
    
    # Generate hashes for analysis
    for _ in range(attempts):
        input_data = generate_random_input(random.randint(8, 64))
        hash_value = enhanced_sha1_signature(input_data)
        hashes.append(hash_value)
    
    # Analyze bit distribution
    all_bits = ''.join(format(int(c, 16), '04b') for h in hashes for c in h)
    ones_count = all_bits.count('1')
    zeros_count = all_bits.count('0')
    
    # Analyze hex value distribution
    hex_distribution = {hex(i)[2:]: 0 for i in range(16)}
    for h in hashes:
        for c in h:
            hex_distribution[c.lower()] += 1
    
    return {
        "bit_ratio": ones_count / zeros_count,
        "hex_distribution": hex_distribution,
        "time_taken": time.time() - start_time
    }

def run_all_tests() -> None:
    """Run all reverse engineering tests and save results."""
    results = {
        "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "test_config": {
            "attempts_per_test": 1_000_000,
            "cpu_cores": multiprocessing.cpu_count()
        }
    }
    
    print("Starting Enhanced SHA1-E3 Reverse Engineering Tests...")
    print("Each test has a 30-second timeout. Progress will be shown.")
    
    # Create results directory if it doesn't exist
    Path("../docs").mkdir(parents=True, exist_ok=True)
    
    # Run all tests
    print("\n1. Testing Known Input Reversal...")
    results["known_input_test"] = test_known_input_reversal()
    
    print("2. Testing Random Input Reversal...")
    results["random_input_test"] = test_random_input_reversal()
    
    print("3. Testing Avalanche Effect...")
    results["avalanche_test"] = test_avalanche_effect()
    
    print("4. Analyzing Patterns...")
    results["pattern_analysis"] = test_pattern_analysis()
    
    # Save results
    output_path = Path(__file__).parent.parent / "docs" / "enhanced_reverse_engineering_results.md"
    
    with open(output_path, 'w') as f:
        f.write("# Enhanced SHA1-E3 Reverse Engineering Test Results\n\n")
        f.write(f"Test Date: {results['test_date']}\n\n")
        
        # Write test configuration
        f.write("## Test Configuration\n")
        for key, value in results['test_config'].items():
            f.write(f"- {key.replace('_', ' ').title()}: {value:,}\n")
        
        # Write known input test results
        f.write("\n## 1. Known Input Reversal Test\n")
        kr = results["known_input_test"]
        f.write(f"- Original Input: {kr['original_input']}\n")
        f.write(f"- Target Hash: {kr['target_hash']}\n")
        f.write(f"- Best Match Bits: {kr['best_match_bits']}/256\n")
        f.write(f"- Success Rate: {kr['avg_match_rate']:.2f}%\n")
        f.write(f"- Standard Deviation: {kr['std_dev']:.2f}%\n")
        f.write(f"- Time Taken: {kr['time_taken']:.2f} seconds\n")
        
        # Write random input test results
        f.write("\n## 2. Random Input Reversal Test\n")
        for r in results["random_input_test"]:
            f.write(f"\nInput Length: {r['length']} bytes\n")
            f.write(f"- Best Match Bits: {r['best_match_bits']}/256\n")
            f.write(f"- Average Match Rate: {r['avg_match_rate']:.2f}%\n")
            f.write(f"- Standard Deviation: {r['std_dev']:.2f}%\n")
            f.write(f"- Time Taken: {r['time_taken']:.2f} seconds\n")
        
        # Write avalanche test results
        f.write("\n## 3. Avalanche Effect Test\n")
        for r in results["avalanche_test"]:
            f.write(f"\nTest Case:\n")
            f.write(f"- Original: {r['original']}\n")
            f.write(f"- Modified: {r['modified']}\n")
            f.write(f"- Bit Differences: {r['bit_differences']}/256\n")
            f.write(f"- Difference Rate: {r['difference_rate']:.2f}%\n")
        
        # Write pattern analysis results
        f.write("\n## 4. Pattern Analysis\n")
        pa = results["pattern_analysis"]
        f.write(f"- Bit Distribution Ratio (1s/0s): {pa['bit_ratio']:.4f}\n")
        f.write("- Hex Value Distribution:\n")
        for hex_val, count in pa['hex_distribution'].items():
            f.write(f"  - {hex_val}: {count:,}\n")
        f.write(f"- Time Taken: {pa['time_taken']:.2f} seconds\n")
        
        # Write overall analysis
        f.write("\n## Overall Analysis\n")
        total_time = (kr['time_taken'] + 
                     sum(r['time_taken'] for r in results["random_input_test"]) +
                     pa['time_taken'])
        f.write(f"- Total Time Taken: {total_time:.2f} seconds\n")
        
        # Determine if implementation is secure
        avg_match_rate = kr['avg_match_rate']
        bit_ratio = pa['bit_ratio']
        is_secure = (avg_match_rate < 52.0 and  # Close to 50% is ideal
                    0.98 < bit_ratio < 1.02)     # Close to 1.0 is ideal
        
        status = "✅ SECURE" if is_secure else "❌ VULNERABLE"
        f.write(f"- Reverse Engineering Status: {status}\n")
        
    print(f"\nResults saved to {output_path}")

if __name__ == "__main__":
    run_all_tests()
