#!/usr/bin/env python3
import sys
import time
import random
import signal
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager

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

def calculate_match_rate(hash1: str, hash2: str) -> float:
    """Calculate percentage of matching bits between two hashes."""
    bin1 = ''.join(format(int(c, 16), '04b') for c in hash1)
    bin2 = ''.join(format(int(c, 16), '04b') for c in hash2)
    matches = sum(1 for a, b in zip(bin1, bin2) if a == b)
    return (matches / len(bin1)) * 100

def quick_test_known_input(attempts: int = 10_000):
    """Optimized known input test with progress monitoring."""
    print("\nQuick Test 1: Known Input Reversal")
    original = b"Test message for SHA1-E3"
    target_hash = enhanced_sha1_signature(original)
    best_match = 0
    
    try:
        with time_limit(15):  # 15 second timeout
            for i in range(attempts):
                if i % (attempts // 20) == 0:
                    progress = (i / attempts) * 100
                    blocks = int(progress / 2)
                    print(f"[{'=' * blocks}{' ' * (50-blocks)}] {progress:.1f}%", end="\r")
                
                test_input = bytes(random.randint(0, 255) for _ in range(len(original)))
                test_hash = enhanced_sha1_signature(test_input)
                match_rate = calculate_match_rate(target_hash, test_hash)
                
                if match_rate > best_match:
                    best_match = match_rate
                    print(f"\nNew best match: {best_match:.2f}%", flush=True)
                
    except TimeoutException:
        print("\nTest 1 timed out!")
    except Exception as e:
        print(f"\nError in Test 1: {str(e)}")
    
    return best_match

def quick_test_random_input(max_length: int = 32, attempts: int = 5_000):
    """Optimized random input test."""
    print("\nQuick Test 2: Random Input Test")
    best_match = 0
    
    try:
        with time_limit(15):  # 15 second timeout
            for i in range(attempts):
                if i % (attempts // 20) == 0:
                    progress = (i / attempts) * 100
                    blocks = int(progress / 2)
                    print(f"[{'=' * blocks}{' ' * (50-blocks)}] {progress:.1f}%", end="\r")
                
                length = random.randint(8, max_length)
                input1 = bytes(random.randint(0, 255) for _ in range(length))
                input2 = bytes(random.randint(0, 255) for _ in range(length))
                
                hash1 = enhanced_sha1_signature(input1)
                hash2 = enhanced_sha1_signature(input2)
                match_rate = calculate_match_rate(hash1, hash2)
                
                if match_rate > best_match:
                    best_match = match_rate
                    print(f"\nNew best match: {best_match:.2f}%", flush=True)
                
    except TimeoutException:
        print("\nTest 2 timed out!")
    except Exception as e:
        print(f"\nError in Test 2: {str(e)}")
    
    return best_match

def main():
    print("Starting Quick SHA1-E3 Tests...")
    print("Each test limited to 15 seconds")
    
    start_time = time.time()
    
    # Run tests
    test1_result = quick_test_known_input()
    test2_result = quick_test_random_input()
    
    # Save results
    results_path = Path(__file__).parent.parent / "docs" / "quick_test_results.md"
    with open(results_path, 'w') as f:
        f.write("# Quick SHA1-E3 Test Results\n\n")
        f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Test 1 (Known Input) Best Match: {test1_result:.2f}%\n")
        f.write(f"Test 2 (Random Input) Best Match: {test2_result:.2f}%\n")
        f.write(f"\nTotal Time: {time.time() - start_time:.2f} seconds\n")
    
    print(f"\nResults saved to {results_path}")

if __name__ == "__main__":
    main()
