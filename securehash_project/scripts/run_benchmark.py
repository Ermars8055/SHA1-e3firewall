"""
Benchmark script for testing the Collatz-SHA1 system with various file types and sizes.
"""
import os
import random
import string
import json
import time
from pathlib import Path
import logging
from typing import Dict, List, Tuple

from storage.utils.api import collatz_sha1_signature_of_data
from storage.utils.hash_store import HashStore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

BENCHMARK_DIR = Path(__file__).parent.parent / 'benchmark_data'
RESULTS_FILE = BENCHMARK_DIR / 'benchmark_results.json'
TEST_FILES_DIR = BENCHMARK_DIR / 'test_files'


def generate_random_text(size_kb: int, pattern_type: str = 'random') -> str:
    """Generate text content of specified size and pattern."""
    if pattern_type == 'random':
        chars = string.ascii_letters + string.digits + string.punctuation + ' \n'
        return ''.join(random.choice(chars) for _ in range(size_kb * 1024))
    elif pattern_type == 'repeat':
        base = "This is a repeating pattern with some variation " + str(random.randint(1, 1000)) + "\n"
        repeats = (size_kb * 1024) // len(base) + 1
        return base * repeats
    elif pattern_type == 'sequential':
        # Generate sequential numbers as text
        return '\n'.join(str(i) for i in range((size_kb * 1024) // 8))
    else:
        raise ValueError(f"Unknown pattern type: {pattern_type}")


def create_test_files() -> List[Tuple[Path, str, int]]:
    """Create test files of various sizes and patterns."""
    TEST_FILES_DIR.mkdir(exist_ok=True)
    files_info = []

    # Different sizes in KB
    sizes = [1, 10, 100, 1000, 10000]  # 1KB to 10MB
    patterns = ['random', 'repeat', 'sequential']

    for size in sizes:
        for pattern in patterns:
            filename = f"test_{size}kb_{pattern}.txt"
            file_path = TEST_FILES_DIR / filename
            
            logging.info(f"Creating {filename} with size {size}KB using {pattern} pattern")
            content = generate_random_text(size, pattern)
            
            with open(file_path, 'w') as f:
                f.write(content)
            
            files_info.append((file_path, pattern, size))

    return files_info


def run_benchmark(files_info: List[Tuple[Path, str, int]]) -> Dict:
    """Run benchmark tests and collect results."""
    results = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'files': []
    }

    hash_store = HashStore(BENCHMARK_DIR / 'hash_store.json')

    for file_path, pattern, size in files_info:
        logging.info(f"Processing {file_path.name}")
        
        # Measure processing time
        start_time = time.time()
        with open(file_path, 'rb') as f:
            data = f.read()
            signature = collatz_sha1_signature_of_data(data)
        end_time = time.time()
        
        processing_time = end_time - start_time
        
        # Store hash and check for collisions
        collision = hash_store.add_hash(
            signature,
            str(file_path),
            {
                'size_kb': size,
                'pattern': pattern,
                'processing_time': processing_time
            }
        )

        file_result = {
            'filename': file_path.name,
            'size_kb': size,
            'pattern': pattern,
            'signature': signature,
            'processing_time': processing_time,
            'collision_detected': collision
        }
        results['files'].append(file_result)
        
        logging.info(f"Signature: {signature}")
        logging.info(f"Processing time: {processing_time:.2f} seconds")
        if collision:
            logging.warning(f"Collision detected for {file_path.name}!")

    return results


def save_results(results: Dict):
    """Save benchmark results to JSON file."""
    # Load existing results if any
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, 'r') as f:
            all_results = json.load(f)
    else:
        all_results = []

    # Add new results
    all_results.append(results)

    # Save updated results
    with open(RESULTS_FILE, 'w') as f:
        json.dump(all_results, f, indent=2)


def analyze_results(results: Dict):
    """Analyze and print benchmark results."""
    logging.info("\nBenchmark Analysis:")
    logging.info("=" * 50)

    # Group by size
    by_size = {}
    for file_info in results['files']:
        size = file_info['size_kb']
        if size not in by_size:
            by_size[size] = []
        by_size[size].append(file_info)

    # Analyze each size group
    for size, files in sorted(by_size.items()):
        logging.info(f"\nSize: {size}KB")
        logging.info("-" * 30)
        
        avg_time = sum(f['processing_time'] for f in files) / len(files)
        logging.info(f"Average processing time: {avg_time:.2f} seconds")
        
        for file_info in files:
            logging.info(f"Pattern: {file_info['pattern']}")
            logging.info(f"Time: {file_info['processing_time']:.2f}s")
            logging.info(f"Signature: {file_info['signature']}\n")


def main():
    """Main benchmark execution."""
    logging.info("Starting benchmark")
    
    # Create test files
    files_info = create_test_files()
    
    # Run benchmark
    results = run_benchmark(files_info)
    
    # Save results
    save_results(results)
    
    # Analyze results
    analyze_results(results)
    
    logging.info("Benchmark completed")


if __name__ == '__main__':
    main()
