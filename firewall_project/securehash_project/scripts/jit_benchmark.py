#!/usr/bin/env python3
"""
JIT Benchmark for SHA1-E3
Tests performance with and without Numba JIT to estimate 2GB timing.
"""

import os
import sys
import time
import tempfile
import subprocess
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def create_test_file(size_mb: int) -> str:
    """Create a test file of specified size in MB."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f'_{size_mb}mb.bin')
    temp_file.close()
    
    print(f"Creating {size_mb} MB test file...")
    start_time = time.time()
    
    # Write random data in chunks
    chunk_size = 1024 * 1024  # 1MB chunks
    with open(temp_file.name, 'wb') as f:
        for _ in range(size_mb):
            chunk = os.urandom(chunk_size)
            f.write(chunk)
        f.flush()
        os.fsync(f.fileno())  # Ensure data is written to disk
    
    creation_time = time.time() - start_time
    print(f"File created in {creation_time:.2f} seconds")
    
    return temp_file.name

def benchmark_with_jit(file_path: str, use_jit: bool = True) -> tuple:
    """Benchmark SHA1-E3 with or without JIT."""
    env = os.environ.copy()
    env['SHA1E3_USE_JIT'] = '1' if use_jit else '0'
    
    print(f"Benchmarking with JIT={'ON' if use_jit else 'OFF'}...")
    
    start_time = time.time()
    
    try:
        # Import and run the hashing
        from storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature_file_fast
        
        hash_result = enhanced_sha1_signature_file_fast(file_path)
        
        hash_time = time.time() - start_time
        
        return hash_result, hash_time, None
        
    except Exception as e:
        return None, 0, str(e)

def main():
    print("SHA1-E3 JIT Performance Benchmark")
    print("=" * 50)
    
    # Test sizes in MB
    test_sizes = [64, 128, 256]  # Start with smaller sizes for quick testing
    
    results = []
    
    for size_mb in test_sizes:
        print(f"\n--- Testing {size_mb} MB ---")
        
        # Create test file
        test_file = create_test_file(size_mb)
        
        try:
            # Test without JIT first
            print("\nTesting WITHOUT JIT:")
            hash_result_no_jit, time_no_jit, error_no_jit = benchmark_with_jit(test_file, use_jit=False)
            
            if error_no_jit:
                print(f"Error (no JIT): {error_no_jit}")
            else:
                print(f"Hash: {hash_result_no_jit}")
                print(f"Time: {time_no_jit:.2f} seconds")
                print(f"Speed: {size_mb / time_no_jit:.2f} MB/s")
            
            # Test with JIT
            print("\nTesting WITH JIT:")
            hash_result_jit, time_jit, error_jit = benchmark_with_jit(test_file, use_jit=True)
            
            if error_jit:
                print(f"Error (JIT): {error_jit}")
                print("JIT not available, falling back to pure Python")
                time_jit = time_no_jit
                speedup = 1.0
            else:
                print(f"Hash: {hash_result_jit}")
                print(f"Time: {time_jit:.2f} seconds")
                print(f"Speed: {size_mb / time_jit:.2f} MB/s")
                
                # Verify hashes are identical
                if hash_result_no_jit and hash_result_jit:
                    if hash_result_no_jit == hash_result_jit:
                        print("✓ Hashes match - JIT preserves correctness")
                    else:
                        print("✗ Hash mismatch - JIT changes output!")
                
                speedup = time_no_jit / time_jit if time_jit > 0 else 1.0
                print(f"Speedup: {speedup:.2f}x")
            
            results.append({
                'size_mb': size_mb,
                'time_no_jit': time_no_jit,
                'time_jit': time_jit,
                'speedup': speedup,
                'error_jit': error_jit
            })
            
        finally:
            # Clean up test file
            try:
                os.unlink(test_file)
            except:
                pass
    
    # Project 2GB timing
    print("\n" + "=" * 50)
    print("PERFORMANCE PROJECTION")
    print("=" * 50)
    
    if results:
        # Use the largest successful test for projection
        successful_results = [r for r in results if not r['error_jit']]
        if successful_results:
            best_result = max(successful_results, key=lambda x: x['size_mb'])
        else:
            print("No successful tests - cannot project timing")
            return
        
        size_mb = best_result['size_mb']
        time_jit = best_result['time_jit']
        speedup = best_result['speedup']
        
        # Project to 2GB (2048 MB)
        projected_time_2gb = (time_jit / size_mb) * 2048
        projected_time_2gb_minutes = projected_time_2gb / 60
        
        print(f"Based on {size_mb} MB test:")
        print(f"  JIT Time: {time_jit:.2f} seconds")
        print(f"  Speedup: {speedup:.2f}x")
        print(f"  Projected 2GB time: {projected_time_2gb:.1f} seconds ({projected_time_2gb_minutes:.1f} minutes)")
        
        if projected_time_2gb_minutes <= 10:
            print("🎉 TARGET ACHIEVED! 2GB in ≤10 minutes")
        elif projected_time_2gb_minutes <= 30:
            print("⚠️  Close to target - may need native optimization")
        else:
            print("❌ Still too slow - native optimization required")
    
    print("\nNext steps:")
    print("- If JIT not available: pip install numba")
    print("- If still too slow: implement native module (Rust/C)")

if __name__ == "__main__":
    main()
