import os
import itertools
import string
import time
from securehash_project.storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature

def find_preimage(target_hash, max_len=4, max_attempts=1000000):
    chars = string.ascii_lowercase + string.digits
    attempts = 0
    start_time = time.time()
    
    for length in range(1, max_len+1):
        print(f"\nTrying length {length}...")
        for candidate in itertools.product(chars, repeat=length):
            attempts += 1
            if attempts % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"Attempts: {attempts}, Time: {elapsed:.1f}s")
            if attempts >= max_attempts:
                print(f"\nReached maximum attempts ({max_attempts})")
                return None
                
            s = ''.join(candidate).encode()
            if enhanced_sha1_signature(s, show_progress=False) == target_hash:
                return s.decode()
    return None

if __name__ == '__main__':
    # Generate a random unknown 6-character string from [a-z0-9]
    chars = string.ascii_lowercase + string.digits
    original = ''.join(chars[b % len(chars)] for b in os.urandom(6))
    data = original.encode()
    h = enhanced_sha1_signature(data, show_progress=False)
    print(f"Original (unknown) string: {original}")
    print(f"Hash: {h}")

    pre = find_preimage(h, max_len=4)
    if pre:
        print(f"Unexpected preimage found: {pre}")
    else:
        print("No preimage found up to length 4 (as expected).")

