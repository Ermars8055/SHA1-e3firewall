#!/usr/bin/env python3
"""
Create a 2 GiB deterministic file and hash it once using SHA1-E3 (streaming).
Logs timing and throughput, and writes a Markdown report.
"""

import os
import time
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature_file


def write_deterministic_file(path: Path, size_bytes: int, chunk_size: int = 4 * 1024 * 1024) -> None:
    """Write a deterministic pseudo-random file without holding it in memory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rng_seed = size_bytes ^ 0x6D2B79F5
    state = rng_seed & 0xFFFFFFFFFFFFFFFF
    with path.open('wb') as f:
        remaining = size_bytes
        buf = bytearray(chunk_size)
        while remaining > 0:
            n = min(remaining, chunk_size)
            # xorshift64* deterministic PRNG
            for i in range(n):
                state ^= (state >> 12) & 0xFFFFFFFFFFFFFFFF
                state ^= (state << 25) & 0xFFFFFFFFFFFFFFFF
                state ^= (state >> 27) & 0xFFFFFFFFFFFFFFFF
                val = (state * 2685821657736338717) & 0xFFFFFFFFFFFFFFFF
                buf[i] = (val >> (8 * (i % 8))) & 0xFF
            f.write(buf[:n])
            remaining -= n
        f.flush()
        os.fsync(f.fileno())


def human_size(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    i = 0
    x = float(n)
    while x >= 1024 and i < len(units) - 1:
        x /= 1024.0
        i += 1
    return f"{x:.2f} {units[i]}"


def main():
    out_dir = Path("securehash_project/benchmark_data/large_nist")
    size = 2 * 1024 * 1024 * 1024  # 2 GiB
    test_path = out_dir / f"nist_{size}.bin"
    report_path = out_dir / "hash_2g_report.md"

    print(f"Preparing file of size {human_size(size)} at {test_path}...")
    t0 = time.time()
    write_deterministic_file(test_path, size)
    t1 = time.time()
    gen_time = t1 - t0
    print(f"Generated in {gen_time:.2f}s")

    print("Hashing with SHA1-E3 (streaming)... this may take many hours.")
    h0 = time.time()
    digest = enhanced_sha1_signature_file(str(test_path), show_progress=True)
    h1 = time.time()
    hash_time = h1 - h0
    mbps = (size / (1024 * 1024)) / hash_time if hash_time > 0 else 0.0

    print(f"Hash: {digest}")
    print(f"Hash time: {hash_time:.2f}s, Throughput: {mbps:.4f} MB/s")

    with report_path.open('w') as f:
        f.write("# SHA1-E3 2 GiB Hash Run\n\n")
        f.write(f"- File size: {human_size(size)} ({size} bytes)\n")
        f.write(f"- Generation time: {gen_time:.2f} s\n")
        f.write(f"- Hash: `{digest}`\n")
        f.write(f"- Hash time: {hash_time:.2f} s\n")
        f.write(f"- Throughput: {mbps:.4f} MB/s\n")
    print(f"Saved report: {report_path}")


if __name__ == "__main__":
    main()


