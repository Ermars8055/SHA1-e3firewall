#!/usr/bin/env python3
"""
NIST-style large file throughput benchmark for SHA1-E3 up to 2 GiB.

- Generates test files of increasing sizes on the fly (streamed, not kept in RAM)
  using a deterministic PRNG so results are reproducible.
- Measures end-to-end hashing time using the streaming API enhanced_sha1_signature_file.
- Reports MB/s throughput and saves a Markdown summary to ./benchmark_results_nist.md.

Note: Generating and hashing up to 2 GiB can take a long time. Start with smaller
sizes (e.g., 64 MiB, 128 MiB) to validate performance before running the full set.
"""

import os
import time
from pathlib import Path
from typing import List, Tuple

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature_file


def write_deterministic_file(path: Path, size_bytes: int, chunk_size: int = 4 * 1024 * 1024) -> None:
    """Write a deterministic pseudo-random file without holding it in memory."""
    rng_seed = size_bytes ^ 0x6D2B79F5
    state = rng_seed & 0xFFFFFFFFFFFFFFFF
    with path.open('wb') as f:
        remaining = size_bytes
        buf = bytearray(chunk_size)
        while remaining > 0:
            n = min(remaining, chunk_size)
            # Fill buffer deterministically (xorshift64*)
            for i in range(n):
                state ^= (state >> 12) & 0xFFFFFFFFFFFFFFFF
                state ^= (state << 25) & 0xFFFFFFFFFFFFFFFF
                state ^= (state >> 27) & 0xFFFFFFFFFFFFFFFF
                val = (state * 2685821657736338717) & 0xFFFFFFFFFFFFFFFF
                buf[i] = (val >> (8 * (i % 8))) & 0xFF
            f.write(buf[:n])
            remaining -= n
        # Ensure data is flushed to disk before hashing
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


def run_benchmark(output_dir: Path, sizes: List[int]) -> Tuple[str, list]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    md_lines = ["# SHA1-E3 NIST-Style Large File Benchmark", ""]
    md_lines.append("| Size | Bytes | Time (s) | Throughput (MB/s) | Hash |")
    md_lines.append("|-----:|------:|--------:|------------------:|------|")

    for size in sizes:
        test_path = output_dir / f"nist_{size}.bin"
        print(f"\nPreparing file of size {human_size(size)} at {test_path}...")
        t0 = time.time()
        write_deterministic_file(test_path, size)
        t1 = time.time()
        gen_time = t1 - t0
        print(f"Generated in {gen_time:.2f}s")

        print("Hashing with SHA1-E3 (streaming)...")
        h0 = time.time()
        digest = enhanced_sha1_signature_file(str(test_path), show_progress=False)
        h1 = time.time()
        hash_time = h1 - h0
        mbps = (size / (1024 * 1024)) / hash_time if hash_time > 0 else 0.0
        print(f"Time: {hash_time:.2f}s, Throughput: {mbps:.2f} MB/s, Hash: {digest[:16]}...")

        rows.append((size, hash_time, mbps, digest))
        md_lines.append(f"| {human_size(size)} | {size} | {hash_time:.2f} | {mbps:.2f} | `{digest}` |")

        # Clean up large files to save disk, comment out to keep files
        try:
            test_path.unlink()
        except Exception:
            pass

    report_path = output_dir / "benchmark_results_nist.md"
    with report_path.open('w') as f:
        f.write("\n".join(md_lines) + "\n")
    print(f"\nSaved report: {report_path}")
    return str(report_path), rows


def main():
    out_dir = Path("securehash_project/benchmark_data/large_nist")
    # Define sizes up to 2 GiB. Start small to validate.
    sizes = [
        1 * 1024 * 1024,        # 1 MiB
        64 * 1024 * 1024,       # 64 MiB
        # 128 * 1024 * 1024,      # 128 MiB
        # 256 * 1024 * 1024,      # 256 MiB
        # Uncomment progressively once validated:
        # 512 * 1024 * 1024,    # 512 MiB
        # 1024 * 1024 * 1024,   # 1 GiB
        # 2 * 1024 * 1024 * 1024, # 2 GiB
    ]

    report, rows = run_benchmark(out_dir, sizes)
    print("\nSummary:")
    for size, t, mbps, dg in rows:
        print(f"  {human_size(size):>10}: {t:>8.2f}s  {mbps:>7.2f} MB/s  {dg[:16]}...")


if __name__ == "__main__":
    main()


