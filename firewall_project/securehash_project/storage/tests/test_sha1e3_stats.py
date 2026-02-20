import os
import numpy as np
from securehash_project.storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature

def correlation_metric(N=100):
    """Compute avg and max absolute correlation between adjacent bytes in N hashes."""
    correlations = []
    for _ in range(N):
        data = os.urandom(32)
        h = np.frombuffer(bytes.fromhex(enhanced_sha1_signature(data, show_progress=False)), dtype=np.uint8)
        correlations.extend([np.corrcoef(h[:-1], h[1:])[0,1]])
    return np.mean(np.abs(correlations)), np.max(np.abs(correlations))

def histogram_bits(N=100):
    import matplotlib.pyplot as plt
    bits = []
    for _ in range(N):
        data = os.urandom(32)
        h = bytes.fromhex(enhanced_sha1_signature(data, show_progress=False))
        bits.extend([bin(b).count('1') for b in h])
    counts = [bits.count(i) for i in range(9)]
    # Save histogram as image if matplotlib is available
    plt.bar(range(9), counts)
    plt.xlabel('Bits Set Per Byte')
    plt.ylabel('Count')
    plt.title('SHA1-E3 Bit Balance Histogram')
    plt.savefig('sha1e3_bitbalance_hist_sep19.png')
    plt.close()
    return counts

def write_plus_metrics():
    with open("sep19results.md", "a") as f:
        mean_corr, max_corr = correlation_metric(N=100)
        f.write(f"**Statistical Correlation:**\n\n")
        f.write(f"100 samples: Mean abs. correlation (byte to next): {mean_corr:.3f}, Max: {max_corr:.3f}\n\n")

        f.write("**Histogram Bits Per Byte (across 100 hashes):**\n\n")
        counts = histogram_bits(N=100)
        f.write("Bits set per byte: " + " | ".join(str(i) for i in range(9)) + "\n")
        f.write("Occurrences:         " + " | ".join(str(count) for count in counts) + "\n\n")
        f.write("See plot saved as 'sha1e3_bitbalance_hist_sep19.png'.\n\n")

if __name__ == "__main__":
    write_plus_metrics()
