import unittest
import os
import sys
import hashlib
import numpy as np

# Add the parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.sha1_sponge_collatz_enhanced import enhanced_block_mixing

class TestSHA1Enhanced(unittest.TestCase):
    def test_block_size_handling(self):
        """Test that blocks are properly sized and padded."""
        # Test with small block
        small_block = b'test'
        result = enhanced_block_mixing(small_block, 0)
        self.assertEqual(len(result), max(16, len(small_block) + (len(small_block) % 2)))
        
        # Test with larger block
        large_block = b'x' * 32
        result = enhanced_block_mixing(large_block, 0)
        self.assertEqual(len(result), len(large_block))

    def test_bit_balance(self):
        """Test that output bytes have balanced bit distribution."""
        def count_bits(data):
            return sum(bin(b).count('1') for b in data)
        
        # Test with various inputs
        test_blocks = [
            b'test',
            b'x' * 16,
            b'hello world!!!!',
            os.urandom(32)  # Random data
        ]
        
        for block in test_blocks:
            result = enhanced_block_mixing(block, 0)
            
            # Check individual bytes are balanced (4 bits set)
            for byte in result:
                bit_count = bin(byte).count('1')
                # Allow for slight deviation from perfect balance
                self.assertLessEqual(abs(bit_count - 4), 1,
                    f"Byte {byte:02x} has {bit_count} bits set, expected close to 4")
            
            # Check overall balance is close to 50%
            total_bits = len(result) * 8
            set_bits = count_bits(result)
            bit_ratio = set_bits / total_bits
            self.assertGreater(bit_ratio, 0.45,
                f"Too few bits set: {bit_ratio:.2%}")
            self.assertLess(bit_ratio, 0.55,
                f"Too many bits set: {bit_ratio:.2%}")

    def test_avalanche_effect(self):
        """Test that small input changes cause significant output changes."""
        base_input = b'test string'
        modified_input = b'test strina'  # Change one character
        
        base_output = enhanced_block_mixing(base_input, 0)
        modified_output = enhanced_block_mixing(modified_input, 0)
        
        # Count bit differences
        differences = 0
        for b1, b2 in zip(base_output, modified_output):
            xor = b1 ^ b2
            differences += bin(xor).count('1')
            
        # Expect around 50% of bits to be different
        bit_ratio = differences / (len(base_output) * 8)
        self.assertGreater(bit_ratio, 0.45,
            f"Poor avalanche effect: only {bit_ratio:.2%} bits changed")
        self.assertLess(bit_ratio, 0.55,
            f"Excessive changes: {bit_ratio:.2%} bits changed")

    def test_position_dependency(self):
        """Test that same input at different positions produces different outputs."""
        test_input = b'test string'
        
        # Generate outputs at different positions
        outputs = [enhanced_block_mixing(test_input, pos) for pos in range(5)]
        
        # Compare each output with every other output
        for i in range(len(outputs)):
            for j in range(i + 1, len(outputs)):
                # Outputs should be different
                self.assertNotEqual(outputs[i], outputs[j],
                    f"Same output for positions {i} and {j}")
                
                # Count bit differences
                differences = 0
                for b1, b2 in zip(outputs[i], outputs[j]):
                    xor = b1 ^ b2
                    differences += bin(xor).count('1')
                
                # Expect significant differences between positions
                bit_ratio = differences / (len(outputs[i]) * 8)
                self.assertGreater(bit_ratio, 0.25,
                    f"Insufficient position dependency: only {bit_ratio:.2%} bits changed")

    def test_statistical_properties(self):
        """Test statistical properties of the mixing function."""
        # Generate large sample of mixed blocks
        samples = []
        for i in range(1000):
            input_data = os.urandom(32)
            output = enhanced_block_mixing(input_data, i % 100)
            samples.extend(output)
        
        samples = np.array(samples, dtype=np.uint8)
        
        # Test byte value distribution
        hist, _ = np.histogram(samples, bins=256, range=(0, 256))
        hist = hist / len(samples)
        
        # Chi-square test against uniform distribution
        expected = np.ones_like(hist) / 256
        chi2 = np.sum((hist - expected) ** 2 / expected)
        
        # For 255 degrees of freedom, critical value at p=0.01 is about 310
        self.assertLess(chi2, 310,
            f"Chi-square test failed with value {chi2}")
        
        # Optimized bit correlation test using sliding window
        bits = np.unpackbits(samples)
        window_size = 64  # Reduced window size for faster processing
        stride = 16  # Skip size for faster processing
        correlations = np.zeros(8)
        total_windows = 0
        
        # Calculate correlations using sliding window
        for start in range(0, len(bits) - window_size, stride):
            window = bits[start:start + window_size]
            # Count matches at each offset
            for offset in range(8):
                matches = np.sum(window[:-offset-1] == window[offset+1:])
                correlations[offset] += matches / (window_size - offset - 1)
            total_windows += 1
        
        if total_windows > 0:
            correlations /= total_windows
        
        # Additional statistical tests
        # 1. Optimized runs test with early exit
        max_run = 0
        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i-1]:
                current_run += 1
                if current_run >= 15:  # Early exit if run is too long
                    self.fail(f"Too long run found: {current_run} bits")
            else:
                max_run = max(max_run, current_run)
                current_run = 1
        max_run = max(max_run, current_run)
        
        self.assertLess(max_run, 15,
            f"Too long runs of same bit found: {max_run} bits")
            
        # 2. Check bit pair frequencies (transition probabilities)
        bit_pairs = np.zeros(4)  # 00, 01, 10, 11
        for i in range(len(bits)-1):
            idx = bits[i] * 2 + bits[i+1]
            bit_pairs[idx] += 1
        bit_pairs /= sum(bit_pairs)
        
        # All transitions should be roughly equally likely
        for prob in bit_pairs:
            self.assertGreater(prob, 0.2,
                f"Unbalanced bit transitions: {bit_pairs}")
            self.assertLess(prob, 0.3,
                f"Unbalanced bit transitions: {bit_pairs}")
        
        # 3. Check for significant correlations
        self.assertTrue(np.all(np.abs(correlations) < 0.1),
            f"Significant bit correlations found: {correlations}")

class ProgressTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_times = {}
        self.current_test = None
        self.test_start_time = None

    def startTest(self, test):
        self.current_test = test
        self.test_start_time = time.time()
        super().startTest(test)
        test_name = self.getDescription(test)
        print(f"\nRunning {test_name}...")

    def stopTest(self, test):
        super().stopTest(test)
        if self.current_test and self.test_start_time:
            elapsed = time.time() - self.test_start_time
            self.test_times[self.getDescription(test)] = elapsed
            print(f"Completed in {elapsed:.2f} seconds")

    def printTimes(self):
        print("\nTest execution times:")
        for test, elapsed in sorted(self.test_times.items(), key=lambda x: x[1], reverse=True):
            print(f"{test}: {elapsed:.2f}s")
        total = sum(self.test_times.values())
        print(f"\nTotal time: {total:.2f}s")

class ProgressTestRunner(unittest.TextTestRunner):
    def _makeResult(self):
        return ProgressTestResult(self.stream, self.descriptions, self.verbosity)

    def run(self, test):
        result = super().run(test)
        result.printTimes()
        return result

if __name__ == '__main__':
    import time
    print("Starting SHA-1 Enhanced Tests")
    print("This test suite includes:")
    print("1. Block size handling (fast)")
    print("2. Bit balance checks (~1-2s)")
    print("3. Avalanche effect tests (~2-3s)")
    print("4. Position dependency tests (~5s)")
    print("5. Statistical properties (longest test, ~30-40s)")
    print("\nTotal estimated time: ~40-50 seconds")
    
    runner = ProgressTestRunner(verbosity=2)
    unittest.main(testRunner=runner, argv=[sys.argv[0]])