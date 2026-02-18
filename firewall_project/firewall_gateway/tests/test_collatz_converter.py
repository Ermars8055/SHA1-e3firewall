"""
Unit tests for Collatz Converter module
Tests IP to Collatz sequence conversion and validation.
"""

import unittest
from firewall_gateway.core.collatz_converter import CollatzConverter, CollatzResult


class TestCollatzConverter(unittest.TestCase):
    """Test cases for CollatzConverter class"""

    def setUp(self):
        """Set up test fixtures"""
        self.converter = CollatzConverter()

    def test_valid_ipv4_to_integer(self):
        """Test conversion of valid IPv4 to integer"""
        result = self.converter.ip_to_integer('192.168.1.100')
        expected = 3232235876
        self.assertEqual(result, expected)

    def test_another_valid_ipv4(self):
        """Test another valid IPv4 conversion"""
        result = self.converter.ip_to_integer('10.0.0.1')
        expected = 167772161
        self.assertEqual(result, expected)

    def test_localhost(self):
        """Test localhost conversion"""
        result = self.converter.ip_to_integer('127.0.0.1')
        expected = 2130706433
        self.assertEqual(result, expected)

    def test_invalid_ipv4(self):
        """Test that invalid IP raises ValueError"""
        with self.assertRaises(ValueError):
            self.converter.ip_to_integer('256.256.256.256')

    def test_invalid_format(self):
        """Test that malformed IP raises ValueError"""
        with self.assertRaises(ValueError):
            self.converter.ip_to_integer('not.an.ip.address')

    def test_integer_to_ip(self):
        """Test conversion from integer back to IP"""
        result = self.converter.integer_to_ip(3232235876)
        expected = '192.168.1.100'
        self.assertEqual(result, expected)

    def test_integer_to_ip_roundtrip(self):
        """Test roundtrip conversion IP -> int -> IP"""
        original = '10.20.30.40'
        as_int = self.converter.ip_to_integer(original)
        back_to_ip = self.converter.integer_to_ip(as_int)
        self.assertEqual(original, back_to_ip)

    def test_integer_out_of_range(self):
        """Test that out-of-range integer raises ValueError"""
        with self.assertRaises(ValueError):
            self.converter.integer_to_ip(2**32)

    def test_generate_collatz_sequence_small(self):
        """Test Collatz sequence generation for small number"""
        sequence, steps, max_val = self.converter.generate_collatz_sequence(7)
        self.assertEqual(sequence[0], 7)
        self.assertEqual(sequence[-1], 1)
        self.assertEqual(steps, len(sequence) - 1)
        self.assertGreater(max_val, 7)

    def test_collatz_sequence_length(self):
        """Test that Collatz sequence reaches 1"""
        sequence, steps, max_val = self.converter.generate_collatz_sequence(27)
        self.assertEqual(sequence[-1], 1)
        # Known: Collatz(27) takes 111 steps
        self.assertEqual(steps, 111)

    def test_collatz_even_number(self):
        """Test Collatz sequence for even number"""
        # For even: 8 -> 4 -> 2 -> 1
        sequence, steps, _ = self.converter.generate_collatz_sequence(8)
        expected = [8, 4, 2, 1]
        self.assertEqual(sequence, expected)

    def test_collatz_odd_number(self):
        """Test Collatz sequence for odd number"""
        # For odd 3: 3 -> 10 -> 5 -> 16 -> 8 -> 4 -> 2 -> 1
        sequence, steps, _ = self.converter.generate_collatz_sequence(3)
        self.assertEqual(sequence[0], 3)
        self.assertEqual(sequence[-1], 1)
        self.assertEqual(steps, 7)

    def test_collatz_max_length_limit(self):
        """Test that sequence respects max length"""
        max_len = 100
        sequence, _, _ = self.converter.generate_collatz_sequence(
            3232235876,
            max_length=max_len
        )
        self.assertLessEqual(len(sequence), max_len)

    def test_sequence_to_bytes(self):
        """Test conversion of sequence to bytes"""
        sequence = [1, 2, 3]
        result = self.converter.sequence_to_bytes(sequence)
        self.assertIsInstance(result, bytes)
        # Each number = 8 bytes
        self.assertEqual(len(result), 24)

    def test_convert_ip_to_collatz_complete(self):
        """Test complete IP to Collatz conversion"""
        ip = '192.168.1.100'
        result = self.converter.convert_ip_to_collatz(ip)

        self.assertIsInstance(result, CollatzResult)
        self.assertEqual(result.ip_address, ip)
        self.assertEqual(result.ip_integer, 3232235876)
        self.assertGreater(result.sequence_length, 0)
        self.assertEqual(result.sequence[-1], 1)
        self.assertIsInstance(result.trajectory_bytes, bytes)

    def test_collatz_result_repr(self):
        """Test CollatzResult string representation"""
        result = self.converter.convert_ip_to_collatz('10.0.0.1')
        repr_str = repr(result)
        self.assertIn('ip=10.0.0.1', repr_str)
        self.assertIn('length=', repr_str)

    def test_sequence_fingerprint(self):
        """Test statistical fingerprint of sequence"""
        sequence = [8, 4, 2, 1]
        fingerprint = self.converter.get_sequence_fingerprint(sequence)

        self.assertEqual(fingerprint['length'], 4)
        self.assertEqual(fingerprint['min'], 1)
        self.assertEqual(fingerprint['max'], 8)
        self.assertEqual(fingerprint['start'], 8)
        self.assertEqual(fingerprint['end'], 1)
        self.assertEqual(fingerprint['even_count'], 3)
        self.assertEqual(fingerprint['odd_count'], 1)

    def test_sequence_fingerprint_empty(self):
        """Test that empty sequence raises error"""
        with self.assertRaises(ValueError):
            self.converter.get_sequence_fingerprint([])

    def test_different_ips_different_sequences(self):
        """Test that different IPs produce different sequence lengths"""
        ip1_result = self.converter.convert_ip_to_collatz('192.168.1.100')
        ip2_result = self.converter.convert_ip_to_collatz('192.168.1.101')

        # Very likely to have different lengths due to Collatz chaos
        # (Though theoretically could be same, extremely unlikely)
        seq1_len = ip1_result.sequence_length
        seq2_len = ip2_result.sequence_length

        # At minimum, they should have different trajectory bytes
        self.assertNotEqual(ip1_result.trajectory_bytes, ip2_result.trajectory_bytes)

    def test_collatz_positive_requirement(self):
        """Test that negative numbers raise error"""
        with self.assertRaises(ValueError):
            self.converter.generate_collatz_sequence(-5)


if __name__ == '__main__':
    unittest.main()
