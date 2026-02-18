"""
Unit tests for Firewall Engine
Tests IP registration, verification, and access control logic.
"""

import unittest
from firewall_gateway.core.firewall_engine import (
    FirewallEngine, VerificationStatus, VerificationResult, RegistrationResult
)


class TestFirewallEngine(unittest.TestCase):
    """Test cases for FirewallEngine class"""

    def setUp(self):
        """Set up test fixtures"""
        self.engine = FirewallEngine()

    def test_register_ip_success(self):
        """Test successful IP registration"""
        ip = '192.168.1.100'
        result = self.engine.register_ip(ip)

        self.assertTrue(result.success)
        self.assertEqual(result.ip_address, ip)
        self.assertGreater(len(result.collatz_hash), 0)
        self.assertGreater(result.sequence_length, 0)

    def test_register_ip_invalid(self):
        """Test registration with invalid IP"""
        result = self.engine.register_ip('999.999.999.999')

        self.assertFalse(result.success)
        self.assertIsNotNone(result.error_message)

    def test_register_ip_with_metadata(self):
        """Test registration with name and description"""
        ip = '10.0.0.1'
        name = 'Test Server'
        desc = 'For testing'

        result = self.engine.register_ip(ip, name=name, description=desc)

        self.assertTrue(result.success)
        self.assertEqual(result.ip_address, ip)

    def test_verify_ip_match(self):
        """Test IP verification with matching hash"""
        ip = '192.168.1.100'

        # First register
        reg_result = self.engine.register_ip(ip)
        self.assertTrue(reg_result.success)

        # Then verify with correct hash
        verify_result = self.engine.verify_ip(ip, reg_result.collatz_hash)

        self.assertEqual(verify_result.status, VerificationStatus.ALLOWED)
        self.assertTrue(verify_result.is_allowed())
        self.assertGreater(verify_result.response_time_ms, 0)

    def test_verify_ip_hash_mismatch(self):
        """Test IP verification with incorrect hash"""
        ip = '192.168.1.100'

        # Try with wrong hash
        wrong_hash = 'abcdef1234567890'
        verify_result = self.engine.verify_ip(ip, wrong_hash)

        self.assertEqual(verify_result.status, VerificationStatus.BLOCKED)
        self.assertFalse(verify_result.is_allowed())

    def test_verify_ip_invalid_ip(self):
        """Test verification with invalid IP format"""
        result = self.engine.verify_ip('invalid.ip.address', 'somehash')

        self.assertEqual(result.status, VerificationStatus.INVALID_IP)
        self.assertFalse(result.is_allowed())

    def test_verification_result_details(self):
        """Test that verification result contains details"""
        ip = '10.0.0.1'
        reg_result = self.engine.register_ip(ip)

        verify_result = self.engine.verify_ip(ip, reg_result.collatz_hash)

        self.assertIsNotNone(verify_result.details)
        self.assertIn('hash_type', verify_result.details)
        self.assertIn('collatz_steps', verify_result.details)
        self.assertIn('collatz_max', verify_result.details)

    def test_batch_register_string_list(self):
        """Test batch registration with IP strings"""
        ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        results = self.engine.batch_register_ips(ips)

        self.assertEqual(len(results), 3)
        for result in results:
            self.assertTrue(result.success)

    def test_batch_register_dict_list(self):
        """Test batch registration with dict entries"""
        ips = [
            {'ip': '10.0.0.1', 'name': 'Server1'},
            {'ip': '10.0.0.2', 'name': 'Server2'},
        ]
        results = self.engine.batch_register_ips(ips)

        self.assertEqual(len(results), 2)
        for result in results:
            self.assertTrue(result.success)

    def test_batch_register_mixed(self):
        """Test batch registration with mixed types"""
        ips = [
            '192.168.1.1',
            {'ip': '192.168.1.2', 'name': 'Server'},
            '192.168.1.3'
        ]
        results = self.engine.batch_register_ips(ips)

        self.assertEqual(len(results), 3)

    def test_deterministic_hash(self):
        """Test that same IP always produces same hash"""
        ip = '172.16.0.1'

        hash1 = self.engine.register_ip(ip).collatz_hash
        hash2 = self.engine.register_ip(ip).collatz_hash

        self.assertEqual(hash1, hash2)

    def test_different_ips_different_hashes(self):
        """Test that different IPs produce different hashes"""
        ip1_hash = self.engine.register_ip('192.168.1.1').collatz_hash
        ip2_hash = self.engine.register_ip('192.168.1.2').collatz_hash

        self.assertNotEqual(ip1_hash, ip2_hash)

    def test_verification_timing(self):
        """Test that verification includes timing info"""
        ip = '10.0.0.1'
        reg_result = self.engine.register_ip(ip)
        verify_result = self.engine.verify_ip(ip, reg_result.collatz_hash)

        self.assertGreaterEqual(verify_result.response_time_ms, 0)
        self.assertLess(verify_result.response_time_ms, 1000)  # Should be < 1 second

    def test_engine_info(self):
        """Test getting engine configuration info"""
        info = self.engine.get_engine_info()

        self.assertIn('hash_config', info)
        self.assertIn('collatz_max_length', info)
        self.assertIsNotNone(info['hash_config'])

    def test_registration_result_repr(self):
        """Test RegistrationResult string representation"""
        result = self.engine.register_ip('192.168.1.100')
        repr_str = repr(result)

        self.assertIn('192.168.1.100', repr_str)

    def test_verification_result_repr(self):
        """Test VerificationResult string representation"""
        ip = '10.0.0.1'
        reg = self.engine.register_ip(ip)
        verify = self.engine.verify_ip(ip, reg.collatz_hash)
        repr_str = repr(verify)

        self.assertIn('10.0.0.1', repr_str)
        self.assertIn('allowed', repr_str)


if __name__ == '__main__':
    unittest.main()
