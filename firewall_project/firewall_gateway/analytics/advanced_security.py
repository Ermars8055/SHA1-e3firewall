"""
Advanced Security Module: SHA1-E3 Enhanced Features
Implements MFA, Rate Limiting, Anomaly Detection, and Audit Logging using SHA1-E3
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import secrets
from dataclasses import asdict, dataclass


@dataclass
class AuditLogEntry:
    """Tamper-proof audit log entry with hash chaining"""
    timestamp: str
    action: str
    user_ip: str
    admin_id: str
    details: Dict[str, Any]
    previous_hash: str  # Hash of previous entry (creates chain)
    entry_hash: str  # Hash of this entry


class SHA1E3AdvancedSecurity:
    """
    Advanced security features using SHA1-E3 cryptographic hashing.
    Includes: MFA, Rate Limiting, Anomaly Detection, Audit Logging
    """

    def __init__(self, analytics_engine):
        """
        Initialize advanced security module.

        Args:
            analytics_engine: Reference to main AnalyticsEngine for hash generation
        """
        self.analytics_engine = analytics_engine
        self.storage_dir = analytics_engine.storage_dir

        # Rate limiting: IP -> {token: hash, timestamp, requests_count}
        self.rate_limit_tracker = defaultdict(lambda: {
            'tokens': {},
            'request_times': [],
            'blocked_until': None
        })

        # MFA: user_token -> {challenge_hash, attempts, created_at, verified}
        self.mfa_challenges = {}

        # Device behavioral profiles: IP -> {hash_patterns, anomaly_score, baseline}
        self.device_profiles = {}

        # Audit log with hash chaining
        self.audit_log = []
        self.last_audit_hash = None

        # Geo-blocking profiles: region -> acceptable_hash_patterns
        self.geo_profiles = self._init_geo_profiles()

        # Session security: session_id -> {device_hash, rotation_count, created_at}
        self.session_security = {}

        self._load_security_data()

    def create_sha1e3_mfa_challenge(self, admin_token: str, device_ip: str) -> Dict[str, Any]:
        """
        Create SHA1-E3 based MFA challenge (alternative to TOTP).
        Uses hash-based challenge/response instead of time-based OTP.

        Args:
            admin_token: Admin session token
            device_ip: IP address of admin device

        Returns:
            Challenge data with hash verification requirement
        """
        # Generate challenge hash from device characteristics
        challenge_seed = f"{device_ip}:{admin_token}:{datetime.now().isoformat()}"
        challenge_hash = hashlib.sha256(challenge_seed.encode()).hexdigest()

        # Create Collatz-based challenge using analytics engine
        collatz_challenge = self.analytics_engine._generate_collatz_hash(device_ip)

        # Store challenge (valid for 5 minutes)
        challenge_id = secrets.token_hex(16)
        self.mfa_challenges[challenge_id] = {
            'challenge_hash': challenge_hash,
            'collatz_challenge': collatz_challenge,
            'device_ip': device_ip,
            'admin_token': admin_token,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(minutes=5)).isoformat(),
            'attempts': 0,
            'verified': False
        }

        return {
            'challenge_id': challenge_id,
            'challenge_type': 'sha1e3_hash_response',
            'message': 'Respond with device hash verification',
            'hash_prefix': challenge_hash[:8],  # Don't expose full hash
            'sequence_hint': collatz_challenge[:20] + '...',  # Partial Collatz hint
            'expires_in_seconds': 300,
            'attempts_allowed': 3
        }

    def verify_sha1e3_mfa(self, challenge_id: str, provided_hash: str) -> Dict[str, Any]:
        """
        Verify SHA1-E3 MFA challenge response.

        Args:
            challenge_id: Challenge ID from create_mfa_challenge
            provided_hash: Hash response from device

        Returns:
            Verification result
        """
        if challenge_id not in self.mfa_challenges:
            return {'success': False, 'error': 'Invalid challenge ID'}

        challenge = self.mfa_challenges[challenge_id]

        # Check expiration
        expires_at = datetime.fromisoformat(challenge['expires_at'])
        if datetime.now() > expires_at:
            del self.mfa_challenges[challenge_id]
            return {'success': False, 'error': 'Challenge expired'}

        # Check attempt limit
        if challenge['attempts'] >= 3:
            del self.mfa_challenges[challenge_id]
            return {'success': False, 'error': 'Too many attempts', 'blocked': True}

        challenge['attempts'] += 1

        # Verify hash response
        if provided_hash == challenge['challenge_hash']:
            challenge['verified'] = True
            return {
                'success': True,
                'message': 'MFA verification successful',
                'verification_token': secrets.token_hex(32),
                'valid_for_hours': 8
            }
        else:
            return {
                'success': False,
                'error': 'Invalid hash response',
                'attempts_remaining': 3 - challenge['attempts']
            }

    def calculate_rate_limit_quota(self, device_ip: str, time_window_minutes: int = 5) -> Dict[str, Any]:
        """
        Calculate rate limit using SHA1-E3 based token system.
        Creates ephemeral rate limit tokens from device hash.

        Args:
            device_ip: IP address of device
            time_window_minutes: Rate limit window in minutes

        Returns:
            Rate limit quota and remaining requests
        """
        tracker = self.rate_limit_tracker[device_ip]
        now = datetime.now()

        # Clean old request times (outside window)
        cutoff_time = now - timedelta(minutes=time_window_minutes)
        tracker['request_times'] = [
            t for t in tracker['request_times']
            if datetime.fromisoformat(t) > cutoff_time
        ]

        # Generate new rate limit token (hash-based)
        token_seed = f"{device_ip}:{now.isoformat()[:16]}"  # New token every minute
        current_token = hashlib.sha256(token_seed.encode()).hexdigest()[:16]

        # Track tokens
        if current_token not in tracker['tokens']:
            tracker['tokens'][current_token] = {
                'created_at': now.isoformat(),
                'request_count': 0
            }

        tracker['tokens'][current_token]['request_count'] += 1
        tracker['request_times'].append(now.isoformat())

        # SHA1-E3 based quota (different per device based on Collatz pattern)
        device_hash = self.analytics_engine._generate_collatz_hash(device_ip)
        hash_score = int(device_hash[:8], 16) % 100  # 0-99

        # Quota increases with trusted device score
        if device_ip in self.analytics_engine.whitelist:
            base_quota = 100 + (hash_score * 0.5)  # Trusted: 100-150 req/min
            tier = 'trusted'
        else:
            base_quota = 20 + (hash_score * 0.1)  # Untrusted: 20-30 req/min
            tier = 'untrusted'

        requests_in_window = len(tracker['request_times'])
        remaining = max(0, int(base_quota) - requests_in_window)

        # Check if blocked
        if tracker['blocked_until']:
            unblock_at = datetime.fromisoformat(tracker['blocked_until'])
            if now > unblock_at:
                tracker['blocked_until'] = None
            else:
                return {
                    'success': False,
                    'blocked': True,
                    'unblock_at': tracker['blocked_until'],
                    'reason': 'Rate limit exceeded - IP temporarily blocked'
                }

        # Auto-block if exceeded
        if requests_in_window > int(base_quota):
            tracker['blocked_until'] = (now + timedelta(minutes=5)).isoformat()
            return {
                'success': False,
                'blocked': True,
                'unblock_at': tracker['blocked_until'],
                'reason': 'Rate limit exceeded'
            }

        return {
            'success': True,
            'allowed': True,
            'requests_in_window': requests_in_window,
            'remaining_quota': remaining,
            'base_quota': int(base_quota),
            'time_window_minutes': time_window_minutes,
            'device_tier': tier,
            'current_token': current_token
        }

    def detect_anomalies(self, device_ip: str, new_sequence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect device anomalies using SHA1-E3 pattern analysis.
        Compares current Collatz patterns against device baseline.

        Args:
            device_ip: IP address to analyze
            new_sequence_data: Current sequence data {sequence, hash, length, etc}

        Returns:
            Anomaly detection results with risk score
        """
        if device_ip not in self.device_profiles:
            # First time seeing this device - establish baseline
            self.device_profiles[device_ip] = {
                'baseline_hash': new_sequence_data.get('hash', ''),
                'hash_history': [new_sequence_data.get('hash', '')],
                'pattern_history': [],
                'anomaly_count': 0,
                'baseline_confidence': 0.3,  # Low confidence for new device
                'created_at': datetime.now().isoformat()
            }
            return {
                'is_anomaly': False,
                'reason': 'Baseline establishment for new device',
                'risk_score': 0.0,
                'recommendation': 'Monitor'
            }

        profile = self.device_profiles[device_ip]
        current_hash = new_sequence_data.get('hash', '')

        # Analyze hash similarity to baseline
        baseline_hash = profile['baseline_hash']
        hash_similarity = self._calculate_hash_similarity(baseline_hash, current_hash)

        # Check for hash mutation patterns
        recent_hashes = profile['hash_history'][-10:]
        hash_variance = self._calculate_hash_variance(recent_hashes)

        # Analyze Collatz sequence patterns
        current_pattern = {
            'length': new_sequence_data.get('sequence_length', 0),
            'max_value': new_sequence_data.get('max_value', 0),
            'min_value': new_sequence_data.get('min_value', 0)
        }

        pattern_history = profile['pattern_history'][-20:]
        pattern_anomaly_score = self._analyze_pattern_deviation(current_pattern, pattern_history)

        # Calculate overall risk
        risk_score = (
            (1.0 - hash_similarity) * 0.4 +  # Hash change weight
            min(hash_variance / 10, 1.0) * 0.3 +  # Variance weight
            pattern_anomaly_score * 0.3  # Pattern deviation weight
        )

        # Update profile
        profile['hash_history'].append(current_hash)
        profile['pattern_history'].append(current_pattern)
        if profile['baseline_confidence'] < 0.95:
            profile['baseline_confidence'] += 0.05

        # Determine if anomalous (threshold: 0.6)
        is_anomaly = risk_score > 0.6
        if is_anomaly:
            profile['anomaly_count'] += 1

        return {
            'is_anomaly': is_anomaly,
            'risk_score': round(risk_score, 3),
            'hash_similarity': round(hash_similarity, 3),
            'pattern_anomaly_score': round(pattern_anomaly_score, 3),
            'hash_variance': round(hash_variance, 3),
            'consecutive_anomalies': profile['anomaly_count'],
            'recommendation': 'BLOCK' if is_anomaly and profile['anomaly_count'] > 3 else 'MONITOR' if is_anomaly else 'ALLOW'
        }

    def create_audit_log_entry(self, action: str, user_ip: str, admin_id: str,
                               details: Dict[str, Any]) -> str:
        """
        Create tamper-proof audit log entry with hash chaining.
        Each entry includes hash of previous entry (creates immutable chain).

        Args:
            action: Action performed (e.g., 'device_approved', 'admin_login')
            user_ip: IP performing action
            admin_id: Admin ID
            details: Additional details about action

        Returns:
            Entry hash (can be verified against chain)
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'user_ip': user_ip,
            'admin_id': admin_id,
            'details': details,
            'previous_hash': self.last_audit_hash or 'genesis',
            'sequence_num': len(self.audit_log)
        }

        # Create entry hash (includes previous hash - chain integrity)
        entry_data = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_data.encode()).hexdigest()

        entry['entry_hash'] = entry_hash
        self.audit_log.append(entry)
        self.last_audit_hash = entry_hash

        # Log every 100 entries for verification
        if len(self.audit_log) % 100 == 0:
            self._save_security_data()

        return entry_hash

    def verify_audit_log_integrity(self) -> Dict[str, Any]:
        """
        Verify audit log hasn't been tampered with.
        Reconstructs hash chain and checks each entry.

        Returns:
            Integrity verification results
        """
        if not self.audit_log:
            return {'success': True, 'integrity_ok': True, 'entries_checked': 0}

        previous_hash = 'genesis'
        corrupted_entries = []

        for i, entry in enumerate(self.audit_log):
            # Verify previous hash matches
            if entry['previous_hash'] != previous_hash:
                corrupted_entries.append({
                    'index': i,
                    'reason': 'Previous hash mismatch',
                    'expected': previous_hash,
                    'found': entry['previous_hash']
                })

            # Verify entry hash
            entry_copy = entry.copy()
            stored_hash = entry_copy.pop('entry_hash')
            entry_data = json.dumps(entry_copy, sort_keys=True)
            calculated_hash = hashlib.sha256(entry_data.encode()).hexdigest()

            if calculated_hash != stored_hash:
                corrupted_entries.append({
                    'index': i,
                    'reason': 'Entry hash mismatch',
                    'expected': calculated_hash,
                    'found': stored_hash
                })

            previous_hash = stored_hash

        return {
            'success': len(corrupted_entries) == 0,
            'integrity_ok': len(corrupted_entries) == 0,
            'entries_checked': len(self.audit_log),
            'corrupted_entries': corrupted_entries,
            'last_hash': self.last_audit_hash
        }

    def get_audit_logs_for_ip(self, ip_address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get audit logs filtered by IP address."""
        matching_logs = [
            entry for entry in self.audit_log
            if entry['user_ip'] == ip_address
        ]
        return matching_logs[-limit:]

    def get_device_security_profile(self, device_ip: str) -> Dict[str, Any]:
        """Get comprehensive security profile for a device."""
        if device_ip not in self.device_profiles:
            return {'status': 'unknown', 'message': 'No profile data'}

        profile = self.device_profiles[device_ip]
        anomalies = len([a for a in profile['pattern_history'][-10:]])  # Recent anomalies

        return {
            'device_ip': device_ip,
            'baseline_hash': profile['baseline_hash'][:16] + '...',
            'baseline_confidence': round(profile['baseline_confidence'], 3),
            'anomaly_count': profile['anomaly_count'],
            'hash_history_length': len(profile['hash_history']),
            'profile_created_at': profile['created_at'],
            'threat_level': self._calculate_threat_level(device_ip),
            'recommendation': self._get_security_recommendation(device_ip)
        }

    def enable_geo_blocking(self, device_ip: str, allowed_regions: List[str]) -> Dict[str, Any]:
        """
        Enable SHA1-E3 based geographic blocking for a device.
        Creates region-specific hash patterns.

        Args:
            device_ip: Device IP to protect
            allowed_regions: List of region codes ('US', 'EU', 'ASIA', etc.)

        Returns:
            Geo-blocking configuration
        """
        # Generate region-specific hash templates
        region_templates = {}
        for region in allowed_regions:
            template_seed = f"{device_ip}:{region}"
            template = hashlib.sha256(template_seed.encode()).hexdigest()
            region_templates[region] = template[:16]  # Use first 16 chars

        self.device_profiles[device_ip] = self.device_profiles.get(device_ip, {})
        self.device_profiles[device_ip]['geo_blocking'] = {
            'enabled': True,
            'allowed_regions': allowed_regions,
            'region_templates': region_templates,
            'detection_enabled': True
        }

        return {
            'success': True,
            'device_ip': device_ip,
            'allowed_regions': allowed_regions,
            'geo_blocking_enabled': True,
            'message': 'Geographic blocking enabled'
        }

    # ========== HELPER METHODS ==========

    def _calculate_hash_similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity between two hashes (0.0-1.0)."""
        if not hash1 or not hash2:
            return 0.0
        common_chars = sum(c1 == c2 for c1, c2 in zip(hash1[:32], hash2[:32]))
        return common_chars / 32

    def _calculate_hash_variance(self, hashes: List[str]) -> float:
        """Calculate variance in hash patterns."""
        if len(hashes) < 2:
            return 0.0
        similarities = [
            self._calculate_hash_similarity(hashes[i], hashes[i+1])
            for i in range(len(hashes)-1)
        ]
        if not similarities:
            return 0.0
        avg = sum(similarities) / len(similarities)
        variance = sum((s - avg) ** 2 for s in similarities) / len(similarities)
        return variance ** 0.5

    def _analyze_pattern_deviation(self, current: Dict, history: List[Dict]) -> float:
        """Analyze deviation of current pattern from historical baseline."""
        if not history:
            return 0.0

        avg_length = sum(h['length'] for h in history) / len(history)
        avg_max = sum(h['max_value'] for h in history) / len(history)

        length_deviation = abs(current['length'] - avg_length) / (avg_length + 1)
        max_deviation = abs(current['max_value'] - avg_max) / (avg_max + 1)

        return min((length_deviation + max_deviation) / 2, 1.0)

    def _calculate_threat_level(self, device_ip: str) -> str:
        """Calculate threat level based on profile."""
        if device_ip not in self.device_profiles:
            return 'unknown'

        profile = self.device_profiles[device_ip]
        anomaly_count = profile['anomaly_count']

        if anomaly_count == 0:
            return 'low'
        elif anomaly_count < 5:
            return 'medium'
        else:
            return 'high'

    def _get_security_recommendation(self, device_ip: str) -> str:
        """Get security recommendation for device."""
        threat = self._calculate_threat_level(device_ip)

        if threat == 'high':
            return 'BLOCK_IMMEDIATE'
        elif threat == 'medium':
            return 'REQUIRE_MFA'
        else:
            return 'ALLOW'

    def _init_geo_profiles(self) -> Dict[str, List[str]]:
        """Initialize geographic region profiles."""
        return {
            'US': ['North America'],
            'EU': ['Europe'],
            'ASIA': ['Asia-Pacific'],
            'LATAM': ['Latin America'],
            'AFRICA': ['Africa'],
            'MIDDLE_EAST': ['Middle East']
        }

    def _load_security_data(self):
        """Load security data from disk."""
        import os
        audit_log_file = os.path.join(self.storage_dir, 'audit_log.json')
        try:
            if os.path.exists(audit_log_file):
                with open(audit_log_file, 'r') as f:
                    self.audit_log = json.load(f)
                    if self.audit_log:
                        self.last_audit_hash = self.audit_log[-1].get('entry_hash')
        except Exception as e:
            print(f"Error loading security data: {e}")

    def _save_security_data(self):
        """Save security data to disk."""
        import os
        audit_log_file = os.path.join(self.storage_dir, 'audit_log.json')
        try:
            with open(audit_log_file, 'w') as f:
                json.dump(self.audit_log, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving security data: {e}")
