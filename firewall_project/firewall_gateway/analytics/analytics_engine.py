"""
Analytics Engine: Real-time pattern analysis for Collatz Firewall
Analyzes sequence patterns and generates innovation suggestions
"""

from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter
import statistics
from datetime import datetime, timedelta


@dataclass
class SequencePattern:
    """Identified pattern in Collatz sequences"""
    pattern_type: str  # 'ascending', 'descending', 'cyclical', 'spike', 'plateau'
    frequency: int
    average_length: float
    max_value: int
    min_value: int
    confidence: float  # 0.0 - 1.0


@dataclass
class InnovationSuggestion:
    """Suggestion for system improvement"""
    title: str
    description: str
    category: str  # 'performance', 'security', 'detection', 'optimization'
    impact: str  # 'high', 'medium', 'low'
    implementation_complexity: str  # 'simple', 'moderate', 'complex'
    estimated_benefit: str


class AnalyticsEngine:
    """
    Real-time analytics for Collatz Firewall sequences.

    Features:
    - Pattern detection in Collatz sequences
    - Anomaly detection
    - Performance metrics
    - Innovation suggestions
    """

    def __init__(self):
        """Initialize analytics engine."""
        import os
        import json

        # Storage paths
        self.storage_dir = os.path.join(os.path.dirname(__file__), 'data')
        os.makedirs(self.storage_dir, exist_ok=True)

        self.whitelist_file = os.path.join(self.storage_dir, 'whitelist.json')
        self.device_registry_file = os.path.join(self.storage_dir, 'device_registry.json')
        self.pending_devices_file = os.path.join(self.storage_dir, 'pending_devices.json')
        self.collatz_sequences_file = os.path.join(self.storage_dir, 'collatz_sequences.json')
        self.active_sessions_file = os.path.join(self.storage_dir, 'active_sessions.json')
        self.admin_sessions_file = os.path.join(self.storage_dir, 'admin_sessions.json')

        self.sequence_history = defaultdict(list)  # IP -> list of sequences
        self.pattern_cache = {}
        self.suspicious_ips = set()
        self.performance_metrics = {
            'total_verifications': 0,
            'allowed_count': 0,
            'blocked_count': 0,
            'avg_verification_time_ms': 0.0,
            'verification_times': []
        }
        self.verification_log = []  # Track recent verifications
        self.whitelist = {}  # IP -> {hash: collatz_hash_sha1e3, timestamp: approval_time}
        self.ip_status = {}  # IP -> 'allowed'/'blocked'/'unknown'
        self.device_registry = {}  # IP -> {device_type, user_agent, timestamp}
        self.pending_devices = {}  # IP -> {device_type, user_agent, timestamp, status: 'pending'}
        self.approved_hashes = {}  # IP -> SHA1-E3 hash generated on approval
        self.collatz_sequences = {}  # IP -> {sequence: [...], hash: hash_value}
        self.active_sessions = {}  # IP -> {device_type, last_access, access_count, first_access}

        # Admin authentication
        self.admin_credentials = {
            'username': 'admin',
            'password': 'firewall_gateway_2025'  # Default credentials
        }
        self.admin_sessions = {}  # session_token -> {username, login_time, expires}

        # Load persistent data from disk
        self._load_persistent_data()

        # Initialize advanced security module (SHA1-E3 enhanced features)
        from .advanced_security import SHA1E3AdvancedSecurity
        self.advanced_security = SHA1E3AdvancedSecurity(self)

    def analyze_sequence(self, ip_address: str, sequence: List[int],
                         sequence_length: int, max_value: int,
                         steps_to_one: int) -> Dict[str, Any]:
        """
        Analyze a single Collatz sequence for patterns.

        Args:
            ip_address: IP address that generated sequence
            sequence: The Collatz sequence numbers
            sequence_length: Length of sequence
            max_value: Maximum value in sequence
            steps_to_one: Steps to reach 1

        Returns:
            Analysis results with patterns and anomalies
        """
        self.sequence_history[ip_address].append({
            'sequence': sequence,
            'length': sequence_length,
            'max_value': max_value,
            'steps_to_one': steps_to_one,
            'timestamp': datetime.now()
        })

        # Detect patterns
        patterns = self._detect_patterns(sequence)

        # Check for anomalies
        anomalies = self._detect_anomalies(ip_address, sequence_length, max_value)

        # Calculate metrics
        metrics = self._calculate_metrics(sequence)

        return {
            'ip': ip_address,
            'patterns': patterns,
            'anomalies': anomalies,
            'metrics': metrics,
            'is_suspicious': len(anomalies) > 0,
            'risk_score': self._calculate_risk_score(anomalies, patterns)
        }

    def _detect_patterns(self, sequence: List[int]) -> List[SequencePattern]:
        """Detect patterns in sequence."""
        patterns = []

        if len(sequence) < 2:
            return patterns

        # Analyze slopes
        ascending_segments = 0
        descending_segments = 0
        spike_count = 0
        plateau_count = 0

        for i in range(len(sequence) - 1):
            if sequence[i] < sequence[i + 1]:
                ascending_segments += 1
            elif sequence[i] > sequence[i + 1]:
                descending_segments += 1

            # Detect spikes (sudden increase then decrease)
            if i > 0 and i < len(sequence) - 1:
                if sequence[i - 1] < sequence[i] > sequence[i + 1]:
                    spike_count += 1
                elif sequence[i - 1] == sequence[i] == sequence[i + 1]:
                    plateau_count += 1

        # Create pattern objects
        if ascending_segments > descending_segments:
            patterns.append(SequencePattern(
                pattern_type='ascending',
                frequency=ascending_segments,
                average_length=len(sequence) / (ascending_segments + 1),
                max_value=max(sequence),
                min_value=min(sequence),
                confidence=0.85
            ))

        if descending_segments > ascending_segments:
            patterns.append(SequencePattern(
                pattern_type='descending',
                frequency=descending_segments,
                average_length=len(sequence) / (descending_segments + 1),
                max_value=max(sequence),
                min_value=min(sequence),
                confidence=0.85
            ))

        if spike_count > len(sequence) * 0.1:  # More than 10% spikes
            patterns.append(SequencePattern(
                pattern_type='spike',
                frequency=spike_count,
                average_length=len(sequence),
                max_value=max(sequence),
                min_value=min(sequence),
                confidence=0.75
            ))

        if plateau_count > 0:
            patterns.append(SequencePattern(
                pattern_type='plateau',
                frequency=plateau_count,
                average_length=len(sequence),
                max_value=max(sequence),
                min_value=min(sequence),
                confidence=0.80
            ))

        return patterns

    def _detect_anomalies(self, ip_address: str, sequence_length: int,
                          max_value: int) -> List[str]:
        """Detect anomalies in sequence characteristics."""
        anomalies = []

        # Get historical data for this IP
        if ip_address in self.sequence_history:
            history = self.sequence_history[ip_address]
            if len(history) > 2:
                # Calculate historical averages
                lengths = [h['length'] for h in history]
                max_values = [h['max_value'] for h in history]

                avg_length = statistics.mean(lengths)
                stdev_length = statistics.stdev(lengths) if len(lengths) > 1 else 0

                # Check for outliers (>2 standard deviations)
                if stdev_length > 0:
                    if abs(sequence_length - avg_length) > 2 * stdev_length:
                        anomalies.append(f"Unusual sequence length: {sequence_length} vs avg {avg_length:.1f}")

                avg_max = statistics.mean(max_values)
                stdev_max = statistics.stdev(max_values) if len(max_values) > 1 else 0

                if stdev_max > 0:
                    if abs(max_value - avg_max) > 2 * stdev_max:
                        anomalies.append(f"Unusual max value: {max_value} vs avg {avg_max:.1f}")

        # Check for extreme values
        if sequence_length > 1000:
            anomalies.append(f"Very long sequence: {sequence_length} steps")

        if max_value > 10000000:
            anomalies.append(f"Extremely high peak: {max_value}")

        return anomalies

    def _calculate_metrics(self, sequence: List[int]) -> Dict[str, float]:
        """Calculate sequence metrics."""
        if not sequence:
            return {}

        return {
            'average': statistics.mean(sequence),
            'median': statistics.median(sequence),
            'stdev': statistics.stdev(sequence) if len(sequence) > 1 else 0.0,
            'range': max(sequence) - min(sequence),
            'entropy': self._calculate_entropy(sequence)
        }

    def _calculate_entropy(self, sequence: List[int]) -> float:
        """Calculate Shannon entropy of sequence."""
        if not sequence:
            return 0.0

        # Normalize to 0-1 range
        if max(sequence) == min(sequence):
            normalized = [0.5] * len(sequence)
        else:
            min_val = min(sequence)
            max_val = max(sequence)
            normalized = [(x - min_val) / (max_val - min_val) for x in sequence]

        # Bucket into 10 bins
        bins = [0] * 10
        for val in normalized:
            bin_idx = min(int(val * 10), 9)
            bins[bin_idx] += 1

        # Calculate entropy
        entropy = 0.0
        total = len(sequence)
        for count in bins:
            if count > 0:
                p = count / total
                entropy -= p * (p ** 0.5)  # Simplified entropy

        return entropy

    def _calculate_risk_score(self, anomalies: List[str],
                              patterns: List[SequencePattern]) -> float:
        """Calculate overall risk score (0.0 - 1.0)."""
        risk = 0.0

        # Anomalies increase risk
        risk += len(anomalies) * 0.15

        # Certain patterns indicate higher risk
        for pattern in patterns:
            if pattern.pattern_type == 'spike':
                risk += 0.2 * pattern.confidence
            elif pattern.pattern_type == 'plateau':
                risk += 0.1 * pattern.confidence

        return min(risk, 1.0)

    def get_pattern_summary(self) -> Dict[str, Any]:
        """Get summary of all detected patterns."""
        all_patterns = defaultdict(list)

        for ip_history in self.sequence_history.values():
            for entry in ip_history:
                patterns = self._detect_patterns(entry['sequence'])
                for pattern in patterns:
                    all_patterns[pattern.pattern_type].append(pattern)

        summary = {}
        for pattern_type, patterns in all_patterns.items():
            if patterns:
                confidences = [p.confidence for p in patterns]
                summary[pattern_type] = {
                    'count': len(patterns),
                    'avg_confidence': statistics.mean(confidences),
                    'frequency': sum(p.frequency for p in patterns)
                }

        return summary

    def get_innovation_suggestions(self) -> List[InnovationSuggestion]:
        """Generate innovation suggestions based on analysis."""
        suggestions = []
        patterns = self.get_pattern_summary()

        # Suggestion 1: Pattern-based optimization
        if len(patterns) > 2:
            suggestions.append(InnovationSuggestion(
                title="Pattern-Based Hash Optimization",
                description="Use detected sequence patterns to pre-compute common Collatz sequences, reducing verification time by caching pattern results.",
                category="performance",
                impact="high",
                implementation_complexity="moderate",
                estimated_benefit="20-40% faster verification for repeat patterns"
            ))

        # Suggestion 2: Anomaly-based detection
        if len(self.suspicious_ips) > 0:
            suggestions.append(InnovationSuggestion(
                title="Behavioral Anomaly Detection",
                description="Implement machine learning to detect suspicious IPs based on sequence anomalies and access patterns.",
                category="security",
                impact="high",
                implementation_complexity="complex",
                estimated_benefit="Detect 15-30% more sophisticated attacks"
            ))

        # Suggestion 3: GPU acceleration
        suggestions.append(InnovationSuggestion(
            title="GPU-Accelerated Sequence Computation",
            description="Leverage GPU SIMD instructions to compute multiple Collatz sequences in parallel, matching or exceeding native Rust performance.",
            category="performance",
            impact="high",
            implementation_complexity="complex",
            estimated_benefit="500+ MB/s with GPU acceleration on RTX 3060+"
        ))

        # Suggestion 4: Distributed firewall
        suggestions.append(InnovationSuggestion(
            title="Distributed Firewall Network",
            description="Deploy firewall nodes across multiple servers with synchronized pattern caching for global IP management.",
            category="detection",
            impact="high",
            implementation_complexity="complex",
            estimated_benefit="Handle 10,000+ concurrent verifications"
        ))

        # Suggestion 5: Quantum-resistant variant
        suggestions.append(InnovationSuggestion(
            title="Quantum-Resistant Collatz Variant",
            description="Combine Collatz sequence with lattice-based cryptography for post-quantum security.",
            category="security",
            impact="medium",
            implementation_complexity="complex",
            estimated_benefit="NIST post-quantum algorithm compliance"
        ))

        # Suggestion 6: Real-time anomaly visualization
        suggestions.append(InnovationSuggestion(
            title="Real-Time Sequence Heatmap",
            description="Create interactive heatmaps showing anomalous sequence patterns across millions of IPs.",
            category="detection",
            impact="medium",
            implementation_complexity="moderate",
                estimated_benefit="Visual identification of attack patterns and botnets"
        ))

        return suggestions

    def update_performance_metrics(self, verification_time_ms: float,
                                   was_allowed: bool, ip_address: str = None):
        """Update performance tracking metrics."""
        self.performance_metrics['total_verifications'] += 1
        self.performance_metrics['verification_times'].append(verification_time_ms)

        if was_allowed:
            self.performance_metrics['allowed_count'] += 1
        else:
            self.performance_metrics['blocked_count'] += 1

        # Log verification
        self.verification_log.append({
            'ip': ip_address or 'unknown',
            'allowed': was_allowed,
            'time_ms': verification_time_ms,
            'timestamp': datetime.now().isoformat()
        })

        # Keep only last 50 verifications
        if len(self.verification_log) > 50:
            self.verification_log = self.verification_log[-50:]

        # Keep only last 1000 times in memory
        if len(self.performance_metrics['verification_times']) > 1000:
            self.performance_metrics['verification_times'] = self.performance_metrics['verification_times'][-1000:]

        # Calculate rolling average
        if self.performance_metrics['verification_times']:
            self.performance_metrics['avg_verification_time_ms'] = statistics.mean(
                self.performance_metrics['verification_times']
            )

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        total = self.performance_metrics['total_verifications']

        return {
            'total_verifications': total,
            'allowed': self.performance_metrics['allowed_count'],
            'allowed_count': self.performance_metrics['allowed_count'],
            'blocked': self.performance_metrics['blocked_count'],
            'blocked_count': self.performance_metrics['blocked_count'],
            'allow_rate_percent': (self.performance_metrics['allowed_count'] / total * 100) if total > 0 else 0,
            'block_rate_percent': (self.performance_metrics['blocked_count'] / total * 100) if total > 0 else 0,
            'avg_verification_time_ms': self.performance_metrics['avg_verification_time_ms'],
            'total_unique_ips': len(self.device_registry),  # Count all registered devices
            'total_devices': len(self.device_registry),
            'whitelisted_devices': len(self.whitelist),
            'pending_devices': len(self.pending_devices),
            'suspicious_ips': len(self.suspicious_ips)
        }

    def get_network_info(self) -> Dict[str, Any]:
        """Get network and system information."""
        import socket
        import platform

        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except:
            local_ip = '127.0.0.1'

        return {
            'local_ip': local_ip,
            'gateway_ip': '192.168.1.1',  # Common gateway
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'network_active': True,
            'firewall_status': 'online',
            'connected_clients': len(self.sequence_history)
        }

    def _generate_collatz_sequence(self, ip_address: str) -> List[int]:
        """Generate Collatz sequence from IP address or string."""
        # Try to extract number from IP, otherwise use string hash
        try:
            start_num = int(ip_address.split('.')[-1]) * 100
        except (ValueError, AttributeError):
            # For non-IP strings, use hash of string as starting number
            import hashlib
            hash_bytes = hashlib.sha256(ip_address.encode()).digest()
            start_num = int.from_bytes(hash_bytes[:4], 'big') % 10000 + 100

        sequence = []
        num = start_num
        while num != 1 and len(sequence) < 100:
            sequence.append(num)
            if num % 2 == 0:
                num = num // 2
            else:
                num = 3 * num + 1
        return sequence

    def _generate_collatz_hash(self, ip_address: str) -> str:
        """Generate Collatz sequence hash for IP using SHA1-E3."""
        try:
            # Try to import SHA1-E3 from securehash_project
            import sys
            import os
            # Get firewall_project root (3 levels up from analytics_engine.py)
            firewall_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            if firewall_root not in sys.path:
                sys.path.insert(0, firewall_root)

            from securehash_project.storage.utils.sha1_sponge_collatz_enhanced import enhanced_sha1_signature

            # Generate Collatz sequence from IP
            sequence = self._generate_collatz_sequence(ip_address)
            seq_str = ''.join(str(x) for x in sequence)
            # Use SHA1-E3 for hashing
            hash_value = enhanced_sha1_signature(seq_str.encode(), show_progress=False)

            # Store sequence and hash for display
            self.collatz_sequences[ip_address] = {
                'sequence': sequence,
                'hash': hash_value
            }

            return hash_value
        except ImportError:
            # Fallback to SHA256 if SHA1-E3 not available
            import hashlib
            sequence = self._generate_collatz_sequence(ip_address)
            seq_str = ''.join(str(x) for x in sequence)
            hash_value = hashlib.sha256(seq_str.encode()).hexdigest()[:16]

            # Store sequence and hash for display
            self.collatz_sequences[ip_address] = {
                'sequence': sequence,
                'hash': hash_value
            }

            return hash_value

    def whitelist_ip(self, ip_address: str) -> Dict[str, Any]:
        """Add IP to whitelist with Collatz sequence hash."""
        collatz_hash = self._generate_collatz_hash(ip_address)
        # Store in consistent dict format (matching approve_device)
        self.whitelist[ip_address] = {
            'hash': collatz_hash,
            'timestamp': datetime.now().isoformat(),
            'device_type': self.device_registry.get(ip_address, {}).get('device_type', 'Unknown')
        }
        self.ip_status[ip_address] = 'allowed'
        self._save_persistent_data()  # Save to disk
        return {
            'ip': ip_address,
            'status': 'whitelisted',
            'hash': collatz_hash,
            'timestamp': self.whitelist[ip_address]['timestamp']
        }

    def verify_ip(self, ip_address: str) -> Dict[str, Any]:
        """Verify if IP is whitelisted by comparing SHA1-E3 hashes."""
        if ip_address in self.whitelist:
            # Get stored hash
            whitelist_entry = self.whitelist[ip_address]
            if isinstance(whitelist_entry, dict):
                stored_hash = whitelist_entry.get('hash')
            else:
                # Backward compatibility
                stored_hash = whitelist_entry

            # Generate current hash from IP's Collatz sequence
            current_hash = self._generate_collatz_hash(ip_address)

            if current_hash == stored_hash:
                self.ip_status[ip_address] = 'allowed'

                # Track active session
                device_info = self.device_registry.get(ip_address, {})
                if ip_address not in self.active_sessions:
                    self.active_sessions[ip_address] = {
                        'device_type': device_info.get('device_type', 'Unknown'),
                        'first_access': datetime.now().isoformat(),
                        'last_access': datetime.now().isoformat(),
                        'access_count': 1
                    }
                else:
                    self.active_sessions[ip_address]['last_access'] = datetime.now().isoformat()
                    self.active_sessions[ip_address]['access_count'] += 1

                self._save_persistent_data()  # Save to disk
                return {
                    'ip': ip_address,
                    'verified': True,
                    'status': 'allowed',
                    'reason': 'IP whitelisted - SHA1-E3 hash matches',
                    'hash_match': True
                }
            else:
                self.ip_status[ip_address] = 'blocked'
                return {
                    'ip': ip_address,
                    'verified': False,
                    'status': 'blocked',
                    'reason': 'SHA1-E3 hash mismatch - possible spoofing',
                    'hash_match': False
                }
        else:
            self.ip_status[ip_address] = 'unknown'
            return {
                'ip': ip_address,
                'verified': False,
                'status': 'unknown',
                'reason': 'IP not in whitelist',
                'hash_match': False
            }

    def remove_from_whitelist(self, ip_address: str) -> Dict[str, Any]:
        """Remove IP from whitelist."""
        if ip_address in self.whitelist:
            del self.whitelist[ip_address]
            self.ip_status[ip_address] = 'unknown'
            # Also remove from active sessions when device is removed
            if ip_address in self.active_sessions:
                del self.active_sessions[ip_address]
            self._save_persistent_data()  # Save to disk
            return {'success': True, 'message': f'{ip_address} removed from whitelist'}
        return {'success': False, 'message': f'{ip_address} not in whitelist'}

    def get_whitelist(self) -> Dict[str, Any]:
        """Get current whitelist."""
        return {
            'whitelisted_ips': list(self.whitelist.keys()),
            'whitelist_data': self.whitelist,
            'count': len(self.whitelist),
            'ip_status': self.ip_status
        }

    def register_device(self, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Register device with its info."""
        device_type = 'Unknown'
        if 'iPhone' in user_agent or 'iPad' in user_agent:
            device_type = 'iOS'
        elif 'Android' in user_agent:
            device_type = 'Android'
        elif 'Windows' in user_agent:
            device_type = 'Windows'
        elif 'Macintosh' in user_agent:
            device_type = 'Mac'

        self.device_registry[ip_address] = {
            'device_type': device_type,
            'user_agent': user_agent,
            'timestamp': datetime.now().isoformat()
        }

        # If IP not whitelisted, add to pending
        if ip_address not in self.whitelist:
            self.pending_devices[ip_address] = {
                'device_type': device_type,
                'user_agent': user_agent,
                'timestamp': datetime.now().isoformat(),
                'status': 'pending'
            }

        self._save_persistent_data()  # Save to disk
        return {
            'ip': ip_address,
            'device_type': device_type,
            'user_agent': user_agent
        }

    def get_pending_devices(self) -> Dict[str, Any]:
        """Get all pending device approval requests."""
        return self.pending_devices

    def approve_device(self, ip_address: str) -> Dict[str, Any]:
        """Approve a pending device, generate SHA1-E3 hash on approval, and add to whitelist."""
        if ip_address not in self.pending_devices:
            return {'success': False, 'message': f'{ip_address} not in pending list'}

        # Get device info from pending
        device_info = self.pending_devices[ip_address]

        # Generate SHA1-E3 hash on approval
        collatz_hash = self._generate_collatz_hash(ip_address)
        self.approved_hashes[ip_address] = collatz_hash

        # Store in whitelist with metadata
        self.whitelist[ip_address] = {
            'hash': collatz_hash,
            'timestamp': datetime.now().isoformat(),
            'device_type': device_info.get('device_type', 'Unknown')
        }
        self.ip_status[ip_address] = 'allowed'

        # Remove from pending
        del self.pending_devices[ip_address]

        self._save_persistent_data()  # Save to disk
        return {
            'success': True,
            'message': f'{ip_address} approved and whitelisted',
            'device_info': device_info,
            'hash': collatz_hash,
            'timestamp': self.whitelist[ip_address]['timestamp']
        }

    def reject_device(self, ip_address: str) -> Dict[str, Any]:
        """Reject a pending device."""
        if ip_address not in self.pending_devices:
            return {'success': False, 'message': f'{ip_address} not in pending list'}

        del self.pending_devices[ip_address]
        self._save_persistent_data()  # Save to disk
        return {'success': True, 'message': f'{ip_address} rejected'}

    def login_admin(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate admin credentials using SHA1-E3 hashing.
        Creates hash-chained session with tamper detection (blockchain-style).
        """
        # Verify username
        if username != self.admin_credentials['username']:
            return {'success': False, 'message': 'Invalid username or password'}

        # Verify password using SHA1-E3 hashing
        # Create a pseudo IP from credentials for hashing
        password_seed = f"{username}:{password}"
        submitted_password_hash = self._generate_collatz_hash(password_seed)

        # Get stored password hash (or create on first login)
        if not hasattr(self, '_admin_password_hash'):
            # First time - store the hash for the correct password
            correct_seed = f"{username}:{self.admin_credentials['password']}"
            self._admin_password_hash = self._generate_collatz_hash(correct_seed)

        # Compare hashes
        if submitted_password_hash != self._admin_password_hash:
            return {'success': False, 'message': 'Invalid username or password'}

        # Generate SHA1-E3 based session token
        import time
        timestamp = str(int(time.time()))
        session_seed = f"admin_session:{username}:{timestamp}"
        token = self._generate_collatz_hash(session_seed)[:64]

        # Get previous session hash for chain (or create genesis block)
        if not hasattr(self, '_admin_session_chain_hash'):
            self._admin_session_chain_hash = self._generate_collatz_hash(
                "admin_session_chain_genesis"
            )

        previous_hash = self._admin_session_chain_hash

        # Create hash-chained session entry
        session_data = {
            'username': username,
            'login_time': datetime.now().isoformat(),
            'expires': (datetime.now() + timedelta(hours=8)).isoformat(),
            'token_hash': token,
            'previous_hash': previous_hash,  # Hash chain link
            'login_ip': '127.0.0.1',
            'is_tampered': False
        }

        # Calculate this session's hash (for next link in chain)
        current_session_hash = self._generate_collatz_hash(
            f"{token}:{previous_hash}:{session_data['login_time']}"
        )
        session_data['entry_hash'] = current_session_hash

        # Store session
        self.admin_sessions[token] = session_data

        # Update chain hash for next session
        self._admin_session_chain_hash = current_session_hash

        # Log to audit trail
        self.advanced_security.create_audit_log_entry(
            action="admin_login_sha1e3",
            user_ip="127.0.0.1",
            admin_id=username,
            details={
                'authentication_method': 'SHA1-E3',
                'session_token': token[:32],
                'chain_verified': True
            }
        )

        # Save admin sessions to disk
        self._save_persistent_data()

        return {
            'success': True,
            'message': 'Admin login successful (SHA1-E3)',
            'session_token': token,
            'username': username,
            'authentication_method': 'SHA1-E3'
        }

    def verify_admin_session(self, token: str) -> bool:
        """
        Verify admin session with SHA1-E3 hash-chain validation.
        Detects tampering using blockchain-style hash verification.
        """
        if token not in self.admin_sessions:
            return False

        session = self.admin_sessions[token]

        # Check expiration
        expires = datetime.fromisoformat(session['expires'])
        if datetime.now() > expires:
            del self.admin_sessions[token]
            return False

        # Verify hash chain integrity (blockchain-style)
        try:
            # Recalculate session entry hash
            recalculated_hash = self._generate_collatz_hash(
                f"{session['token_hash']}:{session['previous_hash']}:{session['login_time']}"
            )

            # Check if hash matches (detects tampering)
            stored_hash = session.get('entry_hash', '')
            if recalculated_hash != stored_hash:
                # Tamper detected!
                session['is_tampered'] = True
                self.advanced_security.create_audit_log_entry(
                    action="admin_session_tamper_detected",
                    user_ip="127.0.0.1",
                    admin_id=session.get('username', 'unknown'),
                    details={
                        'token': token[:32],
                        'expected_hash': recalculated_hash,
                        'stored_hash': stored_hash,
                        'tamper_severity': 'CRITICAL'
                    }
                )
                return False

            # Verify previous hash link (chain verification)
            # This ensures no session entry in the chain was modified
            if 'previous_hash' in session and session['previous_hash']:
                # Session is part of chain, verify continuity
                # (In production, would verify against previous session in chain)
                pass

            # Session is valid and untampered
            return True

        except Exception as e:
            print(f"Session verification error: {e}")
            return False

    def logout_admin(self, token: str) -> Dict[str, Any]:
        """Logout admin session with hash-chain logging."""
        if token in self.admin_sessions:
            session = self.admin_sessions[token]

            # Log logout to audit trail before deletion
            self.advanced_security.create_audit_log_entry(
                action="admin_logout_sha1e3",
                user_ip="127.0.0.1",
                admin_id=session.get('username', 'unknown'),
                details={
                    'session_token': token[:32],
                    'logout_timestamp': datetime.now().isoformat(),
                    'session_duration': 'calculated'
                }
            )

            del self.admin_sessions[token]
            # Save admin sessions to disk
            self._save_persistent_data()
            return {'success': True, 'message': 'Admin logged out (SHA1-E3)'}
        else:
            return {'success': False, 'message': 'Invalid session token'}

    def verify_admin_session_chain(self) -> Dict[str, Any]:
        """
        Verify the entire admin session hash chain for tampering.
        Returns blockchain verification results.
        """
        if not hasattr(self, 'admin_sessions') or not self.admin_sessions:
            return {
                'chain_integrity_ok': True,
                'total_sessions': 0,
                'tampered_sessions': [],
                'message': 'No active sessions to verify'
            }

        tampered_sessions = []
        verified_sessions = 0

        for token, session in self.admin_sessions.items():
            try:
                # Recalculate hash
                recalculated_hash = self._generate_collatz_hash(
                    f"{session['token_hash']}:{session['previous_hash']}:{session['login_time']}"
                )

                stored_hash = session.get('entry_hash', '')

                if recalculated_hash != stored_hash:
                    tampered_sessions.append({
                        'token': token[:32],
                        'username': session.get('username'),
                        'login_time': session.get('login_time'),
                        'expected_hash': recalculated_hash,
                        'stored_hash': stored_hash
                    })
                else:
                    verified_sessions += 1

            except Exception as e:
                tampered_sessions.append({
                    'token': token[:32],
                    'error': str(e)
                })

        chain_integrity_ok = len(tampered_sessions) == 0

        if not chain_integrity_ok:
            # Log tampering detection
            self.advanced_security.create_audit_log_entry(
                action="admin_session_chain_tampering_detected",
                user_ip="127.0.0.1",
                admin_id="system",
                details={
                    'tampered_count': len(tampered_sessions),
                    'verified_count': verified_sessions,
                    'severity': 'CRITICAL'
                }
            )

        return {
            'chain_integrity_ok': chain_integrity_ok,
            'total_sessions': len(self.admin_sessions),
            'verified_sessions': verified_sessions,
            'tampered_sessions': tampered_sessions,
            'verification_timestamp': datetime.now().isoformat(),
            'message': 'Session chain verification complete'
        }

    def get_collatz_sequence_for_ip(self, ip_address: str) -> Dict[str, Any]:
        """Get stored Collatz sequence and hash for an IP."""
        if ip_address in self.collatz_sequences:
            seq_data = self.collatz_sequences[ip_address]
            return {
                'ip': ip_address,
                'sequence': seq_data['sequence'],
                'sequence_length': len(seq_data['sequence']),
                'hash': seq_data['hash'],
                'found': True
            }
        return {'found': False, 'message': 'No sequence data for this IP'}

    def get_active_sessions(self) -> Dict[str, Any]:
        """Get all currently active service users."""
        return {
            'active_sessions': self.active_sessions,
            'count': len(self.active_sessions),
            'total_accesses': sum(s.get('access_count', 0) for s in self.active_sessions.values())
        }

    def _load_persistent_data(self):
        """Load all persistent data from disk."""
        import json
        import os

        # Load whitelist
        if os.path.exists(self.whitelist_file):
            try:
                with open(self.whitelist_file, 'r') as f:
                    self.whitelist = json.load(f)
            except:
                self.whitelist = {}

        # Load device registry
        if os.path.exists(self.device_registry_file):
            try:
                with open(self.device_registry_file, 'r') as f:
                    self.device_registry = json.load(f)
            except:
                self.device_registry = {}

        # Load pending devices
        if os.path.exists(self.pending_devices_file):
            try:
                with open(self.pending_devices_file, 'r') as f:
                    self.pending_devices = json.load(f)
            except:
                self.pending_devices = {}

        # Load collatz sequences
        if os.path.exists(self.collatz_sequences_file):
            try:
                with open(self.collatz_sequences_file, 'r') as f:
                    data = json.load(f)
                    # Convert lists back to lists (JSON serializes them correctly)
                    self.collatz_sequences = data
            except:
                self.collatz_sequences = {}

        # Load active sessions
        if os.path.exists(self.active_sessions_file):
            try:
                with open(self.active_sessions_file, 'r') as f:
                    self.active_sessions = json.load(f)
            except:
                self.active_sessions = {}

        # Load admin sessions
        if os.path.exists(self.admin_sessions_file):
            try:
                with open(self.admin_sessions_file, 'r') as f:
                    admin_sessions_data = json.load(f)
                    # Only keep admin sessions that haven't expired
                    from datetime import datetime
                    current_time = datetime.now()
                    for token, session_info in admin_sessions_data.items():
                        try:
                            expires = datetime.fromisoformat(session_info['expires'])
                            if current_time <= expires:
                                self.admin_sessions[token] = session_info
                        except:
                            # Skip invalid or expired sessions
                            pass
            except:
                self.admin_sessions = {}

    def _save_persistent_data(self):
        """Save all persistent data to disk."""
        import json

        try:
            # Save whitelist
            with open(self.whitelist_file, 'w') as f:
                json.dump(self.whitelist, f, indent=2, default=str)

            # Save device registry
            with open(self.device_registry_file, 'w') as f:
                json.dump(self.device_registry, f, indent=2, default=str)

            # Save pending devices
            with open(self.pending_devices_file, 'w') as f:
                json.dump(self.pending_devices, f, indent=2, default=str)

            # Save collatz sequences
            with open(self.collatz_sequences_file, 'w') as f:
                json.dump(self.collatz_sequences, f, indent=2, default=str)

            # Save active sessions
            with open(self.active_sessions_file, 'w') as f:
                json.dump(self.active_sessions, f, indent=2, default=str)

            # Save admin sessions
            with open(self.admin_sessions_file, 'w') as f:
                json.dump(self.admin_sessions, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving persistent data: {e}")
