"""
Firewall Engine: Core logic for Collatz Firewall operations
Handles IP registration, verification, and access control.
"""

import time
from typing import Tuple, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from .collatz_converter import CollatzConverter, CollatzResult
from .sha1e3_integrator import SHA1E3Integrator, HashResult


class VerificationStatus(Enum):
    """Status codes for IP verification"""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    INVALID_IP = "invalid_ip"
    INTERNAL_ERROR = "internal_error"


@dataclass
class VerificationResult:
    """Result of IP verification against whitelist"""
    ip_address: str
    status: VerificationStatus
    hash_value: str
    sequence_length: int
    matched_whitelist_id: Optional[int] = None
    matched_ip: Optional[str] = None
    error_message: Optional[str] = None
    response_time_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def is_allowed(self) -> bool:
        return self.status == VerificationStatus.ALLOWED

    def __repr__(self):
        return (f"VerificationResult(ip={self.ip_address}, status={self.status.value}, "
                f"time={self.response_time_ms:.2f}ms)")


@dataclass
class RegistrationResult:
    """Result of IP registration"""
    ip_address: str
    success: bool
    collatz_hash: str
    sequence_length: int
    whitelist_id: Optional[int] = None
    error_message: Optional[str] = None

    def __repr__(self):
        status = "✓" if self.success else "✗"
        return f"{status} Registration: {self.ip_address} (hash_len={self.sequence_length})"


class FirewallEngine:
    """
    Core Collatz Firewall Engine.

    Uses SHA1-E3 with Collatz Conjecture for IP verification.

    Workflow:
    1. Registration: IP → Collatz Sequence → SHA1-E3 Hash → Store
    2. Verification: Incoming IP → Collatz Sequence → SHA1-E3 Hash → Compare
    3. Access Control: Grant/Deny based on hash match

    Performance: 50+ MB/s with Numba JIT implementation
    """

    def __init__(self):
        """
        Initialize the firewall engine.

        Raises:
            ImportError: If SHA1-E3 is not available
        """
        self.collatz_converter = CollatzConverter()
        self.hash_integrator = SHA1E3Integrator()

    def register_ip(
        self,
        ip_address: str,
        name: Optional[str] = None,
        description: Optional[str] = None
    ) -> RegistrationResult:
        """
        Register an IP address to the whitelist.

        Process:
        1. Validate IP
        2. Convert to Collatz sequence
        3. Hash the sequence
        4. Store in database (handled by caller)

        Args:
            ip_address: IPv4 address to register
            name: Optional human-readable name
            description: Optional description

        Returns:
            RegistrationResult with all details
        """
        try:
            # Step 1: Convert IP to Collatz sequence
            collatz_result = self.collatz_converter.convert_ip_to_collatz(ip_address)

            # Step 2: Hash the Collatz sequence
            hash_result = self.hash_integrator.hash_collatz_sequence(
                collatz_result.trajectory_bytes
            )

            return RegistrationResult(
                ip_address=ip_address,
                success=True,
                collatz_hash=hash_result.hash_value,
                sequence_length=collatz_result.sequence_length,
            )

        except ValueError as e:
            return RegistrationResult(
                ip_address=ip_address,
                success=False,
                collatz_hash="",
                sequence_length=0,
                error_message=str(e)
            )
        except Exception as e:
            return RegistrationResult(
                ip_address=ip_address,
                success=False,
                collatz_hash="",
                sequence_length=0,
                error_message=f"Internal error: {str(e)}"
            )

    def verify_ip(
        self,
        ip_address: str,
        expected_hash: str
    ) -> VerificationResult:
        """
        Verify if an IP is allowed by comparing hashes.

        Process:
        1. Validate incoming IP
        2. Convert to Collatz sequence
        3. Hash the sequence
        4. Compare with stored hash
        5. Return result with timing

        Args:
            ip_address: IPv4 address to verify
            expected_hash: Stored hash to compare against

        Returns:
            VerificationResult with status and details
        """
        start_time = time.time()

        try:
            # Step 1: Validate and convert IP to Collatz
            collatz_result = self.collatz_converter.convert_ip_to_collatz(ip_address)

            # Step 2: Hash the Collatz sequence
            hash_result = self.hash_integrator.hash_collatz_sequence(
                collatz_result.trajectory_bytes
            )

            # Step 3: Compare hashes
            hash_match = hash_result.hash_value.lower() == expected_hash.lower()

            status = VerificationStatus.ALLOWED if hash_match else VerificationStatus.BLOCKED

            response_time = (time.time() - start_time) * 1000  # Convert to ms

            return VerificationResult(
                ip_address=ip_address,
                status=status,
                hash_value=hash_result.hash_value,
                sequence_length=collatz_result.sequence_length,
                response_time_ms=response_time,
                details={
                    'hash_type': hash_result.hash_type,
                    'collatz_steps': collatz_result.steps_to_one,
                    'collatz_max': collatz_result.max_value,
                }
            )

        except ValueError as e:
            response_time = (time.time() - start_time) * 1000
            return VerificationResult(
                ip_address=ip_address,
                status=VerificationStatus.INVALID_IP,
                hash_value="",
                sequence_length=0,
                response_time_ms=response_time,
                error_message=str(e)
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return VerificationResult(
                ip_address=ip_address,
                status=VerificationStatus.INTERNAL_ERROR,
                hash_value="",
                sequence_length=0,
                response_time_ms=response_time,
                error_message=f"Internal error: {str(e)}"
            )

    def batch_register_ips(
        self,
        ip_list: list
    ) -> list:
        """
        Register multiple IPs at once.

        Args:
            ip_list: List of IP addresses or dicts with 'ip', 'name', 'description'

        Returns:
            List of RegistrationResult objects
        """
        results = []

        for item in ip_list:
            if isinstance(item, str):
                result = self.register_ip(item)
            elif isinstance(item, dict):
                ip = item.get('ip')
                if ip is not None:
                    result = self.register_ip(
                        ip,
                        name=item.get('name'),
                        description=item.get('description')
                    )
                else:
                    continue
            else:
                continue

            results.append(result)

        return results

    def get_engine_info(self) -> Dict[str, Any]:
        """Get information about firewall engine configuration."""
        return {
            'hash_config': self.hash_integrator.get_hash_info(),
            'collatz_max_length': self.collatz_converter.MAX_SEQUENCE_LENGTH,
        }
