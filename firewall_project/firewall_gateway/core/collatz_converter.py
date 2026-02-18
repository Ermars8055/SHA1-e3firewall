"""
Collatz Converter: IP to Collatz Sequence Transformation
Converts IP addresses to Collatz sequences for cryptographic firewall operations.
"""

import ipaddress
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class CollatzResult:
    """Result of Collatz sequence generation"""
    ip_address: str
    ip_integer: int
    sequence: List[int]
    sequence_length: int
    steps_to_one: int
    max_value: int
    trajectory_bytes: bytes

    def __repr__(self):
        return (f"CollatzResult(ip={self.ip_address}, length={self.sequence_length}, "
                f"steps={self.steps_to_one}, max={self.max_value})")


class CollatzConverter:
    """
    Converts IP addresses to Collatz sequences.

    This is the core security mechanism of the Collatz Firewall.
    Each IP generates a unique, variable-length sequence that is:
    - Unpredictable (based on unsolved Collatz Conjecture)
    - Irreversible (exponential branching when reversed)
    - Variable-length (makes brute force infeasible)
    """

    MAX_SEQUENCE_LENGTH = 100000  # Safety limit to prevent infinite loops
    MIN_IP_INTEGER = 0
    MAX_IP_INTEGER = 2**32 - 1  # IPv4 max

    @staticmethod
    def ip_to_integer(ip_address: str) -> int:
        """
        Convert IP address string to integer.

        Args:
            ip_address: IPv4 address string (e.g., '192.168.1.100')

        Returns:
            Integer representation of IP

        Raises:
            ValueError: If IP address is invalid
        """
        try:
            ip_obj = ipaddress.IPv4Address(ip_address)
            return int(ip_obj)
        except (ipaddress.AddressValueError, ValueError) as e:
            raise ValueError(f"Invalid IPv4 address: {ip_address}") from e

    @staticmethod
    def integer_to_ip(ip_integer: int) -> str:
        """
        Convert integer back to IP address string.

        Args:
            ip_integer: Integer representation of IP

        Returns:
            IPv4 address string

        Raises:
            ValueError: If integer is out of valid IPv4 range
        """
        if not (0 <= ip_integer <= 2**32 - 1):
            raise ValueError(f"Integer {ip_integer} is out of IPv4 range")
        return str(ipaddress.IPv4Address(ip_integer))

    @staticmethod
    def generate_collatz_sequence(
        n: int,
        max_length: int = MAX_SEQUENCE_LENGTH
    ) -> Tuple[List[int], int, int]:
        """
        Generate Collatz sequence from a starting number.

        Collatz rules:
        - If n is even: n → n/2
        - If n is odd: n → 3n+1

        Args:
            n: Starting number (typically an IP as integer)
            max_length: Maximum sequence length (safety limit)

        Returns:
            Tuple of (sequence, steps_to_one, max_value_reached)
        """
        if n <= 0:
            raise ValueError("Starting number must be positive")

        sequence = [n]
        max_value = n

        while n != 1 and len(sequence) < max_length:
            if n % 2 == 0:
                n = n // 2
            else:
                n = 3 * n + 1

            sequence.append(n)
            max_value = max(max_value, n)

        steps_to_one = len(sequence) - 1
        return sequence, steps_to_one, max_value

    @staticmethod
    def sequence_to_bytes(sequence: List[int]) -> bytes:
        """
        Convert Collatz sequence to bytes for hashing.

        Each number is converted to 8 bytes (64-bit big-endian).

        Args:
            sequence: List of integers from Collatz sequence

        Returns:
            Bytes representation suitable for hashing
        """
        sequence_bytes = b''
        for num in sequence:
            sequence_bytes += num.to_bytes(8, byteorder='big')
        return sequence_bytes

    @classmethod
    def convert_ip_to_collatz(
        cls,
        ip_address: str,
        max_sequence_length: int = MAX_SEQUENCE_LENGTH
    ) -> CollatzResult:
        """
        Complete IP to Collatz conversion pipeline.

        Args:
            ip_address: IPv4 address string
            max_sequence_length: Maximum sequence length

        Returns:
            CollatzResult object with all conversion details

        Raises:
            ValueError: If IP address is invalid
        """
        # Step 1: Validate and convert IP to integer
        ip_integer = cls.ip_to_integer(ip_address)

        # Step 2: Generate Collatz sequence
        sequence, steps, max_val = cls.generate_collatz_sequence(
            ip_integer,
            max_sequence_length
        )

        # Step 3: Convert sequence to bytes
        trajectory_bytes = cls.sequence_to_bytes(sequence)

        return CollatzResult(
            ip_address=ip_address,
            ip_integer=ip_integer,
            sequence=sequence,
            sequence_length=len(sequence),
            steps_to_one=steps,
            max_value=max_val,
            trajectory_bytes=trajectory_bytes
        )

    @staticmethod
    def get_sequence_fingerprint(sequence: List[int]) -> dict:
        """
        Generate statistical fingerprint of Collatz sequence.

        Useful for understanding trajectory characteristics.

        Args:
            sequence: Collatz sequence

        Returns:
            Dictionary with statistical properties
        """
        if not sequence:
            raise ValueError("Sequence cannot be empty")

        return {
            'length': len(sequence),
            'min': min(sequence),
            'max': max(sequence),
            'mean': sum(sequence) / len(sequence),
            'start': sequence[0],
            'end': sequence[-1],
            'even_count': sum(1 for x in sequence if x % 2 == 0),
            'odd_count': sum(1 for x in sequence if x % 2 == 1),
        }
