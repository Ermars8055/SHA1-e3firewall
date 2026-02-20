#!/usr/bin/env python
"""
Enhanced version of the Collatz-SHA1 signature tool that uses
full block content for signature generation.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Add project root to Python path for Django integration
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'securehash_project.settings')

try:
    import django
    django.setup()
except ImportError:
    pass  # Allow standalone usage without Django

from storage.utils.enhanced_collatz import compute_enhanced_signature
from storage.utils.file_utils import stream_file_in_chunks

def setup_logging(verbose: bool = False):
    """Configure logging level based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def compute_file_signature(file_path: str) -> str:
    """
    Compute enhanced Collatz-based signature for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: Hexadecimal signature string
        
    Raises:
        IOError: If file cannot be read
    """
    # Read file in chunks
    chunks = list(stream_file_in_chunks(file_path))
    combined_data = b''.join(chunks)
    
    # Compute enhanced signature
    signature = compute_enhanced_signature(combined_data)
    
    # Convert to hex string
    return signature.hex()

def verify_file_signature(file_path: str, expected_sig: str) -> bool:
    """
    Verify if a file matches an expected signature.
    
    Args:
        file_path: Path to the file
        expected_sig: Expected signature to verify against
        
    Returns:
        bool: True if signature matches, False otherwise
    """
    actual_sig = compute_file_signature(file_path)
    return actual_sig.lower() == expected_sig.lower()

def demo_collision(file1_path: str, file2_path: str) -> bool:
    """
    Test if two files produce the same signature.
    
    Args:
        file1_path: Path to first file
        file2_path: Path to second file
        
    Returns:
        bool: True if signatures match (collision found), False otherwise
    """
    sig1 = compute_file_signature(file1_path)
    sig2 = compute_file_signature(file2_path)
    return sig1 == sig2

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Enhanced Collatz-Based Signature Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s compute sample.txt
  %(prog)s verify sample.txt 1234abcd...
  %(prog)s demo-collision file1.txt file2.txt
        '''
    )
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose debug output')
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # compute command
    compute_parser = subparsers.add_parser('compute',
                                         help='Compute signature for a file')
    compute_parser.add_argument('file',
                              help='Path to file to compute signature for')
    
    # verify command
    verify_parser = subparsers.add_parser('verify',
                                         help='Verify file against signature')
    verify_parser.add_argument('file',
                             help='Path to file to verify')
    verify_parser.add_argument('signature',
                             help='Expected signature to verify against')
    
    # demo-collision command
    collision_parser = subparsers.add_parser('demo-collision',
                                           help='Test two files for signature collision')
    collision_parser.add_argument('file1',
                                help='Path to first file')
    collision_parser.add_argument('file2',
                                help='Path to second file')
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    try:
        if args.command == 'compute':
            signature = compute_file_signature(args.file)
            print(f"Enhanced Signature: {signature}")
            
        elif args.command == 'verify':
            matches = verify_file_signature(args.file, args.signature)
            print(f"Signature {'matches' if matches else 'does not match'}")
            sys.exit(0 if matches else 1)
            
        elif args.command == 'demo-collision':
            collision = demo_collision(args.file1, args.file2)
            print(f"Files {'have the same' if collision else 'have different'} signatures")
            sys.exit(0 if collision else 1)
            
    except IOError as e:
        logging.error(f"File error: {e}")
        sys.exit(2)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            logging.exception("Detailed error information:")
        sys.exit(3)

if __name__ == '__main__':
    main()
