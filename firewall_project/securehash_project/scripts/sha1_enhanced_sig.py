#!/usr/bin/env python3
"""
CLI tool for enhanced SHA-1 with sponge construction and Collatz sequences.
"""

import argparse
import sys
import logging
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from storage.utils.sha1_sponge_collatz import enhanced_sha1_signature, verify_signature

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def compute_file_signature(file_path: str) -> str:
    """Compute signature for a file."""
    with open(file_path, 'rb') as f:
        data = f.read()
    return enhanced_sha1_signature(data)

def verify_file_signature(file_path: str, signature: str) -> bool:
    """Verify file against a signature."""
    with open(file_path, 'rb') as f:
        data = f.read()
    return verify_signature(data, signature)

def main():
    parser = argparse.ArgumentParser(description='Enhanced SHA-1 Signature Tool')
    parser.add_argument('command', choices=['compute', 'verify'],
                      help='Command to execute')
    parser.add_argument('file', help='File to process')
    parser.add_argument('signature', nargs='?',
                      help='Signature to verify against (for verify command)')
    
    args = parser.parse_args()
    
    try:
        if args.command == 'compute':
            signature = compute_file_signature(args.file)
            print(f"Enhanced Signature: {signature}")
            
        elif args.command == 'verify':
            if not args.signature:
                parser.error('verify command requires a signature')
                
            is_valid = verify_file_signature(args.file, args.signature)
            if is_valid:
                print("Signature verification: VALID")
            else:
                print("Signature verification: INVALID")
                sys.exit(1)
                
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
