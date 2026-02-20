#!/usr/bin/env python3
"""
CLI tool for testing enhanced SHA-1 with content processing
"""

import argparse
import sys
import logging
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from storage.utils.sha1_enhanced_v2 import enhanced_sha1_with_content, verify_signature

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def compute_file_signature(file_path: str) -> str:
    """Compute signature for a file."""
    with open(file_path, 'rb') as f:
        data = f.read()
    return enhanced_sha1_with_content(data)

def main():
    parser = argparse.ArgumentParser(description='Enhanced SHA-1 + Content Signature Tool')
    parser.add_argument('command', choices=['compute', 'verify', 'compare'],
                      help='Command to execute')
    parser.add_argument('file', help='File to process')
    parser.add_argument('file2', nargs='?', help='Second file for compare command')
    
    args = parser.parse_args()
    
    try:
        if args.command == 'compute':
            signature = compute_file_signature(args.file)
            print(f"Enhanced Signature: {signature}")
            
        elif args.command == 'compare':
            if not args.file2:
                parser.error('compare command requires two files')
            
            sig1 = compute_file_signature(args.file)
            sig2 = compute_file_signature(args.file2)
            
            print(f"File 1 signature: {sig1}")
            print(f"File 2 signature: {sig2}")
            print(f"Signatures {'match' if sig1 == sig2 else 'differ'}")
                
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
