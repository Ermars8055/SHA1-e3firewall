"""
Test script for SHA-1 Enhanced v3
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

def compare_files(file1_path: str, file2_path: str) -> None:
    """Compare two files using the enhanced SHA-1 v3 algorithm."""
    # Read files
    with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()
    
    # Generate signatures
    sig1 = enhanced_sha1_with_content(data1)
    sig2 = enhanced_sha1_with_content(data2)
    
    # Compare and display results
    print(f"\nFile 1: {os.path.basename(file1_path)}")
    print(f"Signature: {sig1}")
    print(f"\nFile 2: {os.path.basename(file2_path)}")
    print(f"Signature: {sig2}")
    print(f"\nSignatures match: {sig1 == sig2}")
    
    if sig1 == sig2:
        print("WARNING: Files produce identical signatures!")
    else:
        print("SUCCESS: Files produce different signatures!")

def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) != 4 or sys.argv[1] != 'compare':
        print("Usage: python sha1_enhanced_v3_test.py compare <file1> <file2>")
        sys.exit(1)
    
    file1_path = sys.argv[2]
    file2_path = sys.argv[3]
    
    if not os.path.exists(file1_path) or not os.path.exists(file2_path):
        print("Error: One or both files do not exist!")
        sys.exit(1)
    
    compare_files(file1_path, file2_path)

if __name__ == '__main__':
    main()
