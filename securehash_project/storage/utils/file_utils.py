"""Utility functions for file handling and streaming."""

import logging
from typing import Iterator


def stream_file_in_chunks(path: str, chunk_size: int = 16 * 1024) -> Iterator[bytes]:
    """
    Stream a file's contents in chunks to minimize memory usage.
    
    Args:
        path: Path to the file to read
        chunk_size: Size of chunks to read in bytes
        
    Yields:
        bytes: Chunks of file data
        
    Raises:
        IOError: If file cannot be read
    """
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    except IOError as e:
        logging.error(f"Error reading file {path}: {e}")
        raise
