"""Tests for overall signature consistency and properties."""

import os
import tempfile
from pathlib import Path
import pytest

from storage.utils.api import collatz_sha1_signature_of_data
from storage.utils.file_utils import stream_file_in_chunks


def test_signature_deterministic():
    """Test that signatures are deterministic."""
    test_data = b'test_data'
    sig1 = collatz_sha1_signature_of_data(test_data)
    sig2 = collatz_sha1_signature_of_data(test_data)
    assert sig1 == sig2


def test_signature_different_data():
    """Test that different data produces different signatures."""
    sig1 = collatz_sha1_signature_of_data(b'data1')
    sig2 = collatz_sha1_signature_of_data(b'data2')
    assert sig1 != sig2


def test_signature_empty_data():
    """Test signature generation with empty input."""
    sig = collatz_sha1_signature_of_data(b'')
    assert isinstance(sig, str)
    assert all(c in '0123456789abcdef' for c in sig.lower())


def test_signature_block_count():
    """Test signature generation with different block counts."""
    test_data = b'test' * 1000
    sig2 = collatz_sha1_signature_of_data(test_data, num_blocks=2)
    sig4 = collatz_sha1_signature_of_data(test_data, num_blocks=4)
    sig8 = collatz_sha1_signature_of_data(test_data, num_blocks=8)
    
    # Different block counts should produce different signatures
    assert len({sig2, sig4, sig8}) == 3


def test_file_streaming_signature():
    """Test signature generation with file streaming."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        test_data = b'test_data' * 1000
        tf.write(test_data)
        tf.flush()
        
        # Compute signature directly
        direct_sig = collatz_sha1_signature_of_data(test_data)
        
        # Compute signature through streaming
        chunks = list(stream_file_in_chunks(tf.name))
        streamed_sig = collatz_sha1_signature_of_data(b''.join(chunks))
        
        assert direct_sig == streamed_sig
        
    # Clean up
    os.unlink(tf.name)


def test_signature_format():
    """Test signature format constraints."""
    test_data = b'test_data'
    sig = collatz_sha1_signature_of_data(test_data)
    
    assert isinstance(sig, str)
    assert len(sig) == 40  # SHA-1 hex length
    assert all(c in '0123456789abcdef' for c in sig.lower())
