"""Hash storage and collision detection utility."""
import json
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class HashStore:
    def __init__(self, store_path=None):
        if store_path is None:
            store_path = Path(__file__).parent.parent / 'data' / 'hash_store.json'
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.hashes = self._load_hashes()
        
    def _load_hashes(self):
        """Load existing hashes from storage."""
        if not self.store_path.exists():
            return {}
        try:
            with open(self.store_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("Corrupted hash store detected. Creating new store.")
            return {}

    def _save_hashes(self):
        """Save hashes to storage."""
        with open(self.store_path, 'w') as f:
            json.dump(self.hashes, f, indent=2)

    def add_hash(self, file_hash: str, file_path: str, metadata: dict = None):
        """
        Add a hash to the store and check for collisions.
        
        Args:
            file_hash: The hash value
            file_path: Path to the file that generated this hash
            metadata: Additional metadata about the hash (optional)
        
        Returns:
            bool: True if collision detected, False otherwise
        """
        if metadata is None:
            metadata = {}
            
        collision = False
        if file_hash in self.hashes:
            # Check if this is a different file with same hash
            existing_paths = {entry['file_path'] for entry in self.hashes[file_hash]}
            if file_path not in existing_paths:
                logger.warning(f"Hash collision detected! Hash: {file_hash}")
                logger.warning(f"Existing file(s): {existing_paths}")
                logger.warning(f"New file: {file_path}")
                collision = True
                
        if file_hash not in self.hashes:
            self.hashes[file_hash] = []
            
        entry = {
            'file_path': file_path,
            'timestamp': metadata.get('timestamp'),
            'file_size': metadata.get('file_size'),
            'collided': collision
        }
        
        # Only add if not already present
        if not any(e['file_path'] == file_path for e in self.hashes[file_hash]):
            self.hashes[file_hash].append(entry)
            self._save_hashes()
            
        return collision

    def get_hash_info(self, file_hash: str) -> list:
        """Get information about a specific hash."""
        return self.hashes.get(file_hash, [])

    def get_collisions(self) -> dict:
        """Get all detected hash collisions."""
        return {
            h: entries for h, entries in self.hashes.items()
            if len(entries) > 1 and any(e['collided'] for e in entries)
        }
