"""Progress tracking utilities for cryptographic test suite."""
import time
import psutil
import sys
from datetime import datetime, timedelta

class ProgressTracker:
    def __init__(self, total_steps: int, description: str):
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time = time.time()
        self.description = description
        self.last_update = 0
        
    def update(self, step: int = 1, force: bool = False):
        self.current_step += step
        current_time = time.time()
        
        # Update at most once every 0.1 seconds unless forced
        if not force and current_time - self.last_update < 0.1:
            return
            
        self.last_update = current_time
        progress = (self.current_step / self.total_steps) * 100
        elapsed = current_time - self.start_time
        
        if self.current_step > 0:
            eta = elapsed * (self.total_steps / self.current_step - 1)
            eta_str = str(timedelta(seconds=int(eta)))
        else:
            eta_str = "Unknown"
            
        # Get memory usage
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        # Create progress bar
        bar_width = 50
        filled = int(progress / 2)
        bar = '=' * filled + ' ' * (bar_width - filled)
        
        # Print status
        sys.stdout.write('\r')
        sys.stdout.write(f'{self.description}: [{bar}] {progress:.1f}%')
        sys.stdout.write(f' | ETA: {eta_str} | Memory: {memory_mb:.1f}MB')
        sys.stdout.flush()
        
        if self.current_step >= self.total_steps:
            print()  # New line when complete
            
    def complete(self):
        self.update(self.total_steps - self.current_step, force=True)