"""
Comprehensive Benchmark Suite for SHA1-E3
Tests performance, memory usage, and throughput across different file types and sizes
"""

import sys
import os
import time
import psutil
import matplotlib.pyplot as plt
import json
from datetime import datetime
from typing import Dict, List, Tuple
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage.utils.sha1_enhanced_v3 import enhanced_sha1_with_content

class SHA1E3Benchmark:
    def __init__(self):
        self.results = {
            'file_size_tests': [],
            'content_type_tests': [],
            'memory_usage': [],
            'cpu_usage': [],
            'throughput': []
        }
        
        # Create test directory if it doesn't exist
        self.test_dir = '../benchmark_data/test_files'
        os.makedirs(self.test_dir, exist_ok=True)
        
        # Generate test files
        self.generate_test_files()
        
        self.test_files = {
            # Sequential content files
            'seq_1kb': f'{self.test_dir}/test_1kb_sequential.txt',
            'seq_10kb': f'{self.test_dir}/test_10kb_sequential.txt',
            'seq_100kb': f'{self.test_dir}/test_100kb_sequential.txt',
            'seq_1000kb': f'{self.test_dir}/test_1000kb_sequential.txt',
            'seq_10000kb': f'{self.test_dir}/test_10000kb_sequential.txt',
            
            # Random content files
            'rand_1kb': '../benchmark_data/test_files/test_1kb_random.txt',
            'rand_10kb': '../benchmark_data/test_files/test_10kb_random.txt',
            'rand_100kb': '../benchmark_data/test_files/test_100kb_random.txt',
            'rand_1000kb': '../benchmark_data/test_files/test_1000kb_random.txt',
            'rand_10000kb': '../benchmark_data/test_files/test_10000kb_random.txt',
            
            # Repeated content files
            'repeat_1kb': '../benchmark_data/test_files/test_1kb_repeat.txt',
            'repeat_10kb': '../benchmark_data/test_files/test_10kb_repeat.txt',
            'repeat_100kb': '../benchmark_data/test_files/test_100kb_repeat.txt',
            'repeat_1000kb': '../benchmark_data/test_files/test_1000kb_repeat.txt',
            'repeat_10000kb': '../benchmark_data/test_files/test_10000kb_repeat.txt'
        }

    def measure_performance(self, file_path: str, iterations: int = 5) -> Dict:
        """Measure performance metrics for a single file."""
        file_size = os.path.getsize(file_path)
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        times = []
        memory_usage = []
        cpu_percent = []
        process = psutil.Process()
        
        for _ in range(iterations):
            # Memory before
            mem_before = process.memory_info().rss / 1024 / 1024  # MB
            
            # Time measurement
            start_time = time.time()
            enhanced_sha1_with_content(content)
            end_time = time.time()
            
            # Memory after
            mem_after = process.memory_info().rss / 1024 / 1024  # MB
            
            times.append(end_time - start_time)
            memory_usage.append(mem_after - mem_before)
            cpu_percent.append(process.cpu_percent())
        
        return {
            'file_size': file_size,
            'avg_time': sum(times) / len(times),
            'min_time': min(times),
            'max_time': max(times),
            'avg_memory': sum(memory_usage) / len(memory_usage),
            'avg_cpu': sum(cpu_percent) / len(cpu_percent),
            'throughput': (file_size / 1024 / 1024) / (sum(times) / len(times))  # MB/s
        }

    def run_benchmarks(self):
        """Run all benchmark tests."""
        print("Starting SHA1-E3 Benchmark Suite...")
        
        # Test different file sizes
        for file_type in ['seq', 'rand', 'repeat']:
            print(f"\nTesting {file_type} files...")
            for size in ['1kb', '10kb', '100kb', '1000kb', '10000kb']:
                file_key = f'{file_type}_{size}'
                if file_key in self.test_files:
                    print(f"Processing {file_key}...")
                    result = self.measure_performance(self.test_files[file_key])
                    result['file_type'] = file_type
                    result['size_category'] = size
                    self.results['file_size_tests'].append(result)

    def generate_report(self):
        """Generate comprehensive benchmark report."""
        report = """# SHA1-E3 Benchmark Results
Generated on: {date}

## Performance Overview

### File Size Performance
{size_table}

### Content Type Performance
{type_table}

### Memory Usage
{memory_table}

### Throughput Analysis
{throughput_table}

## Detailed Analysis

### Performance by File Size
{size_analysis}

### Performance by Content Type
{type_analysis}

### Memory Usage Patterns
{memory_analysis}

### Throughput Characteristics
{throughput_analysis}

## System Information
- OS: {os}
- CPU: {cpu}
- Memory: {memory}
- Python Version: {python_version}
"""
        
        # Create DataFrames for analysis
        df = pd.DataFrame(self.results['file_size_tests'])
        
        # Size performance table
        size_table = df.groupby('size_category')[['avg_time', 'throughput']].mean()
        
        # Content type performance table
        type_table = df.groupby('file_type')[['avg_time', 'throughput']].mean()
        
        # Memory usage table
        memory_table = df.groupby('size_category')['avg_memory'].mean()
        
        # Format the report
        report = report.format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            size_table=size_table.to_markdown(),
            type_table=type_table.to_markdown(),
            memory_table=memory_table.to_markdown(),
            throughput_table=df.groupby('size_category')['throughput'].mean().to_markdown(),
            size_analysis=self._generate_size_analysis(df),
            type_analysis=self._generate_type_analysis(df),
            memory_analysis=self._generate_memory_analysis(df),
            throughput_analysis=self._generate_throughput_analysis(df),
            os=os.uname().sysname,
            cpu=os.cpu_count(),
            memory=f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
            python_version=sys.version
        )
        
        # Save report
        with open('../docs/benchmark_results.md', 'w') as f:
            f.write(report)
        
        print("\nBenchmark results saved to docs/benchmark_results.md")

    def _generate_size_analysis(self, df: pd.DataFrame) -> str:
        """Generate detailed size analysis."""
        analysis = "\n### Performance Scaling with File Size\n\n"
        analysis += "File size has a linear impact on processing time:\n\n"
        for size in df['size_category'].unique():
            size_data = df[df['size_category'] == size]
            analysis += f"- {size}: {size_data['avg_time'].mean():.4f}s average\n"
        return analysis

    def _generate_type_analysis(self, df: pd.DataFrame) -> str:
        """Generate detailed content type analysis."""
        analysis = "\n### Content Type Impact\n\n"
        analysis += "Different content types show varying performance characteristics:\n\n"
        for file_type in df['file_type'].unique():
            type_data = df[df['file_type'] == file_type]
            analysis += f"- {file_type}: {type_data['avg_time'].mean():.4f}s average\n"
        return analysis

    def _generate_memory_analysis(self, df: pd.DataFrame) -> str:
        """Generate detailed memory usage analysis."""
        analysis = "\n### Memory Usage Patterns\n\n"
        analysis += "Memory usage scales with file size:\n\n"
        for size in df['size_category'].unique():
            size_data = df[df['size_category'] == size]
            analysis += f"- {size}: {size_data['avg_memory'].mean():.2f}MB average\n"
        return analysis

    def _generate_throughput_analysis(self, df: pd.DataFrame) -> str:
        """Generate detailed throughput analysis."""
        analysis = "\n### Throughput Characteristics\n\n"
        analysis += "Processing throughput (MB/s) for different file sizes:\n\n"
        for size in df['size_category'].unique():
            size_data = df[df['size_category'] == size]
            analysis += f"- {size}: {size_data['throughput'].mean():.2f}MB/s\n"
        return analysis

    def generate_test_files(self):
        """Generate test files of different sizes and patterns."""
        sizes = {
            '1kb': 1024,
            '10kb': 10 * 1024,
            '100kb': 100 * 1024,
            '1000kb': 1000 * 1024,
            '10000kb': 10000 * 1024
        }
        
        for size_name, size_bytes in sizes.items():
            # Sequential content
            with open(f'{self.test_dir}/test_{size_name}_sequential.txt', 'wb') as f:
                for i in range(size_bytes):
                    f.write(bytes([i % 256]))
            
            # Random content
            with open(f'{self.test_dir}/test_{size_name}_random.txt', 'wb') as f:
                f.write(os.urandom(size_bytes))
            
            # Repeated content
            with open(f'{self.test_dir}/test_{size_name}_repeat.txt', 'wb') as f:
                pattern = b'Hello, World! ' * (size_bytes // 14 + 1)
                f.write(pattern[:size_bytes])

def main():
    benchmark = SHA1E3Benchmark()
    benchmark.run_benchmarks()
    benchmark.generate_report()

if __name__ == "__main__":
    main()
