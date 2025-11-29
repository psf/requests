"""
Example script demonstrating the usage of requests metrics functionality.

This script shows how to:
1. Create a MetricsAdapter and attach it to a Session
2. Make HTTP requests with metrics collection
3. Display detailed statistics about the requests
"""

import time
import random
from requests import Session
from requests.metrics import MetricsAdapter, Stats


def simulate_requests_with_metrics():
    """
    Simulate making HTTP requests with metrics collection.
    This example uses httpbin.org for testing purposes.
    """
    print("=== Requests Metrics Example ===\n")
    
    # Create a session with metrics adapter
    session = Session()
    
    # Create a metrics adapter and mount it to the session
    metrics_adapter = MetricsAdapter()
    session.mount('http://', metrics_adapter)
    session.mount('https://', metrics_adapter)
    
    print("Starting to make requests with metrics collection...")
    print("-" * 50)
    
    # Make various types of requests to demonstrate metrics collection
    endpoints = [
        ('https://httpbin.org/status/200', 'Success (200)'),
        ('https://httpbin.org/status/201', 'Created (201)'),
        ('https://httpbin.org/status/404', 'Not Found (404)'),
        ('https://httpbin.org/status/500', 'Server Error (500)'),
        ('https://httpbin.org/delay/1', 'Delayed Response (1s)'),
        ('https://httpbin.org/json', 'JSON Response'),
        ('https://httpbin.org/user-agent', 'User Agent'),
        ('https://httpbin.org/headers', 'Headers'),
    ]
    
    successful_requests = 0
    
    for url, description in endpoints:
        try:
            print(f"Making request to: {description}")
            start_time = time.time()
            
            response = session.get(url)
            elapsed = time.time() - start_time
            
            print(f"  Status: {response.status_code}")
            print(f"  Time: {elapsed:.3f}s")
            successful_requests += 1
            
        except Exception as e:
            print(f"  Error: {str(e)}")
        
        # Small delay between requests
        time.sleep(0.1)
    
    print("\n" + "=" * 50)
    print("METRICS SUMMARY")
    print("=" * 50)
    
    # Get the stats from the metrics adapter
    stats = metrics_adapter.stats
    
    # Print detailed statistics
    print(stats)
    
    # Also demonstrate accessing individual metrics
    print("\n" + "=" * 50)
    print("DETAILED METRICS ACCESS")
    print("=" * 50)
    
    print(f"Total requests made: {stats.total_requests}")
    print(f"Successful requests: {successful_requests}")
    print(f"Total errors: {stats.total_errors}")
    
    if stats.status_distribution:
        print("\nStatus code distribution:")
        for status, count in sorted(stats.status_distribution.items()):
            percentage = (count / stats.total_requests) * 100
            print(f"  HTTP {status}: {count} requests ({percentage:.1f}%)")
    
    if stats.response_times:
        times = stats.response_times
        print(f"\nResponse time statistics:")
        print(f"  Total measurements: {len(times)}")
        print(f"  Average: {sum(times) / len(times):.3f}s")
        print(f"  Minimum: {min(times):.3f}s")
        print(f"  Maximum: {max(times):.3f}s")
    
    # Demonstrate summary dictionary access
    print("\n" + "=" * 50)
    print("SUMMARY DICTIONARY")
    print("=" * 50)
    
    summary = stats.get_summary()
    for key, value in summary.items():
        if key == 'status_distribution':
            print(f"{key}: {dict(value)}")
        else:
            print(f"{key}: {value}")
    
    return stats


def demonstrate_stats_reset():
    """Demonstrate the reset functionality of Stats."""
    print("\n" + "=" * 50)
    print("DEMONSTRATING STATS RESET")
    print("=" * 50)
    
    # Create a new stats instance
    stats = Stats()
    
    # Record some data
    stats.record(status_code=200, response_time=0.1)
    stats.record(status_code=404, response_time=0.05)
    stats.record(error=True)
    
    print("Before reset:")
    print(f"  Total requests: {stats.total_requests}")
    print(f"  Total errors: {stats.total_errors}")
    print(f"  Status distribution: {dict(stats.status_distribution)}")
    
    # Reset the stats
    stats.reset()
    
    print("\nAfter reset:")
    print(f"  Total requests: {stats.total_requests}")
    print(f"  Total errors: {stats.total_errors}")
    print(f"  Status distribution: {dict(stats.status_distribution)}")


def demonstrate_thread_safety():
    """Demonstrate thread safety of the Stats class."""
    print("\n" + "=" * 50)
    print("DEMONSTRATING THREAD SAFETY")
    print("=" * 50)
    
    stats = Stats()
    num_threads = 5
    requests_per_thread = 20
    
    def worker(thread_id):
        """Worker function that makes requests."""
        for i in range(requests_per_thread):
            # Simulate some variety in requests
            if i % 5 == 0:  # 20% errors
                stats.record(error=True)
            else:
                status_codes = [200, 201, 301, 404]
                status = status_codes[i % len(status_codes)]
                response_time = random.uniform(0.01, 0.5)
                stats.record(status_code=status, response_time=response_time)
            
            # Small random delay
            time.sleep(random.uniform(0.001, 0.01))
    
    print(f"Starting {num_threads} threads, each making {requests_per_thread} requests...")
    
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=worker, args=(i,))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("All threads completed!")
    print(f"Total requests recorded: {stats.total_requests}")
    print(f"Total errors recorded: {stats.total_errors}")
    print(f"Status distribution: {dict(stats.status_distribution)}")
    
    expected_total = num_threads * requests_per_thread
    assert stats.total_requests == expected_total, f"Expected {expected_total}, got {stats.total_requests}"
    print("✓ Thread safety verified!")


if __name__ == "__main__":
    import threading
    
    # Run the main example
    stats = simulate_requests_with_metrics()
    
    # Demonstrate reset functionality
    demonstrate_stats_reset()
    
    # Demonstrate thread safety
    demonstrate_thread_safety()
    
    print("\n" + "=" * 50)
    print("EXAMPLE COMPLETED")
    print("=" * 50)
    print("\nThis example demonstrated:")
    print("1. How to use MetricsAdapter with requests Session")
    print("2. Automatic collection of request metrics")
    print("3. Detailed statistics reporting")
    print("4. Thread-safe operation")
    print("5. Stats reset functionality")
    print("\nYou can now integrate this metrics functionality into your own applications!")