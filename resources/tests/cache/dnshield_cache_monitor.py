#!/usr/bin/env python3
"""
DNShield Cache Monitor - Test DNS caching behavior for specific domains
"""
import subprocess
import time
import json
import sys
import statistics
from datetime import datetime

def query_dns(domain, query_type='A', server='127.0.0.1', port=53):
    """Query DNS and return response time in milliseconds"""
    start = time.time()
    try:
        result = subprocess.run(
            ['dig', '+short', f'@{server}', '-p', str(port), domain, query_type],
            capture_output=True, text=True, timeout=5
        )
        end = time.time()
        response_time = (end - start) * 1000  # Convert to milliseconds
        return {
            'time_ms': response_time,
            'result': result.stdout.strip(),
            'error': result.stderr.strip() if result.returncode != 0 else None
        }
    except subprocess.TimeoutExpired:
        return {'time_ms': 5000, 'result': None, 'error': 'Timeout'}

def get_cache_rule(domain):
    """Get cache rule for a specific domain pattern"""
    try:
        result = subprocess.run(
            ['defaults', 'read', 'com.dnshield.app', 'DomainCacheRules'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            # Parse the output to find matching rules
            lines = result.stdout.strip().split('\n')
            for i, line in enumerate(lines):
                if domain in line or f"*.{domain.split('.', 1)[-1]}" in line:
                    # Found a potential match, extract the rule
                    rule_info = {}
                    for j in range(i, min(i+5, len(lines))):
                        if 'action' in lines[j]:
                            rule_info['action'] = lines[j].split('=')[1].strip(' ";')
                        elif 'ttl' in lines[j]:
                            rule_info['ttl'] = int(lines[j].split('=')[1].strip(' ;'))
                    return rule_info
    except:
        pass
    return None

def test_domain_cache(domain, iterations=10, delay=0.1):
    """Test caching behavior for a specific domain"""
    print(f"\nTesting DNS cache for: {domain}")
    print("=" * 50)
    
    # Check cache settings
    managed_result = subprocess.run(
        ['defaults', 'read', 'com.dnshield.app', 'EnableDNSCache'],
        capture_output=True, text=True
    )

    if managed_result.returncode == 0:
        cache_enabled = f"{managed_result.stdout.strip()} (managed)"
    else:
        user_result = subprocess.run(
            ['defaults', 'read', 'com.dnshield.app', 'UserCanAdjustCache'],
            capture_output=True, text=True
        )
        cache_enabled = user_result.stdout.strip() if user_result.returncode == 0 else "0"

    print(f"Cache Enabled: {cache_enabled}")
    
    # Check domain-specific rules
    rule = get_cache_rule(domain)
    if rule:
        print(f"Cache Rule: {rule}")
    else:
        print("Cache Rule: Default (300s TTL)")
    
    # Perform queries
    times = []
    print(f"\nPerforming {iterations} queries with {delay}s delay...")
    
    for i in range(iterations):
        result = query_dns(domain)
        times.append(result['time_ms'])
        
        status = "✓" if result['result'] else "✗"
        cache_indicator = "CACHED" if result['time_ms'] < 5 else "FRESH"
        
        print(f"Query {i+1:2d}: {result['time_ms']:6.2f}ms [{cache_indicator}] {status}")
        
        if i < iterations - 1:
            time.sleep(delay)
    
    # Analyze results
    print(f"\nStatistics:")
    print(f"  Min time: {min(times):.2f}ms")
    print(f"  Max time: {max(times):.2f}ms")
    print(f"  Avg time: {statistics.mean(times):.2f}ms")
    print(f"  Median:   {statistics.median(times):.2f}ms")
    
    # Detect caching
    if len(times) > 1:
        first_query = times[0]
        subsequent = times[1:]
        if all(t < first_query * 0.5 for t in subsequent):
            print("\n✓ Caching appears to be working!")
        elif all(t > 10 for t in times):
            print("\n✗ No caching detected - all queries appear fresh")
        else:
            print("\n? Inconsistent caching behavior detected")

def monitor_cache_ttl(domain, expected_ttl=300, test_duration=None):
    """Monitor cache behavior over time to verify TTL"""
    if test_duration is None:
        test_duration = expected_ttl + 60
    
    print(f"\nMonitoring cache TTL for {domain}")
    print(f"Expected TTL: {expected_ttl}s, Test duration: {test_duration}s")
    print("=" * 50)
    
    start_time = time.time()
    query_count = 0
    cache_hits = 0
    
    # Initial query to populate cache
    initial = query_dns(domain)
    print(f"Initial query: {initial['time_ms']:.2f}ms")
    
    while time.time() - start_time < test_duration:
        elapsed = time.time() - start_time
        result = query_dns(domain)
        query_count += 1
        
        if result['time_ms'] < 5:  # Likely cached
            cache_hits += 1
            status = "CACHED"
        else:
            status = "FRESH"
            if elapsed > expected_ttl - 5 and elapsed < expected_ttl + 5:
                print(f"\n>>> Cache expired at ~{elapsed:.0f}s (expected: {expected_ttl}s)")
        
        print(f"[{elapsed:6.1f}s] {result['time_ms']:6.2f}ms - {status}")
        
        time.sleep(10)  # Check every 10 seconds
    
    print(f"\nSummary: {cache_hits}/{query_count} queries were cached")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dnshield_cache_monitor.py <domain> [command]")
        print("\nCommands:")
        print("  test     - Quick cache test (default)")
        print("  ttl      - Monitor TTL expiration")
        print("  compare  - Compare cached vs uncached performance")
        print("\nExamples:")
        print("  python3 dnshield_cache_monitor.py github.com")
        print("  python3 dnshield_cache_monitor.py okta.com ttl")
        return
    
    domain = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else 'test'
    
    if command == 'test':
        test_domain_cache(domain)
    elif command == 'ttl':
        # Get TTL from rules or use default
        rule = get_cache_rule(domain)
        ttl = rule.get('ttl', 300) if rule else 300
        monitor_cache_ttl(domain, ttl)
    elif command == 'compare':
        print("Testing with cache enabled...")
        test_domain_cache(domain, iterations=5)
        
        print("\n" + "="*50)
        print("Disabling cache for comparison...")
        subprocess.run(['defaults', 'write', 'com.dnshield.app', 'UserCanAdjustCache', '-bool', 'NO'])
        time.sleep(2)
        
        test_domain_cache(domain, iterations=5)
        
        # Re-enable if it was enabled before
        print("\nRe-enabling cache...")
        subprocess.run(['defaults', 'write', 'com.dnshield.app', 'UserCanAdjustCache', '-bool', 'YES'])

if __name__ == '__main__':
    main()
