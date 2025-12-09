#!/usr/bin/env python3
"""
get_server_metrics.py

Fetch and display server metrics from the streamer.

Usage:
  python3 get_server_metrics.py http://192.168.3.177:8000
"""

import requests
import sys
import json

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_server_metrics.py <server_url>")
        print("Example: python3 get_server_metrics.py http://192.168.3.177:8000")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    metrics_url = f"{base_url}/metrics"
    
    try:
        response = requests.get(metrics_url)
        response.raise_for_status()
        data = response.json()
        
        print("\n" + "="*60)
        print("SERVER METRICS")
        print("="*60)
        
        print(f"\n[UPTIME & REQUESTS]")
        print(f"  Uptime: {data['uptime_sec']:.2f} sec")
        print(f"  Total Requests: {data['total_requests']}")
        print(f"  Requests/sec: {data['requests_per_sec']:.2f}")
        
        print(f"\n[CPU UTILIZATION]")
        print(f"  Mean: {data['cpu']['mean_percent']:.2f}%")
        print(f"  Max: {data['cpu']['max_percent']:.2f}%")
        print(f"  Min: {data['cpu']['min_percent']:.2f}%")
        print(f"  Samples: {data['cpu']['samples']}")
        
        print(f"\n[MEMORY]")
        print(f"  Mean: {data['memory']['mean_mb']:.2f} MB")
        print(f"  Max: {data['memory']['max_mb']:.2f} MB")
        print(f"  Current: {data['memory']['current_mb']:.2f} MB")
        
        print(f"\n[BANDWIDTH]")
        print(f"  Mean: {data['bandwidth']['mean_mbps']:.2f} Mbps")
        print(f"  Max: {data['bandwidth']['max_mbps']:.2f} Mbps")
        print(f"  Min: {data['bandwidth']['min_mbps']:.2f} Mbps")
        print(f"  Total Data: {data['bandwidth']['total_mb']:.2f} MB")
        
        print(f"\n[LATENCY]")
        print(f"  Mean: {data['latency']['mean_ms']:.2f} ms")
        print(f"  P50: {data['latency']['p50_ms']:.2f} ms")
        print(f"  P95: {data['latency']['p95_ms']:.2f} ms")
        print(f"  P99: {data['latency']['p99_ms']:.2f} ms")
        print(f"  Max: {data['latency']['max_ms']:.2f} ms")
        
        print(f"\n[ENCRYPTION]")
        print(f"  Mean: {data['encryption']['mean_ms']:.2f} ms")
        print(f"  Max: {data['encryption']['max_ms']:.2f} ms")
        
        print(f"\n[JITTER]")
        print(f"  Mean: {data['jitter']['mean_sec']:.3f} sec")
        print(f"  StdDev: {data['jitter']['stdev_sec']:.3f} sec")
        print(f"  Max: {data['jitter']['max_sec']:.3f} sec")
        
        print(f"\n[TOP 10 SEGMENTS]")
        for seg_id, count in list(data['top_segments'].items())[:10]:
            print(f"  Segment {seg_id}: {count} requests")
        
        print(f"\n[USERS]")
        for user, count in data['users'].items():
            print(f"  {user}: {count} requests")
        
        print("="*60 + "\n")
        
        # Optionally save to file
        if len(sys.argv) > 2:
            output_file = sys.argv[2]
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Metrics saved to {output_file}")
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching metrics: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
