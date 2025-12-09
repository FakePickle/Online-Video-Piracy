#!/bin/bash
# Example: Run stress test with 100 unique users, then scale to 1000 unique users
# Each client simulates a different user (user_0, user_1, user_2, ...)

# Test with 100 unique users (validation run)
echo "=== Testing with 100 unique users ==="
python3 rtsp_python/segments/stress_clients.py \
  --playlist http://127.0.0.1:8000/user/user_0/playlist.m3u8 \
  --clients 100 \
  --segments 20 \
  --concurrency 100 \
  --timeout 60 \
  --rep 3 \
  --out metrics_100_users.json

echo ""
echo "=== Waiting 5 seconds before next test ==="
sleep 5

# Test with 1000 unique users (production scale)
echo ""
echo "=== Testing with 1000 unique users ==="
python3 rtsp_python/segments/stress_clients.py \
  --playlist http://127.0.0.1:8000/user/user_0/playlist.m3u8 \
  --clients 1000 \
  --segments 50 \
  --concurrency 1000 \
  --timeout 120 \
  --rep 3 \
  --out metrics_1000_users.json

echo ""
echo "=== Test completed! Check metrics_100_users.json and metrics_1000_users.json ==="

echo ""
echo "=== Test completed! Check metrics_100_clients.json and metrics_1000_clients.json ==="
