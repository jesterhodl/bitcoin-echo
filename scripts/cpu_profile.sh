#!/bin/bash
# CPU Profile Capture
# Usage: ./cpu_profile.sh [duration_seconds]
#
# Uses macOS 'sample' command to capture CPU profiling data.
# Run while echo node is syncing to identify hotspots.

set -e

DURATION=${1:-60}
PID=$(pgrep -x echo 2>/dev/null || true)

if [ -z "$PID" ]; then
  echo "Error: echo process not found. Is the node running?"
  exit 1
fi

OUTPUT_FILE="$HOME/Desktop/echo_cpu_profile_$(date +%Y%m%d_%H%M%S).txt"

echo "=== CPU Profile ===" | tee /dev/stderr
echo "PID: $PID" | tee /dev/stderr
echo "Duration: ${DURATION} seconds" | tee /dev/stderr
echo "Output: $OUTPUT_FILE" | tee /dev/stderr
echo "---" | tee /dev/stderr

echo "Sampling... (this may require administrator privileges)"
sudo sample $PID $DURATION -file "$OUTPUT_FILE"

echo "---"
echo "Profile complete: $OUTPUT_FILE"
echo ""
echo "Look for high 'Self' weights in functions like:"
echo "  - secp256k1_* (signature verification)"
echo "  - sqlite3_* (database operations)"
echo "  - sha256_* / ripemd160_* (hashing)"
echo "  - script_* (script execution)"
