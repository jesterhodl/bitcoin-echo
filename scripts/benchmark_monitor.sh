#!/bin/bash
# IBD Benchmark Monitor with Bottleneck Diagnostics
# Usage: ./benchmark_monitor.sh [duration_minutes]
#
# Polls getsyncstatus RPC every 10 seconds and logs metrics to CSV.
# Includes network vs CPU bottleneck analysis.
#
# Use with: ./echo --prune=1024 --loglevel=warn

set -e

DURATION=${1:-30}
END_TIME=$(($(date +%s) + DURATION * 60))
LOG_FILE="$HOME/Desktop/ibd_benchmark_$(date +%Y%m%d_%H%M%S).csv"

echo "=== IBD Benchmark with Bottleneck Diagnostics ===" | tee /dev/stderr
echo "Duration: ${DURATION} minutes" | tee /dev/stderr
echo "Log file: $LOG_FILE" | tee /dev/stderr
echo "---" | tee /dev/stderr

# CSV header
echo "timestamp,height,blk_s,pending,inflight,peers,ready,starved,val_ms,starve_ms" > "$LOG_FILE"

SAMPLES=0
TOTAL_BLK_S=0
LAST_VAL_MS=0
LAST_STARVE_MS=0

while [ $(date +%s) -lt $END_TIME ]; do
  RESULT=$(curl -s -X POST http://localhost:8332/ \
    -H "Content-Type: application/json" \
    -d '{"method":"getsyncstatus","params":[],"id":1}' 2>/dev/null)

  if [ -n "$RESULT" ] && echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
    HEIGHT=$(echo "$RESULT" | jq -r '.result.tip_height // 0')
    BLK_S=$(echo "$RESULT" | jq -r '.result.blocks_per_second // 0')
    PENDING=$(echo "$RESULT" | jq -r '.result.blocks_pending // 0')
    INFLIGHT=$(echo "$RESULT" | jq -r '.result.blocks_in_flight // 0')
    PEERS=$(echo "$RESULT" | jq -r '.result.total_peers // 0')

    # Bottleneck metrics
    READY=$(echo "$RESULT" | jq -r '.result.blocks_ready // 0')
    STARVED=$(echo "$RESULT" | jq -r '.result.blocks_starved // 0')
    VAL_MS=$(echo "$RESULT" | jq -r '.result.total_validation_ms // 0')
    STARVE_MS=$(echo "$RESULT" | jq -r '.result.total_starvation_ms // 0')

    TIMESTAMP=$(date +%H:%M:%S)

    # Log to CSV
    echo "$TIMESTAMP,$HEIGHT,$BLK_S,$PENDING,$INFLIGHT,$PEERS,$READY,$STARVED,$VAL_MS,$STARVE_MS" >> "$LOG_FILE"

    # Calculate deltas since last sample
    VAL_DELTA=$((VAL_MS - LAST_VAL_MS))
    STARVE_DELTA=$((STARVE_MS - LAST_STARVE_MS))
    LAST_VAL_MS=$VAL_MS
    LAST_STARVE_MS=$STARVE_MS

    # Determine bottleneck indicator
    if [ "$VAL_DELTA" -gt 0 ] && [ "$STARVE_DELTA" -gt 0 ]; then
      VAL_PCT=$((VAL_DELTA * 100 / (VAL_DELTA + STARVE_DELTA)))
      if [ "$VAL_PCT" -gt 70 ]; then
        BOTTLENECK="CPU"
      elif [ "$VAL_PCT" -lt 30 ]; then
        BOTTLENECK="NET"
      else
        BOTTLENECK="MIX"
      fi
    else
      BOTTLENECK="---"
    fi

    # Display to terminal
    printf "\r%s | h=%s | %.1f blk/s | pend=%s fly=%s | ready=%s starve=%s | %s (%dms val, %dms wait)    " \
      "$TIMESTAMP" "$HEIGHT" "$BLK_S" "$PENDING" "$INFLIGHT" "$READY" "$STARVED" \
      "$BOTTLENECK" "$VAL_DELTA" "$STARVE_DELTA"

    # Track for average
    if [ "$(echo "$BLK_S > 0" | bc)" -eq 1 ]; then
      SAMPLES=$((SAMPLES + 1))
      TOTAL_BLK_S=$(echo "$TOTAL_BLK_S + $BLK_S" | bc)
    fi
  else
    printf "\r%s | ERROR: connection failed or invalid response    " "$(date +%H:%M:%S)"
  fi

  sleep 10
done

echo "" # newline after final update
echo "---"
echo "Benchmark complete."
echo "Samples: $SAMPLES"
if [ "$SAMPLES" -gt 0 ]; then
  AVG=$(echo "scale=2; $TOTAL_BLK_S / $SAMPLES" | bc)
  echo "Average blk/s: $AVG"
fi

# Final bottleneck analysis
if [ "$VAL_MS" -gt 0 ] && [ "$STARVE_MS" -gt 0 ]; then
  TOTAL_TIME=$((VAL_MS + STARVE_MS))
  VAL_PCT=$((VAL_MS * 100 / TOTAL_TIME))
  STARVE_PCT=$((STARVE_MS * 100 / TOTAL_TIME))
  echo ""
  echo "Bottleneck Analysis:"
  echo "  Validation time: ${VAL_MS}ms (${VAL_PCT}%)"
  echo "  Starvation time: ${STARVE_MS}ms (${STARVE_PCT}%)"
  if [ "$VAL_PCT" -gt 70 ]; then
    echo "  -> CPU-BOUND: Optimize signature verification or UTXO operations"
  elif [ "$STARVE_PCT" -gt 70 ]; then
    echo "  -> NETWORK-BOUND: Improve peer management or increase download window"
  else
    echo "  -> MIXED: Both CPU and network are factors"
  fi
fi

echo ""
echo "Log file: $LOG_FILE"
