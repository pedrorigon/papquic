#!/usr/bin/env bash
set -euo pipefail

MODE=${MODE:-all}
KEM=${KEM:-}
SIG=${SIG:-}
COUNT=${COUNT:-50}
RESULTS_DIR=${RESULTS_DIR:-/app/results}
HOST_UID=${HOST_UID:-}
HOST_GID=${HOST_GID:-}
BENCH_KIND=${BENCH_KIND:-benchmarks}
LOSS_PROFILE=${LOSS_PROFILE:-0}
NETEM_INTERFACE=${NETEM_INTERFACE:-lo}
QUIC_MODE=${QUIC_MODE:-0}
DEBUG_LOG=${DEBUG_LOG:-OFF}
MEASURE_ONLY=${MEASURE_ONLY:-OFF}
PRINT_MODE=${PRINT_MODE:-}

print_mode_normalized=""
if [[ -n "$PRINT_MODE" ]]; then
  case "${PRINT_MODE,,}" in
    debug|packet|benchmark)
      print_mode_normalized="${PRINT_MODE,,}"
      ;;
    *)
      echo "Unknown PRINT_MODE value: $PRINT_MODE" >&2
      exit 1
      ;;
  esac
elif [[ "${DEBUG_LOG^^}" == "ON" ]]; then
  print_mode_normalized="debug"
fi

append_print_mode_flag() {
  local mode="$1"
  case "$mode" in
    debug)
      echo "--debug"
      ;;
    packet)
      echo "--packet"
      ;;
    benchmark)
      echo "--benchmark"
      ;;
    *)
      return 0
      ;;
  esac
}

mkdir -p "$RESULTS_DIR"

case "${BENCH_KIND,,}" in
  benchmarks)
    args=("--mode" "$MODE" "--count" "$COUNT" "--results-dir" "$RESULTS_DIR")
    if [[ -n "$KEM" ]]; then
      args+=("--kem" "$KEM")
    fi
    if [[ -n "$SIG" ]]; then
      args+=("--sig" "$SIG")
    fi
    if [[ -n "$QUIC_MODE" ]]; then
      args+=("--quic-mode" "$QUIC_MODE")
    fi
    args+=("--loss-profile" "$LOSS_PROFILE" "--netem-interface" "$NETEM_INTERFACE")
    if [[ "${MEASURE_ONLY^^}" == "ON" ]]; then
      args+=("--measure-only")
    fi
    if [[ -n "$print_mode_normalized" ]]; then
      flag=$(append_print_mode_flag "$print_mode_normalized")
      if [[ -n "$flag" ]]; then
        args+=("$flag")
      fi
    fi
    python3 /app/scripts/run_benchmarks.py "${args[@]}"
    ;;
  packetcount)
    args=("--mode" "$MODE" "--results-dir" "$RESULTS_DIR")
    if [[ -n "$KEM" ]]; then
      args+=("--kem" "$KEM")
    fi
    if [[ -n "$SIG" ]]; then
      args+=("--sig" "$SIG")
    fi
    if [[ -n "$QUIC_MODE" ]]; then
      args+=("--quic-mode" "$QUIC_MODE")
    fi
    args+=("--loss-profile" "$LOSS_PROFILE" "--netem-interface" "$NETEM_INTERFACE")
    python3 /app/scripts/run_packet_count.py "${args[@]}"
    ;;
  *)
    echo "Unknown BENCH_KIND value: $BENCH_KIND" >&2
    exit 1
    ;;
esac

if [[ -n "$HOST_UID" && -n "$HOST_GID" ]]; then
  chown -R "$HOST_UID":"$HOST_GID" "$RESULTS_DIR"
fi
