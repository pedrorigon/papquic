#!/usr/bin/env bash
set -euo pipefail

state_dir="${HOST_TUNING_STATE_DIR:-/tmp/host_tuning}"
state_file="${HOST_TUNING_STATE_FILE:-$state_dir/state.json}"
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
selector_script="$script_dir/select_physical_cpus.py"
layout_file="$state_dir/layout.json"
auto_cpu_count="${HOST_TUNING_AUTO_CPU_COUNT:-2}"
skip_cpus="${HOST_TUNING_SKIP_CPUS:-0}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=HOST_TUNING_CPUS,HOST_TUNING_STATE_DIR,HOST_TUNING_STATE_FILE "$0" "$@"
fi

cpus_to_show="${1:-${HOST_TUNING_CPUS:-}}"

ensure_state_file() {
  [[ -f "$state_file" ]] && return 0

  mkdir -p "$state_dir"

  local cpus="$cpus_to_show"

  if [[ -x "$selector_script" ]]; then
    if [[ -n "$cpus" ]]; then
      HOST_TUNING_LAYOUT_FILE="$layout_file" \
      HOST_TUNING_SKIP_CPUS="$skip_cpus" \
      "$selector_script" --describe "$cpus" >/dev/null 2>&1 || true
    else
      cpus=$(HOST_TUNING_LAYOUT_FILE="$layout_file" \
        HOST_TUNING_SKIP_CPUS="$skip_cpus" \
        "$selector_script" "$auto_cpu_count" 2>/dev/null | tr -d '[:space:]' || true)
      if [[ -n "$cpus" ]]; then
        cpus_to_show="$cpus"
      fi
    fi
  fi

  if [[ ! -f "$layout_file" && -x "$selector_script" && -n "${cpus_to_show:-$cpus}" ]]; then
    HOST_TUNING_LAYOUT_FILE="$layout_file" \
    "$selector_script" --describe "${cpus_to_show:-$cpus}" >/dev/null 2>&1 || true
  fi

  local snapshot_cpus="${cpus_to_show:-$cpus}"

  python3 - "$state_file" "$layout_file" "$snapshot_cpus" <<'PY'
import json
import os
import sys
import time

state_path, layout_path, cpus_raw = sys.argv[1:4]

def parse_cpus(raw: str):
    cpus = []
    for chunk in raw.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            cpus.append(int(chunk))
        except ValueError:
            continue
    return cpus

cpus = parse_cpus(cpus_raw)
layout = {}
if layout_path and os.path.exists(layout_path):
    try:
        with open(layout_path, encoding="utf-8") as handle:
            layout = json.load(handle)
    except (OSError, json.JSONDecodeError):
        layout = {}

if not cpus and layout:
    cpus = layout.get("cpuset", [])

priority = {
    "requested": {
        "nice": -20,
        "rt_policy": "SCHED_FIFO",
        "rt_priority": 99,
    },
    "applied": layout.get("priority", {}).get("applied", {}),
}

state = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "cpuset": cpus,
    "pairs": layout.get("pairs", []),
    "roles": layout.get("roles", {}),
    "priority": priority,
    "capabilities": {
        "cap_sys_nice": {
            "detail": "not evaluated (host-status fallback)",
            "effective": None,
        },
    },
}

with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

ensure_state_file

if [[ -z "$cpus_to_show" && -f "$state_file" ]]; then
  cpus_to_show=$(python3 - "$state_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        data = json.load(handle)
except FileNotFoundError:
    sys.exit(0)
cpus = data.get("cpuset", [])
if cpus:
    print(",".join(str(cpu) for cpu in cpus))
PY
  )
fi

print_header() {
  printf '\n%s\n' "$1"
  printf '%s\n' "$(printf '%*s' "${#1}" '' | tr ' ' '-')"
}

print_state_snapshot() {
  print_header "Host tuning snapshot"
  if [[ ! -f "$state_file" ]]; then
    echo "State file not found at $state_file"
    return
  fi
  python3 - "$state_file" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)

timestamp = data.get("timestamp", "unknown")
cpuset = data.get("cpuset", [])
pairs = data.get("pairs", [])
roles = data.get("roles", {})
priority = data.get("priority", {})
requested = priority.get("requested", {})
applied = priority.get("applied", {})
capabilities = data.get("capabilities", {}).get("cap_sys_nice", {})

print(f"Snapshot timestamp: {timestamp}")
print(f"Reserved CPUs: {','.join(str(cpu) for cpu in cpuset) if cpuset else 'none'}")
if pairs:
    for pair in pairs:
        core = pair.get("core_id")
        cpus = ",".join(str(x) for x in pair.get("cpus", []))
        print(f"  Core {core}: CPUs {cpus}")

for role in ("server", "client"):
    info = roles.get(role)
    if not info:
        continue
    siblings = info.get("siblings", [])
    sibling_text = ",".join(str(x) for x in siblings) if siblings else "none"
    print(
        f"{role.capitalize()} target CPU: {info.get('cpu')} (core {info.get('core_id')}, sibling(s): {sibling_text})"
    )

if requested:
    print(
        "Requested priority: nice {nice}, policy {policy}, priority {prio}".format(
            nice=requested.get("nice"),
            policy=requested.get("rt_policy"),
            prio=requested.get("rt_priority"),
        )
    )

if applied:
    for role, info in applied.items():
        nice = info.get("nice")
        policy = info.get("scheduler")
        prio = info.get("rt_priority")
        print(
            f"{role.capitalize()} applied: nice {nice}, scheduler {policy}, priority {prio}"
        )

if capabilities:
    detail = capabilities.get("detail")
    effective = capabilities.get("effective")
    if effective is True:
        status = "present"
    elif effective is False:
        status = "missing"
    else:
        status = "unknown"
    if detail:
        print(f"CAP_SYS_NICE: {status} ({detail})")
    else:
        print(f"CAP_SYS_NICE: {status}")
PY
}

print_state_snapshot

print_header "CPU governor policies"
found_policy=0
for policy_path in /sys/devices/system/cpu/cpufreq/policy*; do
  [[ -f "$policy_path/scaling_governor" ]] || continue
  policy=$(basename "$policy_path")
  governor=$(<"$policy_path/scaling_governor")
  printf '%s: %s\n' "$policy" "$governor"
  found_policy=1
done
if (( ! found_policy )); then
  echo "No scaling governor information available."
fi

print_header "Turbo / boost state"
if [[ -f /sys/devices/system/cpu/cpufreq/boost ]]; then
  boost=$(< /sys/devices/system/cpu/cpufreq/boost)
  case "$boost" in
    0) echo "Boost disabled (value: 0)" ;;
    1) echo "Boost enabled (value: 1)" ;;
    *) echo "Boost state: $boost" ;;
  esac
else
  echo "Boost control file not present on this platform."
fi

if command -v cset >/dev/null 2>&1; then
  print_header "cset shield status"
  if cset shield status >/dev/null 2>&1; then
    cset shield status
  else
    echo "cset shield not active."
  fi
else
  print_header "cset shield status"
  echo "cset utility not installed."
fi

if [[ -n "$cpus_to_show" ]]; then
  print_header "Processes currently on CPUs $cpus_to_show"
  ps -eo pid,psr,comm,args --sort=psr |
    awk -v list="$cpus_to_show" '
      BEGIN {
        n=split(list, cpus, ",");
        for(i=1;i<=n;i++){ allowed[cpus[i]]=1 }
      }
      NR==1 { printf "%s\n", $0; next }
      {
        cpu=$2
        sub(/^[[:space:]]+/, "", cpu)
        if (cpu in allowed) {
          print
        }
      }
    '
fi
