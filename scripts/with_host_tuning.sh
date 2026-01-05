#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
auto_cpu_selector="$script_dir/select_physical_cpus.py"
state_dir="${HOST_TUNING_STATE_DIR:-/tmp/host_tuning}"
state_file="$state_dir/state.json"
mkdir -p "$state_dir"
declare -A role_cpu=()
declare -A role_core=()
declare -A role_siblings=()
current_layout_file=""
cap_sys_nice_ok=""
cap_sys_nice_detail=""
manual_cgroup_dir=""
manual_cgroup_active=0
manual_cgroup_cpus=""
manual_cgroup_mems=""
verify_governor_target=""
verify_boost_target=""

log() {
  printf '[host-tuning] %s\n' "$*" >&2
}

log_err_trap() {
  local status=$?
  local cmd=${BASH_COMMAND:-unknown}
  log "Error: command '${cmd}' exited with status $status."
  return $status
}

trap 'log_err_trap' ERR

parse_roles_from_layout() {
  local layout_path="$1"
  [[ -f "$layout_path" ]] || return 0
  role_cpu=()
  role_core=()
  role_siblings=()
  while IFS=: read -r role cpu core siblings; do
    [[ -n "$role" ]] || continue
    role_cpu["$role"]="$cpu"
    role_core["$role"]="$core"
    role_siblings["$role"]="$siblings"
  done < <(python3 - "$layout_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

roles = data.get("roles", {})
for role in ("server", "client"):
    info = roles.get(role)
    if not info:
        continue
    siblings = ",".join(str(x) for x in info.get("siblings", []))
    core = str(info.get("core_id", ""))
    cpu = str(info.get("cpu", ""))
    print(f"{role}:{cpu}:{core}:{siblings}")
PY
)
}

log_layout_details() {
  local layout_path="$1"
  [[ -f "$layout_path" ]] || return 0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    log "$line"
  done < <(python3 - "$layout_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

pairs = data.get("pairs", [])
for pair in pairs:
    core = pair.get("core_id")
    cpus = ",".join(str(x) for x in pair.get("cpus", []))
    selected = pair.get("selected")
    if selected is None:
        selected = pair.get("cpus", [])
    selected_str = ",".join(str(x) for x in selected)
    if selected_str and selected_str != cpus:
        print(f"Core {core}: logical CPUs {cpus} (requested: {selected_str})")
    else:
        print(f"Core {core}: logical CPUs {cpus}")

roles = data.get("roles", {})
for role_name, info in roles.items():
    cpu = info.get("cpu")
    siblings = ",".join(str(x) for x in info.get("siblings", []))
    if siblings:
        print(f"{role_name.capitalize()} primary CPU {cpu} with sibling(s) {siblings} reserved")
    else:
        print(f"{role_name.capitalize()} primary CPU {cpu} (no additional siblings)")
PY
)
}

write_state_snapshot() {
  local layout_path="$1"
  local cpus_string="$2"
  local cap_detail="$3"
  local cap_ok="$4"
  mkdir -p "$state_dir"
  python3 - "$state_file" "$layout_path" "$cpus_string" "$cap_detail" "$cap_ok" <<'PY'
import json
import os
import sys
import time

state_path, layout_path, cpus_raw, cap_detail, cap_ok = sys.argv[1:6]
cpus = [int(x) for x in cpus_raw.split(',') if x]
layout = {}
if layout_path and os.path.exists(layout_path):
    with open(layout_path, encoding="utf-8") as handle:
        try:
            layout = json.load(handle)
        except json.JSONDecodeError:
            layout = {}

priority = {
    "requested": {
        "nice": -20,
        "rt_policy": "SCHED_FIFO",
        "rt_priority": 99,
    },
    "applied": layout.get("priority", {}).get("applied", {}),
}

cap_entry = {
    "detail": cap_detail or None,
    "effective": None,
}
if cap_ok in {"0", "1"}:
    cap_entry["effective"] = bool(int(cap_ok))

state = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "cpuset": cpus,
    "pairs": layout.get("pairs", []),
    "roles": layout.get("roles", {}),
    "priority": priority,
    "capabilities": {
        "cap_sys_nice": cap_entry,
    },
}

with open(state_path, "w", encoding="utf-8") as handle:
    json.dump(state, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

check_cap_sys_nice() {
  local result
  result=$(python3 <<'PY'
import sys

cap_eff = None
try:
    with open("/proc/self/status", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("CapEff:"):
                cap_eff = line.split()[1].strip()
                break
except OSError:
    pass

if cap_eff is None:
    print("unknown:CapEff unavailable")
else:
    try:
        value = int(cap_eff, 16)
    except ValueError:
        print(f"unknown:CapEff={cap_eff}")
    else:
        has_cap = 1 if value & (1 << 23) else 0
        print(f"{has_cap}:CapEff={cap_eff}")
PY
)
  cap_sys_nice_ok=${result%%:*}
  cap_sys_nice_detail=${result#*:}
  case "$cap_sys_nice_ok" in
    1)
      log "CAP_SYS_NICE available (${cap_sys_nice_detail})."
      ;;
    0)
      log "Warning: CAP_SYS_NICE missing (${cap_sys_nice_detail}); real-time priority may fail."
      ;;
    *)
      log "Warning: unable to determine CAP_SYS_NICE status (${cap_sys_nice_detail})."
      cap_sys_nice_ok=""
      ;;
  esac
}

configure_role_assignment() {
  local role="$1"
  local cpu="${role_cpu[$role]:-}"
  [[ -n "$cpu" ]] || return 0
  local core="${role_core[$role]:-unknown}"
  local siblings="${role_siblings[$role]:-}"
  local sibling_text="none"
  if [[ -n "$siblings" ]]; then
    sibling_text=${siblings//,/ }
  fi
  local label="${role^}"
  case "$role" in
    server)
      if [[ -n "${PIN_SERVER_CPU:-}" ]]; then
        log "$label CPU preset to ${PIN_SERVER_CPU}; topology indicates CPU $cpu (core $core, sibling(s): $sibling_text)."
      else
        PIN_SERVER_CPU="$cpu"
        export PIN_SERVER_CPU
        log "$label CPU auto-set to $PIN_SERVER_CPU (core $core, sibling(s): $sibling_text)."
      fi
      ;;
    client)
      if [[ -n "${PIN_CLIENT_CPU:-}" ]]; then
        log "$label CPU preset to ${PIN_CLIENT_CPU}; topology indicates CPU $cpu (core $core, sibling(s): $sibling_text)."
      else
        PIN_CLIENT_CPU="$cpu"
        export PIN_CLIENT_CPU
        log "$label CPU auto-set to $PIN_CLIENT_CPU (core $core, sibling(s): $sibling_text)."
      fi
      ;;
    *)
      log "$label role uses CPU $cpu (core $core, sibling(s): $sibling_text)."
      ;;
  esac
}

expand_cpu_list() {
  local list="$1" part start end
  list=${list//,/ }
  for part in $list; do
    [[ -n "$part" ]] || continue
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start=${BASH_REMATCH[1]}
      end=${BASH_REMATCH[2]}
      if (( start > end )); then
        log "Invalid CPU range '$part'."
        return 1
      fi
      seq "$start" "$end"
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      echo "$part"
    else
      log "Invalid CPU entry '$part'."
      return 1
    fi
  done
}

collapse_cpu_list() {
  if (($# == 0)); then
    return
  fi
  local -a sorted
  mapfile -t sorted < <(printf '%s\n' "$@" | sort -n -u)
  local -a ranges=()
  local range_start="" range_end="" cpu
  for cpu in "${sorted[@]}"; do
    if [[ -z "$range_start" ]]; then
      range_start="$cpu"
      range_end="$cpu"
      continue
    fi
    if (( cpu == range_end + 1 )); then
      range_end="$cpu"
    else
      if [[ "$range_start" == "$range_end" ]]; then
        ranges+=("$range_start")
      else
        ranges+=("$range_start-$range_end")
      fi
      range_start="$cpu"
      range_end="$cpu"
    fi
  done
  if [[ -n "$range_start" ]]; then
    if [[ "$range_start" == "$range_end" ]]; then
      ranges+=("$range_start")
    else
      ranges+=("$range_start-$range_end")
    fi
  fi
  local IFS=','
  printf '%s\n' "${ranges[*]}"
}

compute_cpu_mask() {
  if (($# == 0)); then
    echo 0x0
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    log "Warning: python3 not found; unable to compute IRQ mask accurately."
    echo 0x0
    return
  fi
  python3 - "$@" <<'PY'
import sys
try:
    cpus = [int(x) for x in sys.argv[1:]]
except ValueError:
    print("0x0")
    sys.exit(0)
mask = 0
for cpu in cpus:
    if cpu < 0:
        continue
    mask |= 1 << cpu
print(hex(mask))
PY
}

verify_governors() {
  local expected="$1"
  [[ -n "$expected" ]] || return 0
  local mismatch=0
  local -a details=()
  local count=0
  for policy_path in /sys/devices/system/cpu/cpufreq/policy*; do
    [[ -f "$policy_path/scaling_governor" ]] || continue
    local policy current
    policy=$(basename "$policy_path")
    current=$(<"$policy_path/scaling_governor")
    details+=("$policy=$current")
    ((++count))
    if [[ "$current" != "$expected" ]]; then
      mismatch=1
    fi
  done
  ((count)) || return 0
  local summary
  summary=$(IFS=', '; echo "${details[*]}")
  if ((mismatch)); then
    log "Warning: governor verification mismatch (expected '$expected'): $summary"
  else
    log "Verified governors set to '$expected': $summary"
  fi
  return 0
}

verify_boost_state() {
  local expected="$1"
  local boost_file="/sys/devices/system/cpu/cpufreq/boost"
  [[ -f "$boost_file" ]] || return 0
  local current
  current=$(<"$boost_file")
  if [[ "$current" == "$expected" ]]; then
    log "Boost state verification: $current (expected $expected)."
  else
    log "Warning: boost state mismatch (expected $expected, observed $current)."
  fi
  return 0
}

verify_allowed_cpus_state() {
  local slice="$1"
  local target="$2"
  command -v systemctl >/dev/null 2>&1 || return 0
  local configured effective
  if configured=$(systemctl show -p AllowedCPUs "$slice" 2>/dev/null); then
    configured=${configured#AllowedCPUs=}
  else
    configured=""
  fi
  if effective=$(systemctl show -p AllowedCPUsEffective "$slice" 2>/dev/null); then
    effective=${effective#AllowedCPUsEffective=}
  else
    effective=""
  fi
  log "$slice AllowedCPUs -> configured='${configured:-}' effective='${effective:-}' target='${target:-}'"
  return 0
}

verify_irqbalance_service() {
  command -v systemctl >/dev/null 2>&1 || return 0
  if systemctl is-active --quiet irqbalance 2>/dev/null; then
    log "irqbalance service state: active"
  else
    local state
    state=$(systemctl is-active irqbalance 2>/dev/null || true)
    log "Warning: irqbalance service state: ${state:-unknown}"
  fi
  return 0
}

log_irq_totals() {
  local label="$1"
  shift
  if (($# == 0)); then
    return
  fi
  local summary
  summary=$(python3 - "$@" <<'PY'
import sys

try:
    cpus = sorted({int(arg) for arg in sys.argv[1:]})
except ValueError:
    cpus = []

if not cpus:
    sys.exit(0)

counts = {cpu: 0 for cpu in cpus}

try:
    with open("/proc/interrupts", encoding="utf-8") as handle:
        header = handle.readline()
        header_tokens = [tok for tok in header.split() if tok.upper().startswith("CPU")]
        num_cols = len(header_tokens)
        if num_cols == 0:
            raise RuntimeError("no CPU columns detected")
        for line in handle:
            parts = line.split()
            if not parts or not parts[0].endswith(":"):
                continue
            if len(parts) < 1 + num_cols:
                continue
            for idx in range(num_cols):
                token = parts[1 + idx]
                try:
                    value = int(token)
                except ValueError:
                    continue
                cpu_index = idx
                if cpu_index in counts:
                    counts[cpu_index] += value
except OSError:
    pass
except RuntimeError:
    pass

if counts:
    print(" ".join(f"CPU{cpu}={counts.get(cpu, 0)}" for cpu in cpus))
PY
) || summary=""
  if [[ -n "$summary" ]]; then
    log "$label: $summary"
  else
    log "Warning: unable to summarize /proc/interrupts for reserved CPUs."
  fi
  return 0
}

ensure_cpuset_controller() {
  local root="/sys/fs/cgroup"
  local controllers="$root/cgroup.controllers"
  local subtree="$root/cgroup.subtree_control"
  if [[ ! -f "$controllers" ]]; then
    return 1
  fi
  if grep -qw cpuset "$controllers"; then
    return 0
  fi
  if [[ -w "$subtree" ]]; then
    if printf '+cpuset\n' >"$subtree" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

setup_manual_cpuset_scope() {
  local cpus="$1"
  [[ -n "$cpus" ]] || return 1
  local root="/sys/fs/cgroup"
  if ! ensure_cpuset_controller; then
    return 1
  fi
  manual_cgroup_dir="$root/host_tuning_scope_$$"
  if ! mkdir -p "$manual_cgroup_dir"; then
    manual_cgroup_dir=""
    return 1
  fi
  manual_cgroup_cpus="$cpus"
  manual_cgroup_mems=$(</sys/devices/system/node/online 2>/dev/null | tr -d $' \t\n\r')
  if [[ -z "$manual_cgroup_mems" ]]; then
    manual_cgroup_mems="0"
  fi
  if ! printf '%s\n' "$manual_cgroup_mems" >"$manual_cgroup_dir/cpuset.mems"; then
    rmdir "$manual_cgroup_dir" >/dev/null 2>&1 || true
    manual_cgroup_dir=""
    return 1
  fi
  if ! printf '%s\n' "$cpus" >"$manual_cgroup_dir/cpuset.cpus"; then
    rmdir "$manual_cgroup_dir" >/dev/null 2>&1 || true
    manual_cgroup_dir=""
    return 1
  fi
  manual_cgroup_active=1
  log "Using manual cgroup cpuset scope at $manual_cgroup_dir (CPUs $cpus, mems $manual_cgroup_mems)."
  return 0
}

cleanup_manual_cpuset_scope() {
  if [[ -n "$manual_cgroup_dir" ]]; then
    if ((manual_cgroup_active)); then
      log "Removing manual cgroup cpuset scope."
    fi
    rmdir "$manual_cgroup_dir" >/dev/null 2>&1 || true
  fi
  manual_cgroup_dir=""
  manual_cgroup_active=0
  manual_cgroup_cpus=""
  manual_cgroup_mems=""
}

usage() {
  cat <<'USAGE'
Usage: with_host_tuning.sh [options] -- command [args...]

Options:
  --cpus LIST          Comma-separated logical CPUs to reserve (e.g. 0,2).
  --governor NAME      CPU governor to apply during the run (default: performance).
  --disable-boost      Temporarily disable Turbo/boost state while running.
  --no-governor        Skip governor changes.
  --no-disable-boost   Keep current Turbo/boost state.
  --help               Show this message.

The script must run with root privileges. It saves the existing governor and
boost settings and restores them when the wrapped command exits.
USAGE
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=PIN_SERVER_CPU,PIN_CLIENT_CPU,HOST_TUNING_AUTO_CPU_COUNT,HOST_TUNING_SKIP_CPUS,HOST_TUNING_SLICE_MODE "$0" "$@"
fi

cpus=""
go_with="performance"
disable_boost=0
change_governor=0
change_boost=1

while (($#)); do
  case "$1" in
    --cpus)
      [[ $# -ge 2 ]] || { echo "Missing value for --cpus" >&2; exit 2; }
      cpus="$2"
      shift 2
      ;;
    --governor)
      [[ $# -ge 2 ]] || { echo "Missing value for --governor" >&2; exit 2; }
      go_with="$2"
      change_governor=1
      shift 2
      ;;
    --disable-boost)
      disable_boost=1
      shift
      ;;
    --no-governor)
      change_governor=0
      shift
      ;;
    --no-disable-boost)
      change_boost=0
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if (($# == 0)); then
  echo "No command provided. Use -- before the command to run." >&2
  usage
  exit 2
fi

command=("$@")

tmpdir=$(mktemp -d)
restore_governor_file="$tmpdir/governors"
restore_boost_file="$tmpdir/boost"
restore_slice_file="$tmpdir/systemd_allowed_cpus"
restore_irqbalance_file="$tmpdir/irqbalance.conf.backup"
irqbalance_conf="/etc/default/irqbalance"
irqbalance_modified=0
irqbalance_conf_existed=0
manual_irq_backup_dir=""
systemd_slices_modified=0
readonly_irq_warning=0
current_layout_file="$tmpdir/selected_cpu_layout.json"

if [[ -z "$cpus" && -x "$auto_cpu_selector" ]]; then
  auto_count="${HOST_TUNING_AUTO_CPU_COUNT:-2}"
  if ! [[ "$auto_count" =~ ^[0-9]+$ ]] || (( auto_count <= 0 )); then
    auto_count=2
  fi
  auto_err="$tmpdir/auto_cpu_selection.err"
  if [[ -v HOST_TUNING_SKIP_CPUS ]]; then
    auto_selected=$(HOST_TUNING_SKIP_CPUS="$HOST_TUNING_SKIP_CPUS" HOST_TUNING_LAYOUT_FILE="$current_layout_file" "$auto_cpu_selector" "$auto_count" 2>"$auto_err")
    status=$?
  else
    auto_selected=$(HOST_TUNING_LAYOUT_FILE="$current_layout_file" "$auto_cpu_selector" "$auto_count" 2>"$auto_err")
    status=$?
  fi
  if (( status == 0 )); then
    cpus="$auto_selected"
    log "Auto-selected CPUs $cpus from physical core pairs."
  elif [[ -s "$auto_err" ]]; then
    log "Warning: auto CPU selection failed: $(<"$auto_err")"
  else
    log "Warning: auto CPU selection failed; continuing without explicit CPU list."
  fi
fi

check_cap_sys_nice

cleanup_done=0
child_pid=""

restore_settings() {
  local status=${1:-$?}
  if ((cleanup_done)); then
    exit "$status"
  fi
  cleanup_done=1
  trap - EXIT INT TERM HUP
  set +e
  if [[ -f "$restore_governor_file" ]]; then
    log "Restoring original governors."
    while IFS=: read -r policy gov; do
      printf '%s\n' "$gov" > "/sys/devices/system/cpu/cpufreq/$policy/scaling_governor" 2>/dev/null || true
    done <"$restore_governor_file"
  fi
  if [[ -f "$restore_boost_file" ]]; then
    log "Restoring boost state."
    cat "$restore_boost_file" > /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || true
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ -f "$restore_slice_file" && $systemd_slices_modified -eq 1 ]]; then
    log "Restoring AllowedCPUs on systemd slices."
    while IFS=: read -r slice value; do
      [[ -n "$slice" ]] || continue
      if [[ -n "$value" ]]; then
        systemctl set-property --runtime "$slice" "AllowedCPUs=$value" >/dev/null 2>&1 || true
      else
        systemctl set-property --runtime "$slice" AllowedCPUs= >/dev/null 2>&1 || true
      fi
    done <"$restore_slice_file"
  fi
  if ((irqbalance_modified)); then
    log "Restoring irqbalance configuration."
    if ((irqbalance_conf_existed)); then
      cp "$restore_irqbalance_file" "$irqbalance_conf" >/dev/null 2>&1 || true
    else
      rm -f "$irqbalance_conf"
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart irqbalance >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "$manual_irq_backup_dir" && -d "$manual_irq_backup_dir" ]]; then
    log "Restoring IRQ affinity lists."
    readonly_irq_warning=0
    while IFS= read -r -d '' backup_file; do
      rel_path=${backup_file#"$manual_irq_backup_dir/"}
      target="/proc/irq/$rel_path"
      if [[ -f "$target" ]]; then
        if [[ -w "$target" ]]; then
          cat "$backup_file" >"$target" 2>/dev/null || true
        else
          readonly_irq_warning=1
        fi
      fi
    done < <(find "$manual_irq_backup_dir" -type f -print0)
    if ((readonly_irq_warning)); then
      log "Warning: some IRQ affinity files were read-only during restore."
    fi
  fi
  if [[ -n "${cset_active:-}" ]]; then
    log "Removing CPU shield."
    cset shield --reset >/dev/null 2>&1 || true
  fi
  cleanup_manual_cpuset_scope
  rm -rf "$tmpdir"
  exit "$status"
}

forward_signal() {
  local sig="$1"
  if [[ -n "$child_pid" ]]; then
    kill -"$sig" "$child_pid" >/dev/null 2>&1 || true
  fi
}

handle_signal() {
  local sig="$1"
  forward_signal "$sig"
  case "$sig" in
    INT) restore_settings 130 ;;
    TERM) restore_settings 143 ;;
    HUP) restore_settings 129 ;;
    *) restore_settings 128 ;;
  esac
}

trap 'restore_settings $?' EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'handle_signal HUP' HUP

if ((change_governor)); then
  if command -v cpupower >/dev/null 2>&1; then
    log "Saving existing governors before applying '$go_with'."
    : >"$restore_governor_file"
    for policy_path in /sys/devices/system/cpu/cpufreq/policy*; do
      [[ -f "$policy_path/scaling_governor" ]] || continue
      policy=$(basename "$policy_path")
      current=$(<"$policy_path/scaling_governor")
      printf '%s:%s\n' "$policy" "$current" >>"$restore_governor_file"
    done
    if ! cpupower frequency-set --governor "$go_with" >/dev/null; then
      log "Warning: failed to apply governor '$go_with'; leaving existing setting."
      change_governor=0
    else
      if [[ -d /sys/devices/system/cpu/cpufreq/policy0 && -f /sys/devices/system/cpu/cpufreq/policy0/scaling_governor ]]; then
        new_value=$(</sys/devices/system/cpu/cpufreq/policy0/scaling_governor)
        log "Governor applied: policy0 reports '$new_value'."
      else
        log "Governor applied. Use 'make host-status' to inspect policies."
      fi
      verify_governors "$go_with"
    fi
  else
    log "Warning: cpupower not found; skipping governor changes."
    change_governor=0
  fi
fi

if ((change_boost && disable_boost)); then
  if [[ -f /sys/devices/system/cpu/cpufreq/boost ]]; then
    previous_boost=$(</sys/devices/system/cpu/cpufreq/boost)
    printf '%s\n' "$previous_boost" >"$restore_boost_file"
    if ! printf '0\n' > /sys/devices/system/cpu/cpufreq/boost; then
      log "Warning: failed to disable boost; keeping prior state."
      change_boost=0
    else
      log "Boost disabled (previous state: $previous_boost)."
      verify_boost_state "0"
    fi
  else
    log "Warning: boost control not available; skipping."
    change_boost=0
  fi
fi

if [[ -n "$cpus" ]]; then
  if ! HOST_TUNING_LAYOUT_FILE="$current_layout_file" "$auto_cpu_selector" --describe "$cpus" >/dev/null 2>&1; then
    log "Warning: unable to derive topology details for CPUs $cpus."
  fi
  parse_roles_from_layout "$current_layout_file"
  log_layout_details "$current_layout_file"
  configure_role_assignment server
  configure_role_assignment client
  if ! mapfile -t reserved_cpu_list < <(expand_cpu_list "$cpus"); then
    log "Failed to parse CPU list '$cpus'."
    restore_settings 2
  fi
  write_state_snapshot "$current_layout_file" "$cpus" "$cap_sys_nice_detail" "${cap_sys_nice_ok:-}"
  export HOST_TUNING_STATE_FILE="$state_file"
  if state_json=$(python3 - "$state_file" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, json.JSONDecodeError):
    sys.exit(1)
print(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
PY
  ); then
    export HOST_TUNING_STATE_JSON="$state_json"
  else
    unset HOST_TUNING_STATE_JSON || true
    log "Warning: failed to export host tuning state JSON; variable not set."
  fi
  if [[ -f /sys/devices/system/cpu/online ]]; then
    online_cpus=$(</sys/devices/system/cpu/online)
    if ! mapfile -t all_cpu_list < <(expand_cpu_list "$online_cpus"); then
      log "Failed to parse online CPU list '$online_cpus'."
      restore_settings 2
    fi
  else
    log "Warning: /sys/devices/system/cpu/online missing; skipping system CPU isolation."
    all_cpu_list=()
  fi

  rest_cpu_list=()
  if ((${#all_cpu_list[@]})); then
    declare -A reserved_map=()
    for cpu in "${reserved_cpu_list[@]}"; do
      reserved_map["$cpu"]=1
    done
    for cpu in "${all_cpu_list[@]}"; do
      if [[ -z "${reserved_map[$cpu]:-}" ]]; then
        rest_cpu_list+=("$cpu")
      fi
    done
  fi

  all_cpu_string=""
  if ((${#all_cpu_list[@]})); then
    all_cpu_string=$(collapse_cpu_list "${all_cpu_list[@]}")
  fi
  if [[ -z "$all_cpu_string" && -f /sys/devices/system/cpu/online ]]; then
    all_cpu_string=$(</sys/devices/system/cpu/online)
    all_cpu_string=${all_cpu_string//$'\n'/}
    all_cpu_string=${all_cpu_string//$'\r'/}
    all_cpu_string=${all_cpu_string//[[:space:]]/}
  fi

  rest_cpu_string=""
  if ((${#rest_cpu_list[@]})); then
    rest_cpu_string=$(collapse_cpu_list "${rest_cpu_list[@]}")
  fi

  if ((${#all_cpu_list[@]})) && [[ -n "$rest_cpu_string" ]]; then
    if command -v systemctl >/dev/null 2>&1; then
      : >"$restore_slice_file"
      slices=(user.slice)
      log "Skipping machine.slice isolation to keep benchmark CPUs accessible for containers."
      for slice in "${slices[@]}"; do
        if ! current=$(systemctl show -p AllowedCPUs "$slice" 2>/dev/null); then
          log "Warning: unable to read AllowedCPUs for $slice."
          continue
        fi
        current=${current#AllowedCPUs=}
        printf '%s:%s\n' "$slice" "$all_cpu_string" >>"$restore_slice_file"
        if systemctl set-property --runtime "$slice" "AllowedCPUs=$rest_cpu_string" >/dev/null 2>&1; then
          systemd_slices_modified=1
          log "Updated $slice AllowedCPUs to $rest_cpu_string."
          verify_allowed_cpus_state "$slice" "$rest_cpu_string"
        else
          log "Warning: failed to update AllowedCPUs for $slice."
        fi
      done
    else
      log "Warning: systemctl not available; skipping system slice isolation."
    fi
  elif ((${#all_cpu_list[@]})) && [[ -z "$rest_cpu_string" ]]; then
    log "Warning: all online CPUs are reserved; skipping system slice isolation."
  fi

  if ((${#reserved_cpu_list[@]})); then
    reserved_mask=$(compute_cpu_mask "${reserved_cpu_list[@]}")
  else
    reserved_mask="0x0"
  fi

  if [[ -n "$rest_cpu_string" ]]; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet irqbalance 2>/dev/null; then
      irqbalance_modified=1
      if [[ -f "$irqbalance_conf" ]]; then
        cp "$irqbalance_conf" "$restore_irqbalance_file" >/dev/null 2>&1 || true
        irqbalance_conf_existed=1
      else
        : >"$restore_irqbalance_file"
        irqbalance_conf_existed=0
      fi
      touch "$irqbalance_conf"
      if grep -Eq '^[[:space:]#]*IRQBALANCE_BANNED_CPUS=' "$irqbalance_conf"; then
        sed -E -i "s/^[[:space:]#]*IRQBALANCE_BANNED_CPUS=.*/IRQBALANCE_BANNED_CPUS=$reserved_mask/" "$irqbalance_conf"
      elif grep -Eq '^[[:space:]]*export[[:space:]]+IRQBALANCE_BANNED_CPUS=' "$irqbalance_conf"; then
        sed -E -i "s/^[[:space:]]*export[[:space:]]+IRQBALANCE_BANNED_CPUS=.*/export IRQBALANCE_BANNED_CPUS=$reserved_mask/" "$irqbalance_conf"
      else
        printf '\nIRQBALANCE_BANNED_CPUS=%s\n' "$reserved_mask" >>"$irqbalance_conf"
      fi
      if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart irqbalance >/dev/null 2>&1; then
          log "irqbalance restarted with banned CPUs mask $reserved_mask."
        else
          log "Warning: failed to restart irqbalance; IRQ balancing changes may not take effect."
        fi
      fi
      verify_irqbalance_service
    else
      manual_irq_backup_dir="$tmpdir/irq_affinity"
      mkdir -p "$manual_irq_backup_dir"
      readonly_irq_warning=0
      for affinity_file in /proc/irq/*/smp_affinity_list; do
        [[ -f "$affinity_file" ]] || continue
        rel_path=${affinity_file#/proc/irq/}
        mkdir -p "$manual_irq_backup_dir/$(dirname "$rel_path")"
        cat "$affinity_file" >"$manual_irq_backup_dir/$rel_path" 2>/dev/null || true
        if [[ -w "$affinity_file" ]]; then
          printf '%s\n' "$rest_cpu_string" >"$affinity_file" 2>/dev/null || true
        else
          readonly_irq_warning=1
        fi
      done
      log "Set IRQ affinities to CPUs $rest_cpu_string (previous values saved)."
      if ((readonly_irq_warning)); then
        log "Warning: one or more IRQ affinity files were read-only and could not be updated."
      fi
    fi
    log_irq_totals "IRQ counters on reserved CPUs" "${reserved_cpu_list[@]}"
  else
    log "Skipping IRQ affinity adjustments (no alternate CPUs available)."
  fi

  if command -v cset >/dev/null 2>&1; then
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
      log "Warning: unified cgroup hierarchy detected; skipping CPU shielding (cset shield unsupported)."
    else
      if cset_output=$(cset shield --cpu="$cpus" --kthread=on 2>&1); then
        cset_active=1
        command=(cset shield --exec -- "${command[@]}")
        log "Shielded CPUs $cpus for the benchmark."
        if cset shield status >/dev/null 2>&1; then
          cset shield status >&2
        fi
      else
        if [[ -n "$cset_output" ]]; then
          cset_output=${cset_output//$'\n'/; }
          log "Warning: cset shield failed; continuing without CPU shielding. Details: $cset_output"
        else
          log "Warning: cset shield failed; continuing without CPU shielding."
        fi
      fi
    fi
  else
    log "Warning: cset not found; continuing without CPU shielding."
  fi

  if [[ -z "${cset_active:-}" && -f /sys/fs/cgroup/cgroup.controllers ]]; then
    if command -v systemd-run >/dev/null 2>&1; then
      command=(systemd-run --scope -p AllowedCPUs="$cpus" -- "${command[@]}")
      log "Using systemd-run scope with AllowedCPUs=$cpus (cgroup v2)."
    else
      if setup_manual_cpuset_scope "$cpus"; then
        log "Using manual cgroup cpuset scope (systemd-run unavailable)."
      else
        log "Warning: cgroup v2 detected and systemd-run not available; relying on Docker --cpuset-cpus only."
      fi
    fi
  fi
fi

set +e
"${command[@]}" &
child_pid=$!
if ((manual_cgroup_active)) && [[ -n "$manual_cgroup_dir" ]]; then
  if ! printf '%s\n' "$child_pid" >"$manual_cgroup_dir/cgroup.procs" 2>/dev/null; then
    log "Warning: failed to move PID $child_pid into manual cgroup scope."
  fi
fi
wait "$child_pid"
cmd_status=$?
restore_settings "$cmd_status"
