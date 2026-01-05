#!/usr/bin/env python3
"""Select physical CPU pairs suitable for host tuning."""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

SYS_CPU_DIR = Path("/sys/devices/system/cpu")
SYS_NODE_DIR = Path("/sys/devices/system/node")


def _expand_cpu_list(spec: str) -> List[int]:
    cpus: List[int] = []
    if not spec:
        return cpus
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError:
                raise ValueError(f"invalid CPU range '{part}'") from None
            if start > end:
                raise ValueError(f"invalid CPU range '{part}'")
            cpus.extend(range(start, end + 1))
        else:
            try:
                cpus.append(int(part))
            except ValueError:
                raise ValueError(f"invalid CPU entry '{part}'") from None
    return cpus


@dataclass
class CoreInfo:
    core_id: str
    cpus: Tuple[int, ...]
    contains_cpu0: bool
    skipped: bool
    node_id: Optional[int] = None

    @property
    def primary(self) -> int:
        return self.cpus[0]

    @property
    def siblings(self) -> Tuple[int, ...]:
        return self.cpus[1:]


def _read_file(path: Path) -> Optional[str]:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _cpu_online(cpu: int) -> bool:
    cpu_path = SYS_CPU_DIR / f"cpu{cpu}"
    online_file = cpu_path / "online"
    if online_file.exists():
        value = _read_file(online_file)
        return value != "0"
    return cpu_path.exists()


def _thread_siblings(cpu: int) -> Tuple[int, ...]:
    topo_file = SYS_CPU_DIR / f"cpu{cpu}" / "topology" / "thread_siblings_list"
    content = _read_file(topo_file)
    if not content:
        return (cpu,)
    siblings = sorted(set(_expand_cpu_list(content)))
    return tuple(s for s in siblings if _cpu_online(s)) or (cpu,)


_CPU_NODE_MAP: Optional[Dict[int, int]] = None


def _build_cpu_node_map() -> Dict[int, int]:
    mapping: Dict[int, int] = {}
    if not SYS_NODE_DIR.exists():
        return mapping
    for node_dir in sorted(SYS_NODE_DIR.glob("node[0-9]*")):
        name = node_dir.name
        try:
            node_id = int(name[4:])
        except (ValueError, IndexError):
            continue
        cpulist = _read_file(node_dir / "cpulist")
        if not cpulist:
            continue
        try:
            cpus = _expand_cpu_list(cpulist)
        except ValueError:
            continue
        for cpu in cpus:
            mapping[cpu] = node_id
    return mapping


def _cpu_node(cpu: int) -> Optional[int]:
    global _CPU_NODE_MAP
    if _CPU_NODE_MAP is None:
        _CPU_NODE_MAP = _build_cpu_node_map()
    return _CPU_NODE_MAP.get(cpu)


def _collect_cores(skip: Set[int]) -> List[CoreInfo]:
    cores: List[CoreInfo] = []
    seen: Set[Tuple[int, ...]] = set()
    for cpu_path in sorted(SYS_CPU_DIR.glob("cpu[0-9]*"), key=lambda p: int(p.name[3:])):
        cpu_str = cpu_path.name[3:]
        try:
            cpu = int(cpu_str)
        except ValueError:
            continue
        if not _cpu_online(cpu):
            continue
        siblings = _thread_siblings(cpu)
        siblings_tuple = tuple(sorted(siblings))
        if not siblings_tuple:
            continue
        if siblings_tuple in seen:
            continue
        seen.add(siblings_tuple)
        if 0 in siblings_tuple:
            continue
        core_id_text = _read_file(cpu_path / "topology" / "core_id") or cpu_str
        skipped = any(s in skip for s in siblings_tuple)
        cores.append(
            CoreInfo(
                core_id=core_id_text,
                cpus=siblings_tuple,
                contains_cpu0=0 in siblings_tuple,
                skipped=skipped,
                node_id=_cpu_node(cpu),
            )
        )
    cores.sort(key=lambda c: c.primary)
    return cores


def _assign_roles(pairs: Sequence[CoreInfo]) -> Dict[str, Dict[str, object]]:
    roles: Dict[str, Dict[str, object]] = {}
    if pairs:
        server = pairs[0]
        roles["server"] = {
            "core_id": server.core_id,
            "cpu": server.primary,
            "siblings": list(server.siblings),
            "numa_node": server.node_id,
        }
        if server.siblings:
            roles["server"]["reserved"] = list(server.cpus)
    if len(pairs) >= 2:
        client = pairs[1]
        roles["client"] = {
            "core_id": client.core_id,
            "cpu": client.primary,
            "siblings": list(client.siblings),
            "numa_node": client.node_id,
        }
        if client.siblings:
            roles["client"]["reserved"] = list(client.cpus)
    elif pairs:
        # Fallback: reuse the second logical CPU of the first core for the client.
        server = pairs[0]
        alt_cpu = server.siblings[0] if server.siblings else server.primary
        roles["client"] = {
            "core_id": server.core_id,
            "cpu": alt_cpu,
            "siblings": [c for c in server.cpus if c != alt_cpu],
            "numa_node": server.node_id,
        }
    return roles


def _layout_from_pairs(pairs: Sequence[CoreInfo]) -> Dict[str, object]:
    layout_pairs = [
        {
            "core_id": core.core_id,
            "cpus": list(core.cpus),
            "primary": core.primary,
            "siblings": list(core.siblings),
            "numa_node": core.node_id,
        }
        for core in pairs
    ]
    cpuset: List[int] = []
    for core in pairs:
        for cpu in core.cpus:
            if cpu not in cpuset:
                cpuset.append(cpu)
    return {
        "pairs": layout_pairs,
        "cpuset": cpuset,
        "roles": _assign_roles(pairs),
    }


def _describe_cpuset(cpus: Sequence[int]) -> Dict[str, object]:
    seen_core_ids: Set[str] = set()
    pairs: List[CoreInfo] = []
    for cpu in sorted(set(cpus)):
        cpu_path = SYS_CPU_DIR / f"cpu{cpu}"
        if not cpu_path.exists():
            continue
        core_id = _read_file(cpu_path / "topology" / "core_id") or str(cpu)
        if core_id in seen_core_ids:
            continue
        seen_core_ids.add(core_id)
        siblings = _thread_siblings(cpu)
        core = CoreInfo(
            core_id=core_id,
            cpus=tuple(sorted(set(siblings))),
            contains_cpu0=0 in siblings,
            skipped=False,
            node_id=_cpu_node(cpu),
        )
        pairs.append(core)
    pairs.sort(key=lambda c: c.primary)
    layout = _layout_from_pairs(pairs)
    # Mark which CPUs from each pair were explicitly selected.
    selected_lookup = set(cpus)
    for pair in layout["pairs"]:
        pair["selected"] = [cpu for cpu in pair["cpus"] if cpu in selected_lookup]
    return layout


def _order_by_numa(
    cores: Sequence[CoreInfo], prefer_node: Optional[int]
) -> List[CoreInfo]:
    if prefer_node is None:
        return list(cores)
    preferred: List[CoreInfo] = []
    remainder: List[CoreInfo] = []
    for core in cores:
        if core.node_id == prefer_node:
            preferred.append(core)
        else:
            remainder.append(core)
    return preferred + remainder


def select_pairs(
    count: int, skip: Set[int], prefer_node: Optional[int] = None
) -> Dict[str, object]:
    if count <= 0:
        raise ValueError("count must be positive")
    cores = _collect_cores(skip)
    preferred = _order_by_numa([core for core in cores if not core.skipped], prefer_node)
    deferred = _order_by_numa([core for core in cores if core.skipped], prefer_node)
    ordered = preferred + deferred
    selected = ordered[:count]
    if len(selected) < count:
        raise RuntimeError(
            f"only found {len(selected)} suitable core(s) without CPU0; requested {count}"
        )
    return _layout_from_pairs(selected)


def _write_layout(layout: Dict[str, object], path: Optional[str]) -> None:
    if not path:
        return
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(layout, handle, indent=2, sort_keys=True)
        handle.write("\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("count", nargs="?", type=int, help="Number of physical cores to reserve")
    parser.add_argument(
        "--describe",
        metavar="CPUS",
        help="Describe the provided comma-separated CPU list without selecting new cores",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    layout_file = os.environ.get("HOST_TUNING_LAYOUT_FILE")
    skip_env = os.environ.get("HOST_TUNING_SKIP_CPUS", "")
    skip_cpus = set(_expand_cpu_list(skip_env))
    prefer_numa_env = os.environ.get("HOST_TUNING_PREFER_NUMA", "").strip()

    def _parse_prefer_numa(value: str) -> Optional[int]:
        if not value:
            return None
        lowered = value.strip().lower()
        for prefix in ("node", "numa", "socket", "package"):
            if lowered.startswith(prefix):
                lowered = lowered[len(prefix) :]
                break
        lowered = lowered.strip()
        if not lowered:
            return None
        try:
            return int(lowered, 10)
        except ValueError:
            return None

    prefer_node = _parse_prefer_numa(prefer_numa_env)

    if args.describe:
        cpus = _expand_cpu_list(args.describe)
        layout = _describe_cpuset(cpus)
        _write_layout(layout, layout_file)
        if not args.count:
            # For describe operations we do not need to print anything else.
            return 0

    if args.count is None:
        raise SystemExit("count is required when not using --describe")

    try:
        layout = select_pairs(args.count, skip_cpus, prefer_node=prefer_node)
    except Exception as exc:  # pragma: no cover - defensive logging
        raise SystemExit(f"select_physical_cpus.py: {exc}") from exc

    _write_layout(layout, layout_file)
    cpus = layout.get("cpuset", [])
    print(",".join(str(cpu) for cpu in cpus))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
