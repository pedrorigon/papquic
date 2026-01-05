#!/usr/bin/env python3
"""Run QUIC handshake benchmarks for PQC and classical algorithms.

This script also validates the requested algorithm lists before execution.
"""
from __future__ import annotations

import argparse
import csv
import errno
import fcntl
import json
import math
import os
import re
import signal
import statistics
import subprocess
import sys
import time
import unicodedata
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, Union

CLASSIC_GROUPS = ["x25519", "secp256r1", "secp384r1", "secp521r1", "x448"]
CLASSIC_SIGS = ["ED25519", "ED448"]

_CLASSIC_GROUPS_SET = {name.lower() for name in CLASSIC_GROUPS}

_PURE_PQC_GROUPS = {
    "mlkem512",
    "mlkem768",
    "mlkem1024",
    "frodo640aes",
    "frodo640shake",
    "frodo976aes",
    "frodo976shake",
    "frodo1344aes",
    "frodo1344shake",
    "bikel1",
    "bikel3",
    "bikel5",
    "hqc128",
    "hqc192",
    "hqc256",
}

_HYBRID_GROUPS = {
    "secp256r1mlkem768",
    "x25519mlkem768",
    "secp384r1mlkem1024",
    "p256_mlkem512",
    "p384_mlkem768",
    "p521_mlkem1024",
    "x25519_mlkem512",
    "x448_mlkem768",
    "p256_frodo640aes",
    "x25519_frodo640aes",
    "p256_frodo640shake",
    "x25519_frodo640shake",
    "p384_frodo976aes",
    "x448_frodo976aes",
    "p384_frodo976shake",
    "x448_frodo976shake",
    "p521_frodo1344aes",
    "p521_frodo1344shake",
    "p256_bikel1",
    "x25519_bikel1",
    "p384_bikel3",
    "x448_bikel3",
    "p521_bikel5",
    "p256_hqc128",
    "x25519_hqc128",
    "p384_hqc192",
    "x448_hqc192",
    "p521_hqc256",
    "bp256_mlkem512",
    "bp384_mlkem768",
    "bp512_mlkem1024",
}

_PURE_PQC_SIGS = {
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "falcon512",
    "falcon1024",
    "falconpadded512",
    "falconpadded1024",
    "sphincssha2128fsimple",
    "sphincssha2128ssimple",
    "sphincssha2192fsimple",
    "sphincssha2192ssimple",
    "sphincssha2256fsimple",
    "sphincssha2256ssimple",
    "sphincsshake128fsimple",
    "sphincsshake128ssimple",
    "sphincsshake192fsimple",
    "sphincsshake192ssimple",
    "sphincsshake256fsimple",
    "sphincsshake256ssimple",
}

_HYBRID_SIGS = {
    "p256_mldsa44",
    "rsa3072_mldsa44",
    "p384_mldsa65",
    "p521_mldsa87",
    "p256_falcon512",
    "rsa3072_falcon512",
    "p256_falconpadded512",
    "rsa3072_falconpadded512",
    "p521_falcon1024",
    "p521_falconpadded1024",
    "p256_sphincssha2128fsimple",
    "rsa3072_sphincssha2128fsimple",
    "p256_sphincssha2128ssimple",
    "rsa3072_sphincssha2128ssimple",
    "p384_sphincssha2192fsimple",
    "p384_sphincssha2192ssimple",
    "p521_sphincssha2256fsimple",
    "p521_sphincssha2256ssimple",
    "p256_sphincsshake128fsimple",
    "rsa3072_sphincsshake128fsimple",
    "p256_sphincsshake128ssimple",
    "rsa3072_sphincsshake128ssimple",
    "p384_sphincsshake192fsimple",
    "p384_sphincsshake192ssimple",
    "p521_sphincsshake256fsimple",
    "p521_sphincsshake256ssimple",
}


_PQC_KEM_LEVELS: Dict[str, int] = {
    # NIST level 1
    "mlkem512": 1,
    "frodo640aes": 1,
    "frodo640shake": 1,
    "bikel1": 1,
    "hqc128": 1,
    # NIST level 3
    "mlkem768": 3,
    "frodo976aes": 3,
    "frodo976shake": 3,
    "bikel3": 3,
    "hqc192": 3,
    # NIST level 5
    "mlkem1024": 5,
    "frodo1344aes": 5,
    "frodo1344shake": 5,
    "bikel5": 5,
    "hqc256": 5,
}

_PQC_SIG_LEVELS: Dict[str, int] = {
    # NIST level 1
    "mldsa44": 1,
    "falcon512": 1,
    "falconpadded512": 1,
    "sphincssha2128fsimple": 1,
    "sphincssha2128ssimple": 1,
    "sphincsshake128fsimple": 1,
    "sphincsshake128ssimple": 1,
    # NIST level 3
    "mldsa65": 3,
    "sphincssha2192fsimple": 3,
    "sphincssha2192ssimple": 3,
    "sphincsshake192fsimple": 3,
    "sphincsshake192ssimple": 3,
    # NIST level 5
    "mldsa87": 5,
    "falcon1024": 5,
    "falconpadded1024": 5,
    "sphincssha2256fsimple": 5,
    "sphincssha2256ssimple": 5,
    "sphincsshake256fsimple": 5,
    "sphincsshake256ssimple": 5,
}

_CLASSIC_SIGS_SET = {name.lower() for name in CLASSIC_SIGS}


def _build_category_map(
    *,
    classic: Iterable[str],
    pure_pqc: Iterable[str],
    hybrid: Iterable[str],
) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for name in classic:
        mapping[name.lower()] = "classic"
    for name in pure_pqc:
        mapping[name.lower()] = "pqc"
    for name in hybrid:
        mapping[name.lower()] = "pqc-hybrid"
    return mapping


_KEM_CATEGORY_MAP = _build_category_map(
    classic=_CLASSIC_GROUPS_SET,
    pure_pqc=_PURE_PQC_GROUPS,
    hybrid=_HYBRID_GROUPS,
)

_SIG_CATEGORY_MAP = _build_category_map(
    classic=_CLASSIC_SIGS_SET,
    pure_pqc=_PURE_PQC_SIGS,
    hybrid=_HYBRID_SIGS,
)


def _build_mode_allow_list(category_map: Dict[str, str]) -> Dict[str, FrozenSet[str]]:
    classic_names: Set[str] = {name for name, category in category_map.items() if category == "classic"}
    pqc_only: Set[str] = {name for name, category in category_map.items() if category == "pqc"}
    hybrid_names: Set[str] = {name for name, category in category_map.items() if category == "pqc-hybrid"}
    all_names: Set[str] = set(category_map.keys())
    pqc_names = classic_names | pqc_only
    return {
        "all": frozenset(all_names),
        "pqc": frozenset(pqc_names),
        "pqc-level": frozenset(pqc_only),
        "hybrid": frozenset(hybrid_names),
        "classic": frozenset(classic_names),
    }


_MODE_ALLOWED_KEM_NAMES = _build_mode_allow_list(_KEM_CATEGORY_MAP)
_MODE_ALLOWED_SIG_NAMES = _build_mode_allow_list(_SIG_CATEGORY_MAP)

DEFAULT_COUNT = 50
SERVER_PORT = 4433
SERVER_HOST = "127.0.0.1"

OPENSSL_ROOT = Path("/app/openssl-3.6.0")
OPENSSL_BIN = OPENSSL_ROOT / "apps" / "openssl"
SERVER_BIN = OPENSSL_ROOT / "demos" / "quic" / "server" / "server"
PROVIDER_MODULE = Path("/app/oqs-provider/_build/lib/oqsprovider.so")
OPENSSL_CONFIG = Path("/app/config/openssl-oqs.cnf")
DEFAULT_QUIC_MODE = 0
HANDSHAKE_TIMEOUT_SECONDS = 10

QUIC_MODE_LABELS = {
    0: "default",
    1: "unlimited credit",
    2: "reserved",
    3: "retry validation",
}

QUIC_MODE_SUMMARY = {
    0: "RFC 9000 Default (1-RTT, 3x amplification, no RETRY)",
    1: "Unlimited Amplification (1-RTT, no limit, no RETRY)",
    2: "Reserved (no additional behaviour)",
    3: "RETRY-based Validation (2-RTT, early validation, then unlimited)",
}


def describe_quic_mode(mode: int) -> str:
    label = QUIC_MODE_LABELS.get(mode, "custom")
    return f"{mode} - {label}"


def quic_mode_summary(mode: int) -> str:
    return QUIC_MODE_SUMMARY.get(mode, f"Mode {mode}")

_DEFAULT_WANTED_KEMS_STR = (
    "MLKEM512:MLKEM768:MLKEM1024:"
    "SecP256r1MLKEM768:X25519MLKEM768:SecP384r1MLKEM1024:"
    "p256_mlkem512:p384_mlkem768:p521_mlkem1024:x25519_mlkem512:x448_mlkem768:"
    "frodo640aes:p256_frodo640aes:x25519_frodo640aes:"
    "frodo640shake:p256_frodo640shake:x25519_frodo640shake:"
    "frodo976aes:p384_frodo976aes:x448_frodo976aes:"
    "frodo976shake:p384_frodo976shake:x448_frodo976shake:"
    "frodo1344aes:p521_frodo1344aes:"
    "frodo1344shake:p521_frodo1344shake:"
    "bikel1:p256_bikel1:x25519_bikel1:"
    "bikel3:p384_bikel3:x448_bikel3:"
    "bikel5:p521_bikel5:"
    "hqc128:p256_hqc128:x25519_hqc128:hqc192:p384_hqc192:"
    "x448_hqc192:hqc256:p521_hqc256:"
    "bp256_mlkem512:bp384_mlkem768:bp512_mlkem1024"
)

_DEFAULT_WANTED_SIGS = [
    "MLDSA44","MLDSA65","MLDSA87",
    "p256_mldsa44","rsa3072_mldsa44","p384_mldsa65","p521_mldsa87",
    "falcon512","falcon1024",
    "p256_falcon512","rsa3072_falcon512",
    "falconpadded512","p256_falconpadded512","rsa3072_falconpadded512",
    "p521_falcon1024",
    "falconpadded1024","p521_falconpadded1024",
    "sphincssha2128fsimple","p256_sphincssha2128fsimple","rsa3072_sphincssha2128fsimple",
    "sphincssha2128ssimple","p256_sphincssha2128ssimple","rsa3072_sphincssha2128ssimple",
    "sphincssha2192fsimple","p384_sphincssha2192fsimple",
    "sphincssha2192ssimple","p384_sphincssha2192ssimple",
    "sphincssha2256fsimple","p521_sphincssha2256fsimple",
    "sphincssha2256ssimple","p521_sphincssha2256ssimple",
    "sphincsshake128fsimple","p256_sphincsshake128fsimple","rsa3072_sphincsshake128fsimple",
    "sphincsshake128ssimple","p256_sphincsshake128ssimple","rsa3072_sphincsshake128ssimple",
    "sphincsshake192fsimple","p384_sphincsshake192fsimple",
    "sphincsshake192ssimple","p384_sphincsshake192ssimple",
    "sphincsshake256fsimple","p521_sphincsshake256fsimple",
    "sphincsshake256ssimple","p521_sphincsshake256ssimple",
]


def _parse_env_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    parts = re.split(r"[:,\s]+", value.strip())
    return [p for p in parts if p]

def _wanted_kems() -> List[str]:
    env_list = _parse_env_list(os.environ.get("WANTED_KEMS"))
    if env_list:
        return env_list
    return [k for k in _DEFAULT_WANTED_KEMS_STR.split(":") if k]

def _wanted_sigs() -> List[str]:
    env_list = _parse_env_list(os.environ.get("WANTED_SIGS"))
    if env_list:
        return env_list
    return list(_DEFAULT_WANTED_SIGS)

ENV_PIN_SERVER = os.environ.get("PIN_SERVER_CPU")
ENV_PIN_CLIENT = os.environ.get("PIN_CLIENT_CPU")
HOST_TUNING_STATE_FILE = os.environ.get("HOST_TUNING_STATE_FILE")
HOST_TUNING_STATE_JSON = os.environ.get("HOST_TUNING_STATE_JSON")
_HOST_TUNING_STATE_CACHE: Optional[Dict[str, object]] = None
_HOST_TUNING_STATE_MTIME: Optional[float] = None
_HOST_TUNING_STATE_SOURCE: Optional[Tuple[str, Optional[float]]] = None
_HOST_TUNING_OVERVIEW_PRINTED = False
_BENCHMARK_DEBUG_ENABLED = False


def set_benchmark_debug_enabled(enabled: bool) -> None:
    global _BENCHMARK_DEBUG_ENABLED
    _BENCHMARK_DEBUG_ENABLED = bool(enabled)


def benchmark_debug_enabled() -> bool:
    return _BENCHMARK_DEBUG_ENABLED


def _scheduler_name(policy: int) -> str:
    mapping = {
        getattr(os, "SCHED_OTHER", 0): "SCHED_OTHER",
        getattr(os, "SCHED_FIFO", 1): "SCHED_FIFO",
        getattr(os, "SCHED_RR", 2): "SCHED_RR",
        getattr(os, "SCHED_BATCH", 3): "SCHED_BATCH",
        getattr(os, "SCHED_IDLE", 5): "SCHED_IDLE",
    }
    return mapping.get(policy, f"POLICY_{policy}")


def _update_host_tuning_state(role: str, payload: Dict[str, Union[int, str, List[str], None]]) -> None:
    if not HOST_TUNING_STATE_FILE:
        return
    try:
        with open(HOST_TUNING_STATE_FILE, "r+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                state = json.load(handle)
            except json.JSONDecodeError:
                state = {}
            priority = state.setdefault("priority", {})
            applied = priority.setdefault("applied", {})
            entry = applied.setdefault(role, {})
            entry.update(payload)
            entry["timestamp"] = datetime.now().isoformat()
            handle.seek(0)
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.truncate()
    except FileNotFoundError:
        return
    except Exception as exc:  # pragma: no cover - best effort logging
        debug(f"host tuning state update failed for {role}: {exc}")

@dataclass
class AlgorithmCombo:
    kem: str
    signature: str
    kem_category: str  # pqc, pqc-hybrid, classic
    sig_category: str  # pqc, pqc-hybrid, classic
    groups_argument: str
    signature_id: str

@dataclass
class BenchmarkResult:
    combo: AlgorithmCombo
    iterations: int
    outliers_removed: int
    values_ms: List[float]
    mean_ms: float
    std_ms: float
    ci95_low_ms: float
    ci95_high_ms: float
    quic_mode: int
    quic_mode_label: str
    loss_profile: str

class BenchmarkError(RuntimeError):
    pass


class HandshakeTimeout(BenchmarkError):
    """Raised when a client handshake exceeds the configured timeout."""


@dataclass(frozen=True)
class NetemProfile:
    key: str
    description: str
    netem_args: Tuple[str, ...]
    reverse_netem_args: Optional[Tuple[str, ...]] = None
    enabled: bool = True
    kind: str = "random"

    def forward_args(self) -> Tuple[str, ...]:
        return self.netem_args

    def reverse_args(self) -> Tuple[str, ...]:
        return self.reverse_netem_args or self.netem_args


DEFAULT_NETEM_INTERFACE = "lo"
DEFAULT_LOSS_PROFILE = "0"


def _format_percentage(value: float) -> str:
    formatted = f"{value:.3f}".rstrip("0").rstrip(".")
    return formatted or "0"


def _make_random_profile(key: str, percent: float) -> NetemProfile:
    pct = _format_percentage(percent)
    return NetemProfile(
        key=key,
        description=f"Independent random loss of {pct}%",
        netem_args=("loss", f"{pct}%"),
    )


NETEM_PROFILES: Dict[str, NetemProfile] = {
    "0": NetemProfile(
        key="0",
        description="No loss (no netem discipline applied)",
        netem_args=tuple(),
        enabled=False,
    ),
    "0.1": _make_random_profile("0.1", 0.1),
    "0.5": _make_random_profile("0.5", 0.5),
    "1": _make_random_profile("1", 1.0),
    "2": _make_random_profile("2", 2.0),
    "5": _make_random_profile("5", 5.0),
    "10": _make_random_profile("10", 10.0),
    "15": _make_random_profile("15", 15.0),
    "20": _make_random_profile("20", 20.0),
    "25": _make_random_profile("25", 25.0),
    "30": _make_random_profile("30", 30.0),
    "bursty": NetemProfile(
        key="bursty",
        description=(
            "Gilbert–Elliott model (loss state 0.03/0.3) with ≈9% average loss and short bursts"
        ),
        netem_args=("loss", "state", "0.03", "0.3"),
        kind="gilbert-elliott",
    ),
}

LOSS_PROFILE_CHOICES: Tuple[str, ...] = tuple(NETEM_PROFILES.keys())
PRINT_MODE_CHOICES: Tuple[str, ...] = ("benchmark", "debug", "packet")


def get_loss_profile(name: str) -> NetemProfile:
    try:
        return NETEM_PROFILES[name]
    except KeyError as exc:
        raise BenchmarkError(f"Unknown loss profile: {name}") from exc


def format_loss_profile_label(profile: NetemProfile) -> str:
    """Return the label used in CSV outputs for a given loss profile."""

    return "off" if profile.key == "0" else profile.key


def _format_loss_segment(value: str) -> str:
    cleaned = value.replace("%", "").strip()
    return cleaned or "0"


def build_results_directory(
    base_dir: Path,
    *,
    mode: str,
    print_mode: str,
    quic_mode: int = DEFAULT_QUIC_MODE,
    loss_profile_key: str,
    timestamp: Optional[datetime] = None,
) -> Path:
    ts = timestamp or datetime.now()
    date_fragment = f"{ts.day:02d}-{ts.month:02d}-{ts.year:04d}"
    time_fragment = f"{ts.hour:02d}H{ts.minute:02d}M{ts.second:02d}S"
    directory_name = (
        f"{print_mode.upper()}"
        f"-QUIC-OPTION-{quic_mode}_"
        f"ALGORITHMS-SET-{mode.upper()}_"
        f"LOSS-PROFILE-{_format_loss_segment(loss_profile_key)}_"
        f"{date_fragment}_{time_fragment}"
    )
    result_dir = base_dir / directory_name
    result_dir.mkdir(parents=True, exist_ok=True)
    return result_dir


class NetemManager:
    def __init__(self, interface: str, server_port: int) -> None:
        self.interface = interface
        self.server_port = server_port
        self._active = False

    def _run_tc(self, args: Sequence[str], *, check: bool) -> subprocess.CompletedProcess:
        cmd = ["tc", *args]
        try:
            return run_command(cmd, check=check, capture_output=True)
        except FileNotFoundError as exc:
            raise BenchmarkError(
                "tc command not found; install iproute2 or use --loss-profile 0"
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            stdout = (exc.stdout or "").strip()
            details = stderr or stdout
            detail_msg = f": {details}" if details else ""
            raise BenchmarkError(
                f"Failed to execute {' '.join(cmd)} (exit {exc.returncode}){detail_msg}"
            ) from exc

    def apply(self, profile: NetemProfile) -> None:
        if not profile.enabled:
            return

        self._run_tc(["qdisc", "del", "dev", self.interface, "root"], check=False)

        try:
            self._run_tc(
                ["qdisc", "replace", "dev", self.interface, "root", "handle", "1:", "prio", "bands", "3"],
                check=True,
            )
            self._run_tc(
                ["qdisc", "replace", "dev", self.interface, "parent", "1:1", "handle", "10:", "netem", *profile.forward_args()],
                check=True,
            )
            self._run_tc(
                ["qdisc", "replace", "dev", self.interface, "parent", "1:2", "handle", "20:", "netem", *profile.reverse_args()],
                check=True,
            )
            self._run_tc(
                [
                    "filter",
                    "replace",
                    "dev",
                    self.interface,
                    "protocol",
                    "ip",
                    "parent",
                    "1:0",
                    "prio",
                    "1",
                    "u32",
                    "match",
                    "ip",
                    "protocol",
                    "17",
                    "0xff",
                    "match",
                    "ip",
                    "dport",
                    str(self.server_port),
                    "0xffff",
                    "flowid",
                    "1:1",
                ],
                check=True,
            )
            self._run_tc(
                [
                    "filter",
                    "replace",
                    "dev",
                    self.interface,
                    "protocol",
                    "ip",
                    "parent",
                    "1:0",
                    "prio",
                    "2",
                    "u32",
                    "match",
                    "ip",
                    "protocol",
                    "17",
                    "0xff",
                    "match",
                    "ip",
                    "sport",
                    str(self.server_port),
                    "0xffff",
                    "flowid",
                    "1:2",
                ],
                check=True,
            )
        except BenchmarkError:
            self.clear()
            raise

        self._active = True

    def clear(self) -> None:
        if not self._active:
            return
        try:
            self._run_tc(["qdisc", "del", "dev", self.interface, "root"], check=False)
        finally:
            self._active = False


@contextmanager
def apply_netem_profile(
    profile: NetemProfile, *, interface: str = DEFAULT_NETEM_INTERFACE, server_port: int = SERVER_PORT
):
    manager = NetemManager(interface, server_port)
    try:
        manager.apply(profile)
        yield profile
    finally:
        manager.clear()

def debug(msg: str) -> None:
    if not benchmark_debug_enabled():
        return
    print(f"[benchmark] {msg}", flush=True)

def _colour(text: str, code: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m"


def _bold(text: str) -> str:
    return _colour(text, "1")


def _cyan(text: str) -> str:
    return _colour(text, "36")


def _green(text: str) -> str:
    return _colour(text, "32")


def _yellow(text: str) -> str:
    return _colour(text, "33")


def _magenta(text: str) -> str:
    return _colour(text, "35")


def _red(s: str) -> str:
    return _colour(s, "31")


def _format_config_line(label: str, value: str, *, colour: Optional[str] = None) -> str:
    label_text = _bold(f"{label}:")
    if colour == "green":
        value_text = _green(value)
    elif colour == "yellow":
        value_text = _yellow(value)
    elif colour == "magenta":
        value_text = _magenta(value)
    elif colour == "cyan":
        value_text = _cyan(value)
    else:
        value_text = value
    return f"{label_text} {value_text}"


def _allowed_cpus() -> List[int]:
    try:
        return sorted(os.sched_getaffinity(0))
    except Exception:
        return [0]

def _pick_server_client_cpus() -> Tuple[int, int]:
    if ENV_PIN_SERVER is not None and ENV_PIN_CLIENT is not None:
        try:
            return int(ENV_PIN_SERVER), int(ENV_PIN_CLIENT)
        except ValueError:
            pass
    cpus = _allowed_cpus()
    if len(cpus) >= 2:
        return cpus[0], cpus[1]
    return cpus[0], cpus[0]

SERVER_CPU, CLIENT_CPU = _pick_server_client_cpus()


def _load_host_tuning_state() -> Optional[Dict[str, object]]:
    global _HOST_TUNING_STATE_CACHE, _HOST_TUNING_STATE_MTIME, _HOST_TUNING_STATE_SOURCE

    if HOST_TUNING_STATE_JSON:
        if (
            _HOST_TUNING_STATE_CACHE is not None
            and _HOST_TUNING_STATE_SOURCE == ("env", None)
        ):
            return _HOST_TUNING_STATE_CACHE
        try:
            data = json.loads(HOST_TUNING_STATE_JSON)
        except json.JSONDecodeError:
            data = None
        if data is None:
            return None
        _HOST_TUNING_STATE_CACHE = data
        _HOST_TUNING_STATE_SOURCE = ("env", None)
        _HOST_TUNING_STATE_MTIME = None
        return data

    if not HOST_TUNING_STATE_FILE:
        return None
    try:
        stat_info = os.stat(HOST_TUNING_STATE_FILE)
    except OSError:
        return None
    if (
        _HOST_TUNING_STATE_CACHE is not None
        and _HOST_TUNING_STATE_MTIME == stat_info.st_mtime
        and _HOST_TUNING_STATE_SOURCE == ("file", stat_info.st_mtime)
    ):
        return _HOST_TUNING_STATE_CACHE
    try:
        with open(HOST_TUNING_STATE_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    _HOST_TUNING_STATE_CACHE = data
    _HOST_TUNING_STATE_MTIME = stat_info.st_mtime
    _HOST_TUNING_STATE_SOURCE = ("file", stat_info.st_mtime)
    return data


def _host_tuning_cpuset() -> Set[int]:
    layout = _load_host_tuning_state()
    if not layout:
        return set()
    cpuset_raw = layout.get("cpuset")
    cpus: Set[int] = set()
    if isinstance(cpuset_raw, list):
        for value in cpuset_raw:
            if isinstance(value, int):
                cpus.add(value)
            elif isinstance(value, str) and value.isdigit():
                cpus.add(int(value))
    return cpus


def _role_cpu_ids(logical_role: str) -> Tuple[int, ...]:
    layout = _load_host_tuning_state()
    if not layout:
        return ()
    roles = layout.get("roles") or {}
    info = roles.get(logical_role)
    if not isinstance(info, dict):
        return ()
    cpus: List[int] = []
    reserved = info.get("reserved")
    if isinstance(reserved, list) and reserved:
        cpus.extend(int(cpu) for cpu in reserved if isinstance(cpu, int))
    else:
        cpu = info.get("cpu")
        if isinstance(cpu, int):
            cpus.append(cpu)
        siblings = info.get("siblings") or []
        for sibling in siblings:
            if isinstance(sibling, int):
                cpus.append(sibling)
    if not cpus:
        return ()
    seen: Dict[int, None] = {}
    ordered: List[int] = []
    for cpu in cpus:
        if cpu not in seen:
            seen[cpu] = None
            ordered.append(cpu)
    return tuple(ordered)


def _role_core_id(logical_role: str) -> Optional[str]:
    layout = _load_host_tuning_state()
    if not layout:
        return None
    roles = layout.get("roles") or {}
    info = roles.get(logical_role)
    if not isinstance(info, dict):
        return None
    core = info.get("core_id")
    if isinstance(core, str) and core:
        return core
    return None


def _host_tuning_role_message(logical_role: str) -> Optional[str]:
    layout = _load_host_tuning_state()
    if not layout:
        return None
    roles = layout.get("roles") or {}
    info = roles.get(logical_role)
    if not isinstance(info, dict):
        return None
    cpu = info.get("cpu")
    siblings_raw = info.get("siblings") or []
    siblings: List[int] = []
    for entry in siblings_raw:
        if isinstance(entry, int):
            siblings.append(entry)
        elif isinstance(entry, str) and entry.isdigit():
            siblings.append(int(entry))
    label = logical_role.capitalize()
    if siblings:
        sibling_text = ", ".join(str(s) for s in siblings)
        return f"[host-tuning] {label} primary CPU {cpu} with sibling(s) {sibling_text} reserved"
    if cpu is None:
        return None
    return f"[host-tuning] {label} primary CPU {cpu} (no additional siblings)"


def _host_tuning_overview_lines() -> List[str]:
    layout = _load_host_tuning_state()
    lines: List[str] = []
    prefix = _cyan("[host-tuning]")
    if not layout:
        lines.append(
            f"{prefix} Host tuning state unavailable; proceeding with fallback CPU layout"
        )
        return lines

    cpuset = layout.get("cpuset")
    if isinstance(cpuset, list) and cpuset:
        cpuset_values = [
            int(value) for value in cpuset if isinstance(value, int) or str(value).isdigit()
        ]
        if cpuset_values:
            cpu_text = ", ".join(str(value) for value in sorted(set(cpuset_values)))
            lines.append(
                f"{prefix} Reserved CPU set for benchmark scope: {_bold(cpu_text)}"
            )

    for logical_role in ("client", "server"):
        message = _host_tuning_role_message(logical_role)
        if message:
            lines.append(f"{prefix} {message.split('] ', 1)[-1]}")

    return lines


def _log_host_tuning_overview() -> None:
    if not benchmark_debug_enabled():
        return
    for line in _host_tuning_overview_lines():
        print(line, flush=True)


def _ensure_host_tuning_overview_logged() -> None:
    global _HOST_TUNING_OVERVIEW_PRINTED
    if _HOST_TUNING_OVERVIEW_PRINTED or not benchmark_debug_enabled():
        return
    _log_host_tuning_overview()
    _HOST_TUNING_OVERVIEW_PRINTED = True


def _format_cpu_set(cpu_ids: Sequence[int]) -> str:
    unique = []
    seen: Dict[int, None] = {}
    for cpu in cpu_ids:
        if cpu not in seen:
            seen[cpu] = None
            unique.append(cpu)
    if not unique:
        return "<unassigned>"
    if len(unique) == 1:
        return str(unique[0])
    return ",".join(str(cpu) for cpu in unique)


def _select_cpu_ids(
    cpu_id: Optional[int], logical_role: Optional[str]
) -> Tuple[int, ...]:
    if logical_role:
        cpus = _role_cpu_ids(logical_role)
        if cpus:
            return cpus
    if cpu_id is None:
        return ()
    return (cpu_id,)


def _preexec_for(
    cpu_id: Optional[int],
    *,
    role: str = "process",
    logical_role: Optional[str] = None,
    apply_priority: bool = False,
):
    cpu_ids = _select_cpu_ids(cpu_id, logical_role)
    cpu_set = set(cpu_ids)

    def _fn():
        affinity_messages: List[str] = []
        affinity_target = cpu_set or ({cpu_id} if cpu_id is not None else set())
        requested_label = _format_cpu_set(sorted(affinity_target))
        reserved_cpu_hint = _host_tuning_cpuset()
        available_cpus: Optional[Set[int]] = None
        available_cpus_sorted: Optional[List[int]] = None

        if affinity_target:
            try:
                available_cpus = set(os.sched_getaffinity(0))
            except Exception as exc:  # pragma: no cover - best effort logging
                debug(
                    f"{role}: unable to determine available CPUs for affinity: {exc}"
                )
            else:
                unavailable = affinity_target - available_cpus
                available_cpus_sorted = sorted(available_cpus)
                if unavailable:
                    unavailable_sorted = sorted(unavailable)
                    container_label = _format_cpu_set(available_cpus_sorted)
                    if reserved_cpu_hint and affinity_target <= reserved_cpu_hint:
                        reserved_label = _format_cpu_set(sorted(reserved_cpu_hint))
                        affinity_messages.append(
                            "Requested CPU(s) outside the container allowed set "
                            f"({container_label}) but reserved by host-tuning "
                            f"({reserved_label}); keeping original request"
                        )
                        debug(
                            f"{role}: requested CPU(s) {requested_label} not in "
                            f"container allowed set {container_label}; "
                            f"trusting host-tuning reservation {reserved_label}"
                        )
                    else:
                        affinity_messages.append(
                            "Requested CPU(s) "
                            f"{_format_cpu_set(unavailable_sorted)} unavailable; "
                            f"container allows {container_label}"
                        )
                        debug(
                            f"{role}: requested CPU(s) {requested_label} include "
                            f"unavailable CPU(s) {_format_cpu_set(unavailable_sorted)}; "
                            f"allowed set is {container_label}"
                        )
                        affinity_target &= available_cpus

                if not affinity_target:
                    fallback_pool: Set[int] = set(available_cpus or set())
                    if not fallback_pool and reserved_cpu_hint:
                        fallback_pool = set(reserved_cpu_hint)
                    if fallback_pool:
                        fallback_cpu = min(fallback_pool)
                    else:
                        fallback_cpu = None
                    if fallback_cpu is not None:
                        affinity_target = {fallback_cpu}
                        affinity_messages.append(
                            f"Falling back to container-allowed CPU {fallback_cpu}"
                        )
                        debug(
                        f"{role}: falling back to CPU {fallback_cpu} permitted by container"
                    )

        applied_affinity: List[int] = []

        if not affinity_target:
            debug(
                f"{role}: no valid CPU available for affinity request "
                f"(requested {requested_label})"
            )
            if not apply_priority:
                _update_host_tuning_state(
                    role,
                    {
                        "cpu": None,
                        "cpus": [],
                        "messages": affinity_messages
                        or [
                            "No valid CPU available to apply affinity",
                        ],
                    },
                )
            return

        try:
            os.sched_setaffinity(0, affinity_target)
        except Exception as exc:
            hint = ""
            if (
                isinstance(exc, OSError)
                and exc.errno == errno.EINVAL
                and affinity_target
            ):
                hint = (
                    " — verify the container exposes these CPUs (HOST_TUNING_CPUS/"
                    "--cpuset-cpus), confirm they are online on the host, and ensure "
                    "the process has CAP_SYS_NICE"
                )
            debug(
                f"{role}: failed to pin to CPU(s) "
                f"{_format_cpu_set(sorted(affinity_target))}: {exc}{hint}"
            )
            affinity_messages.append(
                f"Failed to apply affinity: {exc}{hint}"
            )
            fallback_pool: Set[int] = set(available_cpus or set())
            if not fallback_pool and reserved_cpu_hint:
                fallback_pool = set(reserved_cpu_hint)
            if fallback_pool:
                fallback_cpu = min(fallback_pool)
                try:
                    os.sched_setaffinity(0, {fallback_cpu})
                except Exception as fallback_exc:
                    debug(
                        f"{role}: fallback to CPU {fallback_cpu} failed: {fallback_exc}"
                    )
                    affinity_messages.append(
                        f"Fallback affinity application failed: {fallback_exc}"
                    )
                else:
                    affinity_messages.append(
                        f"Applied fallback affinity: {fallback_cpu}"
                    )
                    debug(
                        f"{role}: fallback pinned to CPU(s) {fallback_cpu}"
                    )
                    applied_affinity = [fallback_cpu]
                    affinity_target = {fallback_cpu}
        else:
            debug(
                f"{role}: pinned to CPU(s) "
                f"{_format_cpu_set(sorted(affinity_target))}"
            )
            affinity_messages.append(
                f"Applied affinity: {_format_cpu_set(sorted(affinity_target))}"
            )
            applied_affinity = sorted(affinity_target)

        if not apply_priority:
            _update_host_tuning_state(
                role,
                {
                    "cpu": applied_affinity[0] if applied_affinity else None,
                    "cpus": applied_affinity,
                    "messages": affinity_messages
                    or [
                        f"affinity applied for {role}: "
                        f"{_format_cpu_set(sorted(affinity_target))}",
                    ],
                },
            )
            return

        priority_messages: List[str] = []
        requested_nice: Optional[int] = -20
        nice_applied = False
        try:
            os.setpriority(os.PRIO_PROCESS, 0, -20)
        except Exception as exc:
            priority_messages.append(
                f"failed to setpriority(-20) for {role}: {exc}"
            )
        else:
            priority_messages.append(
                f"setpriority(-20) succeeded for {role}"
            )
            nice_applied = True

        sched_applied = False
        sched_policy_name: Optional[str] = None
        sched_priority_value: Optional[int] = None
        try:
            os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(99))
        except Exception as exc:
            priority_messages.append(
                f"failed to apply sched_setscheduler(SCHED_FIFO, 99) for {role}: {exc}"
            )
        else:
            sched_applied = True
            priority_messages.append(
                f"sched_setscheduler(SCHED_FIFO, 99) succeeded for {role}"
            )

        current_nice: Optional[int] = None
        try:
            current_nice = os.getpriority(os.PRIO_PROCESS, 0)
        except Exception as exc:
            priority_messages.append(
                f"could not read nice level for {role}: {exc}"
            )
        else:
            priority_messages.append(
                f"effective nice level for {role}: {current_nice}"
            )
            if current_nice == -20:
                priority_messages.append(
                    f"confirmed nice level -20 for {role}"
                )

        try:
            policy_value = os.sched_getscheduler(0)
            sched_policy_name = _scheduler_name(policy_value)
            sched_priority_value = os.sched_getparam(0).sched_priority
        except Exception as exc:
            priority_messages.append(
                f"could not read scheduler state for {role}: {exc}"
            )
        else:
            priority_messages.append(
                f"scheduler for {role}: {sched_policy_name} (priority {sched_priority_value})"
            )
            if sched_policy_name == "SCHED_FIFO" and sched_priority_value == 99:
                priority_messages.append(
                    f"confirmed FIFO priority 99 for {role}"
                )

        success = (
            nice_applied
            and current_nice == -20
            and sched_applied
            and sched_policy_name == "SCHED_FIFO"
            and sched_priority_value == 99
        )

        _update_host_tuning_state(
            role,
            {
                "cpu": next(iter(affinity_target), None),
                "cpus": sorted(affinity_target),
                "requested_nice": requested_nice,
                "nice": current_nice,
                "setpriority_succeeded": nice_applied,
                "sched_setscheduler_succeeded": sched_applied,
                "scheduler": sched_policy_name,
                "rt_priority": sched_priority_value,
                "messages": list(priority_messages),
            },
        )

        for message in priority_messages:
            debug(message)

        if not success:
            debug(
                f"{role}: failed to guarantee real-time priority (nice -20 + FIFO 99); aborting"
            )
            os._exit(125)

    return _fn


def _log_process_priority(pid: int, role: str) -> None:
    try:
        affinity = sorted(os.sched_getaffinity(pid))
        debug(
            f"{role}: current CPU affinity {_format_cpu_set(affinity)}"
        )
    except Exception as exc:
        debug(f"{role}: could not read CPU affinity: {exc}")

    try:
        nice_level = os.getpriority(os.PRIO_PROCESS, pid)
        debug(f"{role}: current nice level {nice_level}")
    except Exception as exc:
        debug(f"{role}: could not read nice level: {exc}")

    try:
        policy_value = os.sched_getscheduler(pid)
        policy_name = _scheduler_name(policy_value)
        priority_value = os.sched_getparam(pid).sched_priority
        debug(f"{role}: scheduler {policy_name} (priority {priority_value})")
    except Exception as exc:
        debug(f"{role}: could not read scheduler configuration: {exc}")

def run_command(
    cmd: Sequence[str],
    *,
    env: Optional[Dict[str, str]] = None,
    capture_output: bool = False,
    check: bool = True,
    text: bool = True,
    preexec_fn=None,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    debug("running command: " + " ".join(cmd))
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        env=env,
        text=text,
        stdin=subprocess.DEVNULL,
        preexec_fn=preexec_fn,
        timeout=timeout,
    )


def _ensure_text(data: Union[str, bytes, None]) -> str:
    """Return *data* as a str, decoding bytes when necessary."""

    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _parse_openssl_list_names(output: str) -> List[str]:
    names: List[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith(("providers:", "cipher", "mac", "message", "algorithms:", "loaded providers")):
            continue
        if line.startswith("{"):
            m = re.search(r"\{([^}]*)\}", line)
            if m:
                inside = m.group(1)
                parts = [p.strip() for p in inside.split(",") if p.strip()]
                if parts:
                    names.append(parts[-1])
            continue
        candidate = line.split()[0].strip(",{}")
        if candidate and candidate != "@":
            names.append(candidate)
    seen: Dict[str, None] = {}
    out: List[str] = []
    for n in names:
        if n not in seen:
            seen[n] = None
            out.append(n)
    return out

def list_available(openssl_cmd: Sequence[str], keyword: str) -> List[str]:
    env = default_env()
    role = f"openssl-list:{keyword.replace(' ', '-')}"
    try:
        proc = run_command(
            list(openssl_cmd),
            env=env,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        stdout = exc.stdout or ""
        raise BenchmarkError(
            "Failed to query available "
            f"{keyword}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        ) from exc
    items = _parse_openssl_list_names(proc.stdout)
    debug(f"found {len(items)} {keyword}")
    return items

def _normalize_group_entries(entries: Sequence[str]) -> List[str]:
    seen: Dict[str, None] = {}
    for entry in entries:
        fragments = entry.split(":") if ":" in entry else [entry]
        for fragment in fragments:
            fragment = fragment.strip()
            if not fragment:
                continue
            if fragment.lower() in {"tls", "groups"}:
                continue
            if fragment not in seen:
                seen[fragment] = None
    return list(seen.keys())

def available_groups() -> List[str]:
    errors = []
    for flag in ("-tls-groups", "-groups"):
        try:
            raw_entries = list_available([str(OPENSSL_BIN), "list", flag], "groups")
        except BenchmarkError as exc:
            errors.append(str(exc))
            continue
        return _normalize_group_entries(raw_entries)
    raise BenchmarkError(
        "Failed to query available groups with any known flag.\n" +
        "\n".join(errors)
    )

def available_signatures() -> List[str]:
    return list_available([str(OPENSSL_BIN), "list", "-signature-algorithms"],
                          "signature algorithms")

def classify_group(name: str) -> str:
    lower = name.lower()
    try:
        return _KEM_CATEGORY_MAP[lower]
    except KeyError as exc:
        raise BenchmarkError(
            f"KEM/Group '{name}' is not present in the configured classification lists"
        ) from exc


def classify_signature(name: str) -> str:
    lower = name.lower()
    try:
        return _SIG_CATEGORY_MAP[lower]
    except KeyError as exc:
        raise BenchmarkError(
            f"Signature '{name}' is not present in the configured classification lists"
        ) from exc


def _kem_nist_level(name: str) -> int:
    lower = name.lower()
    try:
        return _PQC_KEM_LEVELS[lower]
    except KeyError as exc:
        raise BenchmarkError(
            f"KEM/Group '{name}' does not have an associated NIST level classification"
        ) from exc


def _sig_nist_level(name: str) -> int:
    lower = name.lower()
    try:
        return _PQC_SIG_LEVELS[lower]
    except KeyError as exc:
        raise BenchmarkError(
            f"Signature '{name}' does not have an associated NIST level classification"
        ) from exc

def build_algorithm_matrix(mode: str, specific_kem: Optional[str],
                           specific_sig: Optional[str]) -> List[AlgorithmCombo]:
    groups_avail = available_groups()
    sigs_avail = available_signatures()

    wanted_kems = _wanted_kems()
    wanted_sigs = _wanted_sigs()

    def _resolve_available(
        wanted: Sequence[str],
        available: Sequence[str],
    ) -> Tuple[List[str], List[str]]:
        normalised: Dict[str, str] = {name.lower(): name for name in available}
        selected: List[str] = []
        missing: List[str] = []
        for entry in wanted:
            resolved = normalised.get(entry.lower())
            if resolved:
                if resolved not in selected:
                    selected.append(resolved)
            else:
                missing.append(entry)
        return selected, missing

    selected_kems, missing_kems = _resolve_available(wanted_kems, groups_avail)

    selected_sigs, missing_sigs = _resolve_available(wanted_sigs, sigs_avail)

    classic_groups = [g for g in groups_avail if _KEM_CATEGORY_MAP.get(g.lower()) == "classic"]
    classic_sigs = [s for s in sigs_avail if _SIG_CATEGORY_MAP.get(s.lower()) == "classic"]

    for g in missing_kems:
        print(
            _red(f"[warn] KEM/Group not present in the current build: {g}"),
            file=sys.stderr,
            flush=True,
        )
    for s in missing_sigs:
        print(
            _red(f"[warn] Signature not present in the current build: {s}"),
            file=sys.stderr,
            flush=True,
        )

    combos: List[AlgorithmCombo] = []
    seen_pairs = set()

    def add_combo(kem_name: str, sig_name: str) -> None:
        key = (kem_name.lower(), sig_name.lower())
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        kem_category = classify_group(kem_name)
        sig_category = classify_signature(sig_name)
        combos.append(
            AlgorithmCombo(
                kem=kem_name,
                signature=sig_name,
                kem_category=kem_category,
                sig_category=sig_category,
                groups_argument=kem_name,
                signature_id=sig_name,
            )
        )

    if mode == "one":
        if not specific_kem or not specific_sig:
            raise BenchmarkError("mode=one requires both --kem and --sig")
        kem_candidates = [name for name in groups_avail if name == specific_kem] or \
                         [name for name in groups_avail if name.lower() == specific_kem.lower()]
        sig_candidates = [name for name in sigs_avail if name == specific_sig] or \
                         [name for name in sigs_avail if name.lower() == specific_sig.lower()]
        if not kem_candidates:
            raise BenchmarkError(f"KEM '{specific_kem}' not available in this build")
        if not sig_candidates:
            raise BenchmarkError(f"Signature '{specific_sig}' not available in this build")
        add_combo(kem_candidates[0], sig_candidates[0])
        return combos

    try:
        allowed_kem_names = _MODE_ALLOWED_KEM_NAMES[mode]
        allowed_sig_names = _MODE_ALLOWED_SIG_NAMES[mode]
    except KeyError as exc:
        raise BenchmarkError(f"Unsupported mode: {mode}") from exc

    for kem in selected_kems:
        for sig in selected_sigs:
            add_combo(kem, sig)
        for sig in classic_sigs:
            add_combo(kem, sig)

    for kem in classic_groups:
        for sig in selected_sigs:
            add_combo(kem, sig)
        for sig in classic_sigs:
            add_combo(kem, sig)

    debug(f"total combinations scheduled (before mode filter): {len(combos)}")

    def _mode_allows_combo(combo: AlgorithmCombo) -> bool:
        if combo.kem.lower() not in allowed_kem_names:
            return False
        if combo.signature.lower() not in allowed_sig_names:
            return False
        if mode == "pqc":
            if combo.kem_category == "pqc-hybrid" or combo.sig_category == "pqc-hybrid":
                return False
        if mode == "pqc-level":
            if combo.kem_category != "pqc" or combo.sig_category != "pqc":
                return False
            kem_level = _kem_nist_level(combo.kem)
            sig_level = _sig_nist_level(combo.signature)
            if kem_level != sig_level:
                return False
        return True

    filtered = [combo for combo in combos if _mode_allows_combo(combo)]

    debug(f"total combinations after applying mode={mode}: {len(filtered)}")
    return filtered


def ensure_paths() -> None:
    required = [OPENSSL_BIN, SERVER_BIN, PROVIDER_MODULE, OPENSSL_CONFIG]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise BenchmarkError("Missing required build artefacts: " + ", ".join(missing))

def ensure_certificate_directory(base_dir: Path) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)

def generate_certificate(signature: str, cert_dir: Path) -> Tuple[Path, Path]:
    ensure_certificate_directory(cert_dir)
    sanitized = signature.lower().replace("/", "_")
    key_path = cert_dir / f"{sanitized}.key"
    crt_path = cert_dir / f"{sanitized}.crt"

    if key_path.exists() and crt_path.exists():
        return crt_path, key_path

    env = default_env()
    subj = "/CN=localhost"

    gen_cmd = [str(OPENSSL_BIN), "genpkey", "-algorithm", signature, "-out", str(key_path)]
    run_command(
        gen_cmd,
        env=env,
    )

    req_cmd = [str(OPENSSL_BIN), "req", "-new", "-x509", "-key", str(key_path),
               "-out", str(crt_path), "-days", "365", "-subj", subj]
    run_command(
        req_cmd,
        env=env,
    )
    return crt_path, key_path

def default_env() -> Dict[str, str]:
    env = os.environ.copy()
    env["OPENSSL_CONF"] = str(OPENSSL_CONFIG)
    existing_ld = env.get("LD_LIBRARY_PATH")
    ld_parts = [str(OPENSSL_ROOT), str(PROVIDER_MODULE.parent)]
    if existing_ld:
        ld_parts.append(existing_ld)
    env["LD_LIBRARY_PATH"] = ":".join(ld_parts)
    env["OPENSSL_MODULES"] = str(PROVIDER_MODULE.parent)
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("PYTHONHASHSEED", "0")
    return env


def start_server(
    cert: Path,
    key: Path,
    groups: str,
    *,
    quic_mode: int = DEFAULT_QUIC_MODE,
    server_log_file: Optional[Path] = None,
    debug_mode: bool = False,
    packet_log_mode: bool = False,
) -> subprocess.Popen:
    env = default_env()
    cmd = [
        str(SERVER_BIN),
        str(SERVER_PORT),
        str(cert),
        str(key),
        "--handshake-only",
    ]
    if groups:
        cmd.extend(["--groups", groups])
    if quic_mode == 1:
        cmd.append("--unlimited-amplification")
    elif quic_mode == 3:
        cmd.append("--enable-retry")
    if debug_mode:
        cmd.append("--debug")
    if packet_log_mode:
        cmd.append("--packet-log")
    previously_logged = _HOST_TUNING_OVERVIEW_PRINTED
    _ensure_host_tuning_overview_logged()
    if benchmark_debug_enabled() and previously_logged:
        for logical_role in ("client", "server"):
            message = _host_tuning_role_message(logical_role)
            if message:
                print(message, flush=True)

    server_cpus = _select_cpu_ids(SERVER_CPU, "server") or (SERVER_CPU,)
    server_core = _role_core_id("server")
    detail_parts = [f"CPU(s) {_format_cpu_set(server_cpus)}"]
    if server_core:
        detail_parts.append(f"core {server_core}")
    quic_mode_names = {
        0: "RFC 9000 Default (1-RTT, 3x amplification, no RETRY)",
        1: "Unlimited Amplification (1-RTT, no limit, no RETRY)",
        2: "RFC 9000 Default + Client ACK-Padding (1-RTT, 3x amplification)",
        3: "RETRY-based Validation (2-RTT, early validation, then unlimited)",
    }
    detail_parts.extend(
        [
            f"GROUPS {groups or 'default'}",
            f"QUIC MODE {quic_mode} ({quic_mode_names.get(quic_mode, 'Unknown')})",
        ]
    )
    debug("Preparing QUIC server: " + "+ ".join(detail_parts))
    debug("server command: " + " ".join(cmd))

    log_handle = None
    if server_log_file is not None:
        server_log_file.parent.mkdir(parents=True, exist_ok=True)
        log_handle = open(server_log_file, "w", encoding="utf-8")

    process = subprocess.Popen(
        cmd,
        stdout=(log_handle if server_log_file is not None else subprocess.PIPE),
        stderr=(subprocess.STDOUT if server_log_file is not None else subprocess.PIPE),
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        preexec_fn=_preexec_for(
            SERVER_CPU,
            role="quic-server",
            logical_role="server",
            apply_priority=True,
        ),
    )

    if log_handle is not None:
        try:
            log_handle.close()
        except Exception:
            pass

    time.sleep(0.5)
    if process.poll() is not None:
        if server_log_file is not None:
            details = ""
            try:
                with open(server_log_file, "r", encoding="utf-8", errors="replace") as fh:
                    details = fh.read()
            except Exception:
                details = ""
            raise BenchmarkError("QUIC server exited prematurely:\n" + details)
        stdout, stderr = process.communicate()
        raise BenchmarkError("QUIC server exited prematurely:\n" + (stderr or stdout or ""))
    _log_process_priority(process.pid, "quic-server")
    return process

def stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

def collect_handshake(
    groups: str,
    raw_log_file: Optional[Path] = None,
    *,
    include_keyshare: bool = False,
    include_trace: bool = False,
    debug_mode: bool = False,
    packet_log_mode: bool = False,
    bench_quiet: bool = True,
    measure_only: bool = False,
) -> str:
    env = default_env()
    cmd = [
        str(OPENSSL_BIN),
        "s_client",
        "-quic",
        "-alpn", "ossltest",
        "-connect", f"{SERVER_HOST}:{SERVER_PORT}",
        "-handshaketime",
    ]
    if include_keyshare:
        cmd.append("-keyshare")
    if include_trace:
        cmd.append("-trace")
    if groups:
        cmd.extend(["-groups", groups])
    if measure_only:
        cmd.append("-quic_measure_only")
    effective_packet_log = packet_log_mode or debug_mode
    if debug_mode:
        cmd.append("-quic_debug")
    if not debug_mode and bench_quiet:
        cmd.append("-quic_bench_quiet")
    if effective_packet_log:
        cmd.append("-quic_packet_log")
    debug("client command: " + " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        stdin=subprocess.DEVNULL,
        preexec_fn=_preexec_for(
            CLIENT_CPU,
            role="quic-client",
            logical_role="client",
            apply_priority=True,
        ),
    )

    _log_process_priority(proc.pid, "quic-client")

    try:
        stdout, stderr = proc.communicate(timeout=HANDSHAKE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        stdout, stderr = proc.communicate()
        combined_output = "".join(
            [_ensure_text(stdout), "\n" if stdout and stderr else "", _ensure_text(stderr)]
        )
        if raw_log_file is not None:
            raw_log_file.parent.mkdir(parents=True, exist_ok=True)
            with raw_log_file.open("w", encoding="utf-8") as fh:
                fh.write(combined_output)
                if not combined_output.endswith("\n"):
                    fh.write("\n")
        extra = f"; see raw log at {raw_log_file}" if raw_log_file is not None else ""
        raise HandshakeTimeout(
            "Handshake command exceeded the timeout of "
            f"{HANDSHAKE_TIMEOUT_SECONDS} seconds" + extra
        ) from exc

    combined_output = "".join(
        [_ensure_text(stdout), "\n" if stdout and stderr else "", _ensure_text(stderr)]
    )

    if raw_log_file is not None:
        raw_log_file.parent.mkdir(parents=True, exist_ok=True)
        with raw_log_file.open("w", encoding="utf-8") as fh:
            fh.write(combined_output)
            if not combined_output.endswith("\n"):
                fh.write("\n")

    if proc.returncode != 0:
        debug("Handshake command exited with %d; stdout/stderr:\n%s"
                % (proc.returncode, combined_output.rstrip("\n")))
    return combined_output


def parse_handshake_rtt(combined_output: str, raw_log_file: Optional[Path] = None) -> float:
    needle = "handshake-rtt:"
    for raw_line in combined_output.splitlines():
        lowered = raw_line.lower()
        idx = lowered.find(needle)
        if idx == -1:
            continue
        remainder = raw_line[idx + len(needle):].strip()
        if not remainder:
            continue
        token = remainder.split()[0]
        try:
            return float(token.replace(",", "."))
        except ValueError:
            break
    msg = "Handshake-RTT not found in client output"
    if raw_log_file is not None:
        msg += f"; see raw log at {raw_log_file}"
    raise BenchmarkError(msg)


def _parse_keyshare_value(
    combined_output: str,
    label: str,
    raw_log_file: Optional[Path] = None,
) -> int:
    pattern = re.compile(
        rf"{label}\W*[:=]\W*([0-9]+)(?:\s*bytes?)?",
        re.IGNORECASE,
    )
    ansi_escape_pattern = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    control_garbage = dict.fromkeys(map(ord, "\r\b\0\u200b\u200c\u200d\u2060"), None)

    for raw_line in combined_output.splitlines():
        line = unicodedata.normalize("NFKC", raw_line)
        line = ansi_escape_pattern.sub("", line).translate(control_garbage)
        match = pattern.search(line)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                break

    msg = f"{label} not found in client output"
    if raw_log_file is not None:
        msg += f"; see raw log at {raw_log_file}"
    raise BenchmarkError(msg)


def parse_keyshare_sizes(
    combined_output: str, raw_log_file: Optional[Path] = None
) -> Tuple[int, int]:
    """Extract client/server key share sizes from s_client output."""

    try:
        client = _parse_keyshare_value(
            combined_output, "ClientKeyShare", raw_log_file
        )
        server = _parse_keyshare_value(
            combined_output, "ServerKeyShare", raw_log_file
        )
        return client, server
    except BenchmarkError:
        client, server = _parse_keyshare_from_trace(
            combined_output, raw_log_file
        )
        return client, server


def _parse_keyshare_from_trace(
    combined_output: str, raw_log_file: Optional[Path]
) -> Tuple[int, int]:
    client: Optional[int] = None
    server: Optional[int] = None
    context: Optional[str] = None
    keyshare_context: Optional[str] = None
    length_pattern = re.compile(r"len\s*=\s*([0-9]+)")

    for raw_line in combined_output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if upper.startswith("CLIENTHELLO"):
            context = "client"
            keyshare_context = None
            continue
        if upper.startswith("SERVERHELLO"):
            context = "server"
            keyshare_context = None
            continue
        if "EXTENSION_TYPE=KEY_SHARE" in upper:
            keyshare_context = context
            continue
        if "KEY_EXCHANGE" in upper and "LEN" in upper and keyshare_context:
            match = length_pattern.search(stripped)
            if match:
                length = int(match.group(1))
                if keyshare_context == "client" and client is None:
                    client = length
                elif keyshare_context == "server" and server is None:
                    server = length
            keyshare_context = None
        if client is not None and server is not None:
            break

    if client is None or server is None:
        msg = "Key share lengths not found in trace output"
        if raw_log_file is not None:
            msg += f"; see raw log at {raw_log_file}"
        raise BenchmarkError(msg)
    return client, server

def remove_outliers(values: List[float]) -> Tuple[List[float], int, List[bool]]:
    if len(values) < 4:
        return values[:], 0, [True] * len(values)
    sorted_values = sorted(values)
    quartiles = statistics.quantiles(sorted_values, n=4, method="inclusive")
    q1, q3 = quartiles[0], quartiles[2]
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr
    mask = [lower_bound <= v <= upper_bound for v in values]
    filtered = [v for v, keep in zip(values, mask) if keep]
    removed = len(values) - len(filtered)
    return filtered, removed, mask

def summarise(values: List[float]) -> Tuple[float, float, float, float]:
    if not values:
        return (math.nan, math.nan, math.nan, math.nan)
    mean = statistics.fmean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    stderr = std / math.sqrt(len(values)) if len(values) > 0 else math.nan
    margin = 1.96 * stderr if len(values) > 1 else 0.0
    ci_low = max(mean - margin, 0.0)
    return mean, std, ci_low, mean + margin


def run_benchmark(
    combo: AlgorithmCombo,
    iterations: int,
    cert_dir: Path,
    raw_log_dir: Path,
    *,
    quic_mode: int = DEFAULT_QUIC_MODE,
    loss_profile_label: str,
    debug_mode: bool = False,
    packet_log_mode: bool = False,
    measure_only: bool = False,
) -> BenchmarkResult:
    cert_path, key_path = generate_certificate(combo.signature_id, cert_dir)

    server_raw_log_dir = raw_log_dir.parent / "raw_logs_server"
    server_log_dir = server_raw_log_dir / f"{combo.kem.lower()}__{combo.signature.lower()}"
    server_log_file = server_log_dir / "server.log"

    server = None
    bench_quiet = not debug_mode
    packet_logs_enabled = packet_log_mode or debug_mode
    try:
            server = start_server(
                cert_path,
                key_path,
                combo.groups_argument,
                quic_mode=quic_mode,
                server_log_file=server_log_file,
                debug_mode=debug_mode,
                packet_log_mode=packet_logs_enabled,
            )
    except BenchmarkError:
        raise

    log_dir = raw_log_dir / f"{combo.kem.lower()}__{combo.signature.lower()}"

    outputs: List[str] = []
    log_paths: List[Path] = []
    successful_iterations: List[int] = []
    timeout_skips = 0
    aborted_due_to_timeouts = False
    try:
        for idx in range(iterations):
            iteration_number = idx + 1
            debug(
                f"iteration {iteration_number}/{iterations} for {combo.kem} + {combo.signature}"
            )
            log_path = log_dir / f"iteration_{iteration_number:03d}.log"
            try:
                output = collect_handshake(
                    combo.groups_argument,
                    log_path,
                    debug_mode=debug_mode,
                    packet_log_mode=packet_logs_enabled,
                    bench_quiet=bench_quiet,
                    measure_only=measure_only,
                )
            except HandshakeTimeout:
                timeout_skips += 1
                debug(
                    f"iteration {iteration_number}/{iterations} for {combo.kem} + {combo.signature} "
                    f"timed out after {HANDSHAKE_TIMEOUT_SECONDS}s (skip {timeout_skips})"
                )
                if timeout_skips > 1:
                    aborted_due_to_timeouts = True
                    break
                continue
            except BenchmarkError as exc:
                debug(
                    f"iteration {iteration_number}/{iterations} for {combo.kem} + {combo.signature} failed: {exc}"
                )
                continue
            outputs.append(output)
            log_paths.append(log_path)
            successful_iterations.append(iteration_number)
            debug(
                "\n".join(
                    [
                        f"--- Handshake log {iteration_number}/{iterations} for {combo.kem} + {combo.signature} ---",
                        output.rstrip("\n"),
                        "--- End handshake log ---",
                    ]
                )
            )
    finally:
        if server is not None:
            stop_server(server)

    if aborted_due_to_timeouts:
        raise BenchmarkError(
            "Aborting combination due to multiple handshake timeouts "
            f"(>{HANDSHAKE_TIMEOUT_SECONDS}s)"
        )

    samples: List[float] = []
    parse_errors: List[str] = []
    for iteration_index, (output, log_path) in enumerate(zip(outputs, log_paths)):
        iteration_number = successful_iterations[iteration_index]
        try:
            rtt_value = parse_handshake_rtt(output, log_path)
            samples.append(rtt_value)
            if bench_quiet:
                print(f"Handshake-RTT: {rtt_value:.2f} ms", flush=True)
        except BenchmarkError as exc:
            message = f"iteration {iteration_number}: {exc}"
            parse_errors.append(message)
            debug(
                f"Skipping RTT parse for iteration {iteration_number} of {combo.kem} + {combo.signature}: {exc}"
            )

    if not samples:
        raise BenchmarkError(
            "Failed to parse handshake RTT for all successful iterations;\n"
            + "\n".join(parse_errors)
        )

    filtered, removed, _mask = remove_outliers(samples)
    mean, std, ci_low, ci_high = summarise(filtered)

    return BenchmarkResult(
        combo=combo,
        iterations=len(filtered),
        outliers_removed=removed,
        values_ms=filtered,
        mean_ms=mean,
        std_ms=std,
        ci95_low_ms=ci_low,
        ci95_high_ms=ci_high,
        quic_mode=quic_mode,
        quic_mode_label=describe_quic_mode(quic_mode),
        loss_profile=loss_profile_label,
    )


def _log_benchmark_preamble(
    args: argparse.Namespace,
    combos: Sequence[AlgorithmCombo],
    loss_profile: NetemProfile,
    results_dir: Path,
) -> None:
    if not benchmark_debug_enabled():
        return
    global _HOST_TUNING_OVERVIEW_PRINTED

    header = _bold(_cyan("=== Benchmark configuration ==="))
    print(header, flush=True)
    print(_format_config_line("Mode", args.mode, colour="green"), flush=True)
    print(
        _format_config_line(
            "Handshake iterations per combination",
            str(args.count),
        ),
        flush=True,
    )
    quic_mode_text = quic_mode_summary(args.quic_mode)
    print(_format_config_line("QUIC mode", quic_mode_text, colour="yellow"), flush=True)
    loss_description = (
        f"{loss_profile.key} on interface {args.netem_interface}"
        f" ({loss_profile.description})"
    )
    print(
        _format_config_line("Loss emulation profile", loss_description, colour="cyan"),
        flush=True,
    )
    print(_format_config_line("Results directory", str(results_dir)), flush=True)
    combo_count = len(combos)
    print(
        _format_config_line(
            "Selected algorithm pairs", str(combo_count), colour="green"
        ),
        flush=True,
    )

    print("", flush=True)
    print(_bold(_cyan("=== CPU affinity & priority targets ===")), flush=True)
    for line in _host_tuning_overview_lines():
        print(line, flush=True)
    _HOST_TUNING_OVERVIEW_PRINTED = True

    server_cpus = _format_cpu_set(_select_cpu_ids(SERVER_CPU, "server") or (SERVER_CPU,))
    client_cpus = _format_cpu_set(_select_cpu_ids(CLIENT_CPU, "client") or (CLIENT_CPU,))
    print(
        _format_config_line(
            "Server affinity request",
            f"CPU(s) {server_cpus}",
            colour="magenta",
        ),
        flush=True,
    )
    print(
        _format_config_line(
            "Client affinity request",
            f"CPU(s) {client_cpus}",
            colour="green",
        ),
        flush=True,
    )
    print(
        _format_config_line(
            "Server scheduling target",
            "nice -20 with SCHED_FIFO priority 99",
            colour="magenta",
        ),
        flush=True,
    )
    print(
        _format_config_line(
            "Client scheduling target",
            "nice -20 with SCHED_FIFO priority 99",
            colour="green",
        ),
        flush=True,
    )
    print("", flush=True)


def write_summary(results: List[BenchmarkResult], output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "kem",
                "signature",
                "kem_category",
                "signature_category",
                "loss_profile",
                "iterations",
                "outliers_removed",
                "mean_ms",
                "std_ms",
                "ci95_low_ms",
                "ci95_high_ms",
                "quic_mode",
            ]
        )
        for result in results:
            writer.writerow(
                [
                    result.combo.kem,
                    result.combo.signature,
                    result.combo.kem_category,
                    result.combo.sig_category,
                    result.loss_profile,
                    result.iterations,
                    result.outliers_removed,
                    f"{result.mean_ms:.6f}",
                    f"{result.std_ms:.6f}",
                    f"{result.ci95_low_ms:.6f}",
                    f"{result.ci95_high_ms:.6f}",
                    result.quic_mode_label,
                ]
            )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run QUIC handshake benchmarks")
    parser.add_argument("--mode", default="all", choices=["all", "pqc", "pqc-level", "hybrid", "classic", "one"],
                        help=("Benchmark Mode: all combinations, PQC/classic (mode=pqc), "
                            "Pure PQC pairs grouped by NIST level (mode=pqc-level), "
                            "only hybrid pairs (mode=hybrid), only classical pairs (mode=classic) "
                            "or a specific pair (mode=one)"),)
    parser.add_argument("--kem", dest="kem", help="KEM name for mode=one", default=None)
    parser.add_argument("--sig", dest="sig", help="Signature name for mode=one", default=None)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help="Number of handshakes per combination")
    parser.add_argument("--results-dir", default="/app/results", help="Directory to store aggregated CSV results")
    parser.add_argument("--packet-workflow", dest="packet_workflow", action="store_true",
                        help="Capture packet counts instead of running the multi-iteration benchmark")

    parser.add_argument("--quic-mode", type=int, default=DEFAULT_QUIC_MODE,
                        help=("QUIC mode: "
                                "0=QUIC Default (1-RTT, 3x amplification, no RETRY), "
                                "1=QUIC Default (1-RTT, No-amplification (∞), no RETRY), "
                                "2=QUIC Default (1-RTT, 3x amplification, no RETRY) + ACK-Padding (client-side only), "
                                "3=QUIC RETRY-based Validation (RFC 9000 Optional: 2-RTT, early validation)"),)
    parser.add_argument("--loss-profile", choices=LOSS_PROFILE_CHOICES, default=DEFAULT_LOSS_PROFILE,
                        help=("Loss profile applied via tc netem (0=no loss, numeric values=random loss," \
                            " bursty=Gilbert–Elliott model)."),)
    parser.add_argument("--netem-interface", default=DEFAULT_NETEM_INTERFACE,
                        help=("Local interface where tc netem will be configured (default: %(default)s). "
                            "Use the container/namespace interface to avoid impacting other hosts."),)
    print_mode_group = parser.add_mutually_exclusive_group()
    print_mode_group.add_argument("--benchmark", dest="print_mode_flag", action="store_const", const="benchmark",
                                  help="Only print Handshake-RTT lines (default mode)")
    print_mode_group.add_argument("--debug", dest="print_mode_flag", action="store_const", const="debug",
                                  help="Verbose QUIC debug logging")
    print_mode_group.add_argument("--packet", dest="print_mode_flag", action="store_const", const="packet",
                                  help="Packet transmission logging")
    parser.add_argument("--print-mode", dest="print_mode_name", choices=PRINT_MODE_CHOICES,
                        help="Explicitly select print verbosity (benchmark, debug, packet)")
    parser.add_argument("--measure-only", action="store_true",
                        help="Disable certificate verification/logging on the client to capture raw handshake timing")

    args = parser.parse_args(argv)
    cli_print_mode = getattr(args, "print_mode_flag", None) or getattr(args, "print_mode_name", None)
    env_print_mode = os.environ.get("PRINT_MODE", "").strip().lower()
    if cli_print_mode in PRINT_MODE_CHOICES:
        args.print_mode = cli_print_mode
    elif env_print_mode in PRINT_MODE_CHOICES:
        args.print_mode = env_print_mode
    else:
        args.print_mode = "benchmark"
    # Configure QUIC mode-specific parameters
    # Mode 0: RFC 9000 Default (1-RTT, hardcoded 3x amplification, no RETRY)
    # Mode 1: Unlimited Amplification (1-RTT, no anti-amplification limit)
    # Mode 2: reserved (currently behaves like mode 0)
    # Mode 3: RETRY-based Validation (2-RTT, early validation, then unlimited)

    if args.quic_mode == 2:
        print(
            "[benchmark] QUIC_MODE=2 is reserved and currently behaves like mode 0",
            file=sys.stderr,
            flush=True,
        )

    return args

def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        import gc
        gc.disable()
    except Exception:
        pass
    try:
        os.sched_setaffinity(0, set(_allowed_cpus()))
    except Exception:
        pass

    args = parse_args(argv)
    set_benchmark_debug_enabled(args.print_mode == "debug")
    debug_print_mode = args.print_mode == "debug"
    packet_print_mode = args.print_mode == "packet"
    ensure_paths()
    execution_timestamp = datetime.now()
    results_root = Path(args.results_dir) / "benchmarks"
    results_dir = build_results_directory(
        results_root,
        mode=args.mode,
        print_mode=args.print_mode,
        quic_mode=args.quic_mode,
        loss_profile_key=args.loss_profile,
        timestamp=execution_timestamp,
    )

    combos = build_algorithm_matrix(args.mode, args.kem, args.sig)
    if not combos:
        debug("No algorithm combinations selected; exiting")
        return 0

    loss_profile = get_loss_profile(args.loss_profile)
    _log_benchmark_preamble(args, combos, loss_profile, results_dir)
    loss_profile_label = format_loss_profile_label(loss_profile)

    with apply_netem_profile(loss_profile, interface=args.netem_interface, server_port=SERVER_PORT):
        if args.packet_workflow:
            from run_packet_count import (run_packet_workflow)
            run_packet_workflow(
                combos,
                results_dir=results_dir,
                allow_skips=(args.mode != "one"),
                quic_mode=args.quic_mode,
                loss_profile_label=loss_profile_label,
                timestamp=execution_timestamp,
            )
            return 0

        if args.count <= 0:
            raise BenchmarkError("--count must be a positive integer")

        cert_dir = Path("/app/work/certs")
        raw_log_dir = results_dir / "raw_logs"
        summary_path = (results_dir / f"handshakeResults_{execution_timestamp.strftime('%Yy%mm%dd%Hh%Mm%Ss')}.csv")

        results: List[BenchmarkResult] = []
        for combo in combos:
            server_cpu_text = _format_cpu_set(_select_cpu_ids(SERVER_CPU, "server") or (SERVER_CPU,))
            client_cpu_text = _format_cpu_set(_select_cpu_ids(CLIENT_CPU, "client") or (CLIENT_CPU,))
            debug("Running benchmark for %s + %s (server CPU(s) %s, client CPU(s) %s)"
                % (combo.kem, combo.signature, server_cpu_text, client_cpu_text))
            try:
                result = run_benchmark(
                    combo,
                    args.count,
                    cert_dir,
                    raw_log_dir,
                    quic_mode=args.quic_mode,
                    loss_profile_label=loss_profile_label,
                    debug_mode=debug_print_mode,
                    packet_log_mode=packet_print_mode,
                    measure_only=args.measure_only,
                )
            except BenchmarkError as exc:
                msg = str(exc)
                if args.mode != "one":
                    reason = " | ".join(part.strip() for part in msg.splitlines() if part.strip()) or "unknown error"
                    print(
                        _red(
                            f"[skip] {combo.kem} + {combo.signature}: "
                            f"passing because the combination failed ({reason})"
                        ),
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                raise
            results.append(result)

        write_summary(results, summary_path)
        debug(f"Summary written to {summary_path}")
        return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except BenchmarkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
