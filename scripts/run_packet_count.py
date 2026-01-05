#!/usr/bin/env python3
"""Run a single-handshake QUIC benchmark capturing packet counts, sizes and detailed TLS/QUIC metrics."""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Dict, Any, Tuple

import run_benchmarks as rb

# =========================
# Dataclasses de resultados
# =========================

@dataclass
class PacketStats:
    """Statistics extracted from packet logs."""
    packets_sent: int = 0
    bytes_sent: int = 0
    crypto_bytes_sent: int = 0
    padding_bytes_sent: int = 0
    initial_packets: int = 0
    initial_bytes_sent: int = 0
    handshake_packets: int = 0
    handshake_bytes_sent: int = 0
    
    # Internals
    internals: Dict[str, float] = None

    def __post_init__(self):
        if self.internals is None:
            self.internals = {}

@dataclass
class PacketCountResult:
    combo: rb.AlgorithmCombo
    handshake_ms: float
    quic_mode_label: str
    loss_profile: str
    
    # Client stats
    client_stats: PacketStats
    client_keyshare_bytes: int
    client_hello_size: int
    client_handshake_size: int # Sum of Handshake packet payloads
    
    # Server stats
    server_stats: PacketStats
    server_keyshare_bytes: int
    server_hello_size: int
    server_handshake_size: int # Sum of Handshake packet payloads
    server_certificate_size: int
    
    signature_bytes: int
    server_credit_send: float
    server_credit_received: float
    server_amplification_realized: float
    
    # Totals
    total_bytes_changed: int # Sum of Initial/Handshake payloads both directions

# =========================
# Regex helpers
# =========================

# =========================
# Regex helpers
# =========================

# Log line format: [TIMESTAMP] [ROLE SENT/RECEIVED] [DATAGRAM-SIZE : 123B] PACKET ...
# Ex: [CLIENT SENT] [DATAGRAM-SIZE : 1200B]
DATAGRAM_SENT_PATTERN = re.compile(r"\[(?:CLIENT|SERVER) SENT\] \[DATAGRAM-SIZE : (\d+)B\]")

# Packet Type: PACKET <num> : <Type>
PACKET_TYPE_PATTERN = re.compile(r"PACKET \d+ : ([a-zA-Z]+)")

# Frame sizes: CRYPTO--( ... , SIZE=123B) or PADDING--(SIZE=123B)
# Note: A packet can have multiple frames.
# We need to sum them up.
CRYPTO_FRAME_PATTERN = re.compile(r"CRYPTO--\(.*?SIZE=(\d+)B\)")
PADDING_FRAME_PATTERN = re.compile(r"PADDING--\(SIZE=(\d+)B\)")

# Internals pattern: key=<value>ms
INTERNAL_PATTERN = re.compile(r"([a-zA-Z0-9]+)=([0-9.]+)ms")

# TLS Sizes
# ClientHello(KeyShare=mlkem768(1184B)
CLIENT_KEYSHARE_PATTERN = re.compile(r"ClientHello.*?KeyShare=[^(]+\((\d+)B\)")
SERVER_KEYSHARE_PATTERN = re.compile(r"ServerHello.*?KeyShare=[^(]+\((\d+)B\)")

# Certificate(LeafSig=..., Leaf=3931B)
LEAF_CERT_PATTERN = re.compile(r"Leaf=(\d+)B")
# Signature=2420B
SIGNATURE_PATTERN = re.compile(r"Signature=(\d+)B")

# DELTA-CREDIT pattern for server amplification calculation
# [DELTA-CREDIT : +3600B] or [DELTA-CREDIT : -835B]
DELTA_CREDIT_PATTERN = re.compile(r"\[DELTA-CREDIT\s*:\s*([+-]?\d+)B\]")
PACKET_TYPE_RECEIVED_PATTERN = re.compile(r"\[SERVER RECEIVED\].*PACKET \d+ : ([a-zA-Z]+)")

# ClientHello / ServerHello size
# { ClientHello } , SIZE=1162B
# { ServerHello(...) } , SIZE=1150B
# We look for "ClientHello" or "ServerHello" inside CRYPTO frame content and extract SIZE.
# This is tricky with regex alone if nested.
# But looking at log: "CRYPTO--( { ClientHello } , SIZE=1162B)"
# "CRYPTO--( { ServerHello(...) } , SIZE=1150B)"
CLIENT_HELLO_SIZE_PATTERN = re.compile(r"CRYPTO--\(\s*\{\s*ClientHello.*?\}\s*,\s*SIZE=(\d+)B\)")
SERVER_HELLO_SIZE_PATTERN = re.compile(r"CRYPTO--\(\s*\{\s*ServerHello.*?\}\s*,\s*SIZE=(\d+)B\)")

# =========================
# Parsers
# =========================

def parse_packet_log(log_path: Path) -> PacketStats:
    stats = PacketStats()
    
    if not log_path.exists():
        return stats

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        
        # Datagrams sent
        m_dgram = DATAGRAM_SENT_PATTERN.search(line)
        if m_dgram:
            dgram_size = int(m_dgram.group(1))
            stats.packets_sent += 1
            stats.bytes_sent += dgram_size
            
            # Check packet type for this datagram
            m_type = PACKET_TYPE_PATTERN.search(line)
            if m_type:
                ptype = m_type.group(1)
                if ptype == "Initial":
                    stats.initial_packets += 1
                    stats.initial_bytes_sent += dgram_size
                elif ptype == "Handshake":
                    stats.handshake_packets += 1
                    stats.handshake_bytes_sent += dgram_size

            # Check frames
            # A line might contain multiple frames? The log format shows frames separated by | inside { }
            # "Initial { CRYPTO... | PADDING... }"
            # We can findall
            cryptos = CRYPTO_FRAME_PATTERN.findall(line)
            for c_size in cryptos:
                stats.crypto_bytes_sent += int(c_size)
            
            paddings = PADDING_FRAME_PATTERN.findall(line)
            for p_size in paddings:
                stats.padding_bytes_sent += int(p_size)

        # Internals (can be on lines without [SENT/RECEIVED]?)
        # Yes: [CLIENT INTERNAL] ...
        m_internals = INTERNAL_PATTERN.findall(line)
        for key, val in m_internals:
            stats.internals[key] = float(val)

    return stats

def extract_tls_sizes(client_log: Path, server_log: Path) -> Dict[str, int]:
    sizes = {
        "client_keyshare": 0,
        "server_keyshare": 0,
        "client_hello": 0,
        "server_hello": 0,
        "signature": 0,
        "server_cert": 0,
    }
    
    # Attempt to find specific sizes in client log
    # The client log contains both ClientHello (sent) and ServerHello (received)
    if client_log.exists():
        with client_log.open("r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            
            m_ch = CLIENT_HELLO_SIZE_PATTERN.search(content)
            if m_ch:
                sizes["client_hello"] = int(m_ch.group(1))
            
            m_cks = CLIENT_KEYSHARE_PATTERN.search(content)
            if m_cks:
                sizes["client_keyshare"] = int(m_cks.group(1))
            
            # Server KeyShare is in ServerHello, which the client receives
            m_sks = SERVER_KEYSHARE_PATTERN.search(content)
            if m_sks:
                sizes["server_keyshare"] = int(m_sks.group(1))
            
            # ServerHello size is also in client log
            m_sh = SERVER_HELLO_SIZE_PATTERN.search(content)
            if m_sh:
                sizes["server_hello"] = int(m_sh.group(1))

    # Attempt to find signature and certificate sizes in server log
    if server_log.exists():
        with server_log.open("r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            
            m_sig = SIGNATURE_PATTERN.search(content)
            if m_sig:
                sizes["signature"] = int(m_sig.group(1))
            
            m_cert = LEAF_CERT_PATTERN.search(content)
            if m_cert:
                sizes["server_cert"] = int(m_cert.group(1))

    return sizes

def calculate_server_amplification(server_log: Path) -> Tuple[float, float, float]:
    """Calculate server amplification metrics from DELTA-CREDIT values.
    
    Accumulates credit until first Handshake packet is received by server.
    - server_credit_send: sum of absolute values of negative DELTA-CREDIT
    - server_credit_received: sum of positive DELTA-CREDIT / 3
    - server_amplification_realized: server_credit_received / server_credit_send
    
    Returns: (server_credit_send, server_credit_received, server_amplification_realized)
    """
    if not server_log.exists():
        return (0.0, 0.0, 0.0)
    
    server_credit_send = 0.0  # Absolute value of negative DELTA-CREDIT
    server_credit_received = 0.0  # Positive DELTA-CREDIT / 3
    
    with server_log.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            # Check if this is the first Handshake packet received
            if "[SERVER RECEIVED]" in line:
                m_type = PACKET_TYPE_RECEIVED_PATTERN.search(line)
                if m_type and m_type.group(1) == "Handshake":
                    break  # Stop accumulation
            
            # Extract DELTA-CREDIT
            m_credit = DELTA_CREDIT_PATTERN.search(line)
            if m_credit:
                delta = int(m_credit.group(1))
                if delta < 0:
                    server_credit_send += abs(delta)
                elif delta > 0:
                    server_credit_received += delta / 3.0
    
    if server_credit_received == 0:
        server_amplification_realized = 0.0
    else:
        server_amplification_realized = server_credit_send / server_credit_received
    
    return (server_credit_send, server_credit_received, server_amplification_realized)


# =========================
# Handshake execution helpers
# =========================

def run_single_handshake(
    combo: rb.AlgorithmCombo,
    *,
    cert_dir: Path,
    results_dir: Path,
    loss_profile_label: str,
    quic_mode: int = rb.DEFAULT_QUIC_MODE,
) -> PacketCountResult:
    cert_path, key_path = rb.generate_certificate(combo.signature_id, cert_dir)

    server = None
    
    # Define log paths
    base_name = f"{combo.kem.lower()}__{combo.signature.lower()}"
    
    # Server log
    server_log_dir = results_dir / "raw_logs_server" / base_name
    server_log_dir.mkdir(parents=True, exist_ok=True)
    server_log_path = server_log_dir / "server.log"
    
    # Client log
    client_log_dir = results_dir / "raw_logs" / base_name
    client_log_dir.mkdir(parents=True, exist_ok=True)
    client_log_path = client_log_dir / "client.log"

    try:
        # Start Server with packet logging
        server = rb.start_server(
            cert_path,
            key_path,
            combo.groups_argument,
            quic_mode=quic_mode,
            server_log_file=server_log_path,
            packet_log_mode=True, # Enforce packet logging
            debug_mode=False
        )
        time.sleep(0.2)
        
        # Run Client with packet logging
        handshake_output = rb.collect_handshake(
            combo.groups_argument,
            client_log_path,
            include_trace=False, # Disable trace
            packet_log_mode=True, # Enforce packet logging
            debug_mode=False
        )
        
        # Parse Handshake RTT
        try:
            handshake_ms = rb.parse_handshake_rtt(handshake_output, client_log_path)
        except rb.BenchmarkError:
            handshake_ms = 0.0

        # Parse Logs
        client_stats = parse_packet_log(client_log_path)
        server_stats = parse_packet_log(server_log_path)
        
        tls_sizes = extract_tls_sizes(client_log_path, server_log_path)
        server_credit_send, server_credit_received, server_amp = calculate_server_amplification(server_log_path)
        
        total_bytes_changed = (
            client_stats.initial_bytes_sent + 
            server_stats.initial_bytes_sent + 
            client_stats.handshake_bytes_sent + 
            server_stats.handshake_bytes_sent
        )

    finally:
        if server is not None:
            rb.stop_server(server)

    return PacketCountResult(
        combo=combo,
        handshake_ms=handshake_ms,
        quic_mode_label=rb.describe_quic_mode(quic_mode),
        loss_profile=loss_profile_label,
        client_stats=client_stats,
        client_keyshare_bytes=tls_sizes["client_keyshare"],
        client_hello_size=tls_sizes["client_hello"],
        client_handshake_size=client_stats.handshake_bytes_sent,
        server_stats=server_stats,
        server_keyshare_bytes=tls_sizes["server_keyshare"],
        server_hello_size=tls_sizes["server_hello"],
        server_handshake_size=server_stats.handshake_bytes_sent,
        server_certificate_size=tls_sizes["server_cert"],
        signature_bytes=tls_sizes["signature"],
        server_credit_send=server_credit_send,
        server_credit_received=server_credit_received,
        server_amplification_realized=server_amp,
        total_bytes_changed=total_bytes_changed
    )


# =========================
# CSV generation
# =========================

FINAL_HEADERS: List[str] = [
    "kem",
    "signature",
    "kem_category",
    "signature_category",
    "loss_profile",
    "handshake_time_ms",
    "quic_mode",
    "client_keyshare_bytes",
    "server_keyshare_bytes",
    "signature_bytes",
    "server_credit_send",
    "server_credit_received",
    "server_amplification_realized",
    "client_hello_size",
    "server_hello_size",
    "client_handshake_size",
    "server_handshake_size",
    "server_certificate_size",
    # contadores/datatgram sums (enviado/recebido)
    "client_packets_send",
    "server_packets_send",
    "client_total_bytes_send",
    "server_total_bytes_send",
    "client_CRYPTO_bytes_send",
    "server_CRYPTO_bytes_send",
    "client_PADDING_bytes_send",
    "server_PADDING_bytes_send",
    # totals based on payloads for Initial/Handshake packets (both directions)
    "total_bytes_changed",
    "num_packets_initial_client",
    "num_packets_initial_server",
    "num_packets_handshake_server",
    "num_packets_handshake_client",
    # internals
    "clientKeyshareGeneration",
    "clientHelloBuild",
    "clientHelloRoundTrip",
    "clientKeyExchangeLatency",
    "clientCertificateProcess",
    "clientCertVerifyCheck",
    "serverKeyExchangeLatency",
    "serverHelloPreparation",
    "serverCertificateBuild",
    "serverCertVerifySign",
    "serverHandshakePreparation",
    "clientValidationDelay",
]

def _fmt_float(val: Optional[float]) -> str:
    if val is None:
        return ""
    return f"{val:.6f}"

def write_results(results: List[PacketCountResult], output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(FINAL_HEADERS)

        for res in results:
            c = res.client_stats
            s = res.server_stats
            
            def get_internal(name: str) -> str:
                val = c.internals.get(name) or s.internals.get(name)
                return _fmt_float(val) if val is not None else ""

            row = {
                "kem": res.combo.kem,
                "signature": res.combo.signature,
                "kem_category": res.combo.kem_category,
                "signature_category": res.combo.sig_category,
                "loss_profile": res.loss_profile,
                "handshake_time_ms": _fmt_float(res.handshake_ms),
                "quic_mode": res.quic_mode_label,
                "client_keyshare_bytes": res.client_keyshare_bytes,
                "server_keyshare_bytes": res.server_keyshare_bytes,
                "signature_bytes": res.signature_bytes,
                "server_credit_send": _fmt_float(res.server_credit_send),
                "server_credit_received": _fmt_float(res.server_credit_received),
                "server_amplification_realized": _fmt_float(res.server_amplification_realized),
                "client_hello_size": res.client_hello_size,
                "server_hello_size": res.server_hello_size,
                "client_handshake_size": res.client_handshake_size,
                "server_handshake_size": res.server_handshake_size,
                "server_certificate_size": res.server_certificate_size,
                
                "client_packets_send": c.packets_sent,
                "server_packets_send": s.packets_sent,
                "client_total_bytes_send": c.bytes_sent,
                "server_total_bytes_send": s.bytes_sent,
                "client_CRYPTO_bytes_send": c.crypto_bytes_sent,
                "server_CRYPTO_bytes_send": s.crypto_bytes_sent,
                "client_PADDING_bytes_send": c.padding_bytes_sent,
                "server_PADDING_bytes_send": s.padding_bytes_sent,
                
                "total_bytes_changed": res.total_bytes_changed,
                "num_packets_initial_client": c.initial_packets,
                "num_packets_initial_server": s.initial_packets,
                "num_packets_handshake_server": s.handshake_packets,
                "num_packets_handshake_client": c.handshake_packets,
                
                "clientKeyshareGeneration": get_internal("clientKeyshareGeneration"),
                "clientHelloBuild": get_internal("clientHelloBuild"),
                "clientHelloRoundTrip": get_internal("clientHelloRoundTrip"),
                "clientKeyExchangeLatency": get_internal("clientKeyExchangeLatency"),
                "clientCertificateProcess": get_internal("clientCertificateProcess"),
                "clientCertVerifyCheck": get_internal("clientCertVerifyCheck"),
                "serverKeyExchangeLatency": get_internal("serverKeyExchangeLatency"),
                "serverHelloPreparation": get_internal("serverHelloPreparation"),
                "serverCertificateBuild": get_internal("serverCertificateBuild"),
                "serverCertVerifySign": get_internal("serverCertVerifySign"),
                "serverHandshakePreparation": get_internal("serverHandshakePreparation"),
                "clientValidationDelay": get_internal("clientValidationDelay"),
            }
            
            writer.writerow([row.get(h, "") for h in FINAL_HEADERS])


# =========================
# Orchestration
# =========================

def run_packet_workflow(
    combos: Iterable[rb.AlgorithmCombo],
    *,
    results_dir: Path,
    allow_skips: bool = True,
    loss_profile_label: str,
    quic_mode: int = rb.DEFAULT_QUIC_MODE,
    timestamp: Optional[datetime] = None,
) -> Path:
    combo_list = list(combos)
    if not combo_list:
        rb.debug("No algorithm combinations selected; exiting")
        return results_dir / "packetCount_empty.csv"

    cert_dir = Path("/app/work/certs")
    ts = timestamp or datetime.now()
    summary_path = results_dir / (
        f"packetCount_{ts.strftime('%Yy%mm%dd%Hh%Mm%Ss')}.csv"
    )

    results: List[PacketCountResult] = []
    for combo in combo_list:
        rb.debug(
            f"Running packet count for {combo.kem} + {combo.signature} "
            f"(server CPU {rb.SERVER_CPU}, client CPU {rb.CLIENT_CPU})"
        )
        try:
            result = run_single_handshake(
                combo,
                cert_dir=cert_dir,
                results_dir=results_dir,
                loss_profile_label=loss_profile_label,
                quic_mode=quic_mode,
            )
        except rb.BenchmarkError as exc:
            if not allow_skips:
                raise
            msg = str(exc)
            reason = " | ".join(part.strip() for part in msg.splitlines() if part.strip())
            if not reason:
                reason = "unknown error"
            print(
                rb._red(
                    f"[skip] {combo.kem} + {combo.signature}: "
                    f"passing because the combination failed ({reason})"
                ),
                file=sys.stderr,
                flush=True,
            )
            continue
        results.append(result)

    if not results:
        rb.debug("No packet count results collected; nothing to write")
        return summary_path

    results_dir.mkdir(parents=True, exist_ok=True)
    write_results(results, summary_path)
    rb.debug(f"Packet count summary written to {summary_path}")
    return summary_path


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture QUIC handshake packet counts + detailed metrics")
    parser.add_argument(
        "--mode",
        default="all",
        choices=["all", "pqc", "pqc-level", "hybrid", "classic", "one"],
        help=(
            "Benchmark mode: all combinations, PQC/classic (mode=pqc), "
            "pure PQC pairs grouped by NIST level (mode=pqc-level), "
            "only hybrid pairs (mode=hybrid), only classical pairs (mode=classic) "
            "or a specific pair (mode=one)"
        ),
    )
    parser.add_argument("--kem", dest="kem", help="KEM name for mode=one",
                        default=None)
    parser.add_argument("--sig", dest="sig", help="Signature name for mode=one",
                        default=None)
    parser.add_argument("--results-dir", default="/app/results",
                        help="Directory to store CSV results and raw logs")
    parser.add_argument(
        "--loss-profile",
        choices=rb.LOSS_PROFILE_CHOICES,
        default=rb.DEFAULT_LOSS_PROFILE,
        help=(
            "Loss profile applied via tc netem (0=no loss, numeric values=random loss," \
            " bursty=Gilbert–Elliott model)."
        ),
    )
    parser.add_argument(
        "--netem-interface",
        default=rb.DEFAULT_NETEM_INTERFACE,
        help=(
            "Local interface where tc netem will be configured (default: %(default)s). "
            "Use the container/namespace interface to avoid impacting other hosts."
        ),
    )

    parser.add_argument(
        "--quic-mode",
        type=int,
        default=rb.DEFAULT_QUIC_MODE,
        choices=[0, 1, 2, 3],
        help=(
            "QUIC PQC mode: "
            "0=QUIC Default Mode - RFC 9000, "
            "1=Amplification OFF - No Address Validation, "
            "2=reserved (behaves like mode 0), "
            "3=QUIC RETRY-based Validation, "
        ),
    )

    args = parser.parse_args(argv)

    if args.quic_mode == 2:
        print(
            "[packet-count] QUIC_MODE=2 is reserved and currently behaves like mode 0",
            file=sys.stderr,
            flush=True,
        )

    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    try:
        import gc
        gc.disable()
    except Exception:
        pass
    allowed_cpus_fn = getattr(rb, "_allowed_cpus", None)
    if callable(allowed_cpus_fn):
        try:
            os.sched_setaffinity(0, set(allowed_cpus_fn()))
        except Exception:
            pass

    rb.ensure_paths()

    combos = rb.build_algorithm_matrix(args.mode, args.kem, args.sig)
    execution_timestamp = datetime.now()
    results_dir = rb.build_results_directory(
        Path(args.results_dir) / "packetAnalyzer",
        mode=args.mode,
        print_mode="packet",
        quic_mode=args.quic_mode,
        loss_profile_key=args.loss_profile,
        timestamp=execution_timestamp,
    )

    loss_profile = rb.get_loss_profile(args.loss_profile)
    rb.debug(
        "Using loss profile '%s' on interface %s: %s"
        % (loss_profile.key, args.netem_interface, loss_profile.description)
    )

    with rb.apply_netem_profile(
        loss_profile,
        interface=args.netem_interface,
        server_port=rb.SERVER_PORT,
    ):
        run_packet_workflow(
            combos,
            results_dir=results_dir,
            allow_skips=(args.mode != "one"),
            loss_profile_label=rb.format_loss_profile_label(loss_profile),
            quic_mode=args.quic_mode,
            timestamp=execution_timestamp,
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except rb.BenchmarkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
