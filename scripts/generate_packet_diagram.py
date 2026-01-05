#!/usr/bin/env python3
"""Generate Mermaid packet-flow diagrams from packet-mode benchmark logs."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import textwrap

LINE_RE = re.compile(
    r"^\[(?P<ts>[0-9]+\.[0-9]+) ms\] \[(?P<role>CLIENT|SERVER) (?P<kind>SENT|RECEIVED|INTERNAL)\]\s*(?P<rest>.*)$"
)
PACKET_INFO_RE = re.compile(r"PACKET\s+(?P<num>[0-9]+)\s*:\s*(?P<ptype>[^\{]+)")
DATAGRAM_RE = re.compile(r"\[DATAGRAM-SIZE\s*:\s*(?P<size>[^\]]+)\]")
FRAME_NAME_RE = re.compile(r"^(?P<name>[A-Z0-9_]+)--\((?P<body>.*)\)$")
CREDIT_FIELD_RE = re.compile(
    r"\[(CREDIT(?:[- ]BEFORE|[- ]AFTER)?|CREDIT|AMPLIFICATION-FACTOR)\s*:\s*([^\]]+)\]"
)
DELTA_CREDIT_RE = re.compile(r"\[DELTA-CREDIT\s*:\s*([^\]]+)\]")
CLIENT_HELLO_BUILD_RE = re.compile(r"clientHelloBuild=([0-9\.]+)ms", re.IGNORECASE)
SIZE_FIELD_RE = re.compile(r"SIZE\s*=\s*([^,\)]+)")


@dataclass
class PacketEvent:
    role: str
    kind: str
    timestamp: float
    packet_no: Optional[int]
    packet_type: Optional[str]
    datagram: Optional[str]
    frames: List[str]
    credit_before: Optional[str]
    credit_after: Optional[str]
    amplification: Optional[str]
    credit_delta: Optional[str]
    direction: Optional[str] = None
    norm_time: float = 0.0


@dataclass
class InternalEvent:
    role: str
    timestamp: float
    label: str
    body: str
    norm_time: float = 0.0


@dataclass
class PacketFlow:
    direction: str  # client_to_server / server_to_client
    send_event: PacketEvent
    recv_event: Optional[PacketEvent]
    norm_time: float

    @property
    def label(self) -> str:
        parts: List[str] = []
        if self.send_event.packet_type:
            pkt_type = " ".join(self.send_event.packet_type.split())
            if self.send_event.packet_no is not None:
                parts.append(f"{pkt_type} : Packet {self.send_event.packet_no}")
            else:
                parts.append(pkt_type)
        if self.send_event.datagram:
            parts.append(f"Datagram {self.send_event.datagram.strip()}")
        if self.send_event.frames:
            frames = " | ".join(self.send_event.frames[:4])
            if len(self.send_event.frames) > 4:
                frames += f" | +{len(self.send_event.frames) - 4} more"
            parts.append(frames)
        credit_text = build_credit_annotation(self)
        if credit_text:
            parts.append(credit_text)
        label = " | ".join(parts)
        if self.send_event.packet_type and "INITIAL" in self.send_event.packet_type.upper():
            label = re.sub(r",\s*(Cipher)", r", <br/>\1", label)
        return label
def build_credit_annotation(flow: PacketFlow) -> Optional[str]:
    event: Optional[PacketEvent]
    if flow.direction == "server_to_client":
        event = flow.send_event
    else:
        event = flow.recv_event

    if event is None:
        return None

    parts: List[str] = []
    before = event.credit_before or event.credit_after
    after = event.credit_after or event.credit_before
    norm_before = (before or "").strip()
    norm_after = (after or "").strip()

    def is_unlimited(value: str) -> bool:
        return value.upper() == "UNLIMITED"

    credit_is_unlimited = False
    if norm_after or norm_before:
        if (norm_after and is_unlimited(norm_after) and (not norm_before or is_unlimited(norm_before))) or (
            norm_before and is_unlimited(norm_before) and not norm_after
        ):
            parts.append("CREDIT : UNLIMITED")
            credit_is_unlimited = True
        else:
            parts.append(f"CREDIT : {norm_before or 'UNKNOWN'} --> {norm_after or 'UNKNOWN'}")
    if event.amplification and not credit_is_unlimited:
        parts.append(f"ANTI-AMPLIFICATION : {event.amplification}")
    return " | ".join(parts) if parts else None


def parse_log(path: Path, expected_role: str) -> Tuple[List[PacketEvent], List[InternalEvent]]:
    packets: List[PacketEvent] = []
    internals: List[InternalEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            raw_line = raw_line.rstrip()
            if not raw_line:
                continue
            match = LINE_RE.match(raw_line)
            if not match:
                continue
            role = match.group("role")
            if role != expected_role:
                continue
            kind = match.group("kind")
            ts = float(match.group("ts"))
            rest = match.group("rest").strip()
            if kind in {"SENT", "RECEIVED"}:
                packets.append(parse_packet_line(role, kind, ts, rest))
            elif kind == "INTERNAL":
                internals.append(parse_internal_line(role, ts, rest))
    return packets, internals


def parse_packet_line(role: str, kind: str, ts: float, rest: str) -> PacketEvent:
    pkt_no = pkt_type = None
    match = PACKET_INFO_RE.search(rest)
    if match:
        pkt_no = int(match.group("num"))
        pkt_type = match.group("ptype").strip()
    datagram = None
    dat_match = DATAGRAM_RE.search(rest)
    if dat_match:
        datagram = dat_match.group("size")
    frames = extract_frames(rest)
    credit_before = credit_after = amplification = credit_delta = None
    for field, value in CREDIT_FIELD_RE.findall(rest):
        label = field.replace(" ", "-").lower()
        trimmed = value.strip()
        if label == "credit-before":
            credit_before = trimmed
        elif label == "credit-after":
            credit_after = trimmed
        elif label == "credit":
            if credit_before is None:
                credit_before = trimmed
            if credit_after is None:
                credit_after = trimmed
        elif label == "amplification-factor":
            amplification = trimmed
    delta_match = DELTA_CREDIT_RE.search(rest)
    if delta_match:
        credit_delta = delta_match.group(1).strip()
    return PacketEvent(
        role=role,
        kind=kind,
        timestamp=ts,
        packet_no=pkt_no,
        packet_type=pkt_type,
        datagram=datagram,
        frames=frames,
        credit_before=credit_before,
        credit_after=credit_after,
        amplification=amplification,
        credit_delta=credit_delta,
    )


def parse_internal_line(role: str, ts: float, rest: str) -> InternalEvent:
    label = rest
    body = ""
    if rest.startswith("[") and "]" in rest:
        label_part, _, tail = rest.partition("]")
        label = label_part.strip("[]")
        body = tail.strip()
    return InternalEvent(role=role, timestamp=ts, label=label, body=body)


def extract_frames(rest: str) -> List[str]:
    payload = extract_braced_payload(rest)
    if not payload:
        return []
    segments = split_frames(payload)
    normalized = []
    for seg in segments:
        seg = seg.strip()
        match = FRAME_NAME_RE.match(seg)
        if match:
            normalized.append(summarize_frame(match.group("name"), match.group("body")))
        else:
            normalized.append(" ".join(seg.split()))
    return normalized


def split_frames(payload: str) -> List[str]:
    segments: List[str] = []
    depth = 0
    current: List[str] = []
    i = 0
    while i < len(payload):
        if payload.startswith(" | ", i) and depth == 0:
            seg = "".join(current).strip()
            if seg:
                segments.append(seg)
            current = []
            i += 3
            continue
        ch = payload[i]
        current.append(ch)
        if ch in "{(":
            depth += 1
        elif ch in ")}" and depth > 0:
            depth -= 1
        i += 1
    remainder = "".join(current).strip()
    if remainder:
        segments.append(remainder)
    return segments


def summarize_frame(name: str, body: str) -> str:
    upper = name.upper()
    if upper == "CRYPTO":
        return format_crypto_frame(body)
    if upper == "PADDING":
        return format_padding_frame(body)
    if upper == "ACK":
        return format_ack_frame(body)
    return format_generic_frame(upper, body)


def extract_balanced_section(text: str, open_char: str = "{", close_char: str = "}") -> Tuple[Optional[str], str]:
    start = text.find(open_char)
    if start == -1:
        return None, text
    depth = 0
    begin = None
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == open_char:
            depth += 1
            if depth == 1:
                begin = idx + 1
        elif ch == close_char:
            depth -= 1
            if depth == 0 and begin is not None:
                return text[begin:idx], text[idx + 1 :]
    return None, text


def normalize_segment(text: str) -> str:
    cleaned = re.sub(r"\s*,\s*", ", ", text.strip())
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def normalize_pipe_content(text: str) -> str:
    segments = [normalize_segment(part) for part in text.split("|")]
    return " | ".join(seg for seg in segments if seg)


def extract_attribute_value(text: str, key: str) -> Optional[str]:
    match = re.search(rf"{key}\s*=\s*([^,\)]+)", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def format_crypto_frame(body: str) -> str:
    inner, _ = extract_balanced_section(body)
    if inner:
        inner_text = " | ".join(
            normalize_segment(part) for part in inner.split("|") if part.strip()
        )
    else:
        inner_text = normalize_segment(body)

    size_val = extract_attribute_value(body, "SIZE")
    pieces: List[str] = []
    if inner_text:
        pieces.append(inner_text)
    if size_val:
        pieces.append(f"SIZE={size_val}")
    content = ", ".join(pieces)
    inside = content.strip()
    return f"CRYPTO{{ {inside} }}"


def format_padding_frame(body: str) -> str:
    size_val = extract_attribute_value(body, "SIZE")
    if size_val:
        return f"PADDING({size_val})"
    return "PADDING"


def format_ack_frame(body: str) -> str:
    range_val = extract_attribute_value(body, "RANGE")
    size_val = extract_attribute_value(body, "SIZE")
    details = []
    if range_val:
        details.append(f"Range={range_val}")
    if size_val:
        details.append(f"Size={size_val}")
    if not details:
        return "ACK"
    return f"ACK({', '.join(details)})"


def format_generic_frame(name: str, body: str) -> str:
    content = normalize_segment(body)
    if not content:
        return name
    return f"{name}({content})"


def extract_braced_payload(rest: str) -> Optional[str]:
    start = rest.find("{")
    if start == -1:
        return None
    depth = 0
    begin = None
    for idx in range(start, len(rest)):
        ch = rest[idx]
        if ch == "{":
            depth += 1
            if depth == 1:
                begin = idx + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and begin is not None:
                return rest[begin:idx].strip()
    return None


def normalize_times(
    events: Sequence[PacketEvent],
    internals: Sequence[InternalEvent],
    client_hello_value: Optional[float],
) -> None:
    client_events = [ev.timestamp for ev in events if ev.role == "CLIENT"] + [
        ev.timestamp for ev in internals if ev.role == "CLIENT"
    ]
    if not client_events:
        return
    t0 = min(client_events)
    if client_hello_value is None:
        client_hello_value = 0.0
    offset = client_hello_value - t0
    for ev in events:
        ev.norm_time = ev.timestamp + offset
    for ev in internals:
        ev.norm_time = ev.timestamp + offset


def find_client_hello_build(internals: Sequence[InternalEvent]) -> Optional[float]:
    for ev in internals:
        if ev.role != "CLIENT":
            continue
        if "CLIENT HELLO BUILD" in ev.label.upper():
            match = CLIENT_HELLO_BUILD_RE.search(ev.body)
            if match:
                return float(match.group(1))
    return None


def assign_directions(packets: Sequence[PacketEvent]) -> None:
    for ev in packets:
        if ev.role == "CLIENT" and ev.kind == "SENT":
            ev.direction = "client_to_server"
        elif ev.role == "SERVER" and ev.kind == "RECEIVED":
            ev.direction = "client_to_server"
        elif ev.role == "SERVER" and ev.kind == "SENT":
            ev.direction = "server_to_client"
        elif ev.role == "CLIENT" and ev.kind == "RECEIVED":
            ev.direction = "server_to_client"
        else:
            ev.direction = None


def pair_packets(packets: Sequence[PacketEvent]) -> List[PacketFlow]:
    assign_directions(packets)
    sends: Dict[str, List[PacketEvent]] = {"client_to_server": [], "server_to_client": []}
    recvs: Dict[str, List[PacketEvent]] = {"client_to_server": [], "server_to_client": []}
    for ev in packets:
        if ev.direction is None:
            continue
        if (ev.role == "CLIENT" and ev.kind == "SENT") or (ev.role == "SERVER" and ev.kind == "SENT"):
            sends[ev.direction].append(ev)
        elif (ev.role == "SERVER" and ev.kind == "RECEIVED") or (ev.role == "CLIENT" and ev.kind == "RECEIVED"):
            recvs[ev.direction].append(ev)
    flows: List[PacketFlow] = []
    for direction in ("client_to_server", "server_to_client"):
        send_list = sorted(sends[direction], key=lambda e: e.norm_time)
        recv_list = sorted(recvs[direction], key=lambda e: e.norm_time)
        used = [False] * len(recv_list)
        for send_ev in send_list:
            idx = match_receive(send_ev, recv_list, used)
            recv_ev = recv_list[idx] if idx is not None else None
            flows.append(PacketFlow(direction, send_ev, recv_ev, send_ev.norm_time))
    flows.sort(key=lambda f: f.norm_time)
    return flows


def match_receive(send_ev: PacketEvent, recv_list: Sequence[PacketEvent], used: List[bool]) -> Optional[int]:
    for idx, recv in enumerate(recv_list):
        if used[idx]:
            continue
        if send_ev.packet_no is not None and recv.packet_no == send_ev.packet_no:
            used[idx] = True
            return idx
    for idx, recv in enumerate(recv_list):
        if not used[idx]:
            used[idx] = True
            return idx
    return None


def group_internals(
    internals: Sequence[InternalEvent],
    packet_times: Sequence[float],
) -> List[Tuple[str, float, List[str]]]:
    blocks: List[Tuple[str, float, List[str]]] = []
    for role in ("CLIENT", "SERVER"):
        role_events = sorted((ev for ev in internals if ev.role == role), key=lambda e: e.norm_time)
        for ev in role_events:
            blocks.append((role, ev.norm_time, format_internal_block([ev])))
    blocks.sort(key=lambda blk: blk[1])
    return blocks


def has_packet_between(start: float, end: float, packet_times: Sequence[float]) -> bool:
    low, high = sorted((start, end))
    for ts in packet_times:
        if low < ts < high:
            return True
    return False


def format_internal_block(events: Sequence[InternalEvent]) -> List[str]:
    lines: List[str] = []
    for ev in events:
        title = ev.label.strip()
        if title:
            lines.append(title)
        body = ev.body.replace("|", "/").strip()
        if body:
            for chunk in body.split("/"):
                chunk = chunk.strip()
                if chunk:
                    lines.append(chunk)
    if lines:
        primary = lines[0].strip().upper()
        # no automated amplification suffix anymore
    return lines


def sanitize_label(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\"", "'").replace("\n", "<br/>")


def wrap_label(text: str, width: int = 150) -> str:
    if "<br/>" in text:
        return text
    paragraphs = text.split("\n")
    wrapped: List[str] = []
    for para in paragraphs:
        para = para.strip()
        if not para:
            wrapped.append("")
            continue
        wrapped.extend(
            textwrap.wrap(
                para,
                width=width,
                break_long_words=False,
                break_on_hyphens=False,
            )
            or [para]
        )
    return "\n".join(wrapped)


def build_mermaid_spec(
    flows: Sequence[PacketFlow],
    internal_blocks: Sequence[Tuple[str, float, List[str]]],
    kem: str,
    sig: str,
    mode: Optional[str],
    quic_mode: Optional[int],
) -> str:
    header = "sequenceDiagram"
    theme_vars = {
        "primaryColor": "#ffffff",
        "primaryTextColor": "#000000",
        "primaryBorderColor": "#000000",
        "secondaryColor": "#ffffff",
        "secondaryTextColor": "#000000",
        "lineColor": "#000000",
        "actorLineColor": "#000000",
        "actorTextColor": "#000000",
        "noteBkgColor": "#ffffff",
        "noteTextColor": "#000000",
        "noteBorderColor": "#000000",
        "sequenceNumberColor": "#000000",
        "tertiaryColor": "#ffffff",
        "tertiaryTextColor": "#000000",
        "width": "480",
    }
    theme_css = (
        ".messageText { font-size: 32px !important; font-weight: 600 !important; }\n"
        ".actor > text { font-size: 36px !important; font-weight: 700 !important; }\n"
        ".actor-line { stroke-width: 2px; }\n"
        ".noteText { font-size: 32px !important; font-weight: 600 !important; }\n"
        ".loopLine { stroke-width: 2px; }"
    )
    init_config = {
        "theme": "base",
        "securityLevel": "loose",
        "themeVariables": theme_vars,
        "themeCSS": theme_css,
        "sequence": {
            "actorFontSize": 30,
            "messageFontSize": 28,
            "noteFontSize": 28,
        },
    }
    theme_block = "%%{init: " + json.dumps(init_config) + "}%%"
    lines = [
        theme_block,
        "%% Generated by scripts/generate_packet_diagram.py",
        header,
        "    autonumber",
        "    participant ClientInternal as Client Internal",
        "    participant Client",
        "    participant Server",
        "    participant ServerInternal as Server Internal",
    ]

    timeline: List[Tuple[float, str, object]] = []
    for flow in flows:
        timeline.append((flow.norm_time, "flow", flow))
    for block in internal_blocks:
        timeline.append((block[1], "note", block))
    timeline.sort(key=lambda item: (round(item[0], 6), 0 if item[1] == "note" else 1))

    for _, kind, payload in timeline:
        if kind == "flow":
            flow = payload  # type: ignore[assignment]
            label = sanitize_label(wrap_label(flow.label))
            if flow.direction == "client_to_server":
                lines.append(f"    Client->>Server: {label}")
            else:
                lines.append(f"    Server-->>Client: {label}")
        else:
            role, _, note_lines = payload  # type: ignore[misc]
            if note_lines:
                title = note_lines[0]
                body_lines = note_lines
            else:
                title = f"{role} INTERNAL"
                body_lines = [title]
            primary = sanitize_label(wrap_label(title))
            details = []
            for line in body_lines[1:]:
                stripped = sanitize_label(wrap_label(line))
                if stripped:
                    details.append(stripped)
            src = "Client" if role == "CLIENT" else "Server"
            dst = "ClientInternal" if role == "CLIENT" else "ServerInternal"
            lines.append(f"    {src} ->> {dst}: [{primary}]")
            if details:
                detail_body = '<br/>'.join(details)
                lines.append(f"    {dst} -->> {src}: {detail_body}")
            elif primary.upper() == "HANDSHAKE DONE" and role == "SERVER":
                lines.append(f"    {dst} -->> {src}: handshakeDone=1")

    return "\n".join(lines) + "\n"


def find_latest_run(
    results_root: Path,
    combo: str,
    mode: Optional[str],
    quic_mode: Optional[int],
) -> Optional[Path]:
    bench_root = results_root / "benchmarks"
    if not bench_root.is_dir():
        return None
    candidates: List[Tuple[float, Path]] = []
    for entry in bench_root.iterdir():
        if not entry.is_dir() or not entry.name.startswith("PACKET-"):
            continue
        name_upper = entry.name.upper()
        if mode:
            token = f"ALGORITHMS-SET-{mode.upper()}"
            if token not in name_upper:
                continue
        if quic_mode is not None:
            token = f"QUIC-OPTION-{quic_mode}"
            if token not in name_upper:
                continue
        client_log = find_client_log(entry, combo)
        server_log = find_server_log(entry, combo)
        if client_log and server_log:
            candidates.append((entry.stat().st_mtime, entry))
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1] if candidates else None


def find_client_log(run_dir: Path, combo: str) -> Optional[Path]:
    combo_dir = run_dir / "raw_logs" / combo
    if not combo_dir.is_dir():
        return None
    candidates = sorted(combo_dir.glob("iteration_*.log"))
    if not candidates:
        return None
    return candidates[-1]


def find_server_log(run_dir: Path, combo: str) -> Optional[Path]:
    path = run_dir / "raw_logs_server" / combo / "server.log"
    return path if path.is_file() else None


def run_mermaid_cli(cli: str, mermaid_path: Path, pdf_path: Path) -> None:
    cmd = [cli, "-i", str(mermaid_path), "-o", str(pdf_path), "--pdfFit"]
    subprocess.run(cmd, check=True)


def resolve_run_dir(run_dir_arg: str, results_root: Path) -> Path:
    run_dir = Path(run_dir_arg)
    if not run_dir.is_absolute():
        run_dir = results_root / run_dir
    return run_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Mermaid sequence diagrams from packet-mode logs.")
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--run-dir", help="Benchmark directory (absolute or relative to --results-root)")
    parser.add_argument("--kem", required=True)
    parser.add_argument("--sig", required=True)
    parser.add_argument("--mode")
    parser.add_argument("--quic-mode", type=int)
    parser.add_argument("--output-root", type=Path, default=Path("results/diagram"))
    parser.add_argument("--render-cli", help="Optional mmdc-compatible CLI to render PDF")
    parser.add_argument("--print-latest-run", action="store_true", help="Print latest run dir and exit")
    parser.add_argument("--relative", action="store_true", help="When printing, output path relative to --results-root")
    args = parser.parse_args()

    combo = f"{args.kem.lower()}__{args.sig.lower()}"
    results_root = args.results_root.resolve()

    if args.print_latest_run:
        run_dir = find_latest_run(results_root, combo, args.mode, args.quic_mode)
        if not run_dir:
            return 1
        if args.relative:
            print(run_dir.relative_to(results_root))
        else:
            print(run_dir)
        return 0

    if args.run_dir:
        run_dir = resolve_run_dir(args.run_dir, results_root)
    else:
        run_dir = find_latest_run(results_root, combo, args.mode, args.quic_mode)
        if not run_dir:
            raise SystemExit("Could not locate packet-mode benchmark logs for the requested combination.")

    client_log = find_client_log(run_dir, combo)
    server_log = find_server_log(run_dir, combo)
    if not client_log or not server_log:
        raise SystemExit(f"Missing expected logs under {run_dir}")

    client_packets, client_internals = parse_log(client_log, "CLIENT")
    server_packets, server_internals = parse_log(server_log, "SERVER")

    all_packets = client_packets + server_packets
    all_internals = client_internals + server_internals

    client_hello_value = find_client_hello_build(client_internals)
    normalize_times(all_packets, all_internals, client_hello_value)

    flows = pair_packets(all_packets)
    packet_times = [flow.norm_time for flow in flows]
    internal_blocks = group_internals(all_internals, packet_times)

    diagram_spec = build_mermaid_spec(flows, internal_blocks, args.kem, args.sig, args.mode, args.quic_mode)

    output_dir = (args.output_root / combo).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    mermaid_path = output_dir / f"{combo}.mmd"
    mermaid_path.write_text(diagram_spec, encoding="utf-8")

    if args.render_cli:
        pdf_path = output_dir / f"{combo}.pdf"
        run_mermaid_cli(args.render_cli, mermaid_path, pdf_path)
    else:
        pdf_path = output_dir / f"{combo}.pdf"

    print(f"Mermaid spec saved to {mermaid_path}")
    if args.render_cli:
        print(f"PDF saved to {pdf_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
