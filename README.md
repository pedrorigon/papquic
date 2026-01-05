# PAPQUIC - Performance Analyzer of Post-Quantum QUIC

A benchmarking framework for analyzing QUIC handshake latency and packet exchange behavior with post-quantum cryptography. Built on OpenSSL 3.6.0 with native QUIC support, the OQS provider, and an extended liboqs implementation that includes a broad set of PQC KEMs and signature algorithms.
All operations run entirely within a Docker container, with no host build required.

---

## Overview

This project includes:

* A fully self-contained Docker image that bundles OpenSSL 3.6.0 (QUIC), oqs-provider, and the extended liboqs build.
* A reproducible benchmarking pipeline using GNU Make and Docker that:

  * Launches the QUIC demo server in handshake-only mode.
  * Measures handshake latency using `s_client -quic -handshaketime`.
  * Parses round-trip time (RTT in milliseconds), removes outliers using the interquartile range (IQR), and generates CSV summaries containing the mean, standard deviation, and 95% confidence interval.
  * Automatically generates PQC certificates and keys for each selected signature algorithm using `genpkey` and `req -x509`.
* A structured QUIC packet logger (documented in `doc/packet_logging.md`) that captures per-datagram credit accounting, handshake metadata, and frame contents for both client and server.
* A utility script to list supported algorithms (groups and signature algorithms) in either plain text or JSON format.

---

## Requirements

* Docker (BuildKit recommended)
* GNU Make

---

## Usage

All benchmark operations are managed by the provided Makefile and Dockerfile.

```bash
# 1) Build the image (OpenSSL 3.6.0 + oqs-provider + extended liboqs)
make build

# 2) Run the full KEM × SIG matrix (PQC, hybrids, and selected classic algorithms) 15 times
make run mode=all COUNT=15

# 3) Run only PQC combinations (no hybrids or classic algorithms)
make run mode=pqc

# 4) Run PQC combinations constrained to matching NIST levels
make run mode=pqc-level

# 5) Run only hybrid (PQC + classic) combinations
make run mode=hybrid

# 6) Run a single KEM–SIG pair once
make run mode=one KEM=MLKEM768 SIG=MLDSA44 COUNT=1

# 7) Change the number of iterations (default: 50)
make run mode=all COUNT=200

# 8) Simulate 5% random packet loss inside the container
make run mode=all LOSS_PROFILE=5

# 9) Use the bursty (Gilbert–Elliott) loss model on interface eth0
make run mode=one KEM=MLKEM768 SIG=MLDSA44 LOSS_PROFILE=bursty NETEM_INTERFACE=eth0

# 10) Test with QUIC_MODE=0: QUIC Default (1-RTT, 3x amplification, no RETRY)
make run mode=one KEM=MLKEM768 SIG=MLDSA65 QUIC_MODE=0

# 10) Test with QUIC_MODE=1: QUIC Default (1-RTT, No-amplification (∞), no RETRY)
make run mode=one KEM=MLKEM768 SIG=MLDSA65 QUIC_MODE=1

# 10) Test with QUIC_MODE=2 (reserved for future experiments, currently identical to mode 0)
make run mode=one KEM=MLKEM768 SIG=MLDSA65 QUIC_MODE=2

# 11) Test with QUIC_MODE=3 QUIC RETRY-based (Address Validation - RFC 9000)
make run mode=one KEM=MLKEM768 SIG=MLDSA65 QUIC_MODE=3

# 12) Capture packet and byte counts for each combination once
make packetCount mode=all

# 13) Capture packets for a single pair with 2% simulated loss
make packetCount mode=one KEM=MLKEM768 SIG=MLDSA44 LOSS_PROFILE=2
```

The Python scripts can also be executed directly.
To switch from latency benchmarks to packet counting, add the `--packet-workflow` flag to `scripts/run_benchmarks.py`.
You may also pass options such as `--loss-profile`, `--netem-interface`, `--capture-interface`, or `--tcpdump-bin` to control network simulation or select custom capture tools.

### Print verbosity

Benchmark output can be tailored with the `PRINT_MODE` environment variable (or the
equivalent `--benchmark`, `--debug`, `--packet` CLI flags). The default `benchmark`
mode prints only `Handshake‑RTT` lines. `PRINT_MODE=debug` enables the verbose
instrumentation implemented in OpenSSL (`quic_debug`), while `PRINT_MODE=packet`
emits structured packet transmission logs from both client and server (see
`doc/packet_logging.md` for the exact format). Example:

```bash
make run PRINT_MODE=packet mode=one KEM=MLKEM768 SIG=MLDSA44
```

---

## Optional host tuning wrapper

For experiments that require stricter control over CPU frequency governors, Turbo/boost state, and CPU isolation, the repository ships a helper (`scripts/with_host_tuning.sh`). The Makefile uses this wrapper by default; disable it with `HOST_TUNING=off` if you need to skip host-side adjustments. Examples:

```bash
# Use the automatically selected CPUs (distinct physical cores), disable Turbo,
# and pin server/client to match the exposed CPUs
make run HOST_TUNING=on PIN_SERVER_CPU=0 PIN_CLIENT_CPU=2

# Packet count workflow with tuned host settings but keeping Turbo active
make packetCount HOST_TUNING=on HOST_TUNING_DISABLE_BOOST=off
```

When active, the wrapper:

* Elevates privileges (via `sudo`) to adjust `/sys/devices/system/cpu/cpufreq` settings.
* Stores the current governor for each policy, applies the requested governor (default `performance`), and restores the original governor when the command finishes.
* Optionally disables Turbo/boost while the benchmark is running and restores the prior state afterwards.
* Uses `cset shield --cpu=<list>` (when available) to temporarily isolate the requested logical CPUs so that other host workloads are moved away from the QUIC server/client cores.
* Auto-selects a set of distinct physical cores (two by default) when no CPU list is provided, keeping the container and the `cset` shield aligned. CPU 0 is deprioritised by default so that OS housekeeping threads keep their preferred core; adjust `HOST_TUNING_SKIP_CPUS` (including setting it to an empty string) to change this ordering.
* Accepts `HOST_TUNING_PREFER_NUMA=<node>` to bias the automatic picker toward a specific NUMA node (e.g., `HOST_TUNING_PREFER_NUMA=1` to keep both roles on node 1). When the queue of eligible cores in that node is exhausted, the script falls back to the remaining sockets.
* Allows per-role pinning via `PIN_SERVER_CPU` and `PIN_CLIENT_CPU`. When set, these values override the automatically selected roles so that you can align the QUIC processes with a pre-existing host isolation strategy while the container still uses the broader CPU reservation.
* Automatically cleans up (restores governors/boost and resets the `cset` shield) even if the benchmark exits early or is interrupted with `Ctrl+C`.
* Emits log lines prefixed with `[host-tuning]` that confirm which knobs were changed (governor, boost state, CPU shield) and when they are restored.
* Verifies each applied knob: after changing the governor or Turbo/boost flag it re-reads `/sys/devices/system/cpu/cpufreq/*`, after constraining `user.slice` it logs both `AllowedCPUs` and `AllowedCPUsEffective`, and every IRQ adjustment (service or manual) is followed by the current `irqbalance` status plus a sample of `/proc/interrupts` counters for the reserved CPUs. These checks are reported inline so you can confirm the host state without running extra commands.
* When the host runs cgroup v2 without `systemd-run`, the wrapper creates a temporary cpuset scope under `/sys/fs/cgroup/host_tuning_scope_*`, writes the requested CPU/memory masks, and moves the benchmark process tree into that scope. This keeps the isolation guarantees even on stripped-down distributions; the scope is removed automatically during cleanup.
* Persists a JSON snapshot under `.host_tuning_state/state.json` that records the reserved CPUs, per-role assignments, and real-time priority hints. This file is updated on every run and can be inspected separately.

If `cpupower` or `cset` are not installed on the host, the wrapper will skip the unavailable step with a warning while still running the benchmark. Likewise, if the automatic CPU selection fails, the wrapper logs the reason and continues without shielding.

You can also invoke the wrapper manually (omit `--cpus` to keep the automatic selection):

```bash
sudo scripts/with_host_tuning.sh --governor performance --disable-boost -- \
  docker run --cpuset-cpus=<cpus> ...
```

Set `HOST_TUNING=off` to keep the previous behaviour without any host-side adjustments.

### Verifying host tuning during a run

To inspect the state of the host while the benchmark is running, open a second terminal and execute:

```bash
sudo -v  # cache credentials once
watch -n1 "make host-status"
```

This helper prints the governor for each policy, the current Turbo/boost flag, and the `cset shield` status. It also filters the process list to the CPUs in `HOST_TUNING_CPUS`, which defaults to the automatically selected reservation. The automatic picker deprioritises CPU 0 so that OS housekeeping threads keep their preferred core; adjust `HOST_TUNING_SKIP_CPUS` if you need different exclusions (or set it to an empty value to disable skipping). Override `HOST_TUNING_CPUS` to inspect a different set. Because `make host-status` reuses the same script wrapper, it will reapply `sudo` if needed; caching credentials with `sudo -v` avoids prompts while `watch` is running. The command also refreshes `.host_tuning_state/state.json` even if no benchmark has run yet, ensuring the “Host tuning snapshot” section is always populated with the current reservation metadata.

---

## Output

* **Handshake results:** CSV files are saved under `results/`, with detailed per-iteration logs in `raw_logs/`. Each summary file includes the number of iterations, number of outliers removed, mean latency (ms), standard deviation (ms), 95% confidence interval, applied loss profile, and the configured amplification multiplier. Files are timestamped as `handshakeResults_YYYYyMMmDDdHHhMMmSSs.csv`.

* **Packet capture results:** Generated as `packetCount_*.csv` along with raw QUIC handshake transcripts and tcpdump output under `packetcount_logs/`. Columns include total packets and bytes per direction, aggregate counts, and computed averages.

---

## Visualizations

The `visualizations/` directory contains a standalone toolkit (with its own Makefile) to generate publication-quality charts, including heatmaps for handshake latency. Refer to [`visualizations/Readme.md`](visualizations/Readme.md) for installation requirements, supported scripts, and usage examples such as `make run mode=handshake_heatmap language=english`.

---

## Configuration (Environment Variables)

These variables can be passed using `make run VAR=value` or directly to the container.

| Variable | Description |
| --- | --- |
| `MODE` | Benchmark scope: `all` (full matrix), `pqc` (PQC-only), `hybrid` (PQC + classic), or `one` (single pair). Default is `all`. |
| `KEM` | KEM or group name used when `MODE=one`. Invoke `make kem-sig` to inspect valid values. |
| `SIG` | Signature name used when `MODE=one`. Invoke `make kem-sig` to inspect valid values. |
| `COUNT` | Number of handshakes per combination (positive integer). Default is `50`. |
| `AMPLIFICATION_VALUE` | QUIC anti-amplification multiplier. Accepts `0` (disable validation) or an integer between `3` and `30`. Default is `3`. |
| `LOSS_PROFILE` | Packet loss model applied via `tc netem`: `0`, `0.1`, `0.5`, `1`, `2`, `5`, `10`, `15`, `20`, `25`, `30`, or `bursty` (Gilbert–Elliott). Default is `0`. |
| `NETEM_INTERFACE` | Interface where `tc netem` rules are attached (default `lo`). Apply to the receiving endpoint inside the container, e.g., `eth0`. |
| `RESULTS_DIR` | Output directory inside the container. Default is `/app/results`. |
| `HOST_UID`, `HOST_GID` | Override ownership of generated files to match the host user/group. |
| `PIN_SERVER_CPU`, `PIN_CLIENT_CPU` | Pin server or client processes to specific logical CPUs to reduce jitter. |
| `HOST_TUNING` | Wrap the Docker command with `scripts/with_host_tuning.sh` to adjust governor/boost/CPU shielding. Enabled by default; set to `off` to skip. |
| `HOST_TUNING_CPUS` | Comma-separated CPU list reserved for the container and `cset` shield when `HOST_TUNING=on`; defaults to an automatically detected set of distinct physical cores. Also used by `make host-status` to filter the process list. |
| `HOST_TUNING_AUTO_CPU_COUNT` | Number of unique physical cores to reserve when `HOST_TUNING_CPUS` is not set (default `2`). |
| `HOST_TUNING_SKIP_CPUS` | Comma-separated CPUs to move to the end of the auto-selection order (default `0`). Set to an empty string to consider every CPU equally. |
| `HOST_TUNING_GOVERNOR` | Governor name passed to the host tuning wrapper (default `performance`). |
| `HOST_TUNING_DISABLE_BOOST` | `on` disables Turbo/boost during the run; set to `off` to keep Turbo enabled. |
| `PACKET_CAPTURE_IFACE` | Interface to capture packets when `BENCH_KIND=packetcount`. Default is `lo`. |
| `PACKET_CAPTURE_TOOL` | Capture binary to use in packet counting mode (default `tcpdump`). |
| `DOCKER` | Docker (or compatible) runtime command. Default follows the `DOCKER` variable in the Makefile. |
| `IMAGE_NAME` | Name/tag for the built Docker image. |

---

## Loss Profiles

The following profiles are available via `LOSS_PROFILE` or `--loss-profile`.
They apply only to UDP traffic on the QUIC port configured inside the container.

| Key                                                       | Description                                                                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `0`                                                       | No packet loss. `tc netem` is not applied.                                                                          |
| `0.1`, `0.5`, `1`, `2`, `5`, `10`, `15`, `20`, `25`, `30` | Independent random loss (percentage-based).                                                                         |
| `bursty`                                                  | Gilbert–Elliott bursty loss model (`loss state 0.03/0.3`), averaging approximately 9% total loss with short bursts. |

All network simulations are isolated within the container environment.
The Makefile automatically adds `NET_ADMIN` and `NET_RAW` capabilities and restores the interface state at the end of each execution.

---

## Listing Supported Algorithms

To list available KEM groups and signature algorithms from the built OpenSSL within the container:

```bash
make kem-sig
```

This command attempts `list -tls-groups` (falling back to `list -groups`) and parses `list -signature-algorithms` for the full set of supported algorithms.

---

## Supported KEMs

Case-sensitive names. Use them exactly as listed.

**ML-KEM:**
MLKEM512, p256_mlkem512, x25519_mlkem512, bp256_mlkem512,
MLKEM768, p384_mlkem768, x448_mlkem768, X25519MLKEM768, SecP256r1MLKEM768, bp384_mlkem768,
MLKEM1024, p521_mlkem1024, SecP384r1MLKEM1024, bp512_mlkem1024

**FrodoKEM:**
frodo640aes, frodo640shake, p256_frodo640aes, x25519_frodo640aes, p256_frodo640shake, x25519_frodo640shake, frodo976aes, frodo976shake, p384_frodo976aes, x448_frodo976aes, p384_frodo976shake, x448_frodo976shake, frodo1344aes, frodo1344shake, p521_frodo1344aes, p521_frodo1344shake

**BIKE:**
bikel1, p256_bikel1, x25519_bikel1, bikel3, p384_bikel3, x448_bikel3, bikel5, p521_bikel5

**HQC:**
hqc128, p256_hqc128, x25519_hqc128, hqc192, p384_hqc192, x448_hqc192, hqc256, p521_hqc256

**Classic ECDH:**
x25519, secp256r1, secp384r1, x448

---

## Supported Signatures

**ML-DSA:**
MLDSA44, p256_mldsa44, rsa3072_mldsa44, MLDSA65, p384_mldsa65, MLDSA87, p521_mldsa87

**Falcon:**
falcon512, p256_falcon512, rsa3072_falcon512, falconpadded512, p256_falconpadded512, rsa3072_falconpadded512,
falcon1024, p521_falcon1024, falconpadded1024, p521_falconpadded1024

**SPHINCS+ (SHA-2):**
sphincssha2128fsimple, p256_sphincssha2128fsimple, rsa3072_sphincssha2128fsimple,
sphincssha2128ssimple, p256_sphincssha2128ssimple, rsa3072_sphincssha2128ssimple,
sphincssha2192fsimple, p384_sphincssha2192fsimple, sphincssha2192ssimple, p384_sphincssha2192ssimple,
sphincssha2256fsimple, p521_sphincssha2256fsimple, sphincssha2256ssimple, p521_sphincssha2256ssimple

**SPHINCS+ (SHAKE):**
sphincsshake128fsimple, p256_sphincsshake128fsimple, rsa3072_sphincsshake128fsimple,
sphincsshake128ssimple, p256_sphincsshake128ssimple, rsa3072_sphincsshake128ssimple,
sphincsshake192fsimple, p384_sphincsshake192fsimple, sphincsshake192ssimple, p384_sphincsshake192ssimple,
sphincsshake256fsimple, p521_sphincsshake256fsimple, sphincsshake256ssimple, p521_sphincsshake256ssimple

**Classic:**
ED25519, ED448

---

## Internal Workflow

1. Sets up environment variables `OPENSSL_CONF`, `OPENSSL_MODULES`, and `LD_LIBRARY_PATH` for the OQS provider.
2. Queries OpenSSL for supported groups and signatures, filters to selected ones, and constructs all KEM×SIG pairs.
3. Generates a private key and self-signed certificate for each signature algorithm.
4. Runs the QUIC demo server for each pair, executing multiple handshakes with `s_client -quic -handshaketime`.
5. Parses RTT values, removes outliers (IQR), and computes summary statistics.
6. Produces timestamped CSVs under `results/`.
7. Optionally captures packet counts if the `--packet-workflow` mode is enabled.
8. Fixes file ownership if `HOST_UID` and `HOST_GID` are defined.

---

## Repository Structure

```
.
├── Dockerfile
├── Makefile
├── config/openssl-oqs.cnf
├── doc/
│   └── packet_logging.md
├── openssl-3.6.0/
├── oqs-provider/
├── scripts/
│   ├── run_benchmarks.py
│   ├── run_packet_count.py
│   ├── list_kem_sig.py
│   └── docker_entrypoint.sh
└── results/
    ├── handshakeResults_*.csv
    ├── raw_logs/<kem>__<sig>/iteration_XXX.log
    └── packetcount_logs/{handshakes,tcpdump}/...
```

---

## License

All OpenSSL and OQS components retain their original licenses.
Custom scripts and configurations in this repository are distributed under this repository’s license.

---

## Citation / Reference

If you use this repository in academic work, please cite it as follows:

```
@software{papquic_benchmark,
  author       = {Pedro Rigon},
  title        = {PAPQUIC - Performance Analyzer of Post-Quantum QUIC},
  year         = {2025},
  url          = {https://github.com/pedrorigon/papquic},
  note         = {Benchmarking framework for analyzing QUIC handshake performance with post-quantum key exchange and signature algorithms using OpenSSL 3.6.0 and the OQS provider.}
}
```
