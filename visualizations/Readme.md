# QUIC — Visualization Toolkit

A small, focused toolkit to generate publication-quality graphs for QUIC study.
It favors clarity, reproducibility, and is structured to grow as you add more visualization scripts. 

> **These scripts generate the visual representations for my Bachelor's Thesis in Computer Engineering at the Federal University of Rio Grande do Sul (UFRGS).**

---

## Features

* **Publication-ready heatmap** for handshake latency (ms):

  * Log color scale (low latency = dark red, high latency = dark blue)
  * Per-cell `mean ± std` annotations
  * Dynamic text color for readability
  * Ordering by average performance (best signatures at top, best KEMs at right)
  * Automatic filtering of `classic` categories
* **Language toggle** for figure labels: Portuguese (default) or English

---

## Repository Layout

```
.
├── data/
│   └── handshake_latency/
│       └── handshakeResults_2025y10m15d05h23m25s.csv
├── outputs/
│   └── handshake_heatmap/
│       └── handshake_heatmap_pqc_only_{pt|en}.{png,pdf}   # generated
├── scripts/
│   └── handshake_heatmap.py
├── Makefile
└── README.md
```

---

## Requirements

* Python 3.9+ (3.10/3.11 recommended)
* Packages: `numpy`, `pandas`, `matplotlib`

Install:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install numpy pandas matplotlib
```

(Optional) Virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install numpy pandas matplotlib
```

---

## Quick Start (Makefile)

The Makefile exposes a single entrypoint `run` and takes parameters as variables:

* `mode=all` or `mode=<script>` (e.g., `mode=handshake_heatmap`)
* `language=english` (default is Portuguese when omitted)
* `csv=path` (optional; only valid when `mode=<script>`)

### Examples

Portuguese (default), run all visualizations:

```bash
make run
```

English, run all:

```bash
make run language=english
```

Run only the handshake heatmap (Portuguese):

```bash
make run mode=handshake_heatmap
```

Run only the handshake heatmap (English):

```bash
make run mode=handshake_heatmap language=english
```

Run only the handshake heatmap with a specific CSV (English):

```bash
make run mode=handshake_heatmap csv=data/handshake_latency/my.csv language=english
```

> Note: when `mode=all`, `csv=` is not accepted (each script uses its default input).

---

## Outputs

Generated files (relative to repo root):

```
outputs/<visualization-script>/<visualization-script-name_{pt|en}.{<file-type>}>
```

---

## Script Options (current)

`scripts/handshake_heatmap.py`:

```
usage: handshake_heatmap.py [CSV] [--english]

positional arguments:
  CSV          CSV filename (relative to the script or absolute path).
               Default: ../data/handshake_latency/handshakeResults_2025y10m15d05h23m25s.csv

optional arguments:
  --english    Render axis and colorbar labels in English (default is Portuguese).
```

---

## Adding New Visualization Scripts

1. Put your script under `scripts/` (e.g., `scripts/my_plot.py`).
2. Follow the same structure: constants up top, small helper functions, `parse_args()`, `main()`.
3. Output under `outputs/<tool_name>/...`; suffix filenames with `_pt` / `_en` based on the language flag.
4. Support `--english` in the script (only figure labels should switch language).
5. With this Makefile, your script is automatically available as `mode=<script_basename>` and included in `mode=all`.

---

## Citation

If this toolkit helps in academic work, consider citing your repository or adding an acknowledgement in figure captions.

