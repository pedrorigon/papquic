#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm, LinearSegmentedColormap
from matplotlib import patheffects as pe
from mpl_toolkits.axes_grid1 import make_axes_locatable
import re

CSV_DEFAULT = "../data/handshake_latency/loss-0/handshake_latency_ms.csv"
OUT_DIR_REL = "../outputs/heatmaps_level/handshake_latency"
OUT_BASE_NAME = "handshake_latency_heatmap_pqc_only"

CBAR_LABEL_EN = "Handshake Latency [ms] — Lower is Better"
CBAR_LABEL_PT = "Latência do Handshake [ms] — Menor é Melhor"

SIGNATURE_LABEL_EN = "Signature Algorithms"
SIGNATURE_LABEL_PT = "Algoritmos de Assinatura"

KEM_LABEL_EN = "Key Exchange Algorithms"
KEM_LABEL_PT = "Algoritmos de Troca de Chaves"

CELL_W_IN = 0.60
CELL_H_IN = 0.44
MIN_FIG_W_IN = 10
MIN_FIG_H_IN = 8
FIG_W_MARGIN_IN = 6
FIG_H_MARGIN_IN = 5

FONT_CELL = 12
FONT_AXIS = 14
FONT_AXIS_X = 10
FONT_AXIS_Y = 10
FONT_LABEL = 16

GRID_LW = 0.7
TEXT_STROKE_LW = 1.2
TEXT_STROKE_ALPHA = 0.85

XLABEL_PAD = 2
YLABEL_PAD = 2
LABEL_Y_NUDGE = 0.02

CAX_SIZE = "4%"
CAX_PAD_IN = 0.10
CBAR_LABEL_PAD = 5
CBAR_INIT_LABELSIZE = FONT_AXIS
CBAR_FINAL_LABELSIZE = 12
CBAR_TICKS = np.array([5, 10, 100, 500], dtype=float)

DPI_EXPORT = 300

def build_colormap() -> LinearSegmentedColormap:
    colors = [
        (0.00, "#5a0000"),
        (0.34, "#ff5a5a"),
        (0.40, "#f3f3f3"),
        (0.52, "#5b86d6"),
        (1.00, "#001033"),
    ]
    return LinearSegmentedColormap.from_list("darkred_briefwhite_darkblue", colors)

def dynamic_text_color(val: float, cmap, norm) -> str:
    r, g, b, _ = cmap(norm(val))
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    return "black" if y > 0.62 else "white"

def fmt_alg_label(x) -> str:
    s = str(x).upper().replace("_", " + ")
    if s == "X25519MLKEM768":
        return "X25519 + MLKEM768"
    if s == "SECP256R1MLKEM768":
        return "P256 + MLKEM768"
    if s == "SECP384R1MLKEM1024":
        return "P384 + MLKEM1024"
    return s

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("csv", nargs="?", default=CSV_DEFAULT,
                    help="CSV filename (relative to this script or absolute path)")
    p.add_argument("--english", action="store_true",
                    help="Render labels in English (default is Portuguese)")
    return p.parse_args()

def load_and_filter_csv(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    df["kem_category_norm"] = df.get("kem_category", "").astype(str).str.lower().str.strip()
    df["signature_category_norm"] = df.get("signature_category", "").astype(str).str.lower().str.strip()
    # df = df[(df["kem_category_norm"] != "classic") & (df["signature_category_norm"] != "classic")].copy()
    if df.empty:
        raise RuntimeError("No data to plot after filtering classics.")
    if "signature" not in df.columns or "kem" not in df.columns:
        raise RuntimeError("CSV must include 'signature' and 'kem' columns.")
    if "mean_ms" not in df.columns:
        raise RuntimeError("CSV is missing 'mean_ms' column.")
    return df

def build_pivots(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame | None]:
    pivot_mean = df.pivot_table(index="signature", columns="kem", values="mean_ms", aggfunc="median")
    pivot_std = df.pivot_table(index="signature", columns="kem", values="std_ms", aggfunc="median") if "std_ms" in df.columns else None
    pivot_mean = pivot_mean.dropna(how="all", axis=0).dropna(how="all", axis=1)
    if pivot_mean.empty:
        raise RuntimeError("Pivot matrix is empty after cleanup.")
    if pivot_std is not None:
        pivot_std = pivot_std.loc[pivot_mean.index, pivot_mean.columns]
    return pivot_mean, pivot_std

def compute_orders(pivot_mean: pd.DataFrame) -> tuple[list[str], list[str]]:
    col_order = pivot_mean.mean(axis=0).sort_values(ascending=False).index.tolist()
    row_order = pivot_mean.mean(axis=1).sort_values(ascending=True).index.tolist()
    return col_order, row_order

def get_category_maps(df: pd.DataFrame) -> tuple[dict[str, str], dict[str, str]]:
    # Create mappings from algorithm name to category
    kem_map = df.set_index("kem")["kem_category_norm"].to_dict()
    sig_map = df.set_index("signature")["signature_category_norm"].to_dict()
    return kem_map, sig_map

def matrices_and_labels(pivot_mean: pd.DataFrame, pivot_std: pd.DataFrame | None,
                        row_order: list[str], col_order: list[str],
                        kem_map: dict[str, str], sig_map: dict[str, str]) -> tuple[np.ndarray, np.ndarray, list[str], list[str], list[str], list[str]]:
    M = pivot_mean.loc[row_order, col_order].values
    S = pivot_std.loc[row_order, col_order].values if pivot_std is not None else np.full_like(M, np.nan)
    
    # Columns are KEMs
    raw_cols = pivot_mean.loc[row_order, col_order].columns
    col_labels = [fmt_alg_label(x) for x in raw_cols]
    col_cats = [kem_map.get(x, "unknown") for x in raw_cols]
    
    # Rows are Signatures
    raw_rows = pivot_mean.loc[row_order, col_order].index
    row_labels = [fmt_alg_label(x) for x in raw_rows]
    row_cats = [sig_map.get(x, "unknown") for x in raw_rows]
    
    return M, S, row_labels, col_labels, row_cats, col_cats

def compute_norm(M: np.ndarray) -> tuple[LogNorm, float, float]:
    finite_vals = M[np.isfinite(M)]
    vmin = float(np.nanmin(finite_vals))
    vmax = float(np.nanmax(finite_vals))
    vmin = max(vmin, 1e-6)
    return LogNorm(vmin=vmin, vmax=vmax, clip=True), vmin, vmax

def figure_size(n_rows: int, n_cols: int) -> tuple[float, float]:
    fig_w = max(MIN_FIG_W_IN, n_cols * CELL_W_IN + FIG_W_MARGIN_IN)
    fig_h = max(MIN_FIG_H_IN, n_rows * CELL_H_IN + FIG_H_MARGIN_IN)
    return fig_w, fig_h

def get_cat_color(cat: str) -> str:
    cat = cat.lower()
    if "classic" in cat:
        return "#116a10"
    if "hybrid" in cat:
        return "#001eff"
    # Default to PQC (red)
    return "#ff0000"

def draw_heatmap(M: np.ndarray, S: np.ndarray, row_labels: list[str], col_labels: list[str],
                row_cats: list[str], col_cats: list[str],
                norm: LogNorm, vmin: float, vmax: float,
                xlabel: str, ylabel: str, cbar_label: str) -> tuple[plt.Figure, plt.Axes, plt.Axes, plt.colorbar]:
    cmap = build_colormap()
    n_rows, n_cols = M.shape
    fig_w, fig_h = figure_size(n_rows, n_cols)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    im = ax.imshow(M, cmap=cmap, norm=norm, aspect="auto", interpolation="nearest", rasterized=True)

    ax.set_xticks(np.arange(-0.5, n_cols, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n_rows, 1), minor=True)
    ax.grid(which="minor", color="white", linestyle="-", linewidth=GRID_LW)
    ax.tick_params(which="minor", bottom=False, left=False)
    for spine in ax.spines.values():
        spine.set_visible(False)

    for i in range(n_rows):
        for j in range(n_cols):
            v = M[i, j]
            if not np.isfinite(v):
                continue
            s = S[i, j] if np.isfinite(S[i, j]) else np.nan
            vtxt = f"{float(v):.1f}"
            stxt = "" if np.isnan(s) else f"\n±{float(s):.1f}"
            color = dynamic_text_color(v, cmap, norm)
            t = ax.text(j, i, vtxt + stxt, ha="center", va="center",
                        fontsize=FONT_CELL, fontweight="bold", color=color)
            t.set_path_effects([pe.withStroke(linewidth=TEXT_STROKE_LW,
                                            foreground=("black" if color == "white" else "white"),
                                            alpha=TEXT_STROKE_ALPHA)])

    ax.set_xticks(np.arange(n_cols))
    ax.set_yticks(np.arange(n_rows))
    ax.set_xticklabels(col_labels, rotation=90, ha="center", fontsize=FONT_AXIS_X, fontweight="bold")
    ax.set_yticklabels(row_labels, rotation=0, fontsize=FONT_AXIS_Y, fontweight="bold")

    # Apply colors to tick labels
    for tick_label, cat in zip(ax.get_xticklabels(), col_cats):
        tick_label.set_color(get_cat_color(cat))
    
    for tick_label, cat in zip(ax.get_yticklabels(), row_cats):
        tick_label.set_color(get_cat_color(cat))

    ax.set_xlabel(xlabel, fontsize=FONT_LABEL, fontweight="bold", labelpad=XLABEL_PAD)
    ax.set_ylabel(ylabel, fontsize=FONT_LABEL, fontweight="bold", labelpad=YLABEL_PAD)

    divider = make_axes_locatable(ax)
    cax = divider.append_axes("right", size=CAX_SIZE, pad=CAX_PAD_IN)
    cbar = fig.colorbar(im, cax=cax)
    cbar.set_label(cbar_label, fontsize=FONT_LABEL, fontweight="bold", labelpad=CBAR_LABEL_PAD)
    cbar.ax.tick_params(labelsize=CBAR_INIT_LABELSIZE)
    cbar.ax.invert_yaxis()

    ticks = [t for t in CBAR_TICKS if (vmin <= t <= vmax)]
    cbar.set_ticks(ticks)
    labels = []
    for t in ticks:
        lbl = f"{int(t)}" if float(t).is_integer() else f"{t:.1f}"
        labels.append(rf"$\mathbf{{{lbl}}}$")
    cbar.set_ticklabels(labels)
    cbar.ax.tick_params(labelsize=CBAR_FINAL_LABELSIZE)
    cbar.minorticks_off()

    return fig, ax, cax, cbar

def save_outputs(fig: plt.Figure, out_dir: Path, out_png: Path, out_pdf: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=DPI_EXPORT, bbox_inches="tight")
    fig.savefig(out_pdf, dpi=DPI_EXPORT, bbox_inches="tight")
    print(f"[OK] Saved:\n - {out_png}\n - {out_pdf}")

# --------------------- Security level filtering ---------------------

def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(s).lower())

SEC_LVL_SPECS = {
    1: {
        "kems": [
            # MLKEM
            "mlkem512",
            "p256_mlkem512", "x25519_mlkem512", "bp256_mlkem512",
            # FrodoKEM
            "frodo640aes", "frodo640shake",
            "p256_frodo640aes", "x25519_frodo640aes", "p256_frodo640shake", "x25519_frodo640shake",
            # BIKE
            "bikel1", "p256_bikel1", "x25519_bikel1",
            # HQC
            "hqc128", "p256_hqc128", "x25519_hqc128",
        ],
        "sigs": [
            # MLDSA
            "mldsa44", "p256_mldsa44", "rsa3072_mldsa44",
            # Falcon
            "falcon512", "falconpadded512",
            "p256_falcon512", "rsa3072_falcon512", "p256_falconpadded512", "rsa3072_falconpadded512",
            # SPHINCS+ SHA-2
            "sphincssha2128fsimple", "sphincssha2128ssimple",
            "p256_sphincssha2128fsimple", "rsa3072_sphincssha2128fsimple",
            "p256_sphincssha2128ssimple", "rsa3072_sphincssha2128ssimple",
            # SPHINCS+ SHAKE
            "sphincsshake128fsimple", "sphincsshake128ssimple",
            "p256_sphincsshake128fsimple", "rsa3072_sphincsshake128fsimple",
            "p256_sphincsshake128ssimple", "rsa3072_sphincsshake128ssimple",
        ],
    },
    3: {
        "kems": [
            # MLKEM
            "mlkem768",
            "p384_mlkem768", "x448_mlkem768", "bp384_mlkem768",
            "X25519MLKEM768", "SecP256r1MLKEM768",  # camelCase variants
            # FrodoKEM
            "frodo976aes", "frodo976shake",
            "p384_frodo976aes", "x448_frodo976aes", "p384_frodo976shake", "x448_frodo976shake",
            # BIKE
            "bikel3", "p384_bikel3", "x448_bikel3",
            # HQC
            "hqc192", "p384_hqc192", "x448_hqc192",
        ],
        "sigs": [
            "mldsa65", "p384_mldsa65",
            # SPHINCS+ SHA-2
            "sphincssha2192fsimple", "sphincssha2192ssimple",
            "p384_sphincssha2192fsimple", "p384_sphincssha2192ssimple",
            # SPHINCS+ SHAKE
            "sphincsshake192fsimple", "sphincsshake192ssimple",
            "p384_sphincsshake192fsimple", "p384_sphincsshake192ssimple",
        ],
    },
    5: {
        "kems": [
            # MLKEM
            "mlkem1024",
            "p521_mlkem1024", "SecP384r1MLKEM1024", "bp512_mlkem1024",
            # FrodoKEM
            "frodo1344aes", "frodo1344shake",
            "p521_frodo1344aes", "p521_frodo1344shake",
            # BIKE
            "bikel5", "p521_bikel5",
            # HQC
            "hqc256", "p521_hqc256",
        ],
        "sigs": [
            "mldsa87", "p521_mldsa87",
            # Falcon
            "falcon1024", "falconpadded1024",
            "p521_falcon1024", "p521_falconpadded1024",
            # SPHINCS+ SHA-2
            "sphincssha2256fsimple", "sphincssha2256ssimple",
            "p521_sphincssha2256fsimple", "p521_sphincssha2256ssimple",
            # SPHINCS+ SHAKE
            "sphincsshake256fsimple", "sphincsshake256ssimple",
            "p521_sphincsshake256fsimple", "p521_sphincsshake256ssimple",
        ],
    },
}

# Precompute normalized allowlists
SEC_LVL_ALLOW = {
    lvl: {
        "kems": { _norm(n) for n in spec["kems"] },
        "sigs": { _norm(n) for n in spec["sigs"] },
    }
    for lvl, spec in SEC_LVL_SPECS.items()
}

def filter_by_security_level(df: pd.DataFrame, level: int) -> pd.DataFrame:
    allow = SEC_LVL_ALLOW[level]
    kem_norm = df["kem"].astype(str).map(_norm)
    sig_norm = df["signature"].astype(str).map(_norm)
    mask = kem_norm.isin(allow["kems"]) & sig_norm.isin(allow["sigs"])
    return df.loc[mask].copy()

# --------------------- /Security level filtering ---------------------

def main():
    args = parse_args()
    here = Path(__file__).resolve().parent
    out_dir = here / OUT_DIR_REL

    csv_path = here / args.csv
    df_all = load_and_filter_csv(csv_path)

    if args.english:
        xlabel, ylabel, cbar_label = KEM_LABEL_EN, SIGNATURE_LABEL_EN, CBAR_LABEL_EN
    else:
        xlabel, ylabel, cbar_label = KEM_LABEL_PT, SIGNATURE_LABEL_PT, CBAR_LABEL_PT

    # Generate one heatmap per security level (1, 3, 5)
    for level in (1, 3, 5):
        df = filter_by_security_level(df_all, level)
        if df.empty:
            print(f"[WARN] No data for security level {level}; skipping.")
            continue

        kem_map, sig_map = get_category_maps(df)

        pivot_mean, pivot_std = build_pivots(df)
        col_order, row_order = compute_orders(pivot_mean)
        M, S, row_labels, col_labels, row_cats, col_cats = matrices_and_labels(pivot_mean, pivot_std, row_order, col_order, kem_map, sig_map)
        norm, vmin, vmax = compute_norm(M)

        fig, ax, _, cbar = draw_heatmap(M, S, row_labels, col_labels, row_cats, col_cats, norm, vmin, vmax,
                                        xlabel=xlabel, ylabel=ylabel, cbar_label=cbar_label)
        fig.tight_layout()

        # small nudge on y-label and colorbar label (keep same visual)
        ylab = ax.yaxis.label
        x0, y0 = ylab.get_position()
        ylab.set_position((x0, y0 + LABEL_Y_NUDGE))

        cblab = cbar.ax.yaxis.label
        xc0, yc0 = cblab.get_position()
        cblab.set_position((xc0, yc0 + LABEL_Y_NUDGE))

        suffix_lang = "_en" if args.english else "_pt"
        out_png = out_dir / f"{OUT_BASE_NAME}_security_level_{level}{suffix_lang}.png"
        out_pdf = out_dir / f"{OUT_BASE_NAME}_security_level_{level}{suffix_lang}.pdf"
        save_outputs(fig, out_dir, out_png, out_pdf)

if __name__ == "__main__":
    main()

