#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import argparse, re, shutil, subprocess, textwrap
import pandas as pd
import numpy as np

CSV_DEFAULT = "../data/handshake_packet_analyzer/loss-0/handshake_full.csv"
OUT_DIR_REL = "../outputs/table/handshake_table/signature"
OUT_BASE_NAME_SIGS = "table-signature-sizes-QUIC"
LOSS_EXPECTED = {"off"}

def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(s).lower())

SEC_LVL_SPECS = {
    1: {"kems": ["mlkem512","p256_mlkem512","x25519_mlkem512","bp256_mlkem512",
                "frodo640aes","frodo640shake","p256_frodo640aes","x25519_frodo640aes",
                "p256_frodo640shake","x25519_frodo640shake","bikel1","p256_bikel1",
                "x25519_bikel1","hqc128","p256_hqc128","x25519_hqc128"],
        "sigs": ["falcon512","falconpadded512",
                "p256_falcon512","rsa3072_falcon512","p256_falconpadded512","rsa3072_falconpadded512",
                "sphincssha2128fsimple","sphincssha2128ssimple","p256_sphincssha2128fsimple",
                "rsa3072_sphincssha2128fsimple","p256_sphincssha2128ssimple","rsa3072_sphincssha2128ssimple",
                "sphincsshake128fsimple","sphincsshake128ssimple","p256_sphincsshake128fsimple",
                "rsa3072_sphincsshake128fsimple","p256_sphincsshake128ssimple","rsa3072_sphincsshake128ssimple"]},
    2: {"kems": ["mlkem512","p256_mlkem512","x25519_mlkem512","bp256_mlkem512",
                "frodo640aes","frodo640shake","p256_frodo640aes","x25519_frodo640aes",
                "p256_frodo640shake","x25519_frodo640shake","bikel1","p256_bikel1",
                "x25519_bikel1","hqc128","p256_hqc128","x25519_hqc128"],
        "sigs": ["mldsa44","p256_mldsa44","rsa3072_mldsa44"]},
    3: {"kems": ["mlkem768","p384_mlkem768","x448_mlkem768","bp384_mlkem768",
                "X25519MLKEM768","SecP256r1MLKEM768","frodo976aes","frodo976shake",
                "p384_frodo976aes","x448_frodo976aes","p384_frodo976shake","x448_frodo976shake",
                "bikel3","p384_bikel3","x448_bikel3","hqc192","p384_hqc192","x448_hqc192"],
        "sigs": ["mldsa65","p384_mldsa65","sphincssha2192fsimple","sphincssha2192ssimple",
                "p384_sphincssha2192fsimple","p384_sphincssha2192ssimple","sphincsshake192fsimple",
                "sphincsshake192ssimple","p384_sphincsshake192fsimple","p384_sphincsshake192ssimple"]},
    5: {"kems": ["mlkem1024","p521_mlkem1024","SecP384r1MLKEM1024","bp512_mlkem1024",
                "frodo1344aes","frodo1344shake","p521_frodo1344aes","p521_frodo1344shake",
                "bikel5","p521_bikel5","hqc256","p521_hqc256"],
        "sigs": ["mldsa87","p521_mldsa87","falcon1024","falconpadded1024","p521_falcon1024",
                "p521_falconpadded1024","sphincssha2256fsimple","sphincssha2256ssimple",
                "p521_sphincssha2256fsimple","p521_sphincssha2256ssimple","sphincsshake256fsimple",
                "sphincsshake256ssimple","p521_sphincsshake256fsimple","p521_sphincsshake256ssimple"]},
}

SEC_LVL_ALLOW = {
    lvl: {"kems": {_norm(n) for n in spec["kems"]}, "sigs": {_norm(n) for n in spec["sigs"]}}
    for lvl, spec in SEC_LVL_SPECS.items()
}

_PREFIX_LABEL = {
    "p256": "P256", "p384": "P384", "p521": "P521",
    "rsa3072": "RSA-3072", "rsa2048": "RSA-2048", "rsa4096": "RSA-4096",
    "x25519": "X25519", "x448": "X448", "bp256": "BP256", "bp384": "BP384", "bp512": "BP512",
}

def _pretty_pqc_sig(core: str) -> str:
    n = _norm(core)
    m = re.fullmatch(r"mldsa(\d{2})", n)
    if m:
        return f"ML-DSA-{m.group(1)}"
    m = re.fullmatch(r"falconpadded(512|1024)", n)
    if m:
        return f"FALCON-PADDED-{m.group(1)}"
    m = re.fullmatch(r"falcon(512|1024)", n)
    if m:
        return f"FALCON-{m.group(1)}"
    m = re.fullmatch(r"sphincssha2(128|192|256)([fs])simple", n)
    if m:
        bits, fs = m.group(1), m.group(2).upper()
        return f"SPHINCS-SHA2-{bits}-{fs}-SIMPLE"
    m = re.fullmatch(r"sphincsshake(128|192|256)([fs])simple", n)
    if m:
        bits, fs = m.group(1), m.group(2).upper()
        return f"SPHINCS-SHAKE-{bits}-{fs}-SIMPLE"
    return core.upper().replace("_", r"\_")

def fmt_sig_label(s: str) -> str:
    raw = str(s).strip()
    low = raw.lower()
    if "_" in low:
        pref, rest = low.split("_", 1)
        left = _PREFIX_LABEL.get(pref, pref.upper())
        right = _pretty_pqc_sig(rest)
        return f"{left} + {right}"
    return _pretty_pqc_sig(low)

def is_hybrid_name(name: str) -> bool:
    return "_" in str(name)

def filter_level(df: pd.DataFrame, level: int) -> pd.DataFrame:
    allow = SEC_LVL_ALLOW[level]
    sig_ok = df["signature"].astype(str).map(_norm).isin(allow["sigs"])
    kem_ok = df["kem"].astype(str).map(_norm).isin(allow["kems"])
    return df.loc[sig_ok & kem_ok].copy()

def ensure_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename_map = {
        'signature_bytes': 'signature_bytes',
        'tls_individual_handshake_certificate': 'certificate_bytes',
        'server_certificate_size': 'certificate_bytes',
        'loss_profile': 'loss_profile',
        'loss': 'loss_profile',
    }
    for k,v in list(rename_map.items()):
        if k in df.columns and v != k:
            df.rename(columns={k:v}, inplace=True)
    for c in ['signature_bytes','certificate_bytes']:
        if c not in df.columns:
            df[c] = np.nan
    if 'loss_profile' in df.columns:
        df['loss_profile'] = (
            df['loss_profile'].astype(str).str.lower().str.replace(" ","")
        )
    return df

def load_df(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    df = ensure_columns(df)
    if 'loss_profile' in df.columns:
        df = df[df['loss_profile'].isin(LOSS_EXPECTED) | df['loss_profile'].isna()]
    return df

def level_roman(level: int) -> str:
    return {1:"I", 2:"II", 3:"III", 5:"V"}[level]

def dash_if_nan(x) -> str:
    return "-" if pd.isna(x) else str(int(round(x)))

def _tex_escape(s: str) -> str:
    return (str(s)
            .replace("\\", r"\textbackslash{}")
            .replace("_", r"\_")
            .replace("&", r"\&")
            .replace("%", r"\%")
            .replace("#", r"\#"))

def _latex_preamble_common():
    return r"""
\usepackage[margin=10mm]{geometry}
\usepackage{booktabs}
\usepackage{array}
\usepackage{multirow}
\renewcommand{\arraystretch}{1.05}
\setlength{\tabcolsep}{4pt}
\setlength{\aboverulesep}{0.4ex}
\setlength{\belowrulesep}{0.4ex}
\setlength{\cmidrulesep}{0.18ex}
"""

def build_table_signature_sizes(rows_lines: list[str], english: bool) -> str:
    H_lvl    = "Security Level" if english else "Nível de Segurança"
    H_cat    = "Algorithm Category" if english else "Categoria do Algoritmo"
    H_sigalg = "Signature Algorithm" if english else "Algoritmo de Assinatura"
    H_sizes  = "Sizes [B]" if english else "Tamanhos [B]"
    H_s      = "Signature" if english else "Assinatura"
    H_c      = "Certificate" if english else "Certificado"

    colspec = "@{}c c l c c@{}"
    top  = (r"\multirow[c]{2}{*}{\textbf{" + H_lvl + r"}}"
            + r" & \multirow[c]{2}{*}{\textbf{" + H_cat + r"}}"
            + r" & \multirow[c]{2}{*}{\textbf{" + H_sigalg + r"}}"
            + r" & \multicolumn{2}{c}{\textbf{" + H_sizes + r"}} \\")
    cmid  = r"\cmidrule(lr){4-5}"
    gap   = r"\addlinespace[0.45ex]"
    under = r" &  &  & \textbf{" + H_s + r"} & \textbf{" + H_c + r"} \\"
    body = "\n".join(rows_lines) if rows_lines else r"\multicolumn{5}{c}{No data}"
    doc = f"""
\\documentclass[10pt]{{article}}
{_latex_preamble_common()}
\\begin{{document}}
\\centering
\\small
\\begin{{tabular}}{{{colspec}}}
\\toprule
{top}
{cmid}
{gap}
{under}
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\end{{document}}
"""
    return textwrap.dedent(doc).strip()

def compile_latex(tex_path: Path, out_dir: Path) -> tuple[Path|None, Path|None]:
    pdf_path = out_dir / tex_path.with_suffix(".pdf").name
    png_path = out_dir / tex_path.with_suffix(".png").name
    if shutil.which("pdflatex"):
        try:
            subprocess.run(
                ["pdflatex","-interaction=nonstopmode","-output-directory",str(out_dir),str(tex_path)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            print(f"[WARN] pdflatex failed for {tex_path.name}")
    else:
        print("[WARN] 'pdflatex' not found in PATH; skipping PDF compilation.")
    if pdf_path.exists():
        if shutil.which("pdftoppm"):
            try:
                subprocess.run(
                    ["pdftoppm","-png","-singlefile",str(pdf_path),str(png_path.with_suffix(""))],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                print(f"[WARN] pdftoppm failed; PNG not generated for {pdf_path.name}")
        else:
            print("[WARN] 'pdftoppm' not found; skipping PNG generation.")
    return (pdf_path if pdf_path.exists() else None,
            png_path if png_path.exists() else None)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=CSV_DEFAULT)
    ap.add_argument("--english", action="store_true")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    out_dir = here / OUT_DIR_REL
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_df((here / args.csv) if not Path(args.csv).is_absolute() else Path(args.csv))

    rows_sig: list[str] = []

    # ---- Clássicos a partir de signature_category == "classic" ----
    classics_df = pd.DataFrame()
    if "signature_category" in df.columns:
        cat_norm = df["signature_category"].astype(str).str.strip().str.lower()
        classics_df = df[cat_norm == "classic"].copy()

    if not classics_df.empty:
        sig_cls = (classics_df.groupby("signature", dropna=False)
                   .agg(signature_bytes=("signature_bytes", "median"),
                        certificate_bytes=("certificate_bytes", "median"))
                   .reset_index())
        sig_cls = sig_cls.sort_values(by=["signature_bytes", "signature"], ascending=[True, True], na_position="last")
        n_cls = len(sig_cls)
        if n_cls > 0:
            cat_label = "Classic" if args.english else "Clássico"
            s0 = _tex_escape(sig_cls.iloc[0]["signature"])
            sb0 = dash_if_nan(sig_cls.iloc[0]["signature_bytes"])
            cb0 = dash_if_nan(sig_cls.iloc[0]["certificate_bytes"])
            rows_sig.append(
                rf"\multirow[c]{{{n_cls}}}{{*}}{{\textbf{{-}}}}"
                + rf" & \multirow[c]{{{n_cls}}}{{*}}{{\textbf{{{cat_label}}}}}"
                + f" & {s0} & {sb0} & {cb0} \\\\"
            )
            for _, r in sig_cls.iloc[1:].iterrows():
                s, sb, cb = _tex_escape(r["signature"]), dash_if_nan(r["signature_bytes"]), dash_if_nan(r["certificate_bytes"])
                rows_sig.append(f" &  & {s} & {sb} & {cb} \\\\")
            rows_sig.append(r"\cmidrule(lr){1-5}")

    # ---- PQC / Híbrido por nível (inalterado) ----
    levels = (1, 2, 3, 5)
    for i, level in enumerate(levels):
        dfL = filter_level(df, level)
        if dfL.empty:
            continue

        sig_agg = (dfL.groupby("signature", dropna=False)
                    .agg(signature_bytes=("signature_bytes", "median"),
                         certificate_bytes=("certificate_bytes", "median"))
                    .reset_index())

        pqc_rows = sig_agg[~sig_agg["signature"].apply(is_hybrid_name)].sort_values("signature")
        hyb_rows = sig_agg[sig_agg["signature"].apply(is_hybrid_name)].sort_values("signature")
        n_pqc, n_hyb = len(pqc_rows), len(hyb_rows)
        n_total = n_pqc + n_hyb
        if n_total == 0:
            continue

        roman = level_roman(level)

        def sig_vals(row):
            return (fmt_sig_label(row["signature"]),
                    dash_if_nan(row["signature_bytes"]),
                    dash_if_nan(row["certificate_bytes"]))

        printed_level = False
        if n_pqc > 0:
            s0, sb0, cb0 = sig_vals(pqc_rows.iloc[0])
            rows_sig.append(
                rf"\multirow[c]{{{n_total}}}{{*}}{{\textbf{{{roman}}}}}"
                + rf" & \multirow[c]{{{n_pqc}}}{{*}}{{\textbf{{PQC}}}}"
                + f" & {s0} & {sb0} & {cb0} \\\\"
            )
            printed_level = True
            for _, r in pqc_rows.iloc[1:].iterrows():
                s, sb, cb = sig_vals(r)
                rows_sig.append(f" &  & {s} & {sb} & {cb} \\\\")
        if n_pqc > 0 and n_hyb > 0:
            rows_sig.append(r"\cmidrule(lr){2-5}")
        if n_hyb > 0:
            s0, sb0, cb0 = sig_vals(hyb_rows.iloc[0])
            if printed_level:
                rows_sig.append(
                    rf" & \multirow[c]{{{n_hyb}}}{{*}}{{\textbf{{{'Hybrid' if args.english else 'Híbrido'}}}}}"
                    + f" & {s0} & {sb0} & {cb0} \\\\"
                )
            else:
                rows_sig.append(
                    rf"\multirow[c]{{{n_total}}}{{*}}{{\textbf{{{roman}}}}}"
                    + rf" & \multirow[c]{{{n_hyb}}}{{*}}{{\textbf{{{'Hybrid' if args.english else 'Híbrido'}}}}}"
                    + f" & {s0} & {sb0} & {cb0} \\\\"
                )
            for _, r in hyb_rows.iloc[1:].iterrows():
                s, sb, cb = sig_vals(r)
                rows_sig.append(f" &  & {s} & {sb} & {cb} \\\\")
        if i < len(levels) - 1:
            rows_sig.append(r"\cmidrule(lr){1-5}")

    tex = build_table_signature_sizes(rows_sig, english=args.english)
    base = f"{OUT_BASE_NAME_SIGS}{'_en' if args.english else '_pt'}"
    out_dir.mkdir(parents=True, exist_ok=True)
    tex_path = (out_dir / f"{base}.tex")
    (out_dir / f"{base}.latex").write_text(tex, encoding="utf-8")
    tex_path.write_text(tex, encoding="utf-8")
    print(f"[OK] LaTeX written:\n - {tex_path}")

    pdf_path, png_path = compile_latex(tex_path, out_dir)
    if pdf_path: print(f"[OK] PDF:  {pdf_path}")
    if png_path: print(f"[OK] PNG:  {png_path}")

if __name__ == "__main__":
    main()
