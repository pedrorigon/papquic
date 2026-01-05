#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import argparse, re, shutil, subprocess, textwrap
import pandas as pd
import numpy as np

CSV_DEFAULT = "../data/handshake_packet_analyzer/loss-0/handshake_full.csv"
OUT_DIR_REL = "../outputs/table/handshake_table/kem"
OUT_BASE_NAME_KEX = "table-kex-keyshare-QUIC"
LOSS_EXPECTED = {"off"}

def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(s).lower())

SEC_LVL_SPECS = {
    1: {"kems": [
        "mlkem512",
        "p256_mlkem512","x25519_mlkem512","bp256_mlkem512",
        "frodo640aes","frodo640shake",
        "p256_frodo640aes","x25519_frodo640aes","p256_frodo640shake","x25519_frodo640shake",
        "bikel1","p256_bikel1","x25519_bikel1",
        "hqc128","p256_hqc128","x25519_hqc128",
    ]},
    3: {"kems": [
        "mlkem768",
        "p384_mlkem768","x448_mlkem768","bp384_mlkem768",
        "X25519MLKEM768","SecP256r1MLKEM768",
        "frodo976aes","frodo976shake",
        "p384_frodo976aes","x448_frodo976aes","p384_frodo976shake","x448_frodo976shake",
        "bikel3","p384_bikel3","x448_bikel3",
        "hqc192","p384_hqc192","x448_hqc192",
    ]},
    5: {"kems": [
        "mlkem1024",
        "p521_mlkem1024","SecP384r1MLKEM1024","bp512_mlkem1024",
        "frodo1344aes","frodo1344shake",
        "p521_frodo1344aes","p521_frodo1344shake",
        "bikel5","p521_bikel5",
        "hqc256","p521_hqc256",
    ]},
}
SEC_LVL_ALLOW_KEMS = {lvl: {_norm(n) for n in spec["kems"]} for lvl, spec in SEC_LVL_SPECS.items()}

_PREFIX_LABEL = {
    "p256": "P256", "secp256r1": "P256",
    "p384": "P384", "secp384r1": "P384",
    "p521": "P521", "secp521r1": "P521",
    "x25519": "X25519", "x448": "X448",
    "bp256": "BP256", "bp384": "BP384", "bp512": "BP512",
}

def _pretty_pqc_kem(core: str) -> str:
    n = _norm(core)
    m = re.fullmatch(r"mlkem(512|768|1024)", n)
    if m: return f"ML-KEM-{m.group(1)}"
    m = re.fullmatch(r"frodo(640|976|1344)(aes|shake)", n)
    if m: return f"FRODO-{m.group(1)}-{m.group(2).upper()}"
    m = re.fullmatch(r"bikel([135])", n)
    if m: return f"BIKE-L{m.group(1)}"
    m = re.fullmatch(r"hqc(128|192|256)", n)
    if m: return f"HQC-{m.group(1)}"
    return core.upper().replace("_", "-")

def fmt_kem_label(s: str) -> str:
    raw = str(s).strip()
    low = raw.lower()
    m = re.fullmatch(r"(x25519|x448|secp256r1|secp384r1|secp521r1|p256|p384|p521|bp256|bp384|bp512)(mlkem\d+)", low)
    if m:
        left = _PREFIX_LABEL.get(m.group(1), m.group(1).upper())
        right = _pretty_pqc_kem(m.group(2))
        return f"{left} + {right}"
    if "_" in low:
        pref, rest = low.split("_", 1)
        if pref in _PREFIX_LABEL:
            left = _PREFIX_LABEL[pref]
            right = _pretty_pqc_kem(rest)
            return f"{left} + {right}"
    return _pretty_pqc_kem(low)

def is_hybrid_kem(name: str) -> bool:
    n = _norm(name)
    return (
        "_" in str(name)
        or n.startswith(("p256","p384","p521","x25519","x448","bp256","bp384","bp512","secp256r1","secp384r1","secp521r1"))
        or "x25519mlkem" in n or "secp256r1mlkem" in n or "secp384r1mlkem" in n
    )

TYPE_RANK = {
    "mlkem": 0,
    "bike": 1,
    "frodo_aes": 2,
    "frodo_shake": 3,
    "hqc": 4,
}

def hybrid_sort_key(name: str) -> tuple[str, int, int]:
    low = str(name).lower().strip()
    m = re.match(r'^(x25519|x448|secp256r1|secp384r1|secp521r1|p256|p384|p521|bp256|bp384|bp512)_(.+)$', low)
    if m:
        pref, core = m.group(1), m.group(2)
    else:
        m = re.match(r'^(x25519|x448|secp256r1|secp384r1|secp521r1|p256|p384|p521|bp256|bp384|bp512)(.+)$', low)
        if not m:
            return (_PREFIX_LABEL.get(low, low.upper()), 99, 10**9)
        pref, core = m.group(1), m.group(2)
    t, v = "zzz", 10**9
    if core.startswith("mlkem"):
        t = "mlkem"
        v = int(re.sub(r'[^0-9]', '', core) or 0)
    elif core.startswith("bikel"):
        t = "bike"
        v = int(re.sub(r'[^0-9]', '', core) or 0)
    else:
        mf = re.match(r'^frodo(640|976|1344)(aes|shake)$', core)
        if mf:
            v = int(mf.group(1))
            t = "frodo_aes" if mf.group(2) == "aes" else "frodo_shake"
        else:
            mh = re.match(r'^hqc(128|192|256)$', core)
            if mh:
                t = "hqc"
                v = int(mh.group(1))
    pref_label = _PREFIX_LABEL.get(pref, pref.upper())
    return (pref_label, TYPE_RANK.get(t, 99), v)

def ensure_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename_map = {
        "client_keyshare_bytes": "client_keyshare_bytes",
        "client_key_share_bytes": "client_keyshare_bytes",
        "client_keyshare": "client_keyshare_bytes",
        "tls_client_keyshare_bytes": "client_keyshare_bytes",
        "server_keyshare_bytes": "server_keyshare_bytes",
        "server_key_share_bytes": "server_keyshare_bytes",
        "server_keyshare": "server_keyshare_bytes",
        "tls_server_keyshare_bytes": "server_keyshare_bytes",
        "loss_profile": "loss_profile",
        "loss": "loss_profile",
    }
    for k, v in list(rename_map.items()):
        if k in df.columns and v != k:
            df.rename(columns={k: v}, inplace=True)
    for c in ["client_keyshare_bytes", "server_keyshare_bytes"]:
        if c not in df.columns:
            df[c] = np.nan
    if "loss_profile" in df.columns:
        df["loss_profile"] = (
            df["loss_profile"].astype(str).str.lower().str.replace(" ", "")
        )
    return df

def load_df(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    df = ensure_columns(df)
    if "loss_profile" in df.columns:
        df = df[df["loss_profile"].isin(LOSS_EXPECTED) | df["loss_profile"].isna()]
    return df

def level_roman(level: int) -> str:
    return {1: "I", 3: "III", 5: "V"}[level]

def dash_if_nan(x) -> str:
    return "-" if pd.isna(x) else str(int(round(x)))

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

def build_table_kex_sizes(rows_lines: list[str], english: bool) -> str:
    H_lvl  = "Security Level" if english else "Nível de Segurança"
    H_cat  = "Algorithm Category" if english else "Categoria do Algoritmo"
    H_alg  = "Key Exchange Algorithm" if english else "Algoritmo de Troca de Chave"
    H_sz   = "Key Share Sizes [B]" if english else "Key Share [B]"
    H_ck   = "Cliente"
    H_sk   = "Servidor"
    colspec = "@{}c c l c c@{}"
    top  = (r"\multirow[c]{2}{*}{\textbf{" + H_lvl + r"}}"
            + r" & \multirow[c]{2}{*}{\textbf{" + H_cat + r"}}"
            + r" & \multirow[c]{2}{*}{\textbf{" + H_alg + r"}}"
            + r" & \multicolumn{2}{c}{\textbf{" + H_sz + r"}} \\")
    cmid  = r"\cmidrule(lr){4-5}"
    gap   = r"\addlinespace[0.45ex]"
    under = r" &  &  & \textbf{" + H_ck + r"} & \textbf{" + H_sk + r"} \\"
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

def _canonical_classic(name: str) -> str:
    n = _norm(name)
    if n in {"x25519"}: return "x25519"
    if n in {"x448"}: return "x448"
    if n in {"secp256r1","p256"}: return "secp256r1"
    if n in {"secp384r1","p384"}: return "secp384r1"
    if n in {"secp521r1","p521"}: return "secp521r1"
    return ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=CSV_DEFAULT)
    ap.add_argument("--english", action="store_true")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    out_dir = here / OUT_DIR_REL
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_df((here / args.csv) if not Path(args.csv).is_absolute() else Path(args.csv))

    rows: list[str] = []

    classic_order = ["x25519", "secp256r1", "secp384r1", "secp521r1", "x448"]
    df["kem_norm"] = df["kem"].astype(str).map(_norm)
    df["classic_canon"] = df["kem"].astype(str).map(_canonical_classic)
    classics_df = df[df["classic_canon"].isin(classic_order)].copy()

    def kem_vals_rowlike(rowlike):
        return (
            fmt_kem_label(rowlike["kem"]),
            dash_if_nan(rowlike["client_keyshare_bytes"]),
            dash_if_nan(rowlike["server_keyshare_bytes"]),
        )

    if not classics_df.empty:
        kex_cls = (classics_df.groupby("kem", dropna=False)
                   .agg(client_keyshare_bytes=("client_keyshare_bytes", "median"),
                        server_keyshare_bytes=("server_keyshare_bytes", "median"))
                   .reset_index())
        def _cls_sort_key(nm: str):
            canon = _canonical_classic(nm)
            try:
                return (classic_order.index(canon), fmt_kem_label(nm))
            except ValueError:
                return (len(classic_order), fmt_kem_label(nm))
        kex_cls = kex_cls.sort_values(key=lambda s: s.map(_cls_sort_key), by="kem")
        n_cls = len(kex_cls)
        if n_cls > 0:
            cat_label = "Classic" if args.english else "Clássico"
            a0, ck0, sk0 = kem_vals_rowlike(kex_cls.iloc[0])
            rows.append(
                rf"\multirow[c]{{{n_cls}}}{{*}}{{\textbf{{-}}}}"
                + rf" & \multirow[c]{{{n_cls}}}{{*}}{{\textbf{{{cat_label}}}}}"
                + f" & {a0} & {ck0} & {sk0} \\\\"
            )
            for _, r in kex_cls.iloc[1:].iterrows():
                a, ck, sk = kem_vals_rowlike(r)
                rows.append(f" &  & {a} & {ck} & {sk} \\\\")
            rows.append(r"\cmidrule(lr){1-5}")

    levels = (1, 3, 5)
    for i, level in enumerate(levels):
        kems_ok = SEC_LVL_ALLOW_KEMS[level]
        dfL = df[df["kem"].astype(str).map(_norm).isin(kems_ok)].copy()
        if dfL.empty:
            continue
        kex_agg = (dfL.groupby("kem", dropna=False)
                    .agg(client_keyshare_bytes=("client_keyshare_bytes", "median"),
                         server_keyshare_bytes=("server_keyshare_bytes", "median"))
                    .reset_index())
        pqc_rows = kex_agg[~kex_agg["kem"].apply(is_hybrid_kem)].sort_values("kem")
        hyb_rows = kex_agg[kex_agg["kem"].apply(is_hybrid_kem)]
        hyb_list = sorted(hyb_rows.to_dict("records"), key=lambda r: hybrid_sort_key(r["kem"]))
        n_pqc, n_hyb = len(pqc_rows), len(hyb_list)
        n_total = n_pqc + n_hyb
        if n_total == 0:
            continue
        roman = level_roman(level)

        def kem_vals_rowlike2(rowlike):
            return (
                fmt_kem_label(rowlike["kem"]),
                dash_if_nan(rowlike["client_keyshare_bytes"]),
                dash_if_nan(rowlike["server_keyshare_bytes"]),
            )

        printed_level = False
        if n_pqc > 0:
            a0, ck0, sk0 = kem_vals_rowlike2(pqc_rows.iloc[0])
            rows.append(
                rf"\multirow[c]{{{n_total}}}{{*}}{{\textbf{{{roman}}}}}"
                + rf" & \multirow[c]{{{n_pqc}}}{{*}}{{\textbf{{PQC}}}}"
                + f" & {a0} & {ck0} & {sk0} \\\\"
            )
            printed_level = True
            for _, r in pqc_rows.iloc[1:].iterrows():
                a, ck, sk = kem_vals_rowlike2(r)
                rows.append(f" &  & {a} & {ck} & {sk} \\\\")
        if n_pqc > 0 and n_hyb > 0:
            rows.append(r"\cmidrule(lr){2-5}")
        if n_hyb > 0:
            a0, ck0, sk0 = kem_vals_rowlike2(hyb_list[0])
            if printed_level:
                rows.append(
                    rf" & \multirow[c]{{{n_hyb}}}{{*}}{{\textbf{{{'Hybrid' if args.english else 'Híbrido'}}}}}"
                    + f" & {a0} & {ck0} & {sk0} \\\\"
                )
            else:
                rows.append(
                    rf"\multirow[c]{{{n_total}}}{{*}}{{\textbf{{{roman}}}}}"
                    + rf" & \multirow[c]{{{n_hyb}}}{{*}}{{\textbf{{{'Hybrid' if args.english else 'Híbrido'}}}}}"
                    + f" & {a0} & {ck0} & {sk0} \\\\"
                )
            for r in hyb_list[1:]:
                a, ck, sk = kem_vals_rowlike2(r)
                rows.append(f" &  & {a} & {ck} & {sk} \\\\")
        if i < len(levels) - 1:
            rows.append(r"\cmidrule(lr){1-5}")

    tex = build_table_kex_sizes(rows, english=args.english)
    base = f"{OUT_BASE_NAME_KEX}{'_en' if args.english else '_pt'}"
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
