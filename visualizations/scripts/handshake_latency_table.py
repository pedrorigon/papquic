#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import argparse, re, shutil, subprocess, textwrap
import pandas as pd
import numpy as np

CSV_DEFAULT      = "../data/handshake_packet_analyzer/off/handshake_full.csv"
CSV_OFF_LATENCY  = "../data/handshake_latency/off/handshake_latency_ms.csv"
CSV_3x_LATENCY   = "../data/handshake_latency/3x/handshake_latency_ms.csv"
CSV_5x_LATENCY   = "../data/handshake_latency/5x/handshake_latency_ms.csv"
CSV_10x_LATENCY  = "../data/handshake_latency/10x/handshake_latency_ms.csv"
CSV_15x_LATENCY  = "../data/handshake_latency/15x/handshake_latency_ms.csv"
CSV_20x_LATENCY  = "../data/handshake_latency/20x/handshake_latency_ms.csv"

OUT_DIR_REL   = "../outputs/table/handshake_table/latency_levels"
OUT_BASE_NAME = "table-latency-only"
FACTOR_ORDER  = ["off", "3x", "5x", "10x", "15x", "20x"]

def _norm(s: str) -> str:
    return re.sub(r'[^a-z0-9]', '', str(s).lower())

SEC_LVL_SPECS = {
    1: {
        "kems": [
            "mlkem512",
            "p256_mlkem512","x25519_mlkem512","bp256_mlkem1024".replace("1024","512"),
            "frodo640aes","frodo640shake",
            "p256_frodo640aes","x25519_frodo640aes","p256_frodo640shake","x25519_frodo640shake",
            "bikel1","p256_bikel1","x25519_bikel1",
            "hqc128","p256_hqc128","x25519_hqc128",
        ],
        "sigs": [
            "mldsa44","p256_mldsa44","rsa3072_mldsa44",
            "falcon512","falconpadded512","p256_falcon512","rsa3072_falcon512",
            "p256_falconpadded512","rsa3072_falconpadded512",
            "sphincssha2128fsimple","sphincssha2128ssimple",
            "p256_sphincssha2128fsimple","rsa3072_sphincssha2128fsimple",
            "p256_sphincssha2128ssimple","rsa3072_sphincssha2128ssimple",
            "sphincsshake128fsimple","sphincsshake128ssimple",
            "p256_sphincsshake128fsimple","rsa3072_sphincsshake128fsimple",
            "p256_sphincsshake128ssimple","rsa3072_sphincsshake128ssimple",
        ],
    },
    3: {
        "kems": [
            "mlkem768",
            "p384_mlkem768","x448_mlkem768","bp384_mlkem768",
            "X25519MLKEM768","SecP256r1MLKEM768",
            "frodo976aes","frodo976shake",
            "p384_frodo976aes","x448_frodo976aes","p384_frodo976shake","x448_frodo976shake",
            "bikel3","p384_bikel3","x448_bikel3",
            "hqc192","p384_hqc192","x448_hqc192",
        ],
        "sigs": [
            "mldsa65","p384_mldsa65",
            "sphincssha2192fsimple","sphincssha2192ssimple",
            "p384_sphincssha2192fsimple","p384_sphincssha2192ssimple",
            "sphincsshake192fsimple","sphincsshake192ssimple",
            "p384_sphincsshake192fsimple","p384_sphincsshake192ssimple",
        ],
    },
    5: {
        "kems": [
            "mlkem1024",
            "p521_mlkem1024","SecP384r1MLKEM1024","bp512_mlkem1024",
            "frodo1344aes","frodo1344shake",
            "p521_frodo1344aes","p521_frodo1344shake",
            "bikel5","p521_bikel5",
            "hqc256","p521_hqc256",
        ],
        "sigs": [
            "mldsa87","p521_mldsa87",
            "falcon1024","falconpadded1024",
            "p521_falcon1024","p521_falconpadded1024",
            "sphincssha2256fsimple","sphincssha2256ssimple",
            "p521_sphincssha2256fsimple","p521_sphincssha2256ssimple",
            "sphincsshake256fsimple","sphincsshake256ssimple",
            "p521_sphincsshake256fsimple","p521_sphincsshake256ssimple",
        ],
    },
}
SEC_LVL_ALLOW = {
    lvl: {
        "kems": {_norm(n) for n in spec["kems"]},
        "sigs": {_norm(n) for n in spec["sigs"]},
    } for lvl, spec in SEC_LVL_SPECS.items()
}

_PREFIX_LABEL = {
    "p256": "P256", "secp256r1": "P256",
    "p384": "P384", "secp384r1": "P384",
    "p521": "P521", "secp521r1": "P521",
    "x25519": "X25519", "x448": "X448",
    "bp256": "BP256", "bp384": "BP384", "bp512": "BP512",
    "rsa3072": "RSA3072",
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
    low = str(s).strip().lower()
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

def _pretty_pqc_sig(core: str) -> str:
    n = _norm(core)
    m = re.fullmatch(r"mldsa(44|65|87)", n)
    if m: return f"ML-DSA-{m.group(1)}"
    m = re.fullmatch(r"falcon(512|1024)", n)
    if m: return f"FALCON-{m.group(1)}"
    m = re.fullmatch(r"falconpadded(512|1024)", n)
    if m: return f"FALCON-PADDED-{m.group(1)}"
    m = re.fullmatch(r"sphincssha2(128|192|256)(f|s)simple", n)
    if m: return f"SPHINCS-SHA2-{m.group(1)}-{'F' if m.group(2)=='f' else 'S'}-SIMPLE"
    m = re.fullmatch(r"sphincsshake(128|192|256)(f|s)simple", n)
    if m: return f"SPHINCS-SHAKE-{m.group(1)}-{'F' if m.group(2)=='f' else 'S'}-SIMPLE"
    return core.upper().replace("_", "-")

def fmt_sig_label(s: str) -> str:
    low = str(s).strip().lower()
    if "_" in low:
        pref, rest = low.split("_", 1)
        if pref in _PREFIX_LABEL:
            left = _PREFIX_LABEL[pref]
            right = _pretty_pqc_sig(rest)
            return f"{left} + {right}"
    return _pretty_pqc_sig(low)

def is_hybrid_name(name: str) -> bool:
    n = _norm(name)
    return (
        "_" in str(name)
        or n.startswith(("p256","p384","p521","x25519","x448","bp256","bp384","bp512",
                         "secp256r1","secp384r1","secp521r1","rsa3072"))
        or "x25519mlkem" in n or "secp256r1mlkem" in n or "secp384r1mlkem" in n
    )

TYPE_RANK = {"mlkem": 0, "bike": 1, "frodo_aes": 2, "frodo_shake": 3, "hqc": 4}
SIG_RANK  = {"mldsa": 0, "falcon": 1, "sphincs_sha2": 2, "sphincs_shake": 3}

def hybrid_sort_key_kem(name: str) -> tuple[str, int, int]:
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
        t = "mlkem"; v = int(re.sub(r'[^0-9]', '', core) or 0)
    elif core.startswith("bikel"):
        t = "bike"; v = int(re.sub(r'[^0-9]', '', core) or 0)
    else:
        mf = re.match(r'^frodo(640|976|1344)(aes|shake)$', core)
        if mf:
            v = int(mf.group(1))
            t = "frodo_aes" if mf.group(2) == "aes" else "frodo_shake"
        else:
            mh = re.match(r'^hqc(128|192|256)$', core)
            if mh:
                t = "hqc"; v = int(mh.group(1))
    pref_label = _PREFIX_LABEL.get(pref, pref.upper())
    return (pref_label, TYPE_RANK.get(t, 99), v)

def pqc_sort_key_kem(name: str) -> tuple[int, int, str]:
    n = _norm(name)
    t, v = "zzz", 10**9
    if n.startswith("mlkem"):
        t, v = "mlkem", int(re.sub(r'[^0-9]', '', n) or 0)
    elif n.startswith("bikel"):
        t, v = "bike", int(re.sub(r'[^0-9]', '', n) or 0)
    else:
        mf = re.match(r'^frodo(640|976|1344)(aes|shake)$', n)
        if mf:
            v = int(mf.group(1)); t = "frodo_aes" if mf.group(2) == "aes" else "frodo_shake"
        else:
            mh = re.match(r'^hqc(128|192|256)$', n)
            if mh:
                t, v = "hqc", int(mh.group(1))
    return (TYPE_RANK.get(t, 99), v, fmt_kem_label(name))

def signature_sort_key(name: str) -> tuple[int, int, str]:
    s = str(name).lower().strip()
    core = s.split("_", 1)[1] if "_" in s and s.split("_",1)[0] in _PREFIX_LABEL else s
    n = _norm(core)
    fam_rank = 99
    num_rank = 10**9
    label = fmt_sig_label(name)
    m = re.fullmatch(r"mldsa(44|65|87)", n)
    if m: fam_rank, num_rank = 0, int(m.group(1))
    m = re.fullmatch(r"(falcon|falconpadded)(512|1024)", n)
    if m: fam_rank, num_rank = 1, int(m.group(2))
    m = re.fullmatch(r"sphincssha2(128|192|256)(f|s)simple", n)
    if m: fam_rank, num_rank = 2, int(m.group(1))
    m = re.fullmatch(r"sphincsshake(128|192|256)(f|s)simple", n)
    if m: fam_rank, num_rank = 3, int(m.group(1))
    fam = {0:"mldsa",1:"falcon",2:"sphincs_sha2",3:"sphincs_shake"}.get(fam_rank,"zzz")
    return (SIG_RANK.get(fam, 99), num_rank, label)

def ensure_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename_map = {
        "signature": "signature",
        "kem": "kem",
        "handshake_latency_ms": "lat_mean_ms",
        "handshake_latency_mean_ms": "lat_mean_ms",
        "mean_ms": "lat_mean_ms",
        "std_ms": "lat_std_ms",
        "handshake_latency_std_ms": "lat_std_ms",
        "client_packets_send": "client_packets_send",
        "server_packets_send": "server_packets_send",
        "client_total_bytes_send": "client_total_bytes_send",
        "server_total_bytes_send": "server_total_bytes_send",
        "amplification_factor_setting": "amplification_factor_setting",
        "amplification": "amplification_factor_setting",
        "amp_setting": "amplification_factor_setting",
    }
    for k, v in list(rename_map.items()):
        if k in df.columns and v != k:
            df.rename(columns={k: v}, inplace=True)
    needed = ["signature","kem","client_packets_send","server_packets_send",
              "client_total_bytes_send","server_total_bytes_send",
              "lat_mean_ms","lat_std_ms","amplification_factor_setting"]
    for c in needed:
        if c not in df.columns:
            df[c] = np.nan
    if "amplification_factor_setting" in df.columns:
        df["amplification_factor_setting"] = (
            df["amplification_factor_setting"].astype(str).str.lower().str.replace(" ", "")
        )
    return df

def canon_amp(a) -> str | None:
    if pd.isna(a): return None
    s = str(a).strip().lower().replace(" ", "")
    if s in {"off","desligado","disabled"}: return "off"
    if s.endswith("x"):
        d = re.sub(r'[^0-9]', '', s)
        return f"{d}x" if d else None
    if s.isdigit(): return f"{s}x"
    return s

def load_df(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    df = ensure_columns(df)
    df["amp_can"] = df["amplification_factor_setting"].map(canon_amp)
    return df

def load_latency_csv(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        return pd.DataFrame(columns=["signature","kem","lat_mean_ms","lat_std_ms"])
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    rename_map = {
        "signature": "signature",
        "kem": "kem",
        "handshake_latency_ms": "lat_mean_ms",
        "handshake_latency_mean_ms": "lat_mean_ms",
        "mean_ms": "lat_mean_ms",
        "std_ms": "lat_std_ms",
        "handshake_latency_std_ms": "lat_std_ms",
    }
    for k, v in list(rename_map.items()):
        if k in df.columns and v != k:
            df.rename(columns={k: v}, inplace=True)
    for c in ["signature","kem","lat_mean_ms","lat_std_ms"]:
        if c not in df.columns:
            df[c] = np.nan
    return df[["signature","kem","lat_mean_ms","lat_std_ms"]].copy()

def level_roman(level: int) -> str:
    return {1:"I", 3:"III", 5:"V"}[level]

def fmt_ms_pair(mean_val, std_val) -> str:
    if pd.isna(mean_val):
        return "-"
    try:
        m = float(mean_val)
    except Exception:
        return "-"
    if pd.isna(std_val):
        return f"{m:.1f}"
    try:
        s = float(std_val)
        return f"{m:.1f}±{s:.1f}"
    except Exception:
        return f"{m:.1f}"

def _latex_preamble_common():
    return r"""
\usepackage[margin=10mm]{geometry}
\usepackage{booktabs}
\usepackage{array}
\renewcommand{\arraystretch}{1.05}
\setlength{\tabcolsep}{4pt}
\setlength{\aboverulesep}{0.4ex}
\setlength{\belowrulesep}{0.4ex}
\setlength{\cmidrulesep}{0.18ex}
"""

def build_table_latency_only(rows_lines: list[str], english: bool) -> str:
    H_alg   = "Algorithm" if english else "Algoritmo"
    H_kem   = "Key exchange" if english else "Troca de Chave"
    H_sig   = "Signature" if english else "Assinatura"
    H_lat   = "Handshake Latency [ms]" if english else "Latência do Handshake [ms]"
    L_off   = "Off" if english else "Desligado"
    L_3x    = "Default(3x)" if english else "Padrão(3x)"
    cols = "@{}l l c c c c c c@{}"
    top  = (r"\multicolumn{2}{c}{\textbf{" + H_alg + r"}}"
            + r" & \multicolumn{6}{c}{\textbf{" + H_lat + r"}} \\")
    cmid = r"\cmidrule(lr){1-2}\cmidrule(lr){3-8}"
    under = (r"\textbf{" + H_kem + r"} & \textbf{" + H_sig + r"}"
             + r" & \textbf{"+ L_off + r"} & \textbf{"+ L_3x + r"} & \textbf{5x} & \textbf{10x} & \textbf{15x} & \textbf{20x} \\")
    body = "\n".join(rows_lines) if rows_lines else r"\multicolumn{8}{c}{No data} \\"
    doc = f"""
\\documentclass[10pt]{{article}}
{_latex_preamble_common()}
\\begin{{document}}
\\centering
\\small
\\begin{{tabular}}{{{cols}}}
\\toprule
{top}
{cmid}
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

def _pair_matches_kind(sig: str, kem: str, want_hybrid: bool) -> bool:
    s_h = is_hybrid_name(sig)
    k_h = is_hybrid_name(kem)
    return (s_h and k_h) if want_hybrid else (not s_h and not k_h)

def _pair_allowed(sig: str, kem: str, allow: dict) -> bool:
    return (_norm(sig) in allow["sigs"]) and (_norm(kem) in allow["kems"])

def build_rows_latency_only(df: pd.DataFrame,
                            df_offlat: pd.DataFrame,
                            df_3xlat: pd.DataFrame,
                            df_5xlat: pd.DataFrame,
                            df_10xlat: pd.DataFrame,
                            df_15xlat: pd.DataFrame,
                            df_20xlat: pd.DataFrame,
                            allow: dict,
                            want_hybrid: bool) -> list[str]:
    rows = []
    dfg = df.copy()
    if want_hybrid:
        dfg = dfg[dfg["kem"].apply(is_hybrid_name) & dfg["signature"].apply(is_hybrid_name)]
    else:
        dfg = dfg[~dfg["kem"].apply(is_hybrid_name) & ~dfg["signature"].apply(is_hybrid_name)]
    dfg = dfg[dfg["signature"].astype(str).map(_norm).isin(allow["sigs"])
              & dfg["kem"].astype(str).map(_norm).isin(allow["kems"])]
    base_pairs = set(zip(dfg["signature"], dfg["kem"])) if not dfg.empty else set()

    def build_map(dfi: pd.DataFrame) -> dict:
        if dfi.empty:
            return {}
        dfi = dfi[dfi["signature"].astype(str).map(_norm).isin(allow["sigs"])
                  & dfi["kem"].astype(str).map(_norm).isin(allow["kems"])]
        dfi = dfi[[ _pair_matches_kind(s, k, want_hybrid)
                    for s, k in zip(dfi["signature"], dfi["kem"]) ]]
        agg = (dfi.groupby(["signature","kem"], dropna=False)
                    .agg(lat_mean_ms=("lat_mean_ms","median"),
                         lat_std_ms=("lat_std_ms","median"))
                    .reset_index())
        return {(r["signature"], r["kem"]): (r["lat_mean_ms"], r["lat_std_ms"]) for _, r in agg.iterrows()}

    off_map  = build_map(df_offlat)
    m3_map   = build_map(df_3xlat)
    m5_map   = build_map(df_5xlat)
    m10_map  = build_map(df_10xlat)
    m15_map  = build_map(df_15xlat)
    m20_map  = build_map(df_20xlat)

    union_keys = base_pairs | set(off_map.keys()) | set(m3_map.keys()) | set(m5_map.keys()) \
                 | set(m10_map.keys()) | set(m15_map.keys()) | set(m20_map.keys())
    union_keys = {k for k in union_keys if _pair_allowed(*k, allow=allow) and _pair_matches_kind(*k, want_hybrid)}
    if not union_keys:
        return rows

    pairs = sorted(
        list(union_keys),
        key=lambda sk: (hybrid_sort_key_kem(sk[1]), signature_sort_key(sk[0])) if want_hybrid
                       else (pqc_sort_key_kem(sk[1]), signature_sort_key(sk[0]))
    )

    for sig, kem in pairs:
        kemL = fmt_kem_label(kem)
        sigL = fmt_sig_label(sig)
        l_off = fmt_ms_pair(*off_map.get((sig,kem), (np.nan, np.nan)))
        row_vals = [l_off]
        for a in FACTOR_ORDER:
            if a == "off":
                continue
            if a == "3x":
                m = m3_map.get((sig,kem), (np.nan, np.nan))
            elif a == "5x":
                m = m5_map.get((sig,kem), (np.nan, np.nan))
            elif a == "10x":
                m = m10_map.get((sig,kem), (np.nan, np.nan))
            elif a == "15x":
                m = m15_map.get((sig,kem), (np.nan, np.nan))
            elif a == "20x":
                m = m20_map.get((sig,kem), (np.nan, np.nan))
            else:
                m = (np.nan, np.nan)
            row_vals.append(fmt_ms_pair(*m))
        rows.append(f"{kemL} & {sigL} & " + " & ".join(row_vals) + r" \\")
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=CSV_DEFAULT)
    ap.add_argument("--english", action="store_true")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    out_root = here / OUT_DIR_REL
    out_root.mkdir(parents=True, exist_ok=True)

    df         = load_df((here / args.csv) if not Path(args.csv).is_absolute() else Path(args.csv))
    df_offlat  = load_latency_csv((here / CSV_OFF_LATENCY)  if not Path(CSV_OFF_LATENCY).is_absolute()  else Path(CSV_OFF_LATENCY))
    df_3xlat   = load_latency_csv((here / CSV_3x_LATENCY)   if not Path(CSV_3x_LATENCY).is_absolute()   else Path(CSV_3x_LATENCY))
    df_5xlat   = load_latency_csv((here / CSV_5x_LATENCY)   if not Path(CSV_5x_LATENCY).is_absolute()   else Path(CSV_5x_LATENCY))
    df_10xlat  = load_latency_csv((here / CSV_10x_LATENCY)  if not Path(CSV_10x_LATENCY).is_absolute()  else Path(CSV_10x_LATENCY))
    df_15xlat  = load_latency_csv((here / CSV_15x_LATENCY)  if not Path(CSV_15x_LATENCY).is_absolute()  else Path(CSV_15x_LATENCY))
    df_20xlat  = load_latency_csv((here / CSV_20x_LATENCY)  if not Path(CSV_20x_LATENCY).is_absolute()  else Path(CSV_20x_LATENCY))

    for level in (1,3,5):
        allow = SEC_LVL_ALLOW[level]
        dfL = df[df["kem"].astype(str).map(_norm).isin(allow["kems"])
                 & df["signature"].astype(str).map(_norm).isin(allow["sigs"])].copy()

        for want_hybrid, cat_slug in [(False, "pqc"), (True, "hybrid")]:
            rows_lines = build_rows_latency_only(
                dfL, df_offlat, df_3xlat, df_5xlat, df_10xlat, df_15xlat, df_20xlat,
                allow, want_hybrid=want_hybrid
            )
            if not rows_lines:
                continue
            tex = build_table_latency_only(rows_lines, english=args.english)
            roman = level_roman(level)
            base = f"{OUT_BASE_NAME}_lvl-{roman}_{cat_slug}{'_en' if args.english else '_pt'}"

            cat_dir = out_root / cat_slug
            cat_dir.mkdir(parents=True, exist_ok=True)

            tex_path = cat_dir / f"{base}.tex"
            tex_path.write_text(tex, encoding="utf-8")
            print(f"[OK] LaTeX written:\n - {tex_path}")

            pdf_path, png_path = compile_latex(tex_path, cat_dir)
            if pdf_path: print(f"[OK] PDF:  {pdf_path}")
            if png_path: print(f"[OK] PNG:  {png_path}")

if __name__ == "__main__":
    main()
