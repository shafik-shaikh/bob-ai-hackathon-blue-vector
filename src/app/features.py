"""Column schema and feature building for network-flow events (UNSW-NB15 layout).

The model is trained on flow records as exported by Argus/Zeek-style sensors. An uploaded file is
mapped onto this schema by column name (case-insensitive, with a few common aliases). Columns that
are missing become NaN, which XGBoost handles natively; the response reports what was missing.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# Column order of the original headerless UNSW-NB15 CSV files.
RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

# stcpb/dtcpb (random TCP sequence numbers), IPs and timestamps are deliberately NOT features: they
# identify the testbed, not the behaviour, and would inflate scores without generalising.
NUMERIC = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "sload", "dload", "spkts", "dpkts",
    "swin", "dwin", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "dsport",
]
CATEGORICAL = ["proto", "service", "state"]

ALIASES = {
    "smean": "smeansz", "dmean": "dmeansz", "response_body_len": "res_bdy_len",
    "sinpkt": "sintpkt", "dinpkt": "dintpkt", "src_ip": "srcip", "source_ip": "srcip",
    "dst_ip": "dstip", "destination_ip": "dstip", "dest_ip": "dstip", "dport": "dsport",
    "dst_port": "dsport", "destination_port": "dsport", "src_port": "sport", "source_port": "sport",
    "starttime": "stime", "start_time": "stime", "attack_category": "attack_cat",
    "attack_type": "attack_cat", "is_attack": "label", "malicious": "label",
}

# Analyst-language names for the "why was this flagged" reasons.
PRETTY = {
    "dur": "flow duration", "sbytes": "bytes sent", "dbytes": "bytes received", "sttl": "source TTL",
    "dttl": "destination TTL", "sloss": "source packets lost", "dloss": "destination packets lost",
    "sload": "source load", "dload": "destination load", "spkts": "packets sent",
    "dpkts": "packets received", "swin": "source TCP window", "dwin": "destination TCP window",
    "smeansz": "mean sent packet size", "dmeansz": "mean received packet size",
    "trans_depth": "HTTP transaction depth", "res_bdy_len": "HTTP response size",
    "sjit": "source jitter", "djit": "destination jitter", "sintpkt": "source inter-packet gap",
    "dintpkt": "destination inter-packet gap", "tcprtt": "TCP round-trip", "synack": "SYN-ACK time",
    "ackdat": "ACK time", "is_sm_ips_ports": "same src/dst IP and port",
    "ct_state_ttl": "state/TTL pattern count", "ct_flw_http_mthd": "HTTP methods in flow",
    "is_ftp_login": "FTP login", "ct_ftp_cmd": "FTP commands", "ct_srv_src": "same-service flows from source",
    "ct_srv_dst": "same-service flows to destination", "ct_dst_ltm": "recent flows to destination",
    "ct_src_ltm": "recent flows from source", "ct_src_dport_ltm": "recent flows source→dst port",
    "ct_dst_sport_ltm": "recent flows dst←source port", "ct_dst_src_ltm": "recent flows src↔dst pair",
    "dsport": "destination port",
}


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Lower-case/strip column names and apply aliases. Existing canonical columns win over aliases."""
    seen: dict[str, str] = {}
    for col in df.columns:
        key = str(col).strip().lower().replace(" ", "_")
        seen[col] = ALIASES.get(key, key)
    renamed = df.rename(columns=seen)
    return renamed.loc[:, ~renamed.columns.duplicated()]


def _to_number(series: pd.Series) -> pd.Series:
    """Numeric coercion that also understands the hex ports ('0x000b') found in raw UNSW-NB15 files."""
    if series.dtype == object or str(series.dtype).startswith("string"):
        s = series.astype(str).str.strip()
        hexed = s.str.lower().str.startswith("0x")
        out = pd.to_numeric(s.where(~hexed), errors="coerce")
        if hexed.any():
            out.loc[hexed] = s[hexed].map(lambda v: int(v, 16) if _is_hex(v) else np.nan)
        return out.astype("float64")
    return pd.to_numeric(series, errors="coerce").astype("float64")


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def build_features(df: pd.DataFrame, vocab: dict[str, list[str]]) -> tuple[pd.DataFrame, list[str]]:
    """Return (feature matrix, missing input columns). `df` must already be column-normalised."""
    n = len(df)
    cols: dict[str, np.ndarray] = {}
    missing: list[str] = []
    for name in NUMERIC:
        if name in df.columns:
            cols[name] = _to_number(df[name]).to_numpy(dtype="float32")
        else:
            cols[name] = np.full(n, np.nan, dtype="float32")
            missing.append(name)
    for name in CATEGORICAL:
        known = vocab[name]
        if name in df.columns:
            values = df[name].astype(str).str.strip().str.lower()
            values = values.where(values.isin(known), "other")
        else:
            values = pd.Series(["other"] * n, index=df.index)
            missing.append(name)
        for level in known + ["other"]:
            cols[f"{name}={level}"] = (values == level).to_numpy(dtype="float32")
    return pd.DataFrame(cols, index=df.index), missing


def feature_label(feature: str) -> str:
    if "=" in feature:
        field, level = feature.split("=", 1)
        return f"{field} is {level}"
    return PRETTY.get(feature, feature)
