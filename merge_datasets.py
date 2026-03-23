import os
import csv
import gzip
import shutil
import time
import requests
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import zipfile
from zipfile import ZipFile, BadZipFile
from urllib.parse import urlparse
from tqdm import tqdm
from typing import Iterable, Optional

# ---------- Config ----------
# Verified public network-flow datasets with direct download links.
# Keep this list limited to sources that have been tested successfully.
#
# To add the Kyoto dataset, place your Kaggle API token in ~/.kaggle/kaggle.json
# and verify the download URL before uncommenting it.
URLS = {
    # --- Coburg IDS datasets (hs-coburg.de) ---
    # Flow records: src/dst IP+port, bytes, packets, protocol, duration, flags
    "CIDDS-001": "https://www.hs-coburg.de/wp-content/uploads/2024/11/CIDDS-001.zip",
    "CIDDS-002": "https://www.hs-coburg.de/wp-content/uploads/2024/11/CIDDS-002.zip",

    # Uncomment once ~/.kaggle/kaggle.json is present:
    # "Kyoto": "https://www.kaggle.com/api/v1/datasets/download/harshwardhanb...",
}

REQUIRED_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "duration",
    "tot_bytes", "tot_packets", "bytes_s", "bytes_r",
    "pkts_s", "pkts_r", "protocol", "avg_pkt_len", "max_pkt_len", "flow_rate",
    "attack_label",
]

DEST = "datasets"
OUT_CSV = "merged_flows.csv"
OUT_PARQUET = "merged_flows.parquet"
CHUNKSIZE = 250_000
TIMEOUT = 60
RETRIES = 3

PARQUET_SCHEMA = pa.schema([
    pa.field("src_ip", pa.large_string()),
    pa.field("dst_ip", pa.large_string()),
    pa.field("src_port", pa.int64()),
    pa.field("dst_port", pa.int64()),
    pa.field("duration", pa.float64()),
    pa.field("tot_bytes", pa.float64()),
    pa.field("tot_packets", pa.int64()),
    pa.field("bytes_s", pa.float64()),
    pa.field("bytes_r", pa.float64()),
    pa.field("pkts_s", pa.int64()),
    pa.field("pkts_r", pa.int64()),
    pa.field("protocol", pa.large_string()),
    pa.field("avg_pkt_len", pa.float64()),
    pa.field("max_pkt_len", pa.int64()),
    pa.field("flow_rate", pa.float64()),
    pa.field("attack_label", pa.large_string()),
])


# ---------- Helpers ----------

def http_get(url: str, retries: int = RETRIES, timeout: int = TIMEOUT) -> requests.Response:
    session = requests.Session()
    session.headers.update({"User-Agent": "dataset-merge/1.0"})
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, stream=True, timeout=timeout)
            if resp.status_code == 200:
                return resp
            last_exc = RuntimeError(f"HTTP {resp.status_code} for {url}")
        except Exception as e:
            last_exc = e
        sleep = min(8, 2 ** attempt)
        print(f"  Retry {attempt}/{retries} in {sleep}s...")
        time.sleep(sleep)
    raise last_exc or RuntimeError("Download failed")


def is_valid_archive(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(".zip"):
        return zipfile.is_zipfile(path)
    if lower.endswith(".gz"):
        try:
            with gzip.open(path, "rb") as fh:
                fh.read(1)
            return True
        except OSError:
            return False
    return os.path.getsize(path) > 0


def download_to_file(name: str, url: str, dest_folder: str) -> str:
    os.makedirs(dest_folder, exist_ok=True)
    parsed = urlparse(url)
    ext = os.path.splitext(parsed.path)[1] or ".bin"
    out_path = os.path.join(dest_folder, f"{name}{ext}")

    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        if is_valid_archive(out_path):
            print(f"[{name}] Already downloaded, skipping.")
            return out_path
        print(f"[{name}] Cached file is invalid, re-downloading.")
        os.remove(out_path)

    print(f"[{name}] Downloading from {url}")
    resp = http_get(url)
    total = int(resp.headers.get("Content-Length", 0))
    with open(out_path, "wb") as f, tqdm(
        total=total if total > 0 else None,
        unit="B", unit_scale=True, unit_divisor=1024, desc=name,
    ) as bar:
        for chunk in resp.iter_content(1024 * 128):
            if chunk:
                f.write(chunk)
                bar.update(len(chunk))

    if not is_valid_archive(out_path):
        os.remove(out_path)
        raise RuntimeError(f"Downloaded file for {name} is not a valid archive")

    return out_path


def extract_any(archive_path: str, target_dir: str) -> str:
    os.makedirs(target_dir, exist_ok=True)

    try:
        with ZipFile(archive_path, "r") as zf:
            zf.extractall(target_dir)
            gunzipped = 0
            for root, _, files in os.walk(target_dir):
                for fn in files:
                    if fn.lower().endswith(".gz"):
                        gz_path = os.path.join(root, fn)
                        out_path = os.path.join(root, fn[:-3])
                        try:
                            with gzip.open(gz_path, "rb") as gz, open(out_path, "wb") as out:
                                shutil.copyfileobj(gz, out)
                            gunzipped += 1
                        except Exception as e:
                            print(f"  Warning: could not gunzip {gz_path}: {e}")
            if gunzipped:
                print(f"  Gunzip complete: {gunzipped} file(s)")
            return target_dir
    except BadZipFile:
        pass

    if archive_path.lower().endswith(".gz"):
        out_name = os.path.basename(archive_path)[:-3]
        out_path = os.path.join(target_dir, out_name)
        try:
            print(f"  Decompressing gzip: {os.path.basename(archive_path)}")
            with gzip.open(archive_path, "rb") as gz, open(out_path, "wb") as out:
                shutil.copyfileobj(gz, out)
            return target_dir
        except Exception as e:
            print(f"  Warning: gzip decompression failed: {e}")

    dest = os.path.join(target_dir, os.path.basename(archive_path))
    if os.path.abspath(archive_path) != os.path.abspath(dest):
        shutil.copy2(archive_path, dest)
    print("  Warning: not a recognised archive format; file copied as-is.")
    return target_dir


def sniff_sep(sample_bytes: bytes) -> str:
    sample = sample_bytes.decode("utf-8", errors="ignore")
    try:
        dialect = csv.Sniffer().sniff(sample[:4096], delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        if sample.count("\t") > sample.count(","):
            return "\t"
        return ","


def iter_tabular_files(folder: str) -> Iterable[str]:
    for root, _, files in os.walk(folder):
        for f in files:
            if f.lower().endswith((".csv", ".tsv", ".txt")):
                yield os.path.join(root, f)


def coerce_numeric(series: pd.Series) -> pd.Series:
    """Convert numeric-like strings to numbers, including values like '2.1 M'."""
    text = series.astype("string").str.strip().str.replace(",", "", regex=False)
    direct = pd.to_numeric(text, errors="coerce").astype("Float64")

    extracted = text.str.extract(r"^([-+]?\d*\.?\d+)\s*([KMGTP]?)$", expand=True)
    base = pd.to_numeric(extracted[0], errors="coerce").astype("Float64")
    multiplier = extracted[1].str.upper().map({
        "": 1,
        "K": 1_000,
        "M": 1_000_000,
        "G": 1_000_000_000,
        "T": 1_000_000_000_000,
        "P": 1_000_000_000_000_000,
    }).astype("Float64")
    scaled = (base * multiplier).astype("Float64")
    return direct.where(direct.notna(), scaled)


def coerce_nullable_int(series: pd.Series) -> pd.Series:
    numeric = coerce_numeric(series)
    return numeric.round().astype("Int64")


def normalize_attack_label(series: pd.Series) -> pd.Series:
    """Normalize labels into a supervised target: normal or malicious."""
    s = series.astype("string").str.strip().str.lower()
    s = s.replace({"": pd.NA, "---": pd.NA, "nan": pd.NA, "none": pd.NA})
    normal_tokens = {
        "normal", "benign", "background", "legitimate", "non-attack", "non_attack",
    }
    out = s.copy()
    out = out.where(out.isna() | ~out.isin(normal_tokens), "normal")
    out = out.where(out.isna() | (out == "normal"), "malicious")
    return out.astype("string")


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    label_series: Optional[pd.Series] = None
    label_source_cols = ["attack_label", "class", "label", "attack", "attack_type", "attacktype", "category"]
    for col in label_source_cols:
        if col in df.columns:
            cur = df[col].astype("string").str.strip()
            cur = cur.replace({"": pd.NA, "---": pd.NA, "nan": pd.NA, "none": pd.NA})
            if label_series is None:
                label_series = cur
            else:
                label_series = label_series.fillna(cur)

    rename_map = {
        # Generic / common variants
        "source_ip": "src_ip",           "destination_ip": "dst_ip",
        "srcaddr": "src_ip",             "dstaddr": "dst_ip",
        "ipv4_src_addr": "src_ip",       "ipv4_dst_addr": "dst_ip",
        "l4_src_port": "src_port",       "l4_dst_port": "dst_port",
        "source_port": "src_port",       "destination_port": "dst_port",
        "sport": "src_port",             "dport": "dst_port",
        # CIDDS-001 / CIDDS-002 specific (after strip+lower+underscore)
        "src_ip_addr": "src_ip",         "dst_ip_addr": "dst_ip",
        "src_pt": "src_port",            "dst_pt": "dst_port",
        # Duration
        "flow_duration": "duration",     "duration_ms": "duration",
        "td": "duration",
        # Bytes
        "bytes": "tot_bytes",            "total_bytes": "tot_bytes",
        "in_bytes": "tot_bytes",         "out_bytes": "bytes_s",
        "bytes_sent": "bytes_s",         "bytes_received": "bytes_r",
        # Packets
        "packets": "tot_packets",        "total_packets": "tot_packets",
        "in_pkts": "tot_packets",        "out_pkts": "pkts_s",
        "packets_sent": "pkts_s",        "packets_received": "pkts_r",
        # Protocol
        "proto": "protocol",             "prot": "protocol",
        "protocol_name": "protocol",
        # Packet length
        "avg_packet_len": "avg_pkt_len", "max_packet_len": "max_pkt_len",
        "pkt_size_avg": "avg_pkt_len",
        # Flow rate / throughput
        "throughput": "flow_rate",       "flowrate": "flow_rate",
        "flow_byts_s": "flow_rate",
    }
    df = df.rename(columns=rename_map)

    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA

    if label_series is not None:
        current = df["attack_label"].astype("string").str.strip()
        current = current.replace({"": pd.NA, "---": pd.NA, "nan": pd.NA, "none": pd.NA})
        df["attack_label"] = current.fillna(label_series)

    for col in ("src_ip", "dst_ip", "protocol", "attack_label"):
        df[col] = df[col].astype("string").str.strip()

    int_cols = ["src_port", "dst_port", "tot_packets", "pkts_s", "pkts_r", "max_pkt_len"]
    float_cols = ["duration", "tot_bytes", "bytes_s", "bytes_r", "avg_pkt_len", "flow_rate"]
    for c in int_cols:
        df[c] = coerce_nullable_int(df[c])
    for c in float_cols:
        df[c] = coerce_numeric(df[c])

    if df["tot_bytes"].isna().all():
        bs = coerce_numeric(df["bytes_s"]).fillna(0)
        br = coerce_numeric(df["bytes_r"]).fillna(0)
        df["tot_bytes"] = bs + br

    if df["tot_packets"].isna().all():
        ps = coerce_numeric(df["pkts_s"]).fillna(0)
        pr = coerce_numeric(df["pkts_r"]).fillna(0)
        df["tot_packets"] = (ps + pr).astype("Int64")

    # For unidirectional flow exports, directional fields may be absent.
    # Populate sender side from totals so downstream models always get s/r fields.
    if df["bytes_s"].isna().all() and df["bytes_r"].isna().all():
        df["bytes_s"] = coerce_numeric(df["tot_bytes"])
        df["bytes_r"] = 0.0
    if df["pkts_s"].isna().all() and df["pkts_r"].isna().all():
        df["pkts_s"] = coerce_nullable_int(df["tot_packets"])
        df["pkts_r"] = 0

    if df["avg_pkt_len"].isna().all():
        num = coerce_numeric(df["tot_bytes"])
        den = coerce_numeric(df["tot_packets"]).replace(0, pd.NA)
        df["avg_pkt_len"] = num / den

    if df["flow_rate"].isna().all():
        dur = coerce_numeric(df["duration"])
        if dur.notna().sum() > 0:
            med = dur.median()
            dur_sec = dur / 1000.0 if (pd.notna(med) and med > 1000) else dur
            tb = coerce_numeric(df["tot_bytes"])
            df["flow_rate"] = tb / dur_sec.replace(0, pd.NA)

    df["protocol"] = df["protocol"].astype("string").str.upper()
    df["attack_label"] = normalize_attack_label(df["attack_label"])
    return df[REQUIRED_COLUMNS]


def read_csv_chunks(path: str) -> Iterable[pd.DataFrame]:
    with open(path, "rb") as fh:
        sample = fh.read(4096)
    sep = sniff_sep(sample)
    read_kwargs = dict(
        sep=sep, engine="python", chunksize=CHUNKSIZE,
        dtype=str,
        on_bad_lines="skip",
    )
    try:
        yield from pd.read_csv(path, encoding="utf-8", **read_kwargs)
    except UnicodeDecodeError:
        yield from pd.read_csv(path, encoding="latin-1", **read_kwargs)


def append_to_outputs(
    df: pd.DataFrame,
    csv_path: str,
    pq_writer: Optional[pq.ParquetWriter],
    wrote_header: dict,
) -> Optional[pq.ParquetWriter]:
    """Append one chunk to the CSV and (if requested) the parquet writer.
    Returns the (possibly newly created) ParquetWriter so the caller can keep it open."""
    header = not wrote_header.get("csv", False)
    df.to_csv(csv_path, mode="a", header=header, index=False)
    wrote_header["csv"] = True
    if pq_writer is not None:
        table = pa.Table.from_pandas(df, schema=PARQUET_SCHEMA, preserve_index=False)
        pq_writer.write_table(table)
    return pq_writer


def main() -> None:
    os.makedirs(DEST, exist_ok=True)
    for f in (OUT_CSV, OUT_PARQUET):
        if os.path.exists(f):
            os.remove(f)

    wrote_header: dict = {}
    total_rows = 0
    pq_writer: Optional[pq.ParquetWriter] = None  # opened on first chunk, closed at end

    try:
        for name, url in URLS.items():
            print(f"\n=== {name} ===")
            try:
                archive_path = download_to_file(name, url, DEST)
            except Exception as e:
                print(f"  ERROR: Failed to download {name}: {e}")
                continue

            extract_dir = os.path.join(DEST, name)
            extract_any(archive_path, extract_dir)

            found_any = False
            for file_path in iter_tabular_files(extract_dir):
                found_any = True
                print(f"  Processing: {file_path}")
                try:
                    for chunk in read_csv_chunks(file_path):
                        if chunk.empty:
                            continue
                        norm = normalize_columns(chunk).drop_duplicates()
                        total_rows += len(norm)
                        if pq_writer is None:
                            pq_writer = pq.ParquetWriter(OUT_PARQUET, PARQUET_SCHEMA)
                        append_to_outputs(norm, OUT_CSV, pq_writer, wrote_header)
                except Exception as e:
                    print(f"  WARNING: Skipping {file_path}: {e}")

            if not found_any:
                print(f"  No tabular files found in {extract_dir}")
    finally:
        if pq_writer is not None:
            pq_writer.close()

    print(f"\nDone. Wrote {total_rows:,} rows to {OUT_CSV}.")
    if os.path.exists(OUT_PARQUET):
        print(f"Parquet written: {OUT_PARQUET}")


if __name__ == "__main__":
    main()
