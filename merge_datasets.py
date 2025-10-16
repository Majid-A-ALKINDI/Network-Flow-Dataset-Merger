import os
import io
import csv
import gzip
import shutil
import time
import math
import requests
import pandas as pd
from zipfile import ZipFile, BadZipFile
from urllib.parse import urlparse
from tqdm import tqdm
from typing import Iterable, Optional

# ---------- Config ----------
URLS = {
    "CIDDS-001": "https://www.hs-coburg.de/wp-content/uploads/2024/11/CIDDS-001.zip",
    "Kyoto": "https://www.kaggle.com/api/v1/datasets/download/harshwardhanbhangale/kyoto-2006",
    "MAWILab": "http://mawi.wide.ad.jp/mawi/samplepoint-F/2020/202005011400.pcap.gz",
}

REQUIRED_COLUMNS = [
    "src_ip","dst_ip","src_port","dst_port","duration",
    "tot_bytes","tot_packets","bytes_s","bytes_r",
    "pkts_s","pkts_r","protocol","avg_pkt_len","max_pkt_len","flow_rate"
]

DEST = "datasets"
OUT_CSV = "merged_flows.csv"
OUT_PARQUET = "merged_flows.parquet"
CHUNKSIZE = 250_000  # tune for RAM
TIMEOUT = 60
RETRIES = 3

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
            else:
                last_exc = RuntimeError(f"HTTP {resp.status_code}")
        except Exception as e:
            last_exc = e
        sleep = min(8, 2 ** attempt)
        time.sleep(sleep)
    raise last_exc or RuntimeError("Download failed")

def download_to_file(name: str, url: str, dest_folder: str) -> str:
    os.makedirs(dest_folder, exist_ok=True)
    parsed = urlparse(url)
    ext = os.path.splitext(parsed.path)[1] or ".bin"
    out_path = os.path.join(dest_folder, f"{name}{ext}")
    print(f"Downloading {name} from {url}")

    resp = http_get(url)
    total = int(resp.headers.get("Content-Length", 0))
    with open(out_path, "wb") as f, tqdm(
        total=total if total > 0 else None,
        unit="B", unit_scale=True, unit_divisor=1024, desc=f"{name}"
    ) as bar:
        for chunk in resp.iter_content(1024 * 128):
            if chunk:
                f.write(chunk)
                bar.update(len(chunk))
    return out_path

def extract_any(archive_path: str, target_dir: str) -> str:
    """
    Extracts ZIPs. If ZIP contains .gz members, gunzip them.
    If not a ZIP, just places the file in the folder.
    Returns the folder containing extracted files.
    """
    os.makedirs(target_dir, exist_ok=True)
    try:
        with ZipFile(archive_path, "r") as zf:
            zf.extractall(target_dir)
            # gunzip all .gz files 
            gunzipped = 0
            for root, _, files in os.walk(target_dir):
                for fn in files:
                    if fn.lower().endswith(".gz"):
                        gz_path = os.path.join(root, fn)
                        out_path = os.path.join(root, fn[:-3])  #  .gz
                        try:
                            with gzip.open(gz_path, "rb") as gz, open(out_path, "wb") as out:
                                shutil.copyfileobj(gz, out)
                            gunzipped += 1
                        except Exception as e:
                            print(f"Failed to gunzip {gz_path}: {e}")
            if gunzipped:
                print(f"Gunzip complete: {gunzipped} files")
            return target_dir
    except BadZipFile:
        # Not a ZIP—move/copy as-is
        base = os.path.join(target_dir, os.path.basename(archive_path))
        if archive_path != base:
            shutil.copy2(archive_path, base)
        print("⚠️ Not a ZIP; saved raw.")
        return target_dir

def sniff_sep(sample_bytes: bytes) -> str:
    # Try CSV dialect sniffing; default to comma
    sample = sample_bytes.decode("utf-8", errors="ignore")
    try:
        dialect = csv.Sniffer().sniff(sample[:4096], delimiters=[",",";","\t","|"])
        return dialect.delimiter
    except Exception:
        # fallback: if tabs present often, choose tab
        if sample.count("\t") > sample.count(","):
            return "\t"
        return ","

def iter_tabular_files(folder: str) -> Iterable[str]:
    for root, _, files in os.walk(folder):
        for f in files:
            lower = f.lower()
            if lower.endswith((".csv", ".tsv", ".txt")):
                yield os.path.join(root, f)

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    # canonicalize names
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    rename_map = {
        "source_ip": "src_ip", "destination_ip": "dst_ip",
        "srcaddr": "src_ip", "dstaddr": "dst_ip",
        "source_port": "src_port", "destination_port": "dst_port",
        "sport": "src_port", "dport": "dst_port",
        "flow_duration": "duration", "duration_ms": "duration",
        "bytes": "tot_bytes", "total_bytes": "tot_bytes",
        "packets": "tot_packets", "total_packets": "tot_packets",
        "bytes_sent": "bytes_s", "bytes_received": "bytes_r",
        "packets_sent": "pkts_s", "packets_received": "pkts_r",
        "proto": "protocol", "prot": "protocol",
        "avg_packet_len": "avg_pkt_len", "max_packet_len": "max_pkt_len",
        "throughput": "flow_rate", "flowrate": "flow_rate",
    }
    df = df.rename(columns=rename_map)

    # ensure required columns exist
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA

    # type coercions (safe)
    int_cols = ["src_port","dst_port","tot_packets","pkts_s","pkts_r","max_pkt_len"]
    float_cols = ["duration","tot_bytes","bytes_s","bytes_r","avg_pkt_len","flow_rate"]
    for c in int_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")
    for c in float_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    # derive missing fields
    # tot_bytes = bytes_s + bytes_r
    if df["tot_bytes"].isna().all() and (("bytes_s" in df.columns) and ("bytes_r" in df.columns)):
        df["tot_bytes"] = pd.to_numeric(df["bytes_s"], errors="coerce").fillna(0) + \
                          pd.to_numeric(df["bytes_r"], errors="coerce").fillna(0)

    # tot_packets = pkts_s + pkts_r
    if df["tot_packets"].isna().all() and (("pkts_s" in df.columns) and ("pkts_r" in df.columns)):
        df["tot_packets"] = pd.to_numeric(df["pkts_s"], errors="coerce").fillna(0) + \
                            pd.to_numeric(df["pkts_r"], errors="coerce").fillna(0)
        df["tot_packets"] = df["tot_packets"].astype("Int64")

    # avg_pkt_len = tot_bytes / tot_packets
    if df["avg_pkt_len"].isna().all():
        num = pd.to_numeric(df["tot_bytes"], errors="coerce")
        den = pd.to_numeric(df["tot_packets"], errors="coerce")
        df["avg_pkt_len"] = num / den.replace({0: pd.NA})

    # flow_rate = tot_bytes / duration (bytes/sec). Duration may be in ms; try to normalize.
    # If duration looks like ms (median > 1000), convert to seconds.
    if df["flow_rate"].isna().all():
        dur = pd.to_numeric(df["duration"], errors="coerce")
        if dur.notna().sum():
            med = dur.median()
            dur_sec = dur / 1000.0 if med and med > 1000 else dur
            df["flow_rate"] = pd.to_numeric(df["tot_bytes"], errors="coerce") / dur_sec.replace({0: pd.NA})

    # protocol textual normalization
    df["protocol"] = df["protocol"].astype("string").str.upper()

    return df[REQUIRED_COLUMNS]

def process_file(path: str) -> Iterable[pd.DataFrame]:
    # sniff delimiter
    with open(path, "rb") as fh:
        sample = fh.read(4096)
    sep = sniff_sep(sample)

    # iterate in chunks
    try:
        for chunk in pd.read_csv(
            path,
            sep=sep,
            engine="python",  # flexible
            chunksize=CHUNKSIZE,
            low_memory=False,
            on_bad_lines="skip",
            encoding="utf-8",
        ):
            yield normalize_columns(chunk)
    except UnicodeDecodeError:
        # try latin-1 fallback
        for chunk in pd.read_csv(
            path,
            sep=sep,
            engine="python",
            chunksize=CHUNKSIZE,
            low_memory=False,
            on_bad_lines="skip",
            encoding="latin-1",
        ):
            yield normalize_columns(chunk)

def append_to_outputs(df: pd.DataFrame, csv_path: str, parquet_path: Optional[str], wrote_header: dict):
    # CSV
    header = not wrote_header.get("csv", False)
    df.to_csv(csv_path, mode="a", header=header, index=False)
    wrote_header["csv"] = True
    # Parquet (optional)
    if parquet_path:
        # write append-like by partitioning into row groups
        if not os.path.exists(parquet_path):
            df.to_parquet(parquet_path, index=False)
        else:
            # simple append: write a temp, then concatenate with pandas (costly) or skip
            # To keep things simple and avoid heavy memory, write a sidecar instead.
            sidecar = parquet_path.replace(".parquet", f".part-{int(time.time()*1000)}.parquet")
            df.to_parquet(sidecar, index=False)

def main():
    os.makedirs(DEST, exist_ok=True)
    # Reset outputs if they exist (to avoid mixing old/new runs)
    for f in (OUT_CSV,):
        if os.path.exists(f):
            os.remove(f)
    # We'll produce a main parquet and multiple sidecars, safer for big merges
    if os.path.exists(OUT_PARQUET):
        os.remove(OUT_PARQUET)

    wrote_header = {}
    total_rows = 0
    for name, url in URLS.items():
        try:
            archive_path = download_to_file(name, url, DEST)
        except Exception as e:
            print(f"Failed to download {name}: {e}")
            continue

        extract_dir = os.path.join(DEST, name)
        extract_any(archive_path, extract_dir)

        found_any = False
        for file_path in iter_tabular_files(extract_dir):
            found_any = True
            print(f"Processing {file_path}")
            for norm_chunk in process_file(file_path):
                if norm_chunk.empty:
                    continue
                # Dedup within-chunk to save IO
                norm_chunk = norm_chunk.drop_duplicates()
                total_rows += len(norm_chunk)
                append_to_outputs(norm_chunk, OUT_CSV, OUT_PARQUET, wrote_header)

        if not found_any:
            print(f"No tabular files found in {name}")

    print(f"✅ Done. Wrote {total_rows:,} rows to {OUT_CSV}.")
    if os.path.exists(OUT_PARQUET):
        print(f"ℹ️ Parquet parts written alongside {OUT_PARQUET} (sidecars with .part-*.parquet). Consider consolidating later.")

if __name__ == "__main__":
    main()
