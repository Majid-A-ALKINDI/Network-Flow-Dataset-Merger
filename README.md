# Network Flow Dataset Merger

Merge multiple public flow-based traffic datasets into one machine-learning-ready dataset with a unified schema.

This project focuses on flow-level network data that includes both normal and malicious traffic, and standardizes fields for downstream detection and classification tasks.

## Key Capabilities

- Downloads configured public datasets automatically.
- Validates cached archives and re-downloads invalid files.
- Extracts ZIP and GZ archives.
- Normalizes heterogeneous source columns into one canonical schema.
- Handles large files with chunked processing.
- Writes CSV and Parquet outputs.
- Uses a fixed Parquet schema to avoid cross-chunk schema mismatch issues.
- Includes a unified supervised target column: `attack_label` (`normal` or `malicious`).

## Current Verified Dataset Sources

- CIDDS-001 (HS Coburg)
- CIDDS-002 (HS Coburg)

Only verified public sources are enabled by default in `URLS` inside `merge_datasets.py`.

## Output Files

Running the script produces:

- `merged_flows.csv`
- `merged_flows.parquet`

The script does not create parquet part sidecar files.

## Unified Output Schema

| Column | Description |
|---|---|
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `duration` | Flow duration (auto-normalized if needed) |
| `tot_bytes` | Total flow bytes |
| `tot_packets` | Total flow packets |
| `bytes_s` | Sent bytes |
| `bytes_r` | Received bytes |
| `pkts_s` | Sent packets |
| `pkts_r` | Received packets |
| `protocol` | Transport protocol |
| `avg_pkt_len` | Average packet length |
| `max_pkt_len` | Maximum packet length |
| `flow_rate` | Byte rate for the flow |
| `attack_label` | Supervised label: `normal` or `malicious` |

## Installation

```bash
cd Network-Flow-Dataset-Merger-main
pip install -r requirements.txt
```

## Usage

```bash
python merge_datasets.py
```

## Project Structure

```text
Network-Flow-Dataset-Merger-main/
  merge_datasets.py
  README.md
  requirements.txt
```

Generated files and folders (`datasets/`, `merged_flows.csv`, `merged_flows.parquet`, logs) are runtime artifacts and should not be committed.

## Label Normalization Logic

The merger maps multiple source label fields (for example: `class`, `label`, `attackType`, `category`) into a single `attack_label` target.

- Values like `normal`, `benign`, and `background` are normalized to `normal`.
- Other non-empty attack categories are normalized to `malicious`.

## Notes

- If you add new datasets, verify URLs before enabling them in `URLS`.
- For Kaggle-based datasets, configure API credentials first.
- Large merges can take significant time and disk space.

Built by Majid alkindi





