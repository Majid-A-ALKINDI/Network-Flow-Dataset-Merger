# 🧠 Network Flow Dataset Merger

A Python utility that automatically **downloads**, **extracts**, **normalizes**, and **merges** multiple open network-flow datasets (such as CIDDS-001, Kyoto, and MAWILab) into a single unified CSV or Parquet file — ready for analysis or machine learning.

---

## 🚀 Features

- 📦 **Automatic download** of public datasets (CIDDS-001, Kyoto, MAWILab)  
- 🗜️ **Smart extraction** — handles ZIP and GZ files automatically  
- 🧩 **Schema normalization** — converts heterogeneous field names to a common structure  
- 🧮 **Derived fields** — calculates missing values like total bytes, packet counts, and flow rates  
- 🧰 **Chunked reading** — supports massive datasets without exhausting RAM  
- 🪶 **Flexible output** — saves merged dataset to both `merged_flows.csv` and `merged_flows.parquet`  

---

## 📊 Output Schema

Each flow record in the merged dataset will contain the following standardized columns:

| Column        | Description |
|----------------|--------------|
| `src_ip`       | Source IP address |
| `dst_ip`       | Destination IP address |
| `src_port`     | Source port number |
| `dst_port`     | Destination port number |
| `duration`     | Flow duration (s or ms, auto-normalized) |
| `tot_bytes`    | Total bytes transferred |
| `tot_packets`  | Total packet count |
| `bytes_s`      | Bytes sent |
| `bytes_r`      | Bytes received |
| `pkts_s`       | Packets sent |
| `pkts_r`       | Packets received |
| `protocol`     | Protocol name or number |
| `avg_pkt_len`  | Average packet length |
| `max_pkt_len`  | Maximum packet length |
| `flow_rate`    | Throughput (bytes/sec) |

---

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Majid-A-ALKINDI/Network-Flow-Dataset-Merger.git
   cd network-flow-merger
   pip install -r requirements.txt
   python merge_datasets.py
