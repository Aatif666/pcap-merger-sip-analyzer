# PCAP Merger & SIP Analyzer

A Python desktop app that merges PCAPs, extracts SIP/SDP information, and filters RTP media streams.

## Features

- **Merge PCAPs**: Combine a full PCAP and SIP PCAP into one file using `mergecap`
- **SIP Analysis**: Extract public IPs from SIP signaling
- **SDP Parsing**: Find media IPs from `c=` lines in INVITE, 183, 180, and 200 OK messages
- **RTP Filtering**: Export filtered packets between SDP media IP pairs
- **Persistent Config**: Remembers your output directory across sessions
- **Clean GUI**: Professional tkinter interface with real-time logging

## Requirements

- Python 3.8+
- Wireshark CLI tools (`tshark`, `mergecap`) installed and in PATH
- `pyshark` (optional, used as fallback)

### Install Wireshark CLI (macOS)
```bash
brew install wireshark
```

### Install Python dependencies
```bash
pip install -r requirements.txt
```

## Usage

```bash
python pcap_merger.py
```

1. **Select Files**: Browse for your Full PCAP and SIP PCAP
2. **Set Output Directory**: Choose where to save output files (remembered for next time)
3. **Run All Steps** or run each step individually:
   - Step 1: Merge both PCAPs
   - Step 2: Analyze SIP/SDP to find public and media IPs
   - Step 3: Filter and export RTP packets between media IPs

## Output Files

- `merged.pcap` — Combined PCAP
- `rtp_<ip1>_to_<ip2>.pcap` — RTP packets between specific media IP pairs
- `media_<ip>_all.pcap` — All packets involving a specific media IP
