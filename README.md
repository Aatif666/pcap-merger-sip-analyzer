# PCAP Merger & SIP Analyzer

Chrome Extension + Python backend to merge PCAPs, extract SIP/SDP media IPs, and filter RTP/signaling streams.

---

## Prerequisites

- **Python 3.8+**
- **Wireshark CLI tools** (`tshark`, `mergecap`)
- **Google Chrome**
- **Flask** and **flask-cors** Python packages

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/Aatif666/pcap-merger-sip-analyzer.git
cd pcap-merger-sip-analyzer
```

### 2. Install Wireshark CLI tools

**Ubuntu/Debian:**
```bash
sudo apt install tshark wireshark-common
```

**macOS:**
```bash
brew install wireshark
```

### 3. Install Python dependencies

```bash
pip install flask flask-cors
```

### 4. Start the backend server

```bash
python3 server.py
```

You should see:
```
🦈 PCAP Merger & SIP Analyzer — Backend Server
   tshark: /usr/bin/tshark
   mergecap: /usr/bin/mergecap
   Server: http://localhost:5050
```

### 5. (Optional) Auto-start server on boot (Linux)

```bash
sudo tee /etc/systemd/system/pcap-merger.service << 'EOF'
[Unit]
Description=PCAP Merger & SIP Analyzer Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/pcap-merger-sip-analyzer
ExecStart=/usr/bin/python3 $HOME/pcap-merger-sip-analyzer/server.py
Restart=always
RestartSec=5
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable pcap-merger
sudo systemctl start pcap-merger
```

Replace `$USER` and `$HOME` with your actual username and home path.

### 6. Install the Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (toggle top-right)
3. Click **"Load unpacked"**
4. Select the `extension/` folder inside the cloned repo
5. Click the 🦈 icon in the toolbar to open the app

---

## Usage

1. Click the 🦈 extension icon — opens in a new tab
2. Upload your **Full PCAP** and **SIP PCAP** files
3. Set the **output directory** path and click 💾 Save
4. Click **🚀 Run All**
5. Click **⬇️ Download filtered_signaling_and_media.pcap** to get the result
6. Session auto-refreshes after download for the next analysis

---

## Changelog

### v1.2.0
- **Chrome Extension**: Converted from desktop tkinter app to Chrome extension + Flask backend
- **Tab-based UI**: Opens in a full Chrome tab (not popup) so file picker doesn't close the UI
- **CSP compliance**: All inline event handlers moved to JS (no more Content Security Policy errors)
- **Single download**: Only downloads `filtered_signaling_and_media.pcap` (combined signaling + media)
- **Auto-refresh**: Session resets after download for quick back-to-back analysis
- **Signaling IP filtering**: Filters packets between public SIP signaling IPs (INVITE/180/183/200)
- **SDP media IP filtering**: Filters packets between SDP `c=` line IPs (RTP/media)
- **Combined export**: Merges signaling + media filtered packets into one PCAP
- **Persistent config**: Remembers server URL and output directory across sessions
- **Server status indicator**: Shows connected/offline status in the header
- **Dark themed UI**: Professional dark mode interface
- **systemd support**: Can be set up as a Linux service for auto-start on boot

### v1.0.0
- Initial desktop app (tkinter GUI)
- PCAP merging via `mergecap`
- SIP/SDP analysis via `tshark`
- RTP packet filtering and export
