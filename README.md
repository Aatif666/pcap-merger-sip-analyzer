# PCAP Merger & SIP Analyzer

Chrome Extension + Python backend to merge PCAPs, extract SIP/SDP media IPs, and filter RTP/signaling streams into a single downloadable PCAP.

---

## Prerequisites

- **Python 3.8+**
- **Wireshark CLI tools** (`tshark`, `mergecap`)
- **Google Chrome**

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
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/pcap-merger-sip-analyzer
ExecStart=/usr/bin/python3 /home/YOUR_USERNAME/pcap-merger-sip-analyzer/server.py
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

Replace `YOUR_USERNAME` with your actual username.

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
4. Click **🚀 Run**
5. Download `filtered_signaling_and_media.pcap` when ready
6. Session auto-refreshes after download
