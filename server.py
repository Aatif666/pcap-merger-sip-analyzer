#!/usr/bin/env python3
"""
PCAP Merger & SIP Analyzer — Backend Server
Runs locally and processes PCAP files for the Chrome extension.
"""

import json
import os
import subprocess
import ipaddress
import tempfile
import shutil
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Working directory for processed files
WORK_DIR = os.path.join(tempfile.gettempdir(), "pcap-merger-work")
os.makedirs(WORK_DIR, exist_ok=True)


def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_private and not ip.is_loopback
    except ValueError:
        return False


def find_tool(name):
    try:
        result = subprocess.run(["which", name], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    for path in [f"/usr/local/bin/{name}", f"/opt/homebrew/bin/{name}",
                 f"/Applications/Wireshark.app/Contents/MacOS/{name}"]:
        if os.path.isfile(path):
            return path
    return None


def merge_pcaps(full_pcap, sip_pcap, output_path, logs):
    mergecap = find_tool("mergecap")
    if not mergecap:
        logs.append("ERROR: mergecap not found. Install Wireshark CLI tools.")
        return False
    logs.append(f"Merging PCAPs using {mergecap}...")
    try:
        result = subprocess.run(
            [mergecap, "-w", output_path, full_pcap, sip_pcap],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            logs.append(f"✅ Merged PCAP saved ({os.path.getsize(output_path)} bytes)")
            return True
        else:
            logs.append(f"ERROR: mergecap failed: {result.stderr}")
            return False
    except Exception as e:
        logs.append(f"ERROR: {e}")
        return False


def extract_sip_info(sip_pcap, logs):
    tshark = find_tool("tshark")
    if not tshark:
        logs.append("ERROR: tshark not found.")
        return [], [], []

    public_ips = set()
    sdp_media_ips = set()
    sdp_pairs = []

    logs.append("Extracting SIP signaling IPs and SDP media IPs...")

    # Get public IPs from SIP packets
    try:
        result = subprocess.run(
            [tshark, "-r", sip_pcap, "-Y", "sip",
             "-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    for ip in line.strip().split("\t"):
                        ip = ip.strip()
                        if ip and is_public_ip(ip):
                            public_ips.add(ip)
        logs.append(f"  Found {len(public_ips)} public signaling IPs: {', '.join(sorted(public_ips))}")
    except Exception as e:
        logs.append(f"  WARNING: {e}")

    # Get SDP c= IPs
    sip_filter = (
        'sip.Request-Line contains "INVITE" or '
        'sip.Status-Code == 183 or '
        'sip.Status-Code == 180 or '
        'sip.Status-Code == 200'
    )
    try:
        result = subprocess.run(
            [tshark, "-r", sip_pcap, "-Y", sip_filter,
             "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "sdp.connection_info.address",
             "-e", "sip.Method", "-e", "sip.Status-Code",
             "-E", "separator=|"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.strip().split("|")
                    src_ip = parts[0].strip() if len(parts) > 0 else ""
                    dst_ip = parts[1].strip() if len(parts) > 1 else ""
                    sdp_addr = parts[2].strip() if len(parts) > 2 else ""
                    method = parts[3].strip() if len(parts) > 3 else ""
                    status = parts[4].strip() if len(parts) > 4 else ""
                    msg_type = method if method else f"SIP {status}"

                    if sdp_addr:
                        for addr in sdp_addr.split(","):
                            addr = addr.strip()
                            if addr and addr != "0.0.0.0":
                                sdp_media_ips.add(addr)
                                sdp_pairs.append({
                                    "sig_src": src_ip, "sig_dst": dst_ip,
                                    "media_ip": addr, "msg_type": msg_type
                                })
                                logs.append(f"  SDP c= {addr} (from {msg_type}: {src_ip} → {dst_ip})")

        logs.append(f"  Found {len(sdp_media_ips)} unique SDP media IPs: {', '.join(sorted(sdp_media_ips))}")
    except Exception as e:
        logs.append(f"  WARNING: {e}")

    return sorted(public_ips), sorted(sdp_media_ips), sdp_pairs


def filter_packets(merged_pcap, media_ips, signaling_ips, output_dir, logs):
    tshark = find_tool("tshark")
    if not tshark:
        logs.append("ERROR: tshark not found.")
        return []

    exported_files = []
    pairs_done = set()
    filter_parts = []

    def do_filter(ip1, ip2, prefix, label):
        pair_key = tuple(sorted([ip1, ip2]))
        if pair_key in pairs_done:
            return
        pairs_done.add(pair_key)

        display_filter = f"(ip.addr == {ip1} && ip.addr == {ip2})"
        filter_parts.append(display_filter)
        safe_ip1 = ip1.replace(".", "_")
        safe_ip2 = ip2.replace(".", "_")
        out_file = os.path.join(output_dir, f"{prefix}_{safe_ip1}_to_{safe_ip2}.pcap")

        logs.append(f"Filtering {label}: {ip1} ↔ {ip2}...")
        try:
            result = subprocess.run(
                [tshark, "-r", merged_pcap, "-Y", display_filter, "-w", out_file],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                exported_files.append(out_file)
                logs.append(f"  ✅ {os.path.basename(out_file)} ({os.path.getsize(out_file)} bytes)")
            else:
                logs.append(f"  ⚠️ No packets found")
                if os.path.exists(out_file):
                    os.remove(out_file)
        except Exception as e:
            logs.append(f"  ERROR: {e}")

    # Signaling pairs
    if len(signaling_ips) >= 2:
        logs.append("\n--- Signaling Filters ---")
        for i, ip1 in enumerate(signaling_ips):
            for ip2 in signaling_ips[i + 1:]:
                do_filter(ip1, ip2, "signaling", "signaling")

    # Media pairs
    if len(media_ips) >= 2:
        logs.append("\n--- Media (RTP) Filters ---")
        for i, ip1 in enumerate(media_ips):
            for ip2 in media_ips[i + 1:]:
                do_filter(ip1, ip2, "rtp", "media")

    # Combined export
    if filter_parts:
        logs.append("\n--- Combined Export ---")
        combined_filter = " || ".join(filter_parts)
        out_file = os.path.join(output_dir, "filtered_signaling_and_media.pcap")
        try:
            result = subprocess.run(
                [tshark, "-r", merged_pcap, "-Y", combined_filter, "-w", out_file],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                exported_files.append(out_file)
                logs.append(f"  ✅ {os.path.basename(out_file)} ({os.path.getsize(out_file)} bytes)")
        except Exception as e:
            logs.append(f"  ERROR: {e}")

    # Individual media captures
    logs.append("\n--- Individual Media Captures ---")
    for ip in media_ips:
        safe_ip = ip.replace(".", "_")
        out_file = os.path.join(output_dir, f"media_{safe_ip}_all.pcap")
        try:
            result = subprocess.run(
                [tshark, "-r", merged_pcap, "-Y", f"ip.addr == {ip}", "-w", out_file],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                exported_files.append(out_file)
                logs.append(f"  ✅ {os.path.basename(out_file)} ({os.path.getsize(out_file)} bytes)")
            else:
                if os.path.exists(out_file):
                    os.remove(out_file)
        except Exception as e:
            logs.append(f"  ERROR: {e}")

    return exported_files


# --- Routes ---

@app.route('/health', methods=['GET'])
def health():
    tshark = find_tool("tshark")
    mergecap = find_tool("mergecap")
    return jsonify({
        "status": "ok",
        "tshark": tshark is not None,
        "mergecap": mergecap is not None
    })


@app.route('/process', methods=['POST'])
def process():
    logs = []
    step = request.form.get('step', 'all')
    output_dir = request.form.get('output_dir', WORK_DIR)

    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception:
            output_dir = WORK_DIR

    # Save uploaded files
    full_pcap_file = request.files.get('full_pcap')
    sip_pcap_file = request.files.get('sip_pcap')

    if not full_pcap_file or not sip_pcap_file:
        return jsonify({"success": False, "error": "Both PCAP files are required"})

    full_path = os.path.join(WORK_DIR, "upload_full.pcap")
    sip_path = os.path.join(WORK_DIR, "upload_sip.pcap")
    full_pcap_file.save(full_path)
    sip_pcap_file.save(sip_path)

    merged_path = os.path.join(output_dir, "merged.pcap")
    signaling_ips = []
    sdp_media_ips = []
    exported_files = []

    # Step 1: Merge
    if step in ('merge', 'all'):
        logs.append("═══ Step 1: Merging PCAPs ═══")
        ok = merge_pcaps(full_path, sip_path, merged_path, logs)
        if not ok and step == 'all':
            return jsonify({"success": False, "error": "Merge failed", "logs": logs})

    # Step 2: Analyze
    if step in ('analyze', 'all'):
        logs.append("\n═══ Step 2: Analyzing SIP/SDP ═══")
        signaling_ips, sdp_media_ips, sdp_pairs = extract_sip_info(sip_path, logs)

    # Step 3: Filter
    if step in ('filter', 'all'):
        if step == 'filter':
            # Re-analyze to get IPs
            signaling_ips, sdp_media_ips, _ = extract_sip_info(sip_path, logs)
        if not os.path.isfile(merged_path):
            # Auto-merge if needed
            merge_pcaps(full_path, sip_path, merged_path, logs)

        logs.append("\n═══ Step 3: Filtering & Exporting ═══")
        files = filter_packets(merged_path, sdp_media_ips, signaling_ips, output_dir, logs)
        exported_files = [
            {"name": os.path.basename(f), "size": os.path.getsize(f), "path": f}
            for f in files
        ]

    return jsonify({
        "success": True,
        "signaling_ips": signaling_ips,
        "sdp_media_ips": sdp_media_ips,
        "files": exported_files,
        "logs": logs,
        "output_dir": output_dir
    })


@app.route('/validate-dir', methods=['POST'])
def validate_dir():
    """Validate and optionally create an output directory."""
    data = request.get_json() or {}
    path = data.get('path', '')
    create = data.get('create', False)

    if not path:
        return jsonify({"valid": False, "error": "No path provided"})

    path = os.path.expanduser(path)

    if os.path.isdir(path):
        return jsonify({"valid": True, "path": path})

    if create:
        try:
            os.makedirs(path, exist_ok=True)
            return jsonify({"valid": True, "path": path, "created": True})
        except Exception as e:
            return jsonify({"valid": False, "error": str(e)})

    return jsonify({"valid": False, "error": "Directory does not exist"})


@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    # Check work dir and output dir
    for d in [WORK_DIR]:
        filepath = os.path.join(d, filename)
        if os.path.isfile(filepath):
            return send_from_directory(d, filename, as_attachment=True)

    # Also check the last-used output dir from config
    config_path = os.path.expanduser("~/.pcap_merger_config.json")
    try:
        with open(config_path) as f:
            cfg = json.load(f)
        out_dir = cfg.get("output_dir", "")
        if out_dir and os.path.isfile(os.path.join(out_dir, filename)):
            return send_from_directory(out_dir, filename, as_attachment=True)
    except Exception:
        pass

    return jsonify({"error": "File not found"}), 404


if __name__ == '__main__':
    print("🦈 PCAP Merger & SIP Analyzer — Backend Server")
    print(f"   Working directory: {WORK_DIR}")
    print(f"   tshark: {find_tool('tshark') or 'NOT FOUND'}")
    print(f"   mergecap: {find_tool('mergecap') or 'NOT FOUND'}")
    print(f"   Server: http://localhost:5050")
    print()
    app.run(host='127.0.0.1', port=5050, debug=False)
