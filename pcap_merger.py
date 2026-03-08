#!/usr/bin/env python3
"""
PCAP Merger & SIP Analyzer
Merges full + SIP PCAPs, extracts SDP media IPs, and filters RTP streams.
"""

import json
import os
import re
import subprocess
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime

CONFIG_PATH = os.path.expanduser("~/.pcap_merger_config.json")


class Config:
    """Persistent configuration manager."""

    def __init__(self):
        self.data = self._load()

    def _load(self):
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save(self):
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.data, f, indent=2)

    @property
    def output_dir(self):
        return self.data.get("output_dir", "")

    @output_dir.setter
    def output_dir(self, value):
        self.data["output_dir"] = value
        self.save()


def is_public_ip(ip_str):
    """Check if an IP address is public (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_private and not ip.is_loopback
    except ValueError:
        return False


def find_tool(name):
    """Find a CLI tool path."""
    try:
        result = subprocess.run(["which", name], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    # Common macOS paths
    for path in [f"/usr/local/bin/{name}", f"/opt/homebrew/bin/{name}",
                 f"/Applications/Wireshark.app/Contents/MacOS/{name}"]:
        if os.path.isfile(path):
            return path
    return None


def merge_pcaps(full_pcap, sip_pcap, output_path, log_fn):
    """Merge two PCAPs using mergecap."""
    mergecap = find_tool("mergecap")
    if not mergecap:
        log_fn("ERROR: mergecap not found. Install Wireshark CLI tools.")
        return False

    log_fn(f"Merging PCAPs using {mergecap}...")
    try:
        result = subprocess.run(
            [mergecap, "-w", output_path, full_pcap, sip_pcap],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            log_fn(f"✅ Merged PCAP saved: {output_path}")
            return True
        else:
            log_fn(f"ERROR: mergecap failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        log_fn("ERROR: mergecap timed out")
        return False
    except Exception as e:
        log_fn(f"ERROR: {e}")
        return False


def extract_sip_info(sip_pcap, log_fn):
    """Extract public IPs and SDP c= IPs from SIP PCAP using tshark."""
    tshark = find_tool("tshark")
    if not tshark:
        log_fn("ERROR: tshark not found. Install Wireshark CLI tools.")
        return [], []

    public_ips = set()
    sdp_media_ips = set()
    sdp_pairs = []  # (signaling_src, signaling_dst, media_ip)

    log_fn("Extracting SIP signaling IPs and SDP media IPs...")

    # Step 1: Get all public IPs in SIP packets
    try:
        result = subprocess.run(
            [tshark, "-r", sip_pcap, "-Y", "sip",
             "-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.strip().split("\t")
                    for ip in parts:
                        ip = ip.strip()
                        if ip and is_public_ip(ip):
                            public_ips.add(ip)
        log_fn(f"  Found {len(public_ips)} public IPs in SIP signaling")
    except Exception as e:
        log_fn(f"  WARNING extracting IPs: {e}")

    # Step 2: Get SDP c= line IPs from INVITE, 183, 180, 200
    sip_methods_filter = (
        'sip.Request-Line contains "INVITE" or '
        'sip.Status-Code == 183 or '
        'sip.Status-Code == 180 or '
        'sip.Status-Code == 200'
    )

    try:
        result = subprocess.run(
            [tshark, "-r", sip_pcap, "-Y", sip_methods_filter,
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
                        # Can have multiple addresses comma-separated
                        for addr in sdp_addr.split(","):
                            addr = addr.strip()
                            if addr and addr != "0.0.0.0":
                                sdp_media_ips.add(addr)
                                sdp_pairs.append({
                                    "sig_src": src_ip,
                                    "sig_dst": dst_ip,
                                    "media_ip": addr,
                                    "msg_type": msg_type
                                })
                                log_fn(f"  SDP c= {addr} (from {msg_type}: {src_ip} → {dst_ip})")

        log_fn(f"  Found {len(sdp_media_ips)} unique SDP media IPs")
    except Exception as e:
        log_fn(f"  WARNING extracting SDP: {e}")

    return sorted(public_ips), sorted(sdp_media_ips), sdp_pairs


def filter_rtp_packets(merged_pcap, media_ips, signaling_ips, output_dir, log_fn):
    """Filter and export packets between SDP media IP pairs AND signaling IP pairs."""
    tshark = find_tool("tshark")
    if not tshark:
        log_fn("ERROR: tshark not found.")
        return []

    if len(media_ips) < 1 and len(signaling_ips) < 1:
        log_fn("No IPs to filter.")
        return []

    exported_files = []
    pairs_done = set()
    filter_parts = []  # For combined export

    # --- 1. Filter signaling IP pairs ---
    if len(signaling_ips) >= 2:
        log_fn("\n--- Signaling Filters ---")
        for i, ip1 in enumerate(signaling_ips):
            for ip2 in signaling_ips[i + 1:]:
                pair_key = tuple(sorted([ip1, ip2]))
                if pair_key in pairs_done:
                    continue
                pairs_done.add(pair_key)

                display_filter = f"(ip.addr == {ip1} && ip.addr == {ip2})"
                filter_parts.append(display_filter)
                safe_ip1 = ip1.replace(".", "_")
                safe_ip2 = ip2.replace(".", "_")
                out_file = os.path.join(output_dir, f"signaling_{safe_ip1}_to_{safe_ip2}.pcap")

                log_fn(f"Filtering signaling: {ip1} ↔ {ip2}...")
                try:
                    result = subprocess.run(
                        [tshark, "-r", merged_pcap, "-Y", display_filter,
                         "-w", out_file],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0:
                        if os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                            exported_files.append(out_file)
                            log_fn(f"  ✅ Saved: {os.path.basename(out_file)} "
                                   f"({os.path.getsize(out_file)} bytes)")
                        else:
                            log_fn(f"  ⚠️ No packets found between {ip1} ↔ {ip2}")
                            if os.path.exists(out_file):
                                os.remove(out_file)
                    else:
                        log_fn(f"  ERROR: tshark filter failed: {result.stderr}")
                except Exception as e:
                    log_fn(f"  ERROR: {e}")

    # --- 2. Filter media (SDP c=) IP pairs ---
    if len(media_ips) >= 2:
        log_fn("\n--- Media (RTP) Filters ---")
        for i, ip1 in enumerate(media_ips):
            for ip2 in media_ips[i + 1:]:
                pair_key = tuple(sorted([ip1, ip2]))
                if pair_key in pairs_done:
                    continue
                pairs_done.add(pair_key)

                display_filter = f"(ip.addr == {ip1} && ip.addr == {ip2})"
                filter_parts.append(display_filter)
                safe_ip1 = ip1.replace(".", "_")
                safe_ip2 = ip2.replace(".", "_")
                out_file = os.path.join(output_dir, f"rtp_{safe_ip1}_to_{safe_ip2}.pcap")

                log_fn(f"Filtering media: {ip1} ↔ {ip2}...")
                try:
                    result = subprocess.run(
                        [tshark, "-r", merged_pcap, "-Y", display_filter,
                         "-w", out_file],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0:
                        if os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                            exported_files.append(out_file)
                            log_fn(f"  ✅ Saved: {os.path.basename(out_file)} "
                                   f"({os.path.getsize(out_file)} bytes)")
                        else:
                            log_fn(f"  ⚠️ No packets found between {ip1} ↔ {ip2}")
                            if os.path.exists(out_file):
                                os.remove(out_file)
                    else:
                        log_fn(f"  ERROR: tshark filter failed: {result.stderr}")
                except Exception as e:
                    log_fn(f"  ERROR: {e}")

    # --- 3. Combined export (signaling + media in one file) ---
    if filter_parts:
        log_fn("\n--- Combined Export (Signaling + Media) ---")
        combined_filter = " || ".join(filter_parts)
        out_file = os.path.join(output_dir, "filtered_signaling_and_media.pcap")

        log_fn(f"Exporting combined filter...")
        try:
            result = subprocess.run(
                [tshark, "-r", merged_pcap, "-Y", combined_filter,
                 "-w", out_file],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                if os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                    exported_files.append(out_file)
                    # Count breakdown
                    try:
                        sip_count = subprocess.run(
                            [tshark, "-r", out_file, "-Y", "sip"],
                            capture_output=True, text=True, timeout=30
                        ).stdout.strip().count("\n") + 1 if subprocess.run(
                            [tshark, "-r", out_file, "-Y", "sip"],
                            capture_output=True, text=True, timeout=30
                        ).stdout.strip() else 0
                        rtp_count = subprocess.run(
                            [tshark, "-r", out_file, "-Y", "rtp"],
                            capture_output=True, text=True, timeout=30
                        ).stdout.strip().count("\n") + 1 if subprocess.run(
                            [tshark, "-r", out_file, "-Y", "rtp"],
                            capture_output=True, text=True, timeout=30
                        ).stdout.strip() else 0
                        log_fn(f"  ✅ Saved: {os.path.basename(out_file)} "
                               f"({os.path.getsize(out_file)} bytes) "
                               f"— {sip_count} SIP + {rtp_count} RTP packets")
                    except Exception:
                        log_fn(f"  ✅ Saved: {os.path.basename(out_file)} "
                               f"({os.path.getsize(out_file)} bytes)")
                else:
                    if os.path.exists(out_file):
                        os.remove(out_file)
            else:
                log_fn(f"  ERROR: {result.stderr}")
        except Exception as e:
            log_fn(f"  ERROR: {e}")

    # --- 4. Individual media IP captures ---
    log_fn("\n--- Individual Media IP Captures ---")
    for ip in media_ips:
        safe_ip = ip.replace(".", "_")
        out_file = os.path.join(output_dir, f"media_{safe_ip}_all.pcap")
        display_filter = f"ip.addr == {ip}"

        log_fn(f"Filtering all packets for {ip}...")
        try:
            result = subprocess.run(
                [tshark, "-r", merged_pcap, "-Y", display_filter,
                 "-w", out_file],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and os.path.exists(out_file) and os.path.getsize(out_file) > 24:
                exported_files.append(out_file)
                log_fn(f"  ✅ Saved: {os.path.basename(out_file)} "
                       f"({os.path.getsize(out_file)} bytes)")
            else:
                if os.path.exists(out_file):
                    os.remove(out_file)
        except Exception as e:
            log_fn(f"  ERROR: {e}")

    return exported_files


class PCAPMergerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Merger & SIP Analyzer")
        self.root.geometry("900x750")
        self.root.minsize(800, 650)

        self.config = Config()
        self.public_ips = []
        self.sdp_media_ips = []
        self.sdp_pairs = []

        self._build_ui()

    def _build_ui(self):
        # Main container with padding
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # === Title ===
        title = ttk.Label(main, text="PCAP Merger & SIP Analyzer",
                          font=("Helvetica", 18, "bold"))
        title.pack(pady=(0, 10))

        # === File Selection Frame ===
        file_frame = ttk.LabelFrame(main, text="📁 File Selection", padding=8)
        file_frame.pack(fill=tk.X, pady=5)

        # Full PCAP
        row1 = ttk.Frame(file_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Full PCAP:", width=12, anchor="e").pack(side=tk.LEFT)
        self.full_pcap_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.full_pcap_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(row1, text="Browse", command=self._browse_full_pcap).pack(side=tk.RIGHT)

        # SIP PCAP
        row2 = ttk.Frame(file_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="SIP PCAP:", width=12, anchor="e").pack(side=tk.LEFT)
        self.sip_pcap_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.sip_pcap_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(row2, text="Browse", command=self._browse_sip_pcap).pack(side=tk.RIGHT)

        # === Output Directory Frame ===
        dir_frame = ttk.LabelFrame(main, text="📂 Output Directory", padding=8)
        dir_frame.pack(fill=tk.X, pady=5)

        dir_row = ttk.Frame(dir_frame)
        dir_row.pack(fill=tk.X)
        self.output_dir_var = tk.StringVar(value=self.config.output_dir or "(not set)")
        ttk.Label(dir_row, text="Save to:", width=12, anchor="e").pack(side=tk.LEFT)
        self.dir_label = ttk.Label(dir_row, textvariable=self.output_dir_var,
                                   foreground="blue", cursor="hand2")
        self.dir_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(dir_row, text="Change", command=self._change_output_dir).pack(side=tk.RIGHT, padx=2)
        ttk.Button(dir_row, text="Open", command=self._open_output_dir).pack(side=tk.RIGHT, padx=2)

        # === Action Buttons ===
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=8)

        self.merge_btn = ttk.Button(btn_frame, text="1️⃣ Merge PCAPs",
                                    command=self._do_merge)
        self.merge_btn.pack(side=tk.LEFT, padx=3)

        self.analyze_btn = ttk.Button(btn_frame, text="2️⃣ Analyze SIP/SDP",
                                      command=self._do_analyze)
        self.analyze_btn.pack(side=tk.LEFT, padx=3)

        self.filter_btn = ttk.Button(btn_frame, text="3️⃣ Filter & Export",
                                     command=self._do_filter)
        self.filter_btn.pack(side=tk.LEFT, padx=3)

        self.run_all_btn = ttk.Button(btn_frame, text="🚀 Run All Steps",
                                      command=self._run_all, style="Accent.TButton")
        self.run_all_btn.pack(side=tk.RIGHT, padx=3)

        # === Results Frame ===
        results_frame = ttk.LabelFrame(main, text="📊 Results", padding=8)
        results_frame.pack(fill=tk.X, pady=5)

        # Public IPs
        ip_row = ttk.Frame(results_frame)
        ip_row.pack(fill=tk.X, pady=2)
        ttk.Label(ip_row, text="Public SIP IPs:", anchor="w", font=("Helvetica", 11, "bold")).pack(side=tk.LEFT)
        self.public_ips_var = tk.StringVar(value="—")
        ttk.Label(ip_row, textvariable=self.public_ips_var, wraplength=600).pack(side=tk.LEFT, padx=10)

        # SDP Media IPs
        sdp_row = ttk.Frame(results_frame)
        sdp_row.pack(fill=tk.X, pady=2)
        ttk.Label(sdp_row, text="SDP Media IPs:", anchor="w", font=("Helvetica", 11, "bold")).pack(side=tk.LEFT)
        self.sdp_ips_var = tk.StringVar(value="—")
        ttk.Label(sdp_row, textvariable=self.sdp_ips_var, wraplength=600).pack(side=tk.LEFT, padx=10)

        # Exported Files
        files_row = ttk.Frame(results_frame)
        files_row.pack(fill=tk.X, pady=2)
        ttk.Label(files_row, text="Exported Files:", anchor="w", font=("Helvetica", 11, "bold")).pack(side=tk.LEFT)
        self.exported_var = tk.StringVar(value="—")
        ttk.Label(files_row, textvariable=self.exported_var, wraplength=600).pack(side=tk.LEFT, padx=10)

        # === Log Frame ===
        log_frame = ttk.LabelFrame(main, text="📋 Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = tk.Text(log_frame, height=12, wrap=tk.WORD,
                                font=("Courier", 11), bg="#1e1e1e", fg="#00ff00",
                                insertbackground="#00ff00")
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))

    def log(self, msg):
        """Thread-safe log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        def _append():
            self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
            self.log_text.see(tk.END)
        self.root.after(0, _append)

    def _set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_buttons_state(self, state):
        def _do():
            self.merge_btn.config(state=state)
            self.analyze_btn.config(state=state)
            self.filter_btn.config(state=state)
            self.run_all_btn.config(state=state)
        self.root.after(0, _do)

    # --- Browse dialogs ---
    def _browse_full_pcap(self):
        path = filedialog.askopenfilename(
            title="Select Full PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")]
        )
        if path:
            self.full_pcap_var.set(path)

    def _browse_sip_pcap(self):
        path = filedialog.askopenfilename(
            title="Select SIP PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")]
        )
        if path:
            self.sip_pcap_var.set(path)

    def _change_output_dir(self):
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.config.output_dir = path
            self.output_dir_var.set(path)
            self.log(f"Output directory set to: {path}")

    def _open_output_dir(self):
        d = self.config.output_dir
        if d and os.path.isdir(d):
            subprocess.Popen(["open", d])
        else:
            messagebox.showwarning("No Directory", "Please set an output directory first.")

    # --- Validation ---
    def _validate_files(self):
        full = self.full_pcap_var.get()
        sip = self.sip_pcap_var.get()
        if not full or not os.path.isfile(full):
            messagebox.showerror("Error", "Please select a valid Full PCAP file.")
            return False
        if not sip or not os.path.isfile(sip):
            messagebox.showerror("Error", "Please select a valid SIP PCAP file.")
            return False
        return True

    def _validate_output_dir(self):
        d = self.config.output_dir
        if not d or not os.path.isdir(d):
            # Prompt to set one
            self._change_output_dir()
            d = self.config.output_dir
        if not d or not os.path.isdir(d):
            messagebox.showerror("Error", "Please select an output directory.")
            return False
        return True

    # --- Actions ---
    def _do_merge(self):
        if not self._validate_files() or not self._validate_output_dir():
            return
        self._set_buttons_state("disabled")
        self._set_status("Merging PCAPs...")

        def task():
            out = os.path.join(self.config.output_dir, "merged.pcap")
            ok = merge_pcaps(self.full_pcap_var.get(), self.sip_pcap_var.get(), out, self.log)
            self._set_buttons_state("normal")
            self._set_status("Merge complete" if ok else "Merge failed")

        threading.Thread(target=task, daemon=True).start()

    def _do_analyze(self):
        sip = self.sip_pcap_var.get()
        if not sip or not os.path.isfile(sip):
            messagebox.showerror("Error", "Please select a valid SIP PCAP file.")
            return
        self._set_buttons_state("disabled")
        self._set_status("Analyzing SIP/SDP...")

        def task():
            self.public_ips, self.sdp_media_ips, self.sdp_pairs = extract_sip_info(sip, self.log)
            self.root.after(0, lambda: self.public_ips_var.set(
                ", ".join(self.public_ips) if self.public_ips else "None found"))
            self.root.after(0, lambda: self.sdp_ips_var.set(
                ", ".join(self.sdp_media_ips) if self.sdp_media_ips else "None found"))
            self._set_buttons_state("normal")
            self._set_status("Analysis complete")

        threading.Thread(target=task, daemon=True).start()

    def _do_filter(self):
        if not self._validate_output_dir():
            return
        merged = os.path.join(self.config.output_dir, "merged.pcap")
        if not os.path.isfile(merged):
            messagebox.showerror("Error",
                                 "Merged PCAP not found. Run 'Merge PCAPs' first.")
            return
        if not self.sdp_media_ips and not self.public_ips:
            messagebox.showerror("Error",
                                 "No IPs found. Run 'Analyze SIP/SDP' first.")
            return
        self._set_buttons_state("disabled")
        self._set_status("Filtering & exporting signaling + media...")

        def task():
            files = filter_rtp_packets(merged, self.sdp_media_ips,
                                       self.public_ips,
                                       self.config.output_dir, self.log)
            self.root.after(0, lambda: self.exported_var.set(
                f"{len(files)} file(s) exported" if files else "No packets matched"))
            self._set_buttons_state("normal")
            self._set_status(f"Export complete: {len(files)} file(s)")
            if files:
                self.log(f"\n🎉 Done! {len(files)} file(s) saved to {self.config.output_dir}")

        threading.Thread(target=task, daemon=True).start()

    def _run_all(self):
        """Run all 3 steps sequentially."""
        if not self._validate_files() or not self._validate_output_dir():
            return
        self._set_buttons_state("disabled")
        self._set_status("Running all steps...")

        def task():
            # Step 1: Merge
            self.log("═══ Step 1/3: Merging PCAPs ═══")
            merged_path = os.path.join(self.config.output_dir, "merged.pcap")
            ok = merge_pcaps(self.full_pcap_var.get(), self.sip_pcap_var.get(),
                             merged_path, self.log)
            if not ok:
                self._set_buttons_state("normal")
                self._set_status("Failed at merge step")
                return

            # Step 2: Analyze
            self.log("\n═══ Step 2/3: Analyzing SIP/SDP ═══")
            self.public_ips, self.sdp_media_ips, self.sdp_pairs = extract_sip_info(
                self.sip_pcap_var.get(), self.log)
            self.root.after(0, lambda: self.public_ips_var.set(
                ", ".join(self.public_ips) if self.public_ips else "None found"))
            self.root.after(0, lambda: self.sdp_ips_var.set(
                ", ".join(self.sdp_media_ips) if self.sdp_media_ips else "None found"))

            if not self.sdp_media_ips:
                self.log("⚠️ No SDP media IPs found — skipping RTP filter step.")
                self._set_buttons_state("normal")
                self._set_status("Complete (no media IPs to filter)")
                return

            # Step 3: Filter
            self.log("\n═══ Step 3/3: Filtering & Exporting Signaling + Media ═══")
            files = filter_rtp_packets(merged_path, self.sdp_media_ips,
                                       self.public_ips,
                                       self.config.output_dir, self.log)
            self.root.after(0, lambda: self.exported_var.set(
                f"{len(files)} file(s) exported" if files else "No packets matched"))
            self._set_buttons_state("normal")
            self._set_status(f"✅ All done! {len(files)} file(s) exported")
            self.log(f"\n🎉 All steps complete! {len(files)} file(s) in {self.config.output_dir}")

        threading.Thread(target=task, daemon=True).start()


def main():
    root = tk.Tk()

    # Style
    style = ttk.Style()
    try:
        style.theme_use("aqua")  # macOS native
    except Exception:
        style.theme_use("clam")

    app = PCAPMergerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
