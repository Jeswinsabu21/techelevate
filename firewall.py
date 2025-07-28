import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP
import threading
import time

# --------------------- GUI Setup ---------------------
root = tk.Tk()
root.title("Python Firewall GUI")
root.geometry("950x700")

# --------------------- Live Packet View ---------------------
packet_frame = ttk.LabelFrame(root, text="Live Packet View")
packet_frame.pack(fill="both", expand=True, padx=10, pady=5)

packet_tree = ttk.Treeview(packet_frame, columns=("Time", "Src", "Dst", "Proto"), show="headings")
packet_tree.heading("Time", text="Time")
packet_tree.heading("Src", text="Source IP")
packet_tree.heading("Dst", text="Destination IP")
packet_tree.heading("Proto", text="Protocol")
packet_tree.pack(fill="both", expand=True)

# --------------------- Rules Section ---------------------
rule_frame = ttk.LabelFrame(root, text="Firewall Rules")
rule_frame.pack(fill="x", padx=10, pady=5)

rules = [
    {"id": 1, "rule": "Block ICMP", "enabled": tk.BooleanVar(value=True)},
    {"id": 2, "rule": "Block TCP Port 80", "enabled": tk.BooleanVar(value=False)},
]

for rule in rules:
    cb = ttk.Checkbutton(rule_frame, text=rule["rule"], variable=rule["enabled"])
    cb.pack(anchor="w")

def apply_rules():
    log_text.insert(tk.END, "[INFO] Rules Applied:\n")
    for rule in rules:
        status = 'Enabled' if rule["enabled"].get() else 'Disabled'
        log_text.insert(tk.END, f"- {rule['rule']}: {status}\n")
    log_text.see(tk.END)

apply_btn = ttk.Button(rule_frame, text="Apply Rules", command=apply_rules)
apply_btn.pack(pady=5)

# --------------------- Log Viewer ---------------------
log_frame = ttk.LabelFrame(root, text="Firewall Log Viewer")
log_frame.pack(fill="both", expand=True, padx=10, pady=5)

log_text = scrolledtext.ScrolledText(log_frame, height=10)
log_text.pack(fill="both", expand=True)

# --------------------- Packet Handling ---------------------
def packet_sniffer(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        timestamp = time.strftime("%H:%M:%S")

        # Simulate rule filtering
        if rules[0]["enabled"].get() and packet.haslayer("ICMP"):
            log_text.insert(tk.END, f"[{timestamp}] Blocked ICMP from {src} to {dst}\n")
            log_text.see(tk.END)
            return
        elif rules[1]["enabled"].get() and packet.haslayer("TCP") and packet["TCP"].dport == 80:
            log_text.insert(tk.END, f"[{timestamp}] Blocked TCP port 80 from {src} to {dst}\n")
            log_text.see(tk.END)
            return

        # Show in packet view
        packet_tree.insert("", "end", values=(timestamp, src, dst, proto))
        if len(packet_tree.get_children()) > 100:
            packet_tree.delete(packet_tree.get_children()[0])  # Limit entries

# Use a thread to run sniff in non-blocking mode
def start_sniff():
    sniff(count=5, prn=packet_sniffer, store=False, timeout=2)
    root.after(2000, lambda: threading.Thread(target=start_sniff, daemon=True).start())

# --------------------- Start Everything ---------------------
threading.Thread(target=start_sniff, daemon=True).start()
root.mainloop()

