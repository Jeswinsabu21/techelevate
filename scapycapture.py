
from scapy.all import sniff
import json
import ipaddress

# --- 1. Load rules ---
def load_rules(file_path):
    with open(file_path) as f:
        return json.load(f)

# --- 2. IP match helper ---
def ip_matches(packet_ip, rule_ip):
    if "/" in rule_ip:
        return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip)
    return packet_ip == rule_ip

# --- 3. Rule checking function ---
def check_packet(packet, rules):
    for rule in rules:
        # Debug print for rule checking (optional)
        # print(f"Checking rule {rule} against packet {packet}")

        if packet["protocol"] != rule["protocol"]:
            continue
        if packet["port"] != rule["port"]:
            continue
        if ip_matches(packet["ip"], rule["ip"]):
            # print(f"Matched rule: {rule}")  # Optional debug
            return rule["action"]
    return "allow"

# --- 4. Packet callback ---
def process_packet(pkt):
    if pkt.haslayer("IP") and pkt.haslayer("TCP"):
        simulated_packet = {
            "ip": pkt["IP"].dst,      # Use destination IP here!
            "port": pkt["TCP"].dport,
            "protocol": "tcp"
        }
        action = check_packet(simulated_packet, rules)
        print(f"[{action.upper()}] {simulated_packet}")

# --- 5. Main ---
rules = load_rules("rule.json")
sniff(filter="tcp", prn=process_packet, store=0, count=10)
