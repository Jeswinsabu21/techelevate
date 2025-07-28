# 🔥 Python Firewall – Internship Project

This project is a Python-based firewall that captures TCP packets in real-time and filters them based on custom rules defined in a JSON file. The firewall logs whether each packet is allowed or blocked, based on IP address, port, and protocol.

---

## 📦 Features

- ✅ Live packet sniffing using **Scapy**
- ✅ Rule-based filtering using a **JSON file**
- ✅ IP address matching (exact and CIDR)
- ✅ Port and protocol-based filtering
- ✅ Logs filtered packets (ALLOW or BLOCK)
- ✅ Simple structure for easy extension
- ✅ GUI optional (Tkinter version included in GUI branch)

---

## 🛠 Requirements

- Python 3.7+
- Modules:
  - `scapy`
  - `ipaddress` (comes built-in from Python 3.3+)

To install Scapy:

```bash
pip install scapy
                                          
