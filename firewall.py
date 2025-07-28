import subprocess
import logging

# Logging setup
logging.basicConfig(filename='firewall.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def log_action(rule, action):
    message = f"Rule triggered: {rule} | Action taken: {action}"
    logging.info(message)
    print(message)

def block_ip(ip):
    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(command)
    log_action(f"IP Block - {ip}", "Blocked via iptables")

def unblock_ip(ip):
    command = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(command)
    log_action(f"IP Unblock - {ip}", "Unblocked via iptables")

if __name__ == "__main__":
    blocked_ip = "192.168.1.100"
    block_ip(blocked_ip)

    # Later, unblock if needed
    # unblock_ip(blocked_ip)
