import logging
from datetime import datetime
from termcolor import colored

# Step 1: Set up logging
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Step 2: Define logging function
def log_action(rule, action):
    message = f"Rule triggered: {rule} | Action taken: {action}"
    logging.info(message)

    # Optional: Colorized terminal output
    if action.lower() == 'blocked':
        print(colored(message, 'red'))
    elif action.lower() == 'allowed':
        print(colored(message, 'green'))
    else:
        print(message)

# Step 3: Simulated firewall logic
if __name__ == "__main__":
    blocked_ips = ["192.168.1.100", "10.0.0.5"]
    incoming_ip = "192.168.1.100"

    if incoming_ip in blocked_ips:
        log_action(f"IP Match - {incoming_ip}", "Blocked")
    else:
        log_action(f"IP Not in blocklist - {incoming_ip}", "Allowed")
