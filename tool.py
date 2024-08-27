import subprocess
import os
import logging
import netifaces as ni
import ipaddress

# Configure logging to log only to a file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("firewall_config.log")]
)

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Command failed: {command}")
        logging.error(f"Error: {result.stderr.strip()}")
    else:
        logging.info(f"Command succeeded: {command}")
    return result.stdout.strip()

def rule_exists(rule):
    clean_rule = rule.replace("iptables ", "").replace("ip6tables ", "")
    command = f"sudo iptables-save | grep -- '{clean_rule}'"
    result = run_command(command)
    return bool(result)

def add_rule(rule):
    if not rule_exists(rule):
        logging.info(f"Adding rule: {rule}")
        run_command(f"sudo {rule}")
        logging.info(f"Rule added: {rule}")
    else:
        logging.info(f"Rule already exists: {rule}")

def delete_all_rules():
    rules_file = "added_rules.txt"
    if os.path.exists(rules_file):
        with open(rules_file, "r") as file:
            rules = file.readlines()
        for rule in rules:
            rule = rule.strip()
            rule_without_a = rule.replace("iptables -A ", "", 1)
            run_command(f"sudo iptables -D {rule_without_a}")
            logging.info(f"Rule deleted: {rule_without_a}")
        os.remove(rules_file)
        logging.info("All rules added by this tool have been deleted.")
    else:
        logging.info("No rules to delete.")

def get_main_local_network():
    gateways = ni.gateways()
    default_gateway = gateways["default"][ni.AF_INET][0]
    logging.info(f"Default gateway: {default_gateway}")

    for interface in ni.interfaces():
        if interface == 'lo':
            continue  # Skip the loopback interface
        try:
            addresses = ni.ifaddresses(interface)
            if ni.AF_INET in addresses:
                for addr_info in addresses[ni.AF_INET]:
                    ip = addr_info.get('addr')
                    netmask = addr_info.get('netmask')
                    if ip and netmask:
                        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                        logging.info(f"Interface: {interface}, IP: {ip}, Netmask: {netmask}, Network: {network.network_address}")
                        return (
                            str(network.network_address),
                            str(network.netmask),
                            str(network.broadcast_address),
                        )
        except KeyError:
            logging.error(f"Interface {interface} does not have a valid IPv4 address.")
    return None, None, None

def prompt_user():
    print("Welcome to the iptables configuration tool.")

    while True:
        action = input("Do you want to configure the firewall or delete rules (c/d)? ").lower()
        if action in ["c", "d"]:
            break
        print("Invalid input. Please enter 'c' to configure or 'd' to delete.")

    if action == "d":
        return "delete", None

    print("Rate Limiting Advice: For general use, a limit of 10/s with a burst of 20 is often sufficient.")
    
    while True:
        try:
            syn_limit = int(input("Enter SYN packet rate limit (e.g., 10): "))
            syn_burst = int(input("Enter SYN packet burst limit (e.g., 20): "))
            break
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    return "configure", (f"{syn_limit}/s", syn_burst)

def configure_firewall(syn_limit, syn_burst):
    rules_file = "added_rules.txt"
    added_rules = []

    local_ip, local_netmask, broadcast_ip = get_main_local_network()
    if not local_ip or not local_netmask or not broadcast_ip:
        logging.error("Unable to determine local network.")
        return

    network = f"{local_ip}/{local_netmask}"

    SpoofingRules = [
        f"iptables -A INPUT -s {network} -j ACCEPT",
        f"iptables -A INPUT -s {broadcast_ip} -j ACCEPT",
        "iptables -A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT",
        "iptables -A INPUT -i lo -d 127.0.0.0/8 -j ACCEPT",
        "iptables -A INPUT -s 10.0.0.0/8 -j DROP",
        "iptables -A INPUT -s 172.16.0.0/12 -j DROP",
        "iptables -A INPUT -s 192.168.0.0/16 -j DROP",
        "iptables -A INPUT -s 169.254.0.0/16 -j DROP",
        "iptables -A INPUT -s 100.64.0.0/10 -j DROP",
        "iptables -A INPUT -s 127.0.0.0/8 -j DROP",
        "iptables -A INPUT -d 127.0.0.0/8 -j DROP",
        "iptables -A INPUT -s 224.0.0.0/4 -j DROP",
        "iptables -A INPUT -d 224.0.0.0/4 -j DROP",
        "iptables -A INPUT -s 240.0.0.0/4 -j DROP",
        "iptables -A INPUT -d 240.0.0.0/4 -j DROP",
        "iptables -A INPUT -s 192.0.2.0/24 -j DROP",
        "iptables -A INPUT -s 198.51.100.0/24 -j DROP",
        "iptables -A INPUT -s 203.0.113.0/24 -j DROP",
        f"iptables -A INPUT -d {broadcast_ip} -j DROP",
        "iptables -A INPUT -s 0.0.0.0/8 -j DROP",
        "iptables -A INPUT -d 0.0.0.0/8 -j DROP",
        "iptables -A INPUT -s ::/128 -j DROP",
        "iptables -A INPUT -d ::/128 -j DROP",
    ]

    SmurfAttack = [
        f"iptables -A INPUT -d {broadcast_ip} -j DROP",
        "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second --limit-burst 10 -j ACCEPT",
        "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
        "iptables -A INPUT -p udp --dport 7 -m limit --limit 10/second --limit-burst 20 -j ACCEPT",
        "iptables -A INPUT -p udp --dport 7 -j DROP",
        "iptables -A INPUT -p udp --dport 19 -m limit --limit 10/second --limit-burst 20 -j ACCEPT",
        "iptables -A INPUT -p udp --dport 19 -j DROP",
    ]

    InvalidPackets = [
        "iptables -A INPUT -m state --state INVALID -j DROP",
        "iptables -A FORWARD -m state --state INVALID -j DROP",
        "iptables -A OUTPUT -m state --state INVALID -j DROP",
    ]

    RSTPackets = [
        "iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT",
    ]

    SYNFlood = [
        f"iptables -A INPUT -p tcp --syn -m limit --limit {syn_limit} --limit-burst {syn_burst} -j ACCEPT",
        "iptables -A INPUT -p tcp --syn -j DROP",
    ]

    SYNAckFlood = [
        "iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m connlimit --connlimit-above 20 -j DROP",
    ]

    Logs = [
        'iptables -A INPUT -j LOG --log-prefix "Dropped Packet: " --log-level 4',
        "iptables -A INPUT -j DROP",
    ]

    all_rules = [
        SpoofingRules,
        SmurfAttack,
        InvalidPackets,
        SYNFlood,
        SYNAckFlood,
    ]

    for rules in all_rules:
        for rule in rules:
            add_rule(rule)
            added_rules.append(rule)

    with open(rules_file, "w") as file:
        file.write("\n".join(added_rules))

def main():
    action, config = prompt_user()

    if action == "delete":
        delete_all_rules()
    else:
        syn_limit, syn_burst = config
        configure_firewall(syn_limit, syn_burst)

if __name__ == "__main__":
    main()
