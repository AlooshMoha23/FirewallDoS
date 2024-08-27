# Firewall Configuration Tool

## Overview

This project is a Python-based command-line tool for configuring iptables firewall rules on Linux systems. It allows users to add specific firewall rules to protect against various network attacks, such as spoofing, SYN flood, and smurf attacks. The tool also provides an option to delete all rules that have been added using the tool. The configuration process is user-friendly, with strict input validation to ensure that only correct and expected inputs are processed.

## Features

- **Firewall Rule Configuration**: Add rules to protect against various network attacks, including SYN flood, smurf attacks, and more.
- **Rule Deletion**: Easily delete all rules added by the tool.
- **Input Validation**: Ensures that users input only valid data (e.g., selecting configuration or deletion actions, entering valid rate limits).
- **Logging**: All actions are logged to a file (`firewall_config.log`) for auditing purposes.
- **Network Detection**: Automatically detects the main local network and configures rules accordingly.

## Prerequisites

- Python 3.x
- Linux-based system with iptables installed
- `netifaces` Python package (install with `pip install netifaces`)

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Install required Python package**:
   ```bash
   pip install netifaces
   ```

3. **Ensure iptables is installed** on your system. This tool relies on `iptables` to manage firewall rules.

## Usage

1. **Run the tool**:
   ```bash
   python firewall_tool.py
   ```

2. **Choose an action**:
   - Enter `c` to configure the firewall.
   - Enter `d` to delete all rules added by this tool.

3. **Configure Firewall**:
   - If you choose to configure the firewall, you will be prompted to enter the SYN packet rate limit and burst limit as numeric values. The tool will automatically append the `/s` suffix to the rate limit.

4. **View Logs**:
   - All actions performed by the tool are logged to the `firewall_config.log` file. You can review this file to see which commands were executed and their outcomes.

## Example

**Configure the firewall**:

```bash
Welcome to the iptables configuration tool.
Do you want to configure the firewall or delete rules (c/d)? c
Rate Limiting Advice: For general use, a limit of 10/s with a burst of 20 is often sufficient.
Enter SYN packet rate limit (e.g., 10): 10
Enter SYN packet burst limit (e.g., 20): 20
```

**Delete all rules**:

```bash
Welcome to the iptables configuration tool.
Do you want to configure the firewall or delete rules (c/d)? d
```

## Logging

All operations are logged to `firewall_config.log`, including successful commands and any errors encountered during execution.

## Notes

- **Run as Root**: This tool needs to be run with root privileges since it configures system-level firewall rules.
- **Persistent Rules**: The rules added by this tool are not persistent across reboots by default. You may need to save your iptables configuration depending on your system's requirements.

