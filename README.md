# Arch Linux Hardening Script

This script automates basic hardening measures for Arch Linux, setting up security-related services to make the system more resilient against attacks.

## Note

**Do not run this script as root.**  
Use a regular user with `sudo` privileges instead.

## Features

- Installs the `linux-hardened` kernel
- Enables AppArmor and optional profiles
- Configures GRUB boot options for better isolation
- Sets up USBGuard to control USB devices
- Configures a basic nftables firewall
- Applies kernel hardening via sysctl
- Installs AIDE (Advanced Intrusion Detection Environment) from the AUR
- Installs the ClamAV antivirus scanner
- Sets up dnscrypt-proxy with LibreDNS
- Installs hBlock to block tracking and malware domains
- Automatically installs `yay` (AUR helper) if not present

## Requirements

- Arch Linux or an Arch-based distribution
- A user with sudo privileges (in the `wheel` group)
- Internet connection

## Usage
git clone https://github.com/arch-harden.git && cd arch-harden && chmod +x arch-harden.sh && ./arch-harden.sh

