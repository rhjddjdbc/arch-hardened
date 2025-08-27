# Arch Linux Hardening Script

This script automates basic hardening measures for Arch Linux, setting up security-related services to make the system more resilient against attacks.

## Note

**Do not run this script as root.**  
Use a regular user with `sudo` privileges instead.

## Features

- **Automatically installs `yay` (AUR helper)**  
  Ensures that AUR packages like `aide` and `apparmor-profiles-git` can be installed. If `yay` is missing, it will be built from source using `git` and `makepkg`.

- **Installs the `linux-hardened` kernel**  
  Replaces the default kernel with a security-hardened version to reduce system attack surface.

- **Enables AppArmor and optional profiles**  
  Activates AppArmor for mandatory access control and installs additional profiles from the AUR for extended application sandboxing.

- **Configures GRUB boot options for better isolation**  
  Adds kernel parameters such as `apparmor=1`, `slab_nomerge`, and `page_alloc.shuffle=1` to improve memory protection and enforce AppArmor from boot.

- **Sets up USBGuard to control USB devices**  
  Installs USBGuard, generates a ruleset that defines allowed USB devices, and enables the service to prevent unauthorized USB access.

- **Configures a basic nftables firewall**  
  Sets up a simple firewall using `nftables` to drop all inbound traffic by default and only allow trusted ports (22, 80, 443), ICMP, and loopback.

- **Applies kernel hardening via sysctl**  
  Writes security-relevant `sysctl` settings such as `kptr_restrict`, `dmesg_restrict`, `randomize_va_space`, and hardening for symbolic links.

- **Installs AIDE (Advanced Intrusion Detection Environment)**  
  Uses `AIDE` to generate cryptographic checksums of files so you can detect changes after potential compromise. Initialization is performed immediately.

- **Installs the ClamAV antivirus scanner**  
  Deploys `clamav` for malware detection and enables `freshclam` to maintain up-to-date virus definitions. Runs an initial scan of the home directory.

- **Sets up dnscrypt-proxy with LibreDNS**  
  Encrypts DNS queries using `dnscrypt-proxy`, configures it to use the LibreDNS resolver, and enforces DNSSEC validation for enhanced integrity.

- **Installs hBlock to block tracking and malware domains**  
  Downloads and installs `hBlock`, which filters known ad, tracking, and malware domains system-wide by modifying `/etc/hosts`.

- **Sets up `auditd` with custom rules**  
  Installs and enables the audit daemon, and adds detailed rules to monitor sensitive areas like `/etc`, user/group files, kernel modules, time configuration, and `/boot`.

- **Installs and configures `doas` as a `sudo` replacement**  
  Installs `opendoas`, grants `wheel` group persistent access, and removes `sudo` to reduce code complexity and simplify privilege escalation mechanisms.


## Requirements

- Arch Linux or an Arch-based distribution
- A user with sudo privileges (in the `wheel` group)
- Internet connection

## Usage
git clone https://github.com/arch-hardened.git && cd arch-harden && chmod +x arch-harden.sh && ./arch-harden.sh

