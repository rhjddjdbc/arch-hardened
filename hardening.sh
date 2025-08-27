#!/usr/bin/env bash

set -euo pipefail

# Ensure the script is not run as root
if [ "$EUID" -eq 0 ]; then
  echo "Please DO NOT run this script as root. Use a user account with sudo privileges."
  exit 1
fi

# Function to install doas and remove sudo
setup_doas_and_remove_sudo() {
  if command -v doas &>/dev/null; then
    echo "doas is already installed."
  else
    echo "Installing doas..."
    pacman -S --noconfirm opendoas
    echo "Creating /etc/doas.conf..."
    echo 'permit persist :wheel' | doas tee /etc/doas.conf > /dev/null
  fi

  if command -v sudo &>/dev/null; then
    echo "Removing sudo..."
    doas pacman -Rdd --noconfirm sudo
  fi
}

# Check if yay is installed
if ! command -v yay &> /dev/null; then
  echo "yay not found – installing..."
  doas pacman -S --needed --noconfirm git base-devel
  git clone https://aur.archlinux.org/yay.git /tmp/yay
  pushd /tmp/yay
  makepkg -si --noconfirm
  popd
else
  echo "yay is already installed."
fi

echo "Starting Arch Hardening..."

# Install hardened kernel
echo "Installing hardened kernel..."
doas pacman -Sy --noconfirm linux-hardened linux-hardened-headers

# Configure GRUB
echo "Configuring GRUB..."
if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then
  doas sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor slab_nomerge random.trust_cpu=off page_alloc.shuffle=1 loglevel=3"/' /etc/default/grub
else
  echo 'GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor slab_nomerge random.trust_cpu=off page_alloc.shuffle=1 loglevel=3"' | doas tee -a /etc/default/grub
fi
doas grub-mkconfig -o /boot/grub/grub.cfg

# Enable AppArmor
echo "Enabling AppArmor..."
doas pacman -S --noconfirm apparmor
doas systemctl enable --now apparmor

# Install AppArmor profiles from AUR
echo "Installing AppArmor profiles..."
yay -S --noconfirm apparmor-profiles-git

# Enable USBGuard
echo "Enabling USBGuard..."
doas pacman -S --noconfirm usbguard
doas systemctl enable --now usbguard
doas usbguard generate-policy | doas tee /etc/usbguard/rules.conf > /dev/null

# Configure nftables firewall
echo "Configuring firewall with nftables..."
doas pacman -S --noconfirm nftables
doas systemctl enable --now nftables
doas tee /etc/nftables.conf > /dev/null <<EOF
table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    tcp dport {22, 80, 443} accept
  }
}
EOF

# Apply sysctl hardening parameters
echo "Setting sysctl parameters..."
doas tee /etc/sysctl.d/99-sec.conf > /dev/null <<EOF
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.randomize_va_space=2
fs.protected_symlinks=1
fs.protected_hardlinks=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
EOF
doas sysctl --system

# Install and initialize AIDE
echo "Installing AIDE from AUR..."
yay -S --noconfirm aide
echo "Initializing AIDE..."
doas aide --init
echo "Finalizing AIDE database..."
doas mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Install ClamAV
echo "Installing ClamAV..."
doas pacman -S --noconfirm clamav
doas systemctl enable --now clamav-freshclam
clamscan -r --bell -i "$HOME" || true

# Set up encrypted DNS with dnscrypt-proxy
echo "Setting up encrypted DNS with dnscrypt-proxy..."
doas pacman -S --noconfirm dnscrypt-proxy
doas sed -i 's/^# server_names =.*/server_names = ["libredns"]/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml
doas sed -i 's/^# require_dnssec = false/require_dnssec = true/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml
doas systemctl enable --now dnscrypt-proxy
echo "nameserver 127.0.0.1" | doas tee /etc/resolv.conf > /dev/null

# Install hBlock (tracker/malware blocker)
echo "Installing hBlock..."
doas pacman -S --noconfirm curl
curl -sSL https://hblock.molinero.dev/install | doas bash

# Install and configure auditd
echo "Installing and configuring audit..."
doas pacman -S --noconfirm audit
doas systemctl enable --now auditd

doas tee /etc/audit/rules.d/arch-hardening.rules > /dev/null <<'EOF'
# doas monitoring
-a always,exit -F path=/usr/bin/doas -F perm=x -F auid>=1000 -F auid!=4294967295 -k doas-calls

# Changes in /etc/
-w /etc/ -p wa -k etc-changes

# passwd & shadow files
-w /etc/passwd -p wa -k passwd-watch
-w /etc/shadow -p wa -k shadow-watch

# Critical config files
-w /etc/sudoers -p wa -k sudoers
-w /etc/doas.conf -p wa -k doasconf
-w /etc/pacman.conf -p wa -k pkg-conf

# Kernel module operations
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel-module

# User/group file monitoring
-w /etc/group -p wa -k group-change
-w /etc/gshadow -p wa -k gshadow-change

# Monitor /home directory
-w /home/ -p rwxa -k home-access

# Protect /boot directory
-w /boot/ -p wa -k boot-watch

# Time/date changes
-w /etc/adjtime -p wa -k time-change
-w /etc/systemd/timesyncd.conf -p wa -k timesync-change
EOF

# Apply audit rules
doas augenrules --load

# Install doas and remove sudo if necessary
setup_doas_and_remove_sudo

# Prompt for system reboot
read -rp "Reboot the system to apply all changes? (y/N): " reboot_choice
[[ $reboot_choice =~ ^[Yy]$ ]] && doas reboot
