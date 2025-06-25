#!/usr/bin/env bash

set -euo pipefail

if [ "$EUID" -eq 0 ]; then
  echo "Bitte führe dieses Skript NICHT als root aus. Verwende einen Benutzer mit sudo-Rechten."
  exit 1
fi

echo "Starting Arch Hardening..."

# yay
if ! command -v yay &> /dev/null; then
  echo "yay nicht gefunden – wird installiert..."
  sudo pacman -S --needed git base-devel
  git clone https://aur.archlinux.org/yay.git /tmp/yay
  cd /tmp/yay
  makepkg -si --noconfirm
else
  echo "yay ist bereits installiert."
fi

# Kernel: linux-hardened
echo "Installing hardened kernel..."
sudo pacman -Sy --noconfirm linux-hardened linux-hardened-headers

# GRUB configuration
echo "Configuring GRUB..."
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor slab_nomerge random.trust_cpu=off page_alloc.shuffle=1 loglevel=3"/' /etc/default/grub
sudo grub-mkconfig -o /boot/grub/grub.cfg

# AppArmor
echo "Enabling AppArmor..."
sudo pacman -S --noconfirm apparmor
sudo systemctl enable --now apparmor

# AppArmor profiles from AUR
echo "Installing AppArmor profiles..."
yay -S apparmor-profiles-git

# USBGuard
echo "Enabling USBGuard..."
sudo pacman -S --noconfirm usbguard
sudo systemctl enable --now usbguard
sudo usbguard generate-policy | sudo tee /etc/usbguard/rules.conf > /dev/null

# nftables firewall
echo "Configuring firewall..."
sudo pacman -S --noconfirm nftables
sudo systemctl enable --now nftables
sudo tee /etc/nftables.conf > /dev/null <<EOF
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

# sysctl parameters
echo "Setting sysctl parameters..."
sudo tee /etc/sysctl.d/99-sec.conf > /dev/null <<EOF
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.randomize_va_space=2
fs.protected_symlinks=1
fs.protected_hardlinks=1
EOF
sudo sysctl --system

# AIDE
echo "Installing AIDE from AUR..."
yay -S aide

echo "Initializing AIDE..."
sudo aide --init

# ClamAV
echo "Installing ClamAV..."
sudo pacman -S --noconfirm clamav
sudo systemctl enable --now clamav-freshclam
clamscan -r --bell -i "$HOME" || true

# dnscrypt-proxy for LibreDNS
echo "Setting up encrypted DNS with dnscrypt-proxy..."
sudo pacman -S --noconfirm dnscrypt-proxy
sudo sed 's/^# server_names =.*/server_names = ["libredns"]/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml
sudo sed 's/^# require_dnssec = false/require_dnssec = true/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml
sudo systemctl enable --now dnscrypt-proxy
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf > /dev/null

# hBlock
echo "Installing hBlock to block trackers/malware..."
sudo pacman -S --noconfirm curl
curl -sSL https://hblock.molinero.dev/install | sudo bash
