#!/usr/bin/env bash

set -euo pipefail

echo "Starting Arch Hardening..."

# Kernel: linux-hardened
echo "Installing hardened kernel..."
pacman -Sy --noconfirm linux-hardened linux-hardened-headers

# GRUB configuration
echo "Configuring GRUB..."
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet apparmor=1 security=apparmor slab_nomerge random.trust_cpu=off page_alloc.shuffle=1 loglevel=3"/' /etc/default/grub
grub-mkconfig -o /boot/grub/grub.cfg

# AppArmor
echo "Enabling AppArmor..."
pacman -S --noconfirm apparmor apparmor-utils
systemctl enable --now apparmor

# AppArmor profiles from AUR (manual installation)
echo "Installing AppArmor profiles..."
pacman -S --noconfirm --needed git base-devel
git clone https://aur.archlinux.org/apparmor-profiles-git.git /tmp/apparmor-profiles-git
cd /tmp/apparmor-profiles-git
makepkg -si --noconfirm
aa-enforce /etc/apparmor.d/*

# USBGuard
echo "Enabling USBGuard..."
pacman -S --noconfirm usbguard
systemctl enable --now usbguard
usbguard generate-policy > /etc/usbguard/rules.conf
chattr +i /etc/usbguard/rules.conf

# systemd-homed
echo "Enabling systemd-homed..."
pacman -S --noconfirm systemd-homed
systemctl enable --now systemd-homed.service

# nftables firewall
echo "Configuring firewall..."
pacman -S --noconfirm nftables
systemctl enable --now nftables
cat > /etc/nftables.conf <<EOF
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
cat > /etc/sysctl.d/99-sec.conf <<EOF
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.randomize_va_space=2
fs.protected_symlinks=1
fs.protected_hardlinks=1
EOF
sysctl --system

# AIDE
echo "Initializing AIDE..."
pacman -S --noconfirm aide
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# ClamAV
echo "Installing ClamAV..."
pacman -S --noconfirm clamav
systemctl enable --now clamav-freshclam
clamscan -r --bell -i /home || true

# dnscrypt-proxy for LibreDNS
echo "Setting up encrypted DNS with dnscrypt-proxy..."
pacman -S --noconfirm dnscrypt-proxy
sed -i 's/^# server_names = 



\[.*/server_names = 



\["libredns"\]



/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml
sed -i 's/^# require_dnssec = false/require_dnssec = true/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml
systemctl enable --now dnscrypt-proxy.service
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# hBlock installation
echo "Installing hBlock to block trackers/malware..."
pacman -S --noconfirm curl
curl -sSL https://hblock.molinero.dev/install | bash

