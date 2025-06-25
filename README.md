# Arch Linux Hardening Script

Dieses Skript automatisiert grundlegende Härtungsmaßnahmen für Arch Linux und richtet sicherheitsrelevante Dienste ein, um das System robuster gegenüber Angriffen zu machen.

## Hinweis

**Führe dieses Skript nicht als Root aus.**  
Verwende stattdessen einen normalen Benutzer mit `sudo`-Rechten.

## Funktionen

- Installation des `linux-hardened` Kernels
- Aktivierung von AppArmor mit optionalen Profilen
- Konfiguration der GRUB-Bootoptionen für bessere Isolation
- Einrichtung von USBGuard zur USB-Gerätekontrolle
- Konfiguration einer einfachen nftables-Firewall
- Absicherung des Kernels via sysctl
- Installation von AIDE (Intrusion Detection) aus dem AUR
- Einrichtung des Virenscanners ClamAV
- Aktivierung von dnscrypt-proxy mit LibreDNS
- Installation von hBlock zur Blockierung von Tracker- und Malware-Domains
- Automatische Installation von yay, falls nicht vorhanden

## Voraussetzungen

- Arch Linux oder Arch-basierte Distribution
- Benutzer mit sudo-Rechten (Mitglied der Gruppe `wheel`)
- Internetverbindung

## Nutzung

1. Skript herunterladen:
   ```bash
   git clone https://github.com/arch-harden.git
