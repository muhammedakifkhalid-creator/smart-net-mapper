#!/usr/bin/env python3

import subprocess
import re
from collections import defaultdict

COMMON_PORTS = "22,53,80,139,443,445,515,554,8000,8080,8443,62078"

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)

# -----------------------------
# Auto detect network
# -----------------------------
import platform
import subprocess

def get_network():
    import platform
    import subprocess

    if platform.system() == "Windows":
        output = subprocess.check_output("ipconfig", shell=True, text=True)

        ips = []

        for line in output.splitlines():
            if "IPv4" in line:
                ip = line.split(":")[-1].strip()

                # Collect all IPs
                ips.append(ip)

        # Filter valid ones
        for ip in ips:
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                return ip + "/24"

        # fallback (if nothing found)
        for ip in ips:
            if not ip.startswith("169.254") and not ip.startswith("127."):
                return ip + "/24"

        raise Exception("No valid network found")

    else:
        output = subprocess.check_output("ip -4 addr", shell=True, text=True)

        for line in output.splitlines():
            if "inet " in line:
                ip = line.strip().split()[1]

                if not ip.startswith("127."):
                    return ip

        raise Exception("No valid network found")
# -----------------------------
# Discover live hosts + MAC vendor
# -----------------------------
def discover_hosts(target):
    out = run(f"nmap -sn {target}")
    hosts = re.findall(r"Nmap scan report for ([\d\.]+)", out)
    macs = dict(re.findall(r"MAC Address: ([A-F0-9:]+) \((.*?)\)", out))
    return hosts, macs

# -----------------------------
# Scan ports
# -----------------------------
def scan_host(ip):
    out = run(f"nmap -p {COMMON_PORTS} -sV --open {ip}")
    ports = set(int(p) for p in re.findall(r"(\d+)/tcp\s+open", out))
    services = re.findall(r"\d+/tcp\s+open\s+(\S+)", out)
    return ports, services

# -----------------------------
# Device classification
# -----------------------------
def classify(ports):
    if 554 in ports:
        return "📷 Camera / CCTV"
    if 62078 in ports:
        return "📱 Apple Device (iPhone/iPad)"
    if 135 in ports or 139 in ports or 445 in ports:
        return "💻 Windows System"
    if 53 in ports and (80 in ports or 443 in ports):
        return "🌐 Router / Gateway"
    if 515 in ports or 9100 in ports:
        return "🖨️ Printer / Print Service"
    if any(p in ports for p in (80, 443, 8000, 8080, 8443)):
        return "📡 Web-enabled Device / IoT"
    if len(ports) == 0:
        return "🔒 Secured Device"
    return "❓ Unknown"

# -----------------------------
# Risk analysis
# -----------------------------
def risk_level(ports):
    risky_ports = {21, 23, 135, 139, 445}
    if any(p in ports for p in risky_ports):
        return "⚠️ High Risk"
    elif len(ports) > 5:
        return "⚠️ Medium Risk"
    elif len(ports) > 0:
        return "🟢 Low Risk"
    return "🟢 Very Safe"

# -----------------------------
# Main
# -----------------------------
def main():
    print("\n[+] Detecting network...\n")
    target = get_network()

    if not target:
        print("[-] Could not detect network")
        return

    print(f"[+] Scanning network: {target}\n")

    hosts, macs = discover_hosts(target)

    print("===== Device Analysis =====\n")

    for ip in hosts:
        ports, services = scan_host(ip)
        dtype = classify(ports)
        risk = risk_level(ports)
        vendor = macs.get(ip, "Unknown")

        print(f"IP: {ip}")
        print(f"Ports: {sorted(list(ports)) if ports else 'None'}")
        print(f"Type: {dtype}")
        print(f"Vendor: {vendor}")
        print(f"Risk: {risk}")
        print("-" * 40)

if __name__ == "__main__":
    main()
