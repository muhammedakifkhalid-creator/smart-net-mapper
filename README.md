# smart-net-mapper
Smart network scanner that automatically detects devices on a local network, identifies their type (router, phone, camera, etc.), and highlights potential risks using Nmap.

# Smart Net Mapper

A simple but powerful network scanning tool that automatically detects devices on your local network, identifies their type, and provides a clean, human-readable output.

Built using Python and Nmap.

---

## 🚀 Features

- 🔍 Auto-detects your current network (no manual input needed)
- 🌐 Scans all active devices on the network
- 📡 Identifies device types:
  - Router / Gateway
  - Windows systems
  - iPhone / Apple devices
  - Cameras (RTSP-based detection)
  - Printers
  - IoT devices
- 🏷️ Detects device vendor (Apple, Samsung, Cisco, etc.)
- ⚠️ Assigns risk levels based on open ports
- 📊 Clean and readable output (no raw Nmap clutter)

---

## 🧠 How It Works

The tool uses Nmap to:
1. Discover live hosts in your network
2. Scan common ports
3. Analyze port patterns
4. Classify devices based on known behaviors

Example:
- Port 554 → Camera (RTSP)
- Port 445 → Windows (SMB)
- Port 62078 → Apple device
- Port 80/443 → Web-enabled device

---

## ⚙️ Installation

### 1. Install Nmap

**Arch Linux:**
```bash
sudo pacman -S nmap
