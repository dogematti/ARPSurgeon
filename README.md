# ARPSurgeon

```
 _______  ______  _____  _______ _     _  ______  ______ _______  _____  __   _
 |_____| |_____/ |_____] |______ |     | |_____/ |  ____ |______ |     | | \  |
 |     | |    \_ |       ______| |_____| |    \_ |_____| |______ |_____| |  \_|
                                                                               
```

**ARPSurgeon** is a precision-oriented network manipulation and observation framework designed for security researchers, network engineers, and system administrators. Unlike traditional noisy flooding tools, ARPSurgeon focuses on **surgical precision**, **passive visibility**, and **automation**.

It allows you to map networks, fingerprint devices, intercept traffic, and stress-test infrastructure through a unified CLI, a Web Control Plane, or automated Campaigns.

## Key Capabilities

### Passive Reconnaissance
*   **Asset Discovery:** Passively builds a comprehensive inventory of devices (IP, MAC, Vendor).
*   **OS Fingerprinting:** Identifies operating systems (e.g., "Windows 11", "iOS 15+") by analyzing packet TTL, TCP Window sizes, and **DHCP Option 55** signatures.
*   **Service Discovery:** Extracts hostnames and device roles by snooping on **mDNS** (Bonjour), **LLMNR**, and **NBNS** broadcasts.
*   **Network Topology:** Visualizes relationships between devices (who talks to whom) via interactive graphs.

### Active Operations
*   **Surgical MITM:** Intercepts traffic between specific victims and gateways without disrupting the entire subnet. Features configurable poisoning intervals, jitter, and automatic restoration.
*   **TCP Severing:** Terminates specific TCP connections (e.g., SSH, HTTPS) by injecting **TCP RST** packets, allowing for precise denial-of-service testing.
*   **DNS Spoofing:** Selectively redirects DNS requests for specific domains or all traffic to a controlled IP.
*   **L2 Fuzzing:** Stress-tests network switches and stacks with malformed ARP, invalid Ethernet frames, and MAC flooding.

### Automation & Management
*   **Web Control Plane:** A modern, dark-mode Web Dashboard (FastAPI + React) to manage jobs, view real-time events, and explore the network map from any browser.
*   **Scenario Engine:** Define complex, multi-step workflows ("Campaigns") in YAML files for repeatable security audits.
*   **Centralized Storage:** All data is persisted to an internal **SQLite database**, enabling historical analysis and complex queries.
*   **Notifications:** Receive real-time alerts for critical events (ARP Storms, Conflicts) via **Discord**, **Slack**, or Webhooks.

---\n
## Installation

### Option 1: Local Python Environment
Best for development or quick usage on a laptop.

```bash
# Clone the repository
git clone https://github.com/your-repo/ARPSurgeon.git
cd ARPSurgeon

# Run the setup script (creates venv, installs deps, starts web UI)
./start_local.sh
```

**Manual Setup:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Option 2: Docker Container
Best for persistent deployment on a Raspberry Pi, server, or cloud instance.

```bash
# Build and run in background
docker-compose up -d --build

# Follow logs
docker-compose logs -f
```

Access the dashboard at **http://localhost:8000/static/index.html**.

> **Note:** The container uses `network_mode: host` and `privileged: true` to access raw sockets required for ARP manipulation.

---\n
## Configuration

ARPSurgeon uses a centralized configuration file. It looks for `arpsurgeon.toml` in the current directory or `~/.arpsurgeon.toml`.

**Example Configuration:**

```toml
[global]
# Default interface (optional, auto-detected if omitted)
# iface = "eth0"

[monitor]
# Alert if >200 ARP packets seen in 10 seconds
storm_threshold = 200
storm_window = 10
# Rotate pcap files after 100MB
pcap_rotate_mb = 100

[notifications]
enabled = true
discord_webhook = "https://discord.com/api/webhooks/..."

[poison]
# Seconds between spoofed packets
interval = 2.5
# Randomize interval by +/- 0.5s to evade detection
jitter = 0.5
# Restore ARP tables on exit
restore = true
```

---\n
## Usage Guide

### Web Control Plane
Start the web server to control everything from your browser:
```bash
sudo python -m arpsurgeon web --host 0.0.0.0 --port 8000
```

### Command Line Interface (CLI)

#### 1. Reconnaissance
```bash
# List interfaces and gateway
sudo python -m arpsurgeon interfaces

# Active Scan (ARP Ping)
sudo python -m arpsurgeon discover --cidr 192.168.1.0/24

# Passive Profiling (Recommended)
# Captures traffic to identify OS, Hostnames, and traffic patterns.
sudo python -m arpsurgeon profile --iface en0 --duration 600
```

#### 2. Monitoring & Defense
```bash
# Monitor for attacks (ARP Storms, Conflicts, Spoofing)
sudo python -m arpsurgeon monitor --iface en0 --verbose

# Check if a target is reachable and ARP is healthy
sudo python -m arpsurgeon check --victim 192.168.1.15 --ping
```

#### 3. Active Manipulation
```bash
# Man-in-the-Middle (MITM)
# Poisons victim & gateway, enables forwarding, and starts DNS spoofing.
sudo python -m arpsurgeon mitm \
  --victim 192.168.1.15 \
  --gateway 192.168.1.1 \
  --dns-hosts-file hosts.txt

# Surgical TCP Severing
# Kills SSH connections to the target.
sudo python -m arpsurgeon sever \
  --target 192.168.1.15 \
  --port 22 \
  --duration 60

# Protocol Fuzzing
# Stress-test the switch with random ARP opcodes.
sudo python -m arpsurgeon fuzz \
  --mode arp_opcode \
  --rate 50
```

#### 4. Reporting & Visualization
```bash
# Generate a Markdown report from logs
python -m arpsurgeon report --input monitor.jsonl --format md --output report.md

# Generate an interactive Network Topology Graph
python -m arpsurgeon report --input profile.json --format graph --output topology.html
```

### Campaign Automation
Define workflows in YAML to automate testing:

**Included Templates (`templates/campaigns/`):**
*   `passive_audit.yaml`: Zero-touch reconnaissance and topology mapping.
*   `active_defense.yaml`: Baseline scanning and integrity monitoring.
*   `stress_test.yaml`: L2 fuzzing and switch stress testing.
*   `mitm_investigation.yaml`: Targeted interception workflow.

**Example `audit_campaign.yaml`**:
```yaml
name: "Security Audit Alpha"
steps:
  - action: discover
    name: "Initial Scan"
    args: { cidr: "192.168.1.0/24", timeout: 1.0 }
  - action: profile
    name: "Passive Fingerprinting"
    args: { duration: 60 }
  - action: sever
    name: "Test Resilience"
    args: { target: "192.168.1.50", port: 80, duration: 30 }
```

Run it:
```bash
sudo python -m arpsurgeon campaign --file templates/campaigns/passive_audit.yaml
```

---\n
## Disclaimer

**ARPSurgeon is a powerful tool designed for educational purposes, authorized security testing, and network administration.**

*   **Do not use this tool on networks you do not own or have explicit permission to test.**
*   Unauthorized interception of traffic or denial of service is illegal in many jurisdictions.
*   The authors are not responsible for any damage or legal consequences caused by misuse.

**Handle with care.** 🩺

```