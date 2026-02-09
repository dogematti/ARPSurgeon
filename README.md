# ARPSurgeon

```
 _______  ______  _____  _______ _     _  ______  ______ _______  _____  __   _
 |_____| |_____/ |_____] |______ |     | |_____/ |  ____ |______ |     | | \  |
 |     | |    \_ |       ______| |_____| |    \_ |_____| |______ |_____| |  \_|

```

**ARPSurgeon** is a precision-oriented network manipulation and observation framework for security researchers, network engineers, and pentesters. Unlike traditional noisy flooding tools, ARPSurgeon focuses on **surgical precision**, **passive visibility**, and **automation** through a unified CLI, Web Control Plane, and YAML-driven Campaign engine.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests: 87 passed](https://img.shields.io/badge/tests-87%20passed-brightgreen.svg)](#testing)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Web Control Plane](#web-control-plane)
  - [CLI Reference](#cli-reference)
  - [Campaign Automation](#campaign-automation)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)

---

## Features

### Passive Reconnaissance
- **Asset Discovery** -- Passively inventories devices (IP, MAC, vendor) from broadcast traffic.
- **OS Fingerprinting** -- Identifies operating systems (e.g. "Windows 11", "iOS 15+") via TTL analysis, TCP window sizes, and DHCP Option 55 signatures.
- **Service Discovery** -- Extracts hostnames and device roles by snooping mDNS (Bonjour), LLMNR, and NBNS broadcasts.
- **Network Topology** -- Interactive vis.js graph showing device relationships and traffic patterns.

### Active Operations
- **Surgical MITM** -- Intercepts traffic between specific victims and gateways with configurable poisoning intervals, jitter, and automatic ARP restoration on exit.
- **TCP Severing** -- Terminates specific TCP connections (SSH, HTTPS, etc.) by injecting TCP RST packets for precise denial-of-service testing.
- **DNS Spoofing** -- Selectively redirects DNS requests for specific domains or all traffic to a controlled IP.
- **L2 Fuzzing** -- Stress-tests switches and network stacks with malformed ARP, invalid Ethernet frames, and MAC flooding.

### Automation & Management
- **Web Control Plane** -- Dark-themed dashboard (FastAPI + Bootstrap 5) with sidebar navigation, real-time SSE event streaming, job management, interactive topology map, and data export.
- **Campaign Engine** -- Define multi-step security workflows in YAML for repeatable, automated audits.
- **SQLite Storage** -- All host discoveries and events persisted for historical analysis and querying.
- **Structured Logging** -- Python `logging` with timestamped, leveled output (replaces ad-hoc print statements).
- **Notifications** -- Real-time alerts for critical events (ARP storms, conflicts) via Discord, Slack, or webhooks.
- **REST API** -- Full API with Swagger UI (`/docs`) and ReDoc (`/redoc`) for integration and scripting.

---

## Architecture

```
arpsurgeon/
  engine.py       Job adapter pattern -- 15 job types, threaded execution
  storage.py      SQLite with context-managed connections, paginated queries
  web/api.py      FastAPI REST API + SSE + Bearer auth + request logging
  web/static/     Dark-themed SPA (Bootstrap 5, vis.js, vanilla JS)
  config.py       TOML-based configuration with deep-merge support
  fingerprint.py  OS fingerprinting via TTL/TCP window/DHCP signatures
  campaign.py     YAML campaign runner (sequential multi-step workflows)
  notify.py       Discord / Slack / webhook alert dispatcher
  log.py          Centralized structured logging configuration
```

**Key design decisions:**
- **Job Adapters** -- Each operation (monitor, discover, poison, mitm, etc.) is a plain function `(args: Dict, stop_event: Event) -> None`. The engine manages lifecycle, threading, and cleanup.
- **Module-level Database** -- `api.py` creates a `Database()` at import time for fast startup. Tests bootstrap-patch `__init__` before import.
- **Automatic Cleanup** -- Completed/failed jobs older than 1 hour are automatically pruned from memory.

---

## Installation

### Option 1: Local (pip)

```bash
git clone https://github.com/dogematti/ARPSurgeon.git
cd ARPSurgeon

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Install dev dependencies for testing
pip install -e ".[dev]"
```

### Option 2: Quick Start Script

```bash
./start_local.sh
```

### Option 3: Docker

```bash
docker-compose up -d --build

# Follow logs
docker-compose logs -f
```

The container includes a health check against `/api/v1/stats` (30s interval).

> **Note:** The container requires `network_mode: host` and `privileged: true` for raw socket access (Scapy/ARP).

---

## Configuration

ARPSurgeon loads configuration from `arpsurgeon.toml` in the working directory or `~/.arpsurgeon.toml`.

```toml
[global]
# iface = "eth0"       # Auto-detected if omitted

[monitor]
storm_threshold = 200   # Alert if >200 ARP packets in storm_window seconds
storm_window = 10
pcap_rotate_mb = 100    # Rotate pcap files at 100 MB

[notifications]
enabled = true
discord_webhook = "https://discord.com/api/webhooks/..."

[poison]
interval = 2.5          # Seconds between spoofed packets
jitter = 0.5            # Randomize +/- 0.5s to evade detection
restore = true          # Restore ARP tables on exit
```

---

## Usage

### Web Control Plane

```bash
sudo python3 -m arpsurgeon web --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** in your browser. The dashboard provides:

| Section | Description |
|---------|-------------|
| **Dashboard** | Live stat cards (hosts, active jobs, events, uptime), active jobs table, recent events feed |
| **Jobs** | Full job list with status badges, duration timers, filtering by status, start/stop controls |
| **Hosts** | Sortable table (IP, hostname, MAC, vendor, OS, last seen), search, CSV/JSON export |
| **Events** | Color-coded live event stream with type filtering, auto-scroll toggle, CSV/JSON export |
| **Topology** | Interactive vis.js network graph with fullscreen mode and refresh controls |

Actions are organized in the top bar: **Recon** (discover, observe, profile, health check), **Attack** (poison, MITM, DNS spoof, sever, fuzz, relay), **Defense** (monitor, restore, snapshot), and **Auto** (campaign).

### CLI Reference

#### Reconnaissance

```bash
# List interfaces and detected gateway
sudo python3 -m arpsurgeon interfaces

# Active ARP scan of a subnet
sudo python3 -m arpsurgeon discover --cidr 192.168.1.0/24

# Passive profiling (OS fingerprinting, hostname resolution)
sudo python3 -m arpsurgeon profile --iface en0 --duration 600
```

#### Monitoring & Defense

```bash
# Monitor for ARP storms, conflicts, and spoofing
sudo python3 -m arpsurgeon monitor --iface en0 --verbose

# Health check: verify ARP connectivity to a target
sudo python3 -m arpsurgeon check --victim 192.168.1.15 --ping
```

#### Active Manipulation

```bash
# Man-in-the-Middle with optional DNS spoofing
sudo python3 -m arpsurgeon mitm \
  --victim 192.168.1.15 \
  --gateway 192.168.1.1 \
  --dns-hosts-file hosts.txt

# TCP connection severing (e.g. kill SSH sessions)
sudo python3 -m arpsurgeon sever \
  --target 192.168.1.15 \
  --port 22 \
  --duration 60

# Protocol fuzzing
sudo python3 -m arpsurgeon fuzz --mode arp_opcode --rate 50
```

#### Reporting

```bash
# Markdown report from monitor logs
python3 -m arpsurgeon report --input monitor.jsonl --format md --output report.md

# Interactive topology graph
python3 -m arpsurgeon report --input profile.json --format graph --output topology.html
```

### Campaign Automation

Campaigns are YAML workflows that chain multiple operations sequentially.

**Included templates** (`templates/campaigns/`):

| Template | Purpose |
|----------|---------|
| `passive_audit.yaml` | Zero-touch recon and topology mapping |
| `active_defense.yaml` | Baseline scanning and integrity monitoring |
| `stress_test.yaml` | L2 fuzzing and switch stress testing |
| `mitm_investigation.yaml` | Targeted interception workflow |

**Example campaign:**

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

```bash
sudo python3 -m arpsurgeon campaign --file templates/campaigns/passive_audit.yaml
```

---

## API Reference

The REST API runs on the same port as the web UI. Interactive docs are available at:

- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/stats` | Summary stats (hosts, events, active jobs, uptime) |
| `GET` | `/api/v1/jobs` | List all jobs |
| `GET` | `/api/v1/jobs/{id}` | Get single job details |
| `POST` | `/api/v1/jobs/{type}` | Start a job (body: `{"args": {...}}`) |
| `DELETE` | `/api/v1/jobs/{id}` | Stop a running job |
| `GET` | `/api/v1/hosts` | Paginated host list (`?search=`, `?sort_by=`, `?sort_order=`) |
| `DELETE` | `/api/v1/hosts` | Clear all hosts |
| `GET` | `/api/v1/hosts/export` | Export hosts (`?format=csv` or `json`) |
| `GET` | `/api/v1/events` | Paginated event list (`?event_type=`, `?limit=`, `?offset=`) |
| `DELETE` | `/api/v1/events` | Clear all events |
| `GET` | `/api/v1/events/export` | Export events (`?format=csv` or `json`) |
| `GET` | `/api/v1/topology` | Network topology (nodes + edges for vis.js) |
| `GET` | `/api/v1/profiles` | Available job presets/profiles |
| `GET` | `/api/v1/events/stream` | SSE stream for real-time events |

Authentication: set an API key via the Settings modal or pass `Authorization: Bearer <key>` header.

---

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full suite (87 tests)
python3 -m pytest tests/ -v
```

Test coverage includes:

| Module | Tests |
|--------|-------|
| `test_api.py` | FastAPI endpoints -- jobs, hosts, events, stats, topology, export, redirects |
| `test_engine.py` | Job lifecycle, JobManager start/stop/list, automatic cleanup |
| `test_storage.py` | Database CRUD, pagination, search, sorting, stats, event filtering |
| `test_config.py` | TOML loading, deep-merge, defaults |
| `test_fingerprint.py` | OS fingerprinting via TTL/DHCP signatures |
| `test_health.py` | ARP/ICMP health checks |
| `test_oui.py` | MAC vendor lookup (OUI database) |

---

## Project Structure

```
ARPSurgeon/
  arpsurgeon/
    __main__.py          CLI entry point
    cli.py               Argument parsing and command dispatch
    engine.py            Job adapter engine (15 job types, threaded)
    storage.py           SQLite database (hosts, events, refresh_stats)
    config.py            TOML configuration loader
    log.py               Structured logging setup
    models.py            Pydantic models
    arp.py               Core ARP send/receive primitives
    arp_cache.py         ARP cache management
    discover.py          Active ARP scanning
    observe.py           Passive traffic observation
    fingerprint.py       OS fingerprinting (TTL, TCP window, DHCP)
    dns_spoof.py         DNS spoofing engine
    fuzz.py              L2 protocol fuzzer
    health.py            ARP/ICMP health checks
    notify.py            Alert dispatcher (Discord, Slack, webhooks)
    oui.py               MAC vendor lookup
    relay.py             ARP relay
    report.py            Report generation (Markdown, HTML graph)
    session_log.py       Session logging
    sever.py             TCP RST injection (connection severing)
    campaign.py          YAML campaign runner
    utils.py             Shared utilities
    web/
      api.py             FastAPI application (REST + SSE + static)
      static/
        index.html       SPA control plane
        css/style.css    Dark theme styles
        js/app.js        Frontend logic
  templates/
    campaigns/           YAML campaign templates
  tests/                 87 pytest tests
  Dockerfile             Container image with health check
  docker-compose.yml     Production deployment config
  pyproject.toml         PEP 621 project metadata + pytest config
  requirements.txt       Runtime dependencies
  setup.py               Legacy setuptools config
  start_local.sh         Quick-start script
```

---

## Disclaimer

**ARPSurgeon is designed for authorized security testing, network administration, and educational purposes only.**

- Do not use this tool on networks you do not own or have explicit written permission to test.
- Unauthorized interception of traffic or denial of service is illegal in many jurisdictions.
- The authors are not responsible for any damage or legal consequences caused by misuse.

**Handle with care.**
