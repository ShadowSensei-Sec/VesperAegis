# VesperAegis

> **A Linux-based firewall and network security platform for packet filtering, traffic monitoring, rule management, security-event logging, and firewall visibility.**

![Uploading VA.png…]()

---

## Overview

**VesperAegis** is a web-based firewall application built on top of **Linux nftables**.

It provides a centralized interface for managing firewall rules and monitoring network activity while using nftables as the underlying packet-filtering and enforcement layer.

The application combines:

- **nftables** — Firewall packet filtering and enforcement
- **Rule Engine** — Evaluates traffic against configured firewall rules
- **Traffic Monitor** — Inspects and analyzes network traffic
- **Logging System** — Records firewall security events
- **Traffic Statistics** — Tracks packet, byte, and protocol statistics
- **SQLite** — Local storage for firewall rules, events, statistics, and authentication
- **FastAPI** — Backend API
- **Web Dashboard** — Firewall management and monitoring interface
- **Authentication** — Protects access to the management interface

---

## Features

### Firewall Rule Management

Manage firewall rules directly from the web interface.

Supported operations include:

- Create rules
- Edit rules
- Delete rules
- Enable/disable rules
- Allow or deny traffic
- Configure source IP
- Configure destination IP
- Configure source port
- Configure destination port
- Configure protocol
- Configure rule priority

### Stateful Firewall

VesperAegis uses nftables connection tracking to handle established and related connections.

### Traffic Monitoring

The traffic monitoring component collects network packet information such as:

- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Interface
- Packet size

### Security Event Logging

Traffic matching firewall rules can be recorded as security events with information including:

- Timestamp
- Source and destination
- Protocol
- Action
- Rule
- Packet count
- Byte count

### Traffic Statistics

Normal traffic can be aggregated to provide:

- Packet statistics
- Byte statistics
- Protocol statistics
- Traffic activity over time

### Web Dashboard

The web interface provides:

| Section | Purpose |
|---|---|
| **Dashboard** | Firewall and traffic overview |
| **Rules** | Firewall rule management |
| **Logs** | Security-event monitoring |
| **Traffic** | Traffic statistics and protocol information |
| **System** | Firewall system information |

---

# Installation

## Requirements

- Linux
- Python 3
- Python virtual environment support
- pip
- nftables
- sudo privileges

## 1. Clone the Repository

```bash
git clone <https://github.com/ShadowSensei-Sec/VesperAegis.git>
````

## 2. Make Scripts Executable

```bash
chmod +x install.sh start.sh stop.sh
```

## 3. Install VesperAegis

```bash
./install.sh
```

The installation script installs the required dependencies, creates the Python virtual environment, initializes the SQLite database, and loads the default firewall configuration.

## 4. Start VesperAegis

```bash
./start.sh
```

The application starts the firewall configuration, FastAPI backend, and configured traffic monitoring.

## 5. Access the Dashboard

Open:

```text
http://<firewall-ip>:8000/login
```

For local access:

```text
http://127.0.0.1:8000/login
```

---

# Default Login Credentials

Use the following credentials for the initial login:

```text
Username: admin
Password: admin
```

> **Security Notice:** These credentials are provided only for the initial project setup.

### After the first login

**Immediately change the default username and password** to secure administrator credentials before using VesperAegis in any real or production environment.

Never leave the default credentials active on a deployed firewall.

---
