# Installation

## 1. Requirements

* Linux system
* Python 3
* `python3-venv`
* `python3-pip`
* `nftables`
* `sudo` privileges

## 2. Clone the Repository

```bash
git clone <https://github.com/ShadowSensei-Sec/VesperAegis.git>
cd Firewall-Projet
```

## 3. Make Scripts Executable

```bash
chmod +x install.sh
chmod +x start.sh
chmod +x stop.sh
```

## 4. Install VesperAegis

Run:

```bash
./install.sh
```

The installation script:

* Updates system packages.
* Installs Python, pip, Python virtual environment support, and nftables.
* Creates the `.venv` Python virtual environment.
* Installs dependencies from `requirements.txt`.
* Creates required directories.
* Initializes the SQLite database.
* Loads the default firewall rules.


## 5. Start VesperAegis

```bash
./start.sh
```

The startup process initializes the nftables firewall configuration and starts the VesperAegis FastAPI application and traffic monitoring.

The API listens on:

```text
0.0.0.0:8000
```

## 6. Verify the Firewall

Verify the VesperAegis nftables table:

```bash
sudo nft list table inet nftable
```

Verify the complete nftables ruleset:

```bash
sudo nft list ruleset
```

## 7. Access the Web Interface

Open:

```text
http://your_IP>:8000
```

For local access:

```text
http://127.0.0.1:8000
```

Authenticate through the login page to access the dashboard.

## 8. Stop VesperAegis

```bash
./stop.sh
```

### Reinitialize Database

```bash
PYTHONPATH="$PWD" .venv/bin/python scripts/initialize_database.py
```

Then:

```bash
./start.sh
```

## 9. Runtime Files

The following files are generated locally during installation and runtime:

```text
data/firewall.db
data/firewall.db-wal
data/firewall.db-shm
```

These files are excluded from Git. The repository retains `data/.gitkeep` so the data directory is available after cloning.

