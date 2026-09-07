CREATE TABLE IF NOT EXISTS firewall_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    interface TEXT,
    action TEXT,
    rule_id INTEGER,
    rule_name TEXT,
    rule_match TEXT,
    rule_decision TEXT,
    packets INTEGER DEFAULT 0,
    bytes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    interface TEXT,
    packets INTEGER DEFAULT 0,
    bytes INTEGER DEFAULT 0,
    UNIQUE (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        interface
    )
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    action TEXT NOT NULL,
    protocol TEXT NOT NULL,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    interface TEXT,
    direction TEXT,
    enabled INTEGER DEFAULT 1,
    description TEXT DEFAULT '',
    priority INTEGER DEFAULT 100,
    nft_handle INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1
);