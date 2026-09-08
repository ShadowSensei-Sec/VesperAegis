<img width="1015" height="1574" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/7818af1a-e3bf-433f-b398-453c6f9f7c44" />

                ┌──────────────────────────┐
                │      Network Traffic     │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │    Packet Inspection     │
                │   Traffic Monitor        │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │      Rule Engine         │
                │                          │
                │ IP / Port / Protocol     │
                │ Priority / State         │
                └────────────┬─────────────┘
                             │
                     ┌───────┴───────┐
                     ▼               ▼
                  ALLOW             DENY
                     │               │
                     ▼               ▼
             ┌──────────────┐  ┌──────────────┐
             │   nftables   │  │ Event Logger │
             │ Enforcement  │  │              │
             └──────────────┘  └──────────────┘
                     │               │
                     └───────┬───────┘
                             ▼
                ┌──────────────────────────┐
                │      SQLite Storage      │
                │ Rules / Events / Stats   │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │     FastAPI Backend       │
                └────────────┬─────────────┘
                             │
                             ▼
                ┌──────────────────────────┐
                │       Web Dashboard       │
                │ Rules / Logs / Traffic   │
                └──────────────────────────┘
