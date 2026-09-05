from app.database.database import initialize_database


def main():
    print("=" * 60)
    print("Firewall Project - Database Initialization")
    print("=" * 60)

    print("\n[+] Initializing SQLite database...")

    initialize_database()

    print("[+] Database initialized successfully.")


if __name__ == "__main__":
    main()