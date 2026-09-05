from app.traffic.monitor import TrafficMonitor


def main():
    interface = "enp0s8"

    monitor = TrafficMonitor(interface)

    print("=" * 60)
    print("Firewall Project - Continuous Traffic Monitor")
    print("=" * 60)

    try:
        monitor.start()

    except KeyboardInterrupt:
        print("\n[+] Traffic monitor stopped.")


if __name__ == "__main__":
    main()