import socket
import threading
import datetime

def scan_port(host, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((host, port))

        if result == 0:
            results.append(f"Port {port}: OPEN")
        else:
            results.append(f"Port {port}: CLOSED")

        sock.close()

    except socket.timeout:
        results.append(f"Port {port}: TIMEOUT")
    except Exception as e:
        results.append(f"Port {port}: ERROR ({str(e)})")

def scan_range(host, start_port, end_port):
    threads = []
    results = []

    print(f"\n Scanning {host} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(host, port, results))
        threads.append(thread)
        thread.start()

    for t in threads:
        t.join()

    # Sort results by port number
    results.sort(key=lambda x: int(x.split()[1].replace(":", "")))

    return results


def save_log(host, results):
    filename = f"portscan_{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as file:
        file.write(f"Port Scan Results for {host}\n")
        file.write("-" * 40 + "\n")
        for line in results:
            file.write(line + "\n")

    print(f"\n Results saved to: {filename}")

if __name__ == "__main__":
    print("\n=== TCP PORT SCANNER ===")
    
    host = input("Enter Host/IP to scan: ")

    scan_type = input("Choose scan type:\n1. Single Port\n2. Range of Ports\nEnter choice (1/2): ")

    if scan_type == "1":
        port = int(input("Enter port to scan: "))
        results = []
        scan_port(host, port, results)

    elif scan_type == "2":
        start = int(input("Enter start port: "))
        end = int(input("Enter end port: "))
        results = scan_range(host, start, end)

    else:
        print("Invalid choice!")
        exit()

    print("\n=== Scan Results ===")
    for r in results:
        print(r)

    save_log(host, results)
