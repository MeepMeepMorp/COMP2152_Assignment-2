"""
Author: Sean Anthony Dela Cruz
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Dictionary mapping port numbers to their common service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # @property lets us read the target value without touching the private variable.
    # @target.setter lets us check the value before it gets assigned.
    # This way bad input like empty strings gets blocked before causing issues.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner calls super().__init__(target) to reuse NetworkTool's constructor.
# This means we get the target property and setter for free without rewriting them.
# For example scanner.target works because it was defined in NetworkTool.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except the program would crash on the first connection error.
        # If the target is unreachable the socket throws an exception and stops everything.
        # The try-except lets us catch that error and keep scanning the other ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Each port scan waits up to 1 second for a response so doing them one by one
    # would take forever. Threading lets us scan all ports at the same time.
    # Scanning 1024 ports without threads could take a while.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except:
        print("No past scans found.")

if __name__ == "__main__":
    try:
        target = input("Enter target IP address (press Enter for 127.0.0.1): ")
        if target == "":
            target = "127.0.0.1"

        start_port = input("Enter start port (1-1024): ")
        start_port = int(start_port)
        if start_port < 1 or start_port > 1024:
            print("Port must be between 1 and 1024.")
            exit()

        end_port = input("Enter end port (1-1024): ")
        end_port = int(end_port)
        if end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port in open_ports:
        print(f"Port {port[0]}: Open ({port[2]})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history = input("\nWould you like to see past scan history? (yes/no): ")
    if history.lower() == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# I would add a feature that lets the user scan multiple IP addresses at once.
# It would use a list comprehension to loop through the list of targets and
# create a PortScanner object for each one automatically.
# Diagram: See diagram_101298786.png in the repository root