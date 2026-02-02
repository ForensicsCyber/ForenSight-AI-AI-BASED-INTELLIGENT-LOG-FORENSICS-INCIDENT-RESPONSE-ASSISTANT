import sqlite3
from datetime import datetime, timedelta
import random

DB_PATH = "../data/structured_samples/structured_logs.db"

ips = ["192.168.1.10", "192.168.1.50", "10.0.0.23", "172.16.0.5"]
users = ["admin", "root", "gshobowale", "mfurmaga", "vsrathore", "guest", None]
endpoints = ["/login", "/admin", "/index.php", "/wp-login.php"]
methods = ["GET", "POST"]
statuses = [200, 401, 403, 404]

def generate_logs():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    base_time = datetime.now()

    for i in range(300):
        ts = base_time + timedelta(seconds=i * random.randint(1, 5))
        log_type = random.choice(["apache", "auth", "firewall"])

        if log_type == "apache":
            cur.execute("""
                INSERT INTO logs (
                    timestamp, source_ip, destination_ip, username,
                    request_method, endpoint, status_code, message, log_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts.isoformat(),
                random.choice(ips),
                "192.168.1.100",
                None,
                random.choice(methods),
                random.choice(endpoints),
                random.choice(statuses),
                "HTTP request received",
                "apache"
            ))

        elif log_type == "auth":
            status = random.choice([200, 401])
            cur.execute("""
                INSERT INTO logs VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                ts.isoformat(),
                random.choice(ips),
                "192.168.1.100",
                random.choice(users),
                "SSH",
                "ssh-login",
                status,
                "Authentication attempt",
                "auth"
            ))

        else:
            cur.execute("""
                INSERT INTO logs VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                ts.isoformat(),
                random.choice(ips),
                "192.168.1.1",
                None,
                "TCP",
                "port-scan",
                random.choice([0, 1]),
                "Firewall connection logged",
                "firewall"
            ))

    conn.commit()
    conn.close()
    print("Structured logs generated successfully.")

if __name__ == "__main__":
    generate_logs()