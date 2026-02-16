import os
import django
import random
import time
from datetime import datetime
import uuid

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
django.setup()

from audit.ingestion import LogIngestionService

def generate_firewall_log():
    start_port = random.randint(1024, 65535)
    dest_port = random.choice([80, 443, 22, 3389, 8080])
    action = "allow" if random.random() > 0.1 else "deny"
    return {
        "src_ip": f"192.168.1.{random.randint(2, 254)}",
        "src_port": start_port,
        "dest_ip": f"10.0.0.{random.randint(2, 254)}",
        "dest_port": dest_port,
        "protocol": "tcp",
        "action": action
    }, "firewall"

def generate_edr_log():
    processes = ["powershell.exe", "cmd.exe", "svchost.exe", "chrome.exe", "ncat.exe"]
    users = ["admin", "system", "harya", "guest"]
    proc = random.choice(processes)
    return {
        "process_name": proc,
        "pid": random.randint(1000, 9999),
        "cmd_line": f"{proc} /c echo 'test'",
        "file_path": f"C:\\Windows\\System32\\{proc}",
        "user": random.choice(users),
        "hostname": f"WORKSTATION-{random.randint(1, 20)}"
    }, "edr"

def generate_os_log():
    events = ["service_started", "service_stopped", "user_logon", "update_installed"]
    return {
        "event_type": random.choice(events),
        "message": "Service BITS changed state to running",
        "hostname": "SERVER-01"
    }, "os"

def simulate():
    print("Simulating External Logs...")
    for i in range(10):
        # Round robin generation
        if i % 3 == 0:
            data, source = generate_firewall_log()
        elif i % 3 == 1:
            data, source = generate_edr_log()
        else:
            data, source = generate_os_log()
            
        print(f"[{source.upper()}] Sending log...")
        LogIngestionService.ingest_log(data, source)
        time.sleep(0.5)
    
    print("Simulation Complete.")

if __name__ == "__main__":
    simulate()
