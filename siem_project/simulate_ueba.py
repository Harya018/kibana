import os
import django
import time
import random
from datetime import datetime, timedelta

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
django.setup()

from audit.ingestion import LogIngestionService

def generate_login(username, ip, hour_offset=0):
    # Mock log data
    return {
        "event_type": "LOGIN_SUCCESS",
        "username": username,
        "ip_address": ip,
        "timestamp": (datetime.now() + timedelta(hours=hour_offset)).isoformat()
    }, "django_auth"

def simulate_ueba():
    username = "analytics_user"
    base_ip = "192.168.1.50"
    
    print(f"--- 1. Building Baseline for {username} ---")
    print(f"Logging in from {base_ip} at current hour...")
    
    # Simulate 5 normal logins to build profile
    for i in range(5):
        data, source = generate_login(username, base_ip)
        res = LogIngestionService.ingest_log(data, source)
        print(f"Normal Login #{i+1}: {res}")
        time.sleep(1.5)

    print("\n--- 2. Triggering Anomalies ---")
    
    # Anomaly 1: New IP
    new_ip = "10.66.77.88"
    print(f"Attempting login from NEW IP: {new_ip}...")
    data, source = generate_login(username, new_ip)
    res = LogIngestionService.ingest_log(data, source)
    print(f"Result: {res}")
    
    # Anomaly 2: New Hour (Simulated by just logging in - if current hour is different from what we built, incident triggers?
    # Actually our ingestion uses datetime.now() for timestamping in ingestion.py usually, 
    # but let's see if normalization respects input timestamp.
    # Looking at NormalizationPipeline, it sets @timestamp to datetime.now().
    # So we can't easily simulate 'Unusual Hour' without mocking datetime or wait.
    # We will rely on IP anomaly for this test.
    
    print("\n--- Simulation Complete ---")
    print("Check Kibana 'logs-siem-default' for 'behavioral_anomaly' event type.")

if __name__ == "__main__":
    simulate_ueba()
