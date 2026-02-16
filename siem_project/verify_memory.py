import os
import django
import json
import time
from elasticsearch import Elasticsearch
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
django.setup()

from audit.memory import IncidentMemory
from audit.analytics import RiskScorer

def verify_memory_and_scoring():
    es = Elasticsearch(
        hosts=settings.ELASTICSEARCH_HOSTS,
        api_key=settings.ELASTICSEARCH_API_KEY,
        verify_certs=False
    )
    
    print("--- 1. Testing Risk Scorer ---")
    event_doc = {
        "event": {
            "action": "login_attempt", 
            "severity": "high",
            "type": "behavioral_anomaly"
        },
        "risk": {"score": 0},
        "host": {"name": "web-server-01"}
    }
    score = RiskScorer.calculate_risk(event_doc)
    print(f"Risk Score Calculation: {score}")
    
    if score > 50:
         print("[PASS] High risk score calculated correctly.")
    else:
         print("[FAIL] Risk score too low.")

    print("\n--- 2. Testing Incident Memory ---")
    # We need a fake incident to search for
    # Assuming we ran Phase 3 verification, we have at least one incident.
    
    # Let's search for *any* incident first to get a baseline ID/Title
    res = es.search(index="siem-incidents", size=1)
    if res['hits']['total']['value'] == 0:
        print("[WARN] No incidents found in 'siem-incidents'. Cannot test memory retrieval.")
        return

    existing_incident = res['hits']['hits'][0]['_source']
    title = existing_incident['incident']['title']
    print(f"Existing Incident Title: {title}")
    
    # Now use Memory to search for it
    memory = IncidentMemory()
    # We construct a dummy new incident with similar title
    new_incident_doc = {
        "incident": {"title": title, "id": "new-test-id"},
        "rule": existing_incident.get("rule", {}),
        "correlation": existing_incident.get("correlation", {})
    }
    
    history = memory.search_similar(new_incident_doc)
    print(f"Memory Search Result Count: {len(history)}")
    
    if len(history) > 0:
        print("[PASS] Incident Memory retrieved similar incidents.")
        print(f"Top Match: {history[0]['title']} (Score: {history[0]['score']})")
    else:
        print("[FAIL] Incident Memory found nothing (unexpected if we just searched using existing title).")

if __name__ == "__main__":
    verify_memory_and_scoring()
