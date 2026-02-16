from django.conf import settings
from elasticsearch import Elasticsearch
import json
import time

def verify():
    es = Elasticsearch(
        hosts=settings.ELASTICSEARCH_HOSTS,
        api_key=settings.ELASTICSEARCH_API_KEY, 
        verify_certs=False
    )
    
    # Wait a moment for indexing
    time.sleep(2)
    
    print("Verifying UEBA Anomalies in ES...")
    
    query = {
        "bool": {
            "must": [
                {"match": {"event.type": "behavioral_anomaly"}}
            ]
        }
    }
    
    res = es.search(index="logs-*", query=query, size=5)
    hits = res['hits']['total']['value']
    
    if hits > 0:
        print(f"[PASS] Found {hits} behavioral anomalies.")
        for hit in res['hits']['hits']:
            source = hit['_source']
            user = source.get('user', {}).get('name')
            reason = source.get('risk', {}).get('reason')
            score = source.get('risk', {}).get('score')
            print(f" - User: {user} | Score: {score} | Reason: {reason}")
    else:
        print(f"[FAIL] No behavioral anomalies found.")
        
        # Debug: Check if any logs were ingested at all
        print("Debugging: showing last 3 logs...")
        debug_res = es.search(index="logs-*", size=3, sort=[{"@timestamp": "desc"}])
        for hit in debug_res['hits']['hits']:
            print(json.dumps(hit['_source'], indent=2))
            
        # Debug: Check profile
        print("\nChecking 'siem-profiles' index...")
        try:
            profile_res = es.search(index="siem-profiles", size=1)
            print(f"Found {profile_res['hits']['total']['value']} profiles.")
            if profile_res['hits']['total']['value'] > 0:
                print(json.dumps(profile_res['hits']['hits'][0]['_source'], indent=2))
        except Exception as e:
            print(f"Could not query profiles: {e}")

if __name__ == "__main__":
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
    django.setup()
    verify()
