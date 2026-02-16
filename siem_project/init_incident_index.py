from django.conf import settings
from elasticsearch import Elasticsearch
from datetime import datetime, timezone

def create_dummy_incident():
    print("Connecting to ES...")
    es = Elasticsearch(
        hosts=settings.ELASTICSEARCH_HOSTS,
        api_key=settings.ELASTICSEARCH_API_KEY, 
        verify_certs=False
    )
    
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "incident",
        "incident": {
            "id": "dummy-init-001",
            "title": "Initialization Incident",
            "severity": "low",
            "status": "closed",
            "risk_score": 0,
            "playbook": "System Initialization check."
        },
        "rule": {
            "name": "system_init"
        },
        "message": "This incident was created to initialize the siem-incidents index."
    }
    
    try:
        res = es.index(index="siem-incidents", document=doc)
        print(f"Index 'siem-incidents' initialized: {res['result']}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
    django.setup()
    create_dummy_incident()
