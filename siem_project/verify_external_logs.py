from django.conf import settings
from elasticsearch import Elasticsearch
import json

def verify():
    es = Elasticsearch(
        hosts=settings.ELASTICSEARCH_HOSTS,
        api_key=settings.ELASTICSEARCH_API_KEY, 
        verify_certs=False
    )
    
    categories = ["network", "process", "host"]
    
    print("Verifying External Logs in ES...")
    
    for cat in categories:
        query = {
            "bool": {
                "must": [
                    {"match": {"event.category": cat}}
                ]
            }
        }
        res = es.search(index="logs-*", query=query, size=1)
        if res['hits']['total']['value'] > 0:
            print(f"[PASS] Found logs for category: {cat}")
            print(json.dumps(res['hits']['hits'][0]['_source'], indent=2))
        else:
            print(f"[FAIL] No logs found for category: {cat}")

if __name__ == "__main__":
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
    django.setup()
    verify()
