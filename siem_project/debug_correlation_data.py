from django.conf import settings
from elasticsearch import Elasticsearch
import json

def check_failed_logins():
    es = Elasticsearch(
        hosts=settings.ELASTICSEARCH_HOSTS,
        api_key=settings.ELASTICSEARCH_API_KEY, 
        verify_certs=False
    )
    
    # 1. Search for recent failed logins
    print("Searching for recent failed logins...")
    query = {
        "bool": {
            "must": [
                {"match": {"event.action": "login_attempt"}},
                {"match": {"event.outcome": "failure"}}
            ]
        }
    }
    
    res = es.search(index="logs-*", query=query, size=10, sort=[{"@timestamp": "desc"}])
    hits = res['hits']['hits']
    
    print(f"Found {len(hits)} failed login logs.")
    
    if len(hits) > 0:
        print("Sample Log:")
        print(json.dumps(hits[0]['_source'], indent=2))
        
        # Check aggregations manually
        print("\nChecking aggregation pattern...")
        agg_query = {
            "bool": {
                "must": [
                    {"match": {"event.action": "login_attempt"}},
                    {"match": {"event.outcome": "failure"}}
                ]
            }
        }
        aggs = {
            "by_ip": {
                "terms": {"field": "source.ip", "min_doc_count": 1} # Lowered to 1 to see counts
            }
        }
        res = es.search(index="logs-*", query=agg_query, aggs=aggs, size=0)
        print("Aggregation Results:")
        print(json.dumps(res['aggregations'], indent=2))
    else:
        print("No failed logins found in ES! Ingestion might be failing.")

if __name__ == "__main__":
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
    django.setup()
    check_failed_logins()
