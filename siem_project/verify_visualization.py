import os
import django
from elasticsearch import Elasticsearch
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
django.setup()

def verify_visualization():
    es = Elasticsearch(
        hosts=settings.ELASTICSEARCH_HOSTS,
        api_key=settings.ELASTICSEARCH_API_KEY,
        verify_certs=False
    )
    
    print("--- Verifying Playbook Visualization ---")
    
    # Get latest incident
    res = es.search(index="siem-incidents", sort=[{"@timestamp": "desc"}], size=1)
    
    if res['hits']['total']['value'] == 0:
        print("[FAIL] No incidents found.")
        return

    incident = res['hits']['hits'][0]['_source']
    title = incident['incident']['title']
    playbook = incident['incident']['playbook']
    
    print(f"Latest Incident: {title}")
    
    if "## Attack Chain Visualization" in playbook:
        print("[PASS] Visualization section found in playbook.")
        if "```mermaid" in playbook:
             print("[PASS] Mermaid code block found.")
             # Print snippet
             start = playbook.find("```mermaid")
             end = playbook.find("```", start + 3)
             print("\nMermaid Snippet:")
             print(playbook[start:end+3])
        else:
             print("[FAIL] Mermaid code block MISSING.")
    else:
        print("[FAIL] Visualization section MISSING.")
        print("Playbook Content Preview:")
        print(playbook)

if __name__ == "__main__":
    verify_visualization()
