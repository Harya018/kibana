import requests
import json
import uuid

KIBANA_URL = "http://localhost:5601"

def create_index_pattern(title, pattern, time_field="@timestamp"):
    # Using Saved Objects API instead of Data View API
    url = f"{KIBANA_URL}/api/saved_objects/index-pattern/{title.lower().replace(' ', '-')}"
    
    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json"
    }
    
    payload = {
        "attributes": {
            "title": pattern,
            "timeFieldName": time_field
        }
    }
    
    print(f"Creating Index Pattern '{title}' for pattern '{pattern}'...")

    try:
        # Try creating it
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            print(f"[SUCCESS] Created Index Pattern: {title}")
            return True
        elif response.status_code == 409:
             print(f"[INFO] Index Pattern '{title}' already exists.")
             return True
        else:
            print(f"[ERROR] Failed to create {title}: {response.text}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

def setup():
    print("Setting up Kibana Saved Objects...")
    
    # 1. SIEM Logs
    create_index_pattern("siem-logs", "logs-*")
    
    # 2. Incidents
    create_index_pattern("siem-incidents", "siem-*") # Matching siem-* to catch siem-incidents

if __name__ == "__main__":
    setup()
