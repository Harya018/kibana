import requests
import json

KIBANA_URL = "http://localhost:5601"

def create_data_view(title, pattern, time_field="@timestamp"):
    url = f"{KIBANA_URL}/api/data_views/data_view"
    headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json"
    }
    # API Endpoint for 8.x
    url = f"{KIBANA_URL}/api/data_views/data_view"
    
    # Payload
    payload = {
        "data_view": {
             "title": pattern,
             "name": title,
             "timeFieldName": time_field
        }
    }
    
    print(f"Creating Data View '{title}' for pattern '{pattern}'...")

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            print(f"[SUCCESS] Created Data View: {title}")
            return True
        elif response.status_code == 409:
            print(f"[INFO] Data View '{title}' already exists.")
            return True
        else:
            print(f"[ERROR] Failed to create {title}: {response.text}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

def setup():
    print("Setting up Kibana Data Views...")
    
    # 1. SIEM Logs
    create_data_view("SIEM Logs", "logs-*")
    
    # 2. Incidents
    create_data_view("SIEM Incidents", "siem-incidents")

if __name__ == "__main__":
    setup()
