import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
django.setup()

from audit.ingestion import LogIngestionService

def test_ingest():
    print("Attempting to ingest test log...")
    
    test_data = {
        'event_type': 'TEST_EVENT',
        'username': 'test_admin',
        'ip_address': '127.0.0.1',
        'message': 'This is a manual test log to verify index creation.'
    }
    
    result = LogIngestionService.ingest_log(test_data, source_type='django_auth')
    print(f"Ingestion Result: {result}")

if __name__ == "__main__":
    test_ingest()
