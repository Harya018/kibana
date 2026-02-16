from django.conf import settings
from elasticsearch import Elasticsearch

def check_es():
    print(f"Connecting to ES at: {settings.ELASTICSEARCH_HOSTS}")
    try:
        es = Elasticsearch(
            hosts=settings.ELASTICSEARCH_HOSTS,
            api_key=settings.ELASTICSEARCH_API_KEY, 
            verify_certs=False
        )
        
        if es.ping():
            print("Successfully connected to Elasticsearch!")
            print(f"Cluster Info: {es.info()['version']['number']}")
            
            indices = list(es.indices.get_alias(index="*").keys())
            print("\n----- EXISTING INDICES -----")
            for idx in indices:
                count = es.count(index=idx)['count']
                print(f"- {idx} (Docs: {count})")
            print("----------------------------")
        else:
            print("Failed to ping Elasticsearch.")
            
    except Exception as e:
        print(f"Connection Error: {e}")

if __name__ == "__main__":
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_project.settings')
    django.setup()
    check_es()
