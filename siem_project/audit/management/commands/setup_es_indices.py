from django.core.management.base import BaseCommand
from django.conf import settings
from elasticsearch import Elasticsearch

class Command(BaseCommand):
    help = 'Setup Elasticsearch Index Templates and Mappings for SIEM'

    def handle(self, *args, **options):
        es = Elasticsearch(
            hosts=settings.ELASTICSEARCH_HOSTS,
            api_key=settings.ELASTICSEARCH_API_KEY,
            verify_certs=False
        )

        # 1. Define ECS-Compliant Mapping for General Logs
        # We use a component template to be reusable
        component_name = "siem-ecs-mappings"
        mapping_body = {
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "category": {"type": "keyword"}, # e.g., authentication, network
                                "type": {"type": "keyword"},     # e.g., start, end, info
                                "action": {"type": "keyword"},   # e.g., login, connection_attempt
                                "severity": {"type": "long"},    # Normalized 0-100
                                "outcome": {"type": "keyword"}   # success, failure
                            }
                        },
                        "source": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "long"},
                                "geo": {"properties": {"location": {"type": "geo_point"}}}
                            }
                        },
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "long"}
                            }
                        },
                        "user": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "id": {"type": "keyword"},
                                "email": {"type": "keyword"}
                            }
                        },
                        "host": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "ip": {"type": "ip"},
                                "os": {"properties": {"name": {"type": "keyword"}}}
                            }
                        },
                        "risk": {
                            "properties": {
                                "score": {"type": "float"}, # 0.0 to 100.0
                                "level": {"type": "keyword"} # low, medium, high, critical
                            }
                        },
                        "siem": {
                            "properties": {
                                "log_source": {"type": "keyword"}, # e.g., firewall-1, app-backend
                                "ingested_at": {"type": "date"}
                            }
                        }
                    }
                }
            }
        }

        self.stdout.write(f"Creating Component Template: {component_name}...")
        try:
            es.cluster.put_component_template(name=component_name, body=mapping_body)
            self.stdout.write(self.style.SUCCESS("Success!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed: {e}"))

        # 2. Create Index Template for 'logs-*' and 'siem-*'
        index_template_name = "siem-logs-template"
        template_body = {
            "index_patterns": ["logs-*", "siem-*"],
            "composed_of": [component_name],
            "priority": 500,
            "_meta": {
                "description": "Template for SIEM logs"
            }
        }

        self.stdout.write(f"Creating Index Template: {index_template_name}...")
        try:
            es.indices.put_index_template(name=index_template_name, body=template_body)
            self.stdout.write(self.style.SUCCESS("Success!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed: {e}"))

        self.stdout.write(self.style.SUCCESS("\nElasticsearch Setup Complete. New indices matching 'logs-*' or 'siem-*' will use ECS mappings."))
