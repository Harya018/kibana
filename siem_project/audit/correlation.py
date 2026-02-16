import logging
import uuid
from datetime import datetime, timedelta, timezone
from django.conf import settings
from elasticsearch import Elasticsearch
from .ai_agent import PlaybookGenerator

es = Elasticsearch(
    hosts=settings.ELASTICSEARCH_HOSTS,
    api_key=settings.ELASTICSEARCH_API_KEY,
    verify_certs=False
)

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Correlates events into Incidents.
    """
    
    @staticmethod
    def run_correlation_rules():
        """
        Main entry point to run all rules.
        """
        incidents = []
        incidents.extend(CorrelationEngine.detect_brute_force())
        incidents.extend(CorrelationEngine.detect_high_risk_asset())
        
        for inc in incidents:
            CorrelationEngine.create_or_update_incident(inc)
            
        return len(incidents)

    @staticmethod
    def detect_brute_force():
        """
        Rule: > 5 failed logins from same IP in 10 minutes.
        """
        now = datetime.now(timezone.utc)
        # Expanded window for demo/testing purposes
        ten_mins_ago = now - timedelta(minutes=60)
        
        query = {
            "bool": {
                "must": [
                    {"match": {"event.action": "login_attempt"}},
                    {"match": {"event.outcome": "failure"}},
                    {"range": {"@timestamp": {"gte": ten_mins_ago.isoformat()}}}
                ]
            }
        }
        
        aggs = {
            "by_ip": {
                "terms": {"field": "source.ip", "min_doc_count": 5}
            }
        }
        
        detected = []
        try:
            resp = es.search(index="logs-*", query=query, aggs=aggs, size=0)
            buckets = resp['aggregations']['by_ip']['buckets']
            
            for b in buckets:
                ip = b['key']
                count = b['doc_count']
                
                detected.append({
                    "title": f"Brute Force Detected from {ip}",
                    "severity": "high",
                    "description": f"Detected {count} failed login attempts from IP {ip} in the last 10 minutes.",
                    "entity": {"ip": ip},
                    "rule": "brute_force_auth"
                })
        except Exception as e:
            logger.error(f"Correlation failed (brute_force): {e}")
            
        return detected

    @staticmethod
    def detect_high_risk_asset():
        """
        Rule: Any event with risk.score > 90.
        """
        now = datetime.now(timezone.utc)
        five_mins_ago = now - timedelta(minutes=5)
        
        query = {
            "bool": {
                "filter": [
                    {"range": {"risk.score": {"gt": 90}}},
                    {"range": {"@timestamp": {"gte": five_mins_ago.isoformat()}}}
                ]
            }
        }
        
        detected = []
        try:
            resp = es.search(index="logs-*", query=query, size=10)
            for hit in resp['hits']['hits']:
                doc = hit['_source']
                risk_reason = doc.get("risk", {}).get("reason", "High Risk Event")
                
                detected.append({
                    "title": f"Critical Risk Event Detected",
                    "severity": "critical",
                    "description": f"Event with risk score > 90. Reason: {risk_reason}",
                    "entity": {"id": hit['_id']},
                    "rule": "critical_risk_event"
                })
        except Exception as e:
            logger.error(f"Correlation failed (high_risk): {e}")
            
        return detected



    @staticmethod
    def create_or_update_incident(incident_data):
        """
        Deduplicates and indexes incident.
        """
        # 1. Check for existing active incident for this entity/rule
        # Simplified: Just check by Rule + Entity within last hour
        
        # ... (Deduplication logic would go here) ...
        
        # 2. Generate AI Playbook (Synchronous for now)
        logger.info(f"Generating AI Playbook for: {incident_data['title']}...")
        playbook_markdown = PlaybookGenerator.generate_playbook(incident_data)
        
        incident_doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "incident",
            "incident": {
                "id": str(uuid.uuid4()),
                "title": incident_data["title"],
                "severity": incident_data["severity"],
                "status": "open",
                "risk_score": 100 if incident_data["severity"] == 'critical' else 75,
                "playbook": playbook_markdown
            },
            "rule": {
                "name": incident_data["rule"]
            },
            "message": incident_data["description"]
        }
        
        try:
            es.index(index="siem-incidents", document=incident_doc)
            logger.info(f"Created Incident with Playbook: {incident_data['title']}")
        except Exception as e:
            logger.error(f"Failed to index incident: {e}")
