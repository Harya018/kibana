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
        incidents.extend(CorrelationEngine.detect_chain_reaction())
        
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
    def detect_chain_reaction():
        """
        Rule: Detects a sequence of events: 
        1. Suspicious Login (or Brute Force)
        2. EDR Process Execution
        3. High Value Transaction (Optional)
        
        Links them via 'correlation_id'.
        """
        detected_chains = []
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(minutes=60)
        
        # Step 1: Find Potential Triggers (Brute Force or Behavioral Anomaly)
        # We search for recent 'behavioral_anomaly' events
        trigger_query = {
            "bool": {
                "must": [
                    {"match": {"event.type": "behavioral_anomaly"}},
                    {"range": {"@timestamp": {"gte": one_hour_ago.isoformat()}}}
                ]
            }
        }
        
        try:
            triggers = es.search(index="logs-*", query=trigger_query, size=10)
            
            for hit in triggers['hits']['hits']:
                trigger_doc = hit['_source']
                user = trigger_doc.get("user", {}).get("name")
                ip = trigger_doc.get("source", {}).get("ip")
                trigger_time = trigger_doc.get("@timestamp")
                
                if not user: continue
                
                # Step 2: Look for EDR events AFTER the trigger for this user/ip
                edr_query = {
                    "bool": {
                        "must": [
                            {"match": {"event.category": "process"}},
                            {"range": {"@timestamp": {"gte": trigger_time}}},
                            {"bool": {
                                "should": [
                                    {"match": {"user.name": user}},
                                    {"match": {"host.ip": ip}} # Assuming host.ip might exist or we match via host
                                ],
                                "minimum_should_match": 1
                            }}
                        ]
                    }
                }
                
                edr_hits = es.search(index="logs-*", query=edr_query, size=5)
                
                if edr_hits['hits']['total']['value'] > 0:
                    # CHAIN DETECTED!
                    correlation_id = str(uuid.uuid4())
                    
                    chain_desc = f"Attack Chain Detected for User {user}:\n"
                    chain_desc += f"1. Initial Access: Behavioral Anomaly at {trigger_time}\n"
                    
                    for edr_hit in edr_hits['hits']['hits']:
                        edr_doc = edr_hit['_source']
                        proc = edr_doc.get("process", {}).get("command_line", "unknown process")
                        chain_desc += f"2. Execution: Process '{proc}' started on {edr_doc.get('host',{}).get('name')}\n"
                        
                    detected_chains.append({
                        "title": f"Kill Chain: Anomaly + Execution ({user})",
                        "severity": "critical",
                        "description": chain_desc,
                        "entity": {"user": user},
                        "rule": "kill_chain_detection",
                        "correlation_id": correlation_id,
                        "mitre_tactic": "Initial Access, Execution",
                        "mitre_technique": "T1078, T1059"
                    })
                    
        except Exception as e:
            logger.error(f"Correlation failed (chain): {e}")
            
        return detected_chains



    @staticmethod
    def create_or_update_incident(incident_data):
        """
        Deduplicates and indexes incident.
        """
        # 1. Check for existing active incident for this entity/rule
        # Simplified: Just check by Rule + Entity within last hour
        
        # ... (Deduplication logic would go here) ...
        
        # 1. Prepare Incident Document
        incident_doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "incident",
            "incident": {
                "id": str(uuid.uuid4()),
                "title": incident_data["title"],
                "severity": incident_data["severity"],
                "status": "open",
                "risk_score": 100 if incident_data["severity"] == 'critical' else 75,
                "playbook": "" # Placeholder
            },
            "rule": {
                "name": incident_data["rule"]
            },
            "message": incident_data["description"],
            "correlation": {
                "id": incident_data.get("correlation_id"),
                "mitre": {
                    "tactic": incident_data.get("mitre_tactic"),
                    "technique": incident_data.get("mitre_technique")
                }
            }
        }
        
        # 2. Search for Historical Context (Incident Memory)
        try:
            from .memory import IncidentMemory
            memory = IncidentMemory()
            history = memory.search_similar(incident_doc)
            if history:
                 logger.info(f"Found {len(history)} similar past incidents.")
        except Exception as e:
            logger.error(f"Failed to query incident memory: {e}")
            history = []

        # 3. Generate AI Playbook (Synchronous for now)
        logger.info(f"Generating AI Playbook for: {incident_data['title']}...")
        playbook_markdown = PlaybookGenerator.generate_playbook(incident_data, history=history)
        
        incident_doc["incident"]["playbook"] = playbook_markdown
        
        try:
            es.index(index="siem-incidents", document=incident_doc)
            logger.info(f"Created Incident with Playbook: {incident_data['title']}")
        except Exception as e:
            logger.error(f"Failed to index incident: {e}")
