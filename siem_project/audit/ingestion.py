import json
import logging
from datetime import datetime, timezone
from django.conf import settings
from elasticsearch import Elasticsearch

# Initialize ES Client
es_client = Elasticsearch(
    hosts=settings.ELASTICSEARCH_HOSTS,
    api_key=settings.ELASTICSEARCH_API_KEY,
    verify_certs=False
)

logger = logging.getLogger(__name__)

class NormalizationPipeline:
    """
    Standardizes raw logs into Elastic Common Schema (ECS) format.
    """
    
    @staticmethod
    def normalize(raw_data, source_type):
        """
        Main entry point for normalization.
        :param raw_data: Dictionary containing raw log data.
        :param source_type: String identifier for the source (e.g., 'django_auth', 'transaction', 'syslog').
        :return: ECS-compliant dictionary.
        """
        # Base ECS Structure
        ecs_doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {
                "kind": "event",
                "category": "host", # Default, overridden below
                "type": "info",
                "action": "log",
                "ingested": datetime.now(timezone.utc).isoformat()
            },
            "validation": {
                "source": source_type
            },
            "host": {
                "name": "siem-server" # In a real agent, this would be dynamic
            },
            "risk": {
                "score": 0.0,
                "level": "low"
            }
        }

        # Source-Specific Normalization
        if source_type == 'django_auth':
            NormalizationPipeline._normalize_auth(ecs_doc, raw_data)
        elif source_type == 'transaction':
            NormalizationPipeline._normalize_transaction(ecs_doc, raw_data)
        elif source_type == 'firewall':
            NormalizationPipeline._normalize_firewall(ecs_doc, raw_data)
        elif source_type == 'edr':
            NormalizationPipeline._normalize_edr(ecs_doc, raw_data)
        elif source_type == 'os':
            NormalizationPipeline._normalize_os_event(ecs_doc, raw_data)
        elif source_type == 'syslog':
            NormalizationPipeline._normalize_syslog(ecs_doc, raw_data)
        else:
            # Fallback for generic/unknown logs
            ecs_doc["message"] = str(raw_data)
            ecs_doc["event"]["category"] = "uncategorized"

        return ecs_doc

    @staticmethod
    def _normalize_firewall(doc, data):
        doc["event"]["category"] = "network"
        doc["event"]["type"] = "connection"
        doc["event"]["action"] = data.get("action", "allow") # allow/deny
        doc["event"]["outcome"] = "success" if data.get("action") == "allow" else "failure"
        
        doc["source"] = {"ip": data.get("src_ip"), "port": data.get("src_port")}
        doc["destination"] = {"ip": data.get("dest_ip"), "port": data.get("dest_port")}
        doc["network"] = {"protocol": data.get("protocol")}
        
    @staticmethod
    def _normalize_edr(doc, data):
        doc["event"]["category"] = "process"
        doc["event"]["type"] = "start"
        doc["event"]["action"] = "process_started"
        
        doc["process"] = {
            "name": data.get("process_name"),
            "pid": data.get("pid"),
            "command_line": data.get("cmd_line"),
            "executable": data.get("file_path")
        }
        user_val = data.get("user")
        if isinstance(user_val, dict):
            doc["user"] = {"name": user_val.get("name")}
        else:
            doc["user"] = {"name": user_val}
        doc["host"] = {"name": data.get("hostname", "unknown-host")}
        
    @staticmethod
    def _normalize_os_event(doc, data):
        doc["event"]["category"] = "host"
        doc["event"]["action"] = data.get("event_type", "system_event")
        doc["message"] = data.get("message")
        doc["host"] = {"name": data.get("hostname")}

    @staticmethod
    def _normalize_auth(doc, data):
        doc["event"]["category"] = "authentication"
        doc["event"]["action"] = "login_attempt"
        
        # User details
        if "username" in data:
            doc["user"] = {"name": data["username"]}
        
        # Network details
        if "ip_address" in data:
            doc["source"] = {"ip": data["ip_address"]}
        
        # Outcome
        if data.get("event_type") == "LOGIN_SUCCESS":
            doc["event"]["outcome"] = "success"
            doc["event"]["type"] = "start"
        elif data.get("event_type") == "LOGIN_FAILED":
            doc["event"]["outcome"] = "failure"
            doc["event"]["type"] = "info"
        elif data.get("event_type") == "LOGOUT":
            doc["event"]["action"] = "logout"
            doc["event"]["type"] = "end"
            doc["event"]["outcome"] = "success"

    @staticmethod
    def _normalize_transaction(doc, data):
        doc["event"]["category"] = "financial"
        doc["event"]["action"] = "transaction"
        
        tx_data = data.get("transaction_data", {})
        
        doc["transaction"] = {
            "id": tx_data.get("account_number"), # Using account as loose ID for now
            "amount": tx_data.get("amount"),
            "currency": "USD", # Default
            "type": tx_data.get("transaction_type")
        }
        
        # Map specific fields to ECS-like extensions or custom fields
        doc["source"] = {"geo": {"city_name": tx_data.get("location")}}
        
        # Risk / Flags
        if tx_data.get("is_flagged"):
            doc["risk"] = {
                "score": 100.0 if tx_data.get("amount", 0) > 10000 else 50.0,
                "level": "high",
                "reason": tx_data.get("flag_reason")
            }
        else:
            doc["risk"] = {"score": 0.0, "level": "low"}


    @staticmethod
    def _normalize_syslog(doc, data):
        doc["event"]["category"] = "system"
        doc["message"] = data.get("message", "")
        doc["process"] = {"name": data.get("process", "unknown")}


from .analytics import AnomalyDetector, RiskScorer
from .ueba import UEBAEngine

# Initialize UEBA Engine (Lazy or Global)
ueba_engine = UEBAEngine()

class LogIngestionService:
    """
    Service to handle ingestion of logs from various sources.
    """
    
    @staticmethod
    def ingest_log(raw_data, source_type):
        """
        Ingests a log entry: Normalizes -> Detects Anomalies -> Scores Risk -> Indexes to ES.
        """
        try:
            # 1. Normalize
            normalized_doc = NormalizationPipeline.normalize(raw_data, source_type)
            
            # 2. Anomaly Detection (Simplified Synchronous Call)
            anomaly_score = 0.0
            is_anomaly = False
            
            category = normalized_doc["event"].get("category")
            action = normalized_doc["event"].get("action")
            
            if category == "authentication" and action == "login_attempt":
                # UEBA Analysis
                is_behavior_anomaly, risk_boost, reason = ueba_engine.analyze_behavior(normalized_doc)
                if is_behavior_anomaly:
                    normalized_doc["event"]["type"] = "behavioral_anomaly"
                    # Safe access to risk field
                    risk_field = normalized_doc.get("risk", {})
                    if not isinstance(risk_field, dict):
                        risk_field = {}
                        
                    existing_reason = risk_field.get("reason", "")
                    new_reason = f"{existing_reason}; {reason}".strip("; ")
                    
                    if "risk" not in normalized_doc or not isinstance(normalized_doc["risk"], dict):
                        normalized_doc["risk"] = {}
                        
                    normalized_doc["risk"]["reason"] = new_reason
                    anomaly_score += risk_boost
                    logger.info(f"UEBA Anomaly Detected: {reason}")
                    
                username = normalized_doc.get("user", {}).get("name")
                if username:
                    # Legacy check (placeholder)
                    pass 

            elif category == "financial" and action == "transaction":
                account = normalized_doc.get("transaction", {}).get("id")
                amount = normalized_doc.get("transaction", {}).get("amount", 0)
                if account:
                    is_anomaly, z_score = AnomalyDetector.detect_transaction_anomaly(account, amount)
                    if is_anomaly:
                        normalized_doc["event"]["type"] = "anomaly"
                        normalized_doc["risk"]["reason"] = f"Transaction amount anomaly (Z-Score: {z_score:.2f})"
                        anomaly_score = 50.0 # High base boost for anomalies

            # 3. Risk Scoring
            # Inject anomaly score boost into the doc context for the scorer if needed, 
            # or just add it to the final result.
            base_risk = RiskScorer.calculate_risk(normalized_doc)
            final_risk = min(base_risk + anomaly_score, 100.0)
            
            normalized_doc["risk"]["score"] = final_risk
            if final_risk > 70:
                normalized_doc["risk"]["level"] = "critical"
            elif final_risk > 40:
                normalized_doc["risk"]["level"] = "high"
            elif final_risk > 20:
                normalized_doc["risk"]["level"] = "medium"
            
            # 2. Determine Index Name (Time-series based or simple)
            # using 'logs-siem-default' which matches our 'logs-*' template
            index_name = "logs-siem-default"
            
            # 3. Index to ES
            response = es_client.index(index=index_name, document=normalized_doc)
            
            return response['result']
        except Exception as e:
            import traceback
            logger.error(f"Failed to ingest log: {e}")
            with open("ingestion_error.log", "a") as f:
                f.write(f"{datetime.now()}: {e}\n{traceback.format_exc()}\n")
            print(f"DEBUG: Ingestion Error: {e}") 
            return "failed"
