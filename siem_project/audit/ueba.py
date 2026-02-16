import logging
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from django.conf import settings

logger = logging.getLogger(__name__)

class UEBAEngine:
    """
    User and Entity Behavior Analytics Engine.
    Tracks user profiles, baselines, and detects behavioral anomalies.
    """
    
    def __init__(self, es_client=None):
        self.es = es_client or Elasticsearch(
            hosts=settings.ELASTICSEARCH_HOSTS,
            api_key=settings.ELASTICSEARCH_API_KEY,
            verify_certs=False
        )
        self.profile_index = "siem-profiles"
        self._ensure_index()

    def _ensure_index(self):
        """Ensures the profile index exists."""
        if not self.es.indices.exists(index=self.profile_index):
            self.es.indices.create(index=self.profile_index, body={
                "mappings": {
                    "properties": {
                        "user_id": {"type": "keyword"},
                        "last_seen": {"type": "date"},
                        "behavior": {
                            "properties": {
                                "login_ips": {"type": "keyword"},
                                "login_hours": {"type": "integer"}, # 0-23
                                "typical_locations": {"type": "keyword"}
                            }
                        }
                    }
                }
            })

    def analyze_behavior(self, event_doc):
        """
        Main entry point. Analyzes an event against the user's profile.
        Returns (is_anomaly, risk_score_boost, reason).
        """
        category = event_doc.get("event", {}).get("category")
        action = event_doc.get("event", {}).get("action")
        
        if category == "authentication" and action == "login_attempt":
            return self._analyze_login(event_doc)
            
        return False, 0.0, None

    def _analyze_login(self, doc):
        username = doc.get("user", {}).get("name")
        if not username:
            return False, 0.0, None

        # Fetch Profile
        profile = self._get_profile(username)
        
        # New behavior features
        current_ip = doc.get("source", {}).get("ip")
        current_hour = datetime.fromisoformat(doc["@timestamp"]).hour
        
        # Anomaly Checks
        anomalies = []
        risk_boost = 0.0
        
        # 1. New IP Check
        if profile and current_ip and current_ip not in profile.get("behavior", {}).get("login_ips", []):
            anomalies.append(f"Login from new IP: {current_ip}")
            risk_boost += 15.0
            
        # 2. Unusual Time Check
        known_hours = profile.get("behavior", {}).get("login_hours", [])
        if profile and known_hours and current_hour not in known_hours:
            # Simple check: if we have history and this hour is new
            # Relaxed check: if we have enough data (len > 5) and it's missing
            if len(known_hours) > 5: 
                anomalies.append(f"Login at unusual hour: {current_hour}:00")
                risk_boost += 10.0

        # Update Profile (Self-learning)
        self._update_profile_login(username, current_ip, current_hour)
        
        if anomalies:
            return True, risk_boost, "; ".join(anomalies)
            
        return False, 0.0, None

    def _get_profile(self, username):
        try:
            res = self.es.get(index=self.profile_index, id=username)
            return res['_source']
        except Exception:
            return None

    def _update_profile_login(self, username, ip, hour):
        """Updates the user profile with new observed data."""
        script = {
            "source": """
                if (ctx._source.behavior == null) { ctx._source.behavior = [:]; }
                
                // Add IP if not exists
                if (params.ip != null) {
                    if (ctx._source.behavior.login_ips == null) { ctx._source.behavior.login_ips = []; }
                    if (!ctx._source.behavior.login_ips.contains(params.ip)) { ctx._source.behavior.login_ips.add(params.ip); }
                }
                
                // Add Hour if not exists
                if (params.hour != null) {
                    if (ctx._source.behavior.login_hours == null) { ctx._source.behavior.login_hours = []; }
                    if (!ctx._source.behavior.login_hours.contains(params.hour)) { ctx._source.behavior.login_hours.add(params.hour); }
                }
                
                ctx._source.last_seen = params.now;
            """,
            "params": {
                "ip": ip,
                "hour": hour,
                "now": datetime.now(timezone.utc).isoformat()
            }
        }
        
        try:
            self.es.update(
                index=self.profile_index,
                id=username,
                body={"script": script, "upsert": {
                    "user_id": username,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "behavior": {
                        "login_ips": [ip] if ip else [],
                        "login_hours": [hour] if hour is not None else []
                    }
                }}
            )
        except Exception as e:
            logger.error(f"Failed to update profile for {username}: {e}")
