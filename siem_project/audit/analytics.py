import logging
import statistics
from datetime import datetime, timedelta
from django.conf import settings
from elasticsearch import Elasticsearch

# Reuse ES client configuration
es = Elasticsearch(
    hosts=settings.ELASTICSEARCH_HOSTS,
    api_key=settings.ELASTICSEARCH_API_KEY,
    verify_certs=False
)

logger = logging.getLogger(__name__)

class UEBAEngine:
    """
    User and Entity Behavior Analytics Engine.
    Calculates baselines from historical data in Elasticsearch.
    """

    @staticmethod
    def get_user_login_baseline(username, days=30):
        """
        Calculates the average and std_dev of successful logins per day for a user.
        """
        # Search for past N days
        now = datetime.now()
        start_date = now - timedelta(days=days)
        
        query = {
            "bool": {
                "must": [
                    {"match": {"user.name": username}},
                    {"match": {"event.action": "login_attempt"}},
                    {"match": {"event.outcome": "success"}},
                    {"range": {"@timestamp": {"gte": start_date.isoformat()}}}
                ]
            }
        }
        
        # Aggregate by day
        aggs = {
            "logins_per_day": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "day"
                }
            }
        }
        
        try:
            response = es.search(index="logs-*", query=query, aggs=aggs, size=0)
            buckets = response['aggregations']['logins_per_day']['buckets']
            
            counts = [b['doc_count'] for b in buckets if b['doc_count'] > 0]
            
            if not counts:
                return {"mean": 0, "std_dev": 0, "count": 0}
            
            mean = statistics.mean(counts)
            std_dev = statistics.stdev(counts) if len(counts) > 1 else 0
            
            return {"mean": mean, "std_dev": std_dev, "count": len(counts)}
            
        except Exception as e:
            logger.error(f"Error calculating baseline for {username}: {e}")
            return None

    @staticmethod
    def get_transaction_amount_baseline(account_number, days=90):
        """
        Calculates avg transaction amount for an account.
        """
        now = datetime.now()
        start_date = now - timedelta(days=days)

        query = {
            "bool": {
                "must": [
                    {"match": {"transaction.id": account_number}},
                    {"match": {"event.action": "transaction"}},
                    {"range": {"@timestamp": {"gte": start_date.isoformat()}}}
                ]
            }
        }
        
        aggs = {
            "avg_amount": {"avg": {"field": "transaction.amount"}},
            "std_dev_amount": {"extended_stats": {"field": "transaction.amount"}}
        }

        try:
            # We need to target the correct index pattern
            response = es.search(index="logs-*", query=query, aggs=aggs, size=0)
            stats = response['aggregations']['std_dev_amount']
            
            return {
                "mean": stats['avg'],
                "std_dev": stats['std_deviation'],
                "count": stats['count']
            }
        except Exception as e:
            logger.error(f"Error calculating tx baseline for {account_number}: {e}")
            return None


class AnomalyDetector:
    """
    Detects anomalies based on baselines.
    """
    
    @staticmethod
    def detect_login_anomaly(username, current_count):
        baseline = UEBAEngine.get_user_login_baseline(username)
        if not baseline or baseline['count'] < 5:
             # Not enough data to call it an anomaly
            return False, 0.0

        mean = baseline['mean']
        std_dev = baseline['std_dev']
        
        # Z-Score
        if std_dev == 0:
            return False, 0.0 # Standard deviation is zero, can't calculate Z-score
        
        z_score = (current_count - mean) / std_dev
            
        # Threshold: Z-score > 3 (3 sigma event)
        is_anomaly = abs(z_score) > 3
        return is_anomaly, z_score

    @staticmethod
    def detect_transaction_anomaly(account_number, amount):
        baseline = UEBAEngine.get_transaction_amount_baseline(account_number)
        if not baseline or baseline['count'] < 5:
            return False, 0.0
            
        mean = baseline['mean']
        std_dev = baseline['std_dev']
        
        if std_dev == 0:
            return False, 0.0
            
        z_score = (amount - mean) / std_dev
        
        # High amount anomaly
        is_anomaly = z_score > 3
        return is_anomaly, z_score


class RiskScorer:
    """
    Calculates dynamic risk scores for events.
    """
    
    BASE_SCORES = {
        "login_attempt": 5,
        "transaction": 0,
        "file_access": 2
    }
    
    SEVERITY_MULTIPLIER = {
        "low": 1.0,
        "medium": 2.0,
        "high": 5.0,
        "critical": 10.0
    }
    
    @staticmethod
    def calculate_risk(event_doc):
        """
        Calculate risk score 0-100.
        """
        action = event_doc.get("event", {}).get("action", "unknown")
        severity = event_doc.get("event", {}).get("severity", "low").lower() # Assuming mapped to string
        
        base = RiskScorer.BASE_SCORES.get(action, 1)
        multiplier = RiskScorer.SEVERITY_MULTIPLIER.get(severity, 1.0)
        
        # Check explicit risk from normalization
        existing_risk = event_doc.get("risk", {}).get("score", 0)
        if existing_risk > 0:
            return existing_risk
            
        score = base * multiplier
        
        # Cap at 100
        return min(score, 100.0)
