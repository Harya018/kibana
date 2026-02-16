import logging
from elasticsearch import Elasticsearch
from django.conf import settings

logger = logging.getLogger(__name__)

class IncidentMemory:
    """
    Retrieves historical context from past resolved incidents.
    """
    
    def __init__(self):
        self.es = Elasticsearch(
            hosts=settings.ELASTICSEARCH_HOSTS,
            api_key=settings.ELASTICSEARCH_API_KEY,
            verify_certs=False
        )
        self.index = "siem-incidents"
        
    def search_similar(self, incident_doc, limit=3):
        """
        Finds past incidents similar to the current one.
        Matches on: Rule Name, MITRE Tactic, and Title (Fuzzy).
        """
        rule_name = incident_doc.get("rule", {}).get("name")
        mitre_tactic = incident_doc.get("correlation", {}).get("mitre", {}).get("tactic")
        title = incident_doc.get("incident", {}).get("title")
        
        # Build Query
        should_clauses = [
            {"match": {"rule.name": {"query": rule_name, "boost": 2.0}}},
            {"match": {"incident.title": {"query": title, "fuzziness": "AUTO"}}}
        ]
        
        if mitre_tactic:
             should_clauses.append({"match": {"correlation.mitre.tactic": mitre_tactic}})
             
        query = {
            "bool": {
                "must_not": [
                    {"match": {"incident.id": incident_doc.get("incident", {}).get("id")}} # Exclude self
                ],
                "should": should_clauses,
                "minimum_should_match": 1
            }
        }
        
        try:
            res = self.es.search(index=self.index, query=query, size=limit)
            hits = res['hits']['hits']
            
            history = []
            for hit in hits:
                s = hit['_source']
                history.append({
                    "id": s.get("incident", {}).get("id"),
                    "title": s.get("incident", {}).get("title"),
                    "date": s.get("@timestamp"),
                    "score": hit['_score']
                })
                
            return history
            
        except Exception as e:
            logger.error(f"Failed to search incident memory: {e}")
            return []
