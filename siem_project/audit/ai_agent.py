import logging
import json
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

class LLMClient:
    """
    Client for local LLM (Ollama).
    """
    OLLAMA_URL = "http://localhost:11434/api/chat"
    MODEL = "llama2" # Or mistral, vicuna

    @staticmethod
    def generate_response(prompt, context=None):
        try:
            payload = {
                "model": LLMClient.MODEL,
                "messages": [
                    {"role": "system", "content": "You are a Senior Security Analyst AI. Your goal is to analyze security incidents and provide actionable response playbooks locally. Do not ask for external data."},
                    {"role": "user", "content": f"Context: {context}\n\nTask: {prompt}"}
                ],
                "stream": False
            }
            
            response = requests.post(LLMClient.OLLAMA_URL, json=payload, timeout=60)
            response.raise_for_status()
            
            return response.json().get("message", {}).get("content", "No response generated.")
            
        except requests.exceptions.ConnectionError:
            logger.error(f"Failed to connect to Local LLM at {LLMClient.OLLAMA_URL}. Ensure Ollama is running.")
            return "Error: Local LLM unavailable."
        except Exception as e:
            logger.error(f"LLM Generation Error: {e}")
            return f"Error generating playbook: {e}"

class PlaybookGenerator:
    """
    Generates IR playbooks for Incidents.
    """
    
    @staticmethod
    def generate_playbook(incident_doc, history=None):
        """
        Generates a markdown playbook for the given incident.
        """
        incident_json = json.dumps(incident_doc, indent=2)
        history_text = ""
        if history:
            history_text = "Similar Past Incidents:\n" + json.dumps(history, indent=2)
        
        try:
            from .visualization import VisualizationService
            diagram = VisualizationService.generate_attack_chain_diagram(incident_doc)
            if diagram:
                diagram_section = f"\n\n## Attack Chain Visualization\n{diagram}\n"
            else:
                diagram_section = ""
        except ImportError:
            diagram_section = ""

        prompt = f"""
        Analyze the following Security Incident and generate a comprehensive Incident Response Playbook in Markdown format.
        
        {history_text}
        
        Include:
        1. **Executive Summary**: What happened? severity?
        2. **Analysis**: Why is this suspicious? (Reference the rules/anomalies)
        3. **Containment Steps**: Immediate actions to stop the threat (e.g., Block IP, Disable User).
        4. **Remediation**: Long-term fixes.
        5. **Investigation Questions**: What should the human analyst check next?
        6. **Historical Context**: Briefly mention if this looks like a recurring issue based on past incidents.
        
        Keep it professional, concise, and actionable.
        """
        
        playbook_content = LLMClient.generate_response(prompt, context=incident_json)
        
        return playbook_content + diagram_section
