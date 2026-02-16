import logging

logger = logging.getLogger(__name__)

class VisualizationService:
    """
    Generates visual representations of incidents.
    """
    
    @staticmethod
    def generate_attack_chain_diagram(incident_doc):
        """
        Generates a Mermaid sequence diagram or flow chart for the attack chain.
        """
        # Parse the description or use raw events if available
        # For now, we'll parse the description which is structured.
        description = incident_doc.get("message", "")
        lines = description.split('\n')
        
        events = []
        for line in lines:
            if ". " in line: # e.g. "1. Initial Access: ..."
                parts = line.split(": ", 1)
                if len(parts) == 2:
                    stage = parts[0].split(". ")[1]
                    detail = parts[1]
                    events.append((stage, detail))
                    
        if not events:
             return ""
             
        # Build Mermaid Diagram
        mermaid = "```mermaid\nsequenceDiagram\n"
        mermaid += "    participant Attacker\n"
        mermaid += "    participant Target\n"
        
        for stage, detail in events:
             mermaid += f"    Attacker->>Target: {stage} ({detail[:30]}...)\n"
             
        mermaid += "```"
        return mermaid
