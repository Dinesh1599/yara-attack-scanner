import json
from pathlib import Path
from typing import Dict, Any, Optional
from config import ATTACK_MAPPING_DIR

class AttackMapper:
    """
    Maps YARA rule matches to MITRE ATT&CK techniques and generates Navigator layers.
    """
    
    def __init__(self):
        self.techniques = self._load_techniques()
    
    def _load_techniques(self) -> Dict[str, Dict[str, Any]]:
        """
        Loads MITRE ATT&CK techniques from JSON mapping files.
        Returns: { "T1059": {"name": "Command-Line Interface", ...}, ... }
        """
        techniques = {}
        try:
            for mapping_file in Path(ATTACK_MAPPING_DIR).glob("*.json"):
                with open(mapping_file) as f:
                    data = json.load(f)
                    for tech in data.get("techniques", []):
                        # Handle both "techniqueID" and "technique_id" for robustness
                        tech_id = tech.get("techniqueID") or tech.get("technique_id")
                        if not tech_id:
                            continue
                            
                        techniques[tech_id] = {
                            "name": self._get_technique_name(tech),
                            "tactic": tech.get("tactic", ""),
                            "metadata": tech.get("metadata", [])
                        }
        except Exception as e:
            print(f"[!] Error loading ATT&CK mappings: {str(e)}")
        return techniques

    def _get_technique_name(self, technique_data: Dict) -> str:
        """Extracts human-readable technique name from mapping data"""
        if "name" in technique_data:
            return technique_data["name"]
        return technique_data.get("comment", "").split("Detected by")[0].strip()

    def map_to_technique(self, yara_meta: Dict) -> Optional[Dict[str, Any]]:
        """
        Maps YARA rule metadata to MITRE ATT&CK technique.
        Args:
            yara_meta: {"mitre_attack_id": "T1059", "severity": "high", ...}
        Returns:
            {"id": "T1059", "name": "Command-Line Interface", ...} or None
        """
        technique_id = yara_meta.get("mitre_attack_id")
        if not technique_id:
            return None
            
        tech_data = self.techniques.get(technique_id, {})
        return {
            "id": technique_id,
            "name": tech_data.get("name", "Unknown"),
            "tactic": tech_data.get("tactic", ""),
            "severity": yara_meta.get("severity", "medium"),
            "reference": yara_meta.get("reference", "")
        }

    def generate_attack_layer(self, detections: list) -> Dict[str, Any]:
        """
        Generates MITRE ATT&CK Navigator layer JSON from detections.
        Args:
            detections: List of {"technique_id": "T1059", "severity": "high"}
        Returns:
            ATT&CK Navigator layer JSON
        """
        techniques = []
        severity_colors = {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffcc00",
            "low": "#00ff00"
        }
        
        for detection in detections:
            tech_id = detection.get("technique_id")
            if tech_id in self.techniques:
                techniques.append({
                    "techniqueID": tech_id,
                    "color": severity_colors.get(detection.get("severity", "medium"), "#cccccc"),
                    "comment": f"Detected by: {detection.get('rule_name', 'unknown')}",
                    "enabled": True
                })
        
        return {
            "name": "YARA Detection Coverage",
            "versions": {
                "attack": "14",
                "navigator": "4.8.2",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": "ATT&CK techniques detected by YARA rules",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff0000"],
                "minValue": 0,
                "maxValue": 100
            }
        }

if __name__ == "__main__":
    mapper = AttackMapper()
    
    # Test mapping
    yara_meta = {
        "mitre_attack_id": "T1059",
        "severity": "high",
        "reference": "https://attack.mitre.org/techniques/T1059/"
    }
    print("Technique Mapping:", mapper.map_to_technique(yara_meta))
    
    # Test layer generation
    test_detections = [
        {"technique_id": "T1059", "severity": "high", "rule_name": "PowerShell_Attack"},
        {"technique_id": "T1190", "severity": "critical", "rule_name": "Log4Shell_Exploit"}
    ]
    print("Navigator Layer:", json.dumps(mapper.generate_attack_layer(test_detections), indent=2))