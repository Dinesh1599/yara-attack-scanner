import yara
import os
import json
import time
from datetime import datetime
from config import YARA_RULES_DIR, REALTIME_SCAN_TARGETS, LOG_FILE

class YaraScanner:
    def __init__(self):
        self.rules = self._compile_rules()
        
    def _compile_rules(self):
        """Compile all YARA rules from the rules directory"""
        try:
            rule_files = [os.path.join(YARA_RULES_DIR, f) 
                         for f in os.listdir(YARA_RULES_DIR) 
                         if f.endswith('.yar')]
            if not rule_files:
                raise ValueError("No YARA rules found in rules directory")
            return yara.compile(filepaths={
                os.path.basename(f).split('.')[0]: f for f in rule_files
            })
        except yara.Error as e:
            print(f"[!] YARA compilation error: {str(e)}")
            raise

    def scan_target(self, target):
        """Scan a single target (file or directory)"""
        if not os.path.exists(target):
            print(f"[!] Target not found: {target}")
            return []

        matches = []
        try:
            if os.path.isfile(target):
                file_matches = self.rules.match(target)
                if file_matches:
                    matches.extend(self._process_matches(file_matches, target))
            elif os.path.isdir(target):
                for root, _, files in os.walk(target):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_matches = self.rules.match(file_path)
                        if file_matches:
                            matches.extend(self._process_matches(file_matches, file_path))
        except Exception as e:
            print(f"[!] Error scanning {target}: {str(e)}")
        return matches
    
    def _process_matches(self, matches, target):
        """Process YARA matches and add metadata"""
        return [{
            'target': target,
            'rule': match.rule,
            'description': match.meta.get('description', ''),
            'severity': match.meta.get('severity', 'medium'),
            'timestamp': datetime.now().isoformat(),
            'mitre_attack_id': match.meta.get('mitre_attack_id', 'N/A')
        } for match in matches]

    def log_results(self, matches):
        """Log scan results to file"""
        if not matches:
            return
            
        with open(LOG_FILE, 'a') as f:
            for match in matches:
                f.write(json.dumps(match) + '\n')
        print(f"[+] Logged {len(matches)} detection(s) to {LOG_FILE}")

    def real_time_scan(self):
        """Continuously monitor default directories"""
        print(f"[+] Starting real-time monitoring of:")
        for target in REALTIME_SCAN_TARGETS:
            print(f"    - {target}")
        
        try:
            while True:
                for target in REALTIME_SCAN_TARGETS:
                    matches = self.scan_target(target)
                    if matches:
                        self.log_results(matches)
                        for match in matches:
                            print(f"[!] Threat detected: {match['rule']} in {match['target']} (Severity: {match['severity']})")
                time.sleep(10)  # Scan interval (10 seconds)
        except KeyboardInterrupt:
            print("\n[!] Real-time monitoring stopped by user")
        except Exception as e:
            print(f"[!] Fatal error in real-time scan: {str(e)}")

if __name__ == "__main__":
    try:
        print("[+] Initializing YARA scanner...")
        scanner = YaraScanner()
        scanner.real_time_scan()
    except Exception as e:
        print(f"[!] Startup failed: {str(e)}")