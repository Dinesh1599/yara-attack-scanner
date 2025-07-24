#!/usr/bin/env python3
import os
import yara
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
from config import YARA_RULES_DIR, REALTIME_SCAN_TARGETS, LOG_FILE

class YaraScanner:
    def __init__(self):
        self.rules = self._compile_rules()
        self.skip_patterns = [
            '\\Temp\\*.tmp',
            '\\Windows\\Temp\\*',
            '\\$Recycle.Bin\\*'
        ]
    
    def _compile_rules(self):
        """Compile all YARA rules"""
        try:
            rule_files = [f for f in Path(YARA_RULES_DIR).glob('*.yar')]
            return yara.compile(filepaths={f.stem: str(f) for f in rule_files})
        except yara.Error as e:
            print(f"[!] YARA Error: {str(e)}")
            raise

    def should_skip(self, path):
        """Windows-specific file skipping"""
        path = str(path).lower()
        return any(pattern.lower() in path for pattern in self.skip_patterns)

    def scan_file(self, file_path):
        """Scan a single file"""
        try:
            if self.should_skip(file_path):
                return []
            return self.rules.match(str(file_path))
        except Exception as e:
            print(f"[!] Scan error: {file_path} - {str(e)}")
            return []

    def scan_target(self, target):
        """Scan file or directory"""
        target_path = Path(target)
        if not target_path.exists():
            return []
            
        if target_path.is_file():
            return self._process_matches(self.scan_file(target_path), str(target_path))
            
        matches = []
        for item in target_path.glob('*'):
            if item.is_file():
                matches.extend(self._process_matches(self.scan_file(item), str(item)))
        return matches

    def _process_matches(self, matches, target):
        """Format detection results"""
        return [{
            'target': target,
            'rule': match.rule,
            'severity': match.meta.get('severity', 'medium'),
            'timestamp': datetime.now().isoformat()
        } for match in matches]

    def log_results(self, matches):
        """Save detections to log"""
        with open(LOG_FILE, 'a') as f:
            for match in matches:
                f.write(json.dumps(match) + '\n')

    def real_time_scan(self):  # Correct method name (with underscore)
        """Continuous monitoring"""
        print("[+] Starting real-time monitoring...")
        try:
            while True:
                for target in REALTIME_SCAN_TARGETS:
                    self.log_results(self.scan_target(target))
                time.sleep(10)
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['realtime', 'on-demand'], default='realtime')
    parser.add_argument('--target', help="File/directory to scan")
    args = parser.parse_args()

    scanner = YaraScanner()
    
    if args.mode == 'on-demand':
        if not args.target:
            print("[!] Specify target with --target")
            return
            
        matches = scanner.scan_target(args.target)
        print(f"Scanned {args.target}. Found {len(matches)} threats.")
    else:
        scanner.real_time_scan()  # Correct method call

if __name__ == "__main__":
    main()