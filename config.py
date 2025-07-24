import os
import platform

# Directory configurations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_DIR = os.path.join(BASE_DIR, 'yara_rules')
ATTACK_MAPPING_DIR = os.path.join(BASE_DIR, 'attack_mapping')

# OS-specific scan targets
if platform.system() == 'Windows':
    REALTIME_SCAN_TARGETS = [
        os.environ.get('TEMP', 'C:\\Windows\\Temp'),
        os.path.expanduser('~\\Downloads'),
        os.path.expanduser('~\\AppData\\Local\\Temp'),
        'C:\\Windows\\System32\\Tasks'  # Scheduled tasks location
    ]
else:  # Linux/macOS
    REALTIME_SCAN_TARGETS = [
        '/tmp',
        '/var/tmp',
        os.path.expanduser('~/Downloads'),
        os.path.expanduser('~/.local/bin'),
        '/etc/cron.d'  # Cron jobs location
    ]

# Log file location
LOG_FILE = os.path.join(BASE_DIR, 'scan_logs.jsonl')

# Print configuration for debugging
print(f"[*] Running on: {platform.system()}")
print("[*] Monitoring targets:")
for target in REALTIME_SCAN_TARGETS:
    print(f"    - {target}")