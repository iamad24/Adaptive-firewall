"""
Logging & Audit Module
"""

import json
import os
from datetime import datetime
from collections import Counter


class FirewallLogger:

    def __init__(self):
        self.logs = []
        self.threats = []
        self.request_count = 0
        self.blocked_count = 0

    # =========================
    # REQUEST LOGGING
    # =========================
    def log_request(self, ip, method, path, action, reason):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'method': method,
            'path': path,
            'action': action,
            'reason': reason,
            'type': action,
            'message': reason
        }

        self.logs.append(entry)
        self.request_count += 1

        if action == 'BLOCKED':
            self.blocked_count += 1

        self._save_log(entry)

    # =========================
    # THREAT LOGGING (CRITICAL)
    # =========================
    def log_threat(self, ip, threat_type, threat_data, method, path):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'threat_type': threat_type,   # 🔥 MUST EXIST
            'method': method,
            'path': path,
            'type': threat_type,          # 🔥 UI USES THIS
            'message': f'{threat_type} detected',
            'details': str(threat_data)
        }

        self.threats.append(entry)
        self.logs.append(entry)

        print(f"🔥 THREAT LOGGED: {threat_type}")  # DEBUG

        self._save_log(entry)

    # =========================
    # SAVE LOG
    # =========================
    def _save_log(self, entry):
        os.makedirs('logs', exist_ok=True)

        with open('logs/firewall.log', 'a') as f:
            f.write(json.dumps(entry) + '\n')

    # =========================
    # STATS
    # =========================
    def get_statistics(self):
        return {
            'total_requests': self.request_count,
            'blocked_requests': self.blocked_count,
            'allowed_requests': self.request_count - self.blocked_count,
            'total_threats': len(self.threats)
        }

    # =========================
    # LOG FETCH
    # =========================
    def get_recent_logs(self, limit=100):
        return self.logs[-limit:]

    # =========================
    # 🔥 FIXED THREAT SUMMARY
    # =========================
    def get_threat_summary(self):
        summary = Counter()

        for t in self.threats:
            summary[t['threat_type']] += 1

        print("📊 THREAT SUMMARY:", summary)  # DEBUG

        return dict(summary)

    # =========================
    # TIMELINE
    # =========================
    def get_request_timeline(self):
        timeline = {}

        for log in self.logs:
            if 'timestamp' in log:
                ts = log['timestamp'][:19]

                if ts not in timeline:
                    timeline[ts] = {'allowed': 0, 'blocked': 0}

                if log.get('action') == 'BLOCKED':
                    timeline[ts]['blocked'] += 1
                else:
                    timeline[ts]['allowed'] += 1

        timestamps = list(timeline.keys())
        allowed = [timeline[t]['allowed'] for t in timestamps]
        blocked = [timeline[t]['blocked'] for t in timestamps]

        return {
            'timestamps': timestamps,
            'allowed': allowed,
            'blocked': blocked
        }

    # =========================
    # CLEAR
    # =========================
    def clear_logs(self):
        self.logs = []
        self.threats = []
        self.request_count = 0
        self.blocked_count = 0

        open('logs/firewall.log', 'w').close()