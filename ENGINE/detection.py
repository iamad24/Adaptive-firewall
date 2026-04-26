"""
Threat Detection Engine (FINAL FIXED VERSION)
"""

import time
from collections import defaultdict
from urllib.parse import unquote_plus


class ThreatDetector:

    def __init__(self):
        self.request_history = defaultdict(list)
        self.idor_tracking = defaultdict(set)

    # =========================
    # PAYLOAD EXTRACTION (FIXED)
    # =========================
    def _get_payload(self, request):
        payload = ""

        try:
            if request.query_string:
                payload += unquote_plus(request.query_string.decode())

            if request.data:
                payload += unquote_plus(request.data.decode('utf-8', errors='ignore'))

        except:
            pass

        payload = payload.lower()

        print("🔥 PAYLOAD:", payload)  # DEBUG

        return payload

    # =========================
    # SQL INJECTION
    # =========================
    def detect_sql_injection(self, request):
        payload = self._get_payload(request)

        if (
            "or 1=1" in payload or
            "union select" in payload or
            "drop table" in payload or
            "insert into" in payload or
            "delete from" in payload or
            "--" in payload
        ):
            print("🚨 SQL DETECTED:", payload)
            return {'payload': payload}

        return None

    # =========================
    # XSS
    # =========================
    def detect_xss(self, request):
        payload = self._get_payload(request)

        if (
            "<script>" in payload or
            "alert(" in payload or
            "onerror=" in payload or
            "onload=" in payload
        ):
            print("🚨 XSS DETECTED:", payload)
            return {'payload': payload}

        return None

    # =========================
    # PATH TRAVERSAL
    # =========================
    def detect_path_traversal(self, request):
        payload = self._get_payload(request)

        if "../" in payload or "..\\" in payload or "/etc/passwd" in payload:
            print("🚨 PATH TRAVERSAL:", payload)
            return {'payload': payload}

        return None

    # =========================
    # COMMAND INJECTION
    # =========================
    def detect_command_injection(self, request):
        payload = self._get_payload(request)

        if (
            ";ls" in payload or
            ";cat" in payload or
            "&&" in payload or
            "| bash" in payload or
            "`" in payload
        ):
            print("🚨 COMMAND INJECTION:", payload)
            return {'payload': payload}

        return None

    # =========================
    # BOT DETECTION
    # =========================
    def detect_scanner(self, user_agent):
        suspicious = [
            'sqlmap', 'nikto', 'nmap', 'masscan',
            'metasploit', 'burp', 'zap', 'acunetix'
        ]

        ua = user_agent.lower()

        for s in suspicious:
            if s in ua:
                print("🚨 BOT DETECTED:", ua)
                return {'agent': s}

        return None

    # =========================
    # RATE LIMIT
    # =========================
    def check_rate_limit(self, client_ip):
        now = time.time()
        self.request_history[client_ip] = [
            t for t in self.request_history[client_ip] if now - t < 60
        ]

        self.request_history[client_ip].append(now)

        if len(self.request_history[client_ip]) > 30:
            print("🚨 RATE LIMIT:", client_ip)
            return {'count': len(self.request_history[client_ip])}

        return None

    # =========================
    # IDOR DETECTION
    # =========================
    def detect_idor(self, client_ip, request):
        parts = request.path.split('/')

        for p in parts:
            if p.isdigit():
                now = time.time()
                key = f"{client_ip}:{p}"

                if key not in self.idor_tracking:
                    self.idor_tracking[key] = set()

                self.idor_tracking[key].add((p, now))

                if len(self.idor_tracking[key]) > 5:
                    print("🚨 IDOR:", client_ip)
                    return {'id': p}

        return None