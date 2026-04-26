"""
Adaptive Firewall Engine
"""

import time


class AdaptiveFirewall:

    def __init__(self, logger, rule_manager, threat_detector, ml_detector, config):
        self.logger = logger
        self.rule_manager = rule_manager
        self.threat_detector = threat_detector
        self.ml_detector = ml_detector
        self.config = config

    # =========================
    # MAIN REQUEST PROCESSOR
    # =========================
    def process_request(self, request):

        decision = {
            'blocked': False,
            'reason': 'No threat detected',
            'details': {}
        }

        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', '')

        # =========================
        # 🔥 CHECK BLOCKED IP (MODIFIED)
        # =========================
        if self.rule_manager.is_ip_blocked(client_ip):

            print("⚠️ BLOCKED IP STILL BEING MONITORED:", client_ip)

            threats = []

            # 🔥 STILL RUN DETECTION
            sqli = self.threat_detector.detect_sql_injection(request)
            if sqli:
                threats.append(('SQL_INJECTION', sqli))

            xss = self.threat_detector.detect_xss(request)
            if xss:
                threats.append(('XSS', xss))

            cmd = self.threat_detector.detect_command_injection(request)
            if cmd:
                threats.append(('COMMAND_INJECTION', cmd))

            path = self.threat_detector.detect_path_traversal(request)
            if path:
                threats.append(('PATH_TRAVERSAL', path))

            bot = self.threat_detector.detect_scanner(user_agent)
            if bot:
                threats.append(('BOT_DETECTED', bot))

            rate = self.threat_detector.check_rate_limit(client_ip)
            if rate:
                threats.append(('RATE_LIMIT', rate))

            idor = self.threat_detector.detect_idor(client_ip, request)
            if idor:
                threats.append(('IDOR', idor))

            ml = self.ml_detector.detect_anomaly(request)
            if ml:
                threats.append(('ML_ANOMALY', ml))

            # 🔥 LOG EVEN IF BLOCKED
            for t, d in threats:
                self.logger.log_threat(client_ip, t, d, request.method, request.path)

            # 🔥 ALSO LOG BLOCK EVENT
            self.logger.log_request(
                client_ip,
                request.method,
                request.path,
                'BLOCKED',
                'IP blocked but monitored'
            )

            decision['blocked'] = True
            decision['reason'] = 'IP blocked but monitored'

            return decision

        # =========================
        # NORMAL DETECTION FLOW
        # =========================
        threats = []

        sqli = self.threat_detector.detect_sql_injection(request)
        if sqli:
            threats.append(('SQL_INJECTION', sqli))

        xss = self.threat_detector.detect_xss(request)
        if xss:
            threats.append(('XSS', xss))

        cmd = self.threat_detector.detect_command_injection(request)
        if cmd:
            threats.append(('COMMAND_INJECTION', cmd))

        path = self.threat_detector.detect_path_traversal(request)
        if path:
            threats.append(('PATH_TRAVERSAL', path))

        bot = self.threat_detector.detect_scanner(user_agent)
        if bot:
            threats.append(('BOT_DETECTED', bot))

        rate = self.threat_detector.check_rate_limit(client_ip)
        if rate:
            threats.append(('RATE_LIMIT', rate))

        idor = self.threat_detector.detect_idor(client_ip, request)
        if idor:
            threats.append(('IDOR', idor))

        ml = self.ml_detector.detect_anomaly(request)
        if ml:
            threats.append(('ML_ANOMALY', ml))

        # =========================
        # IF THREATS FOUND
        # =========================
        if threats:

            for t, d in threats:
                self.logger.log_threat(client_ip, t, d, request.method, request.path)

            self.rule_manager.add_blocked_ip(
                client_ip,
                duration=self.config['BLOCK_DURATION'],
                reason="Threat detected"
            )

            self.logger.log_request(
                client_ip,
                request.method,
                request.path,
                'BLOCKED',
                f'{len(threats)} threat(s) detected'
            )

            decision['blocked'] = True
            decision['reason'] = f'{len(threats)} threat(s) detected'

            return decision

        # =========================
        # ALLOWED REQUEST
        # =========================
        self.logger.log_request(
            client_ip,
            request.method,
            request.path,
            'ALLOWED',
            'No threat detected'
        )

        return decision

    # =========================
    # GET CLIENT IP
    # =========================
    def _get_client_ip(self, request):
       forwarded = request.headers.get("X-Forwarded-For")
       real_ip = request.headers.get("X-Real-IP")

       if forwarded:
        return forwarded.split(",")[0].strip()

       if real_ip:
        return real_ip.strip()

       return request.environ.get("REMOTE_ADDR", "unknown")