"""
Adaptive Firewall Configuration
Central configuration for all security rules and thresholds
"""

# ============================================================================
# FIREWALL ENABLE/DISABLE
# ============================================================================
FIREWALL_CONFIG = {
    'ENABLE_FIREWALL': True,
    'THREAT_DETECTION_ENABLED': True,
    'ML_DETECTION_ENABLED': True,
    
    # RATE LIMITING
    'RATE_LIMIT_THRESHOLD': 100,
    'RATE_LIMIT_WINDOW': 60,
    'RATE_LIMIT_BLOCK_DURATION': 300,
    
    # REQUEST SIZE & TIMEOUT
    'REQUEST_SIZE_LIMIT': 10 * 1024 * 1024,
    'REQUEST_TIMEOUT': 30,
    
    # BLOCKING POLICIES
    'BLOCK_DURATION': 600,
    'BAN_DURATION': 86400,
    'BLOCK_ATTEMPTS_BEFORE_BAN': 3,
    
    # SQL INJECTION DETECTION
    'SQLI_DETECTION': {
        'enabled': True,
        'patterns': [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(--|#|/\*)",
            r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(\bAND\b\s+\d+\s*=\s*\d+)",
            r"(\'\s*OR\s*\'1\'=\'1)",
            r"(exec\s*\()",
            r"(execute\s*\()",
        ]
    },
    
    # XSS DETECTION
    'XSS_DETECTION': {
        'enabled': True,
        'patterns': [
            r"(<script[^>]*>)",
            r"(javascript:)",
            r"(onerror\s*=)",
            r"(onload\s*=)",
            r"(onclick\s*=)",
            r"(onmouseover\s*=)",
            r"(eval\s*\()",
            r"(expression\s*\()",
            r"(<iframe[^>]*>)",
            r"(<object[^>]*>)",
            r"(<embed[^>]*>)",
            r"(<img[^>]*on)",
            r"(alert\s*\()",
            r"(svg.*on)",
        ]
    },
    
    # PATH TRAVERSAL DETECTION
    'PATH_TRAVERSAL_DETECTION': {
        'enabled': True,
        'patterns': [
            r"(\.\./)",
            r"(\.\.\\)",
            r"(%2e%2e)",
            r"(/etc/passwd)",
            r"(/etc/shadow)",
            r"(c:\\windows)",
            r"(file://)",
            r"(../../../)",
        ]
    },
    
    # COMMAND INJECTION DETECTION
    'COMMAND_INJECTION_DETECTION': {
        'enabled': True,
        'patterns': [
            r"(;\s*(cat|ls|rm|mv|cp|chmod))",
            r"(\|\s*(nc|bash|sh|cmd))",
            r"(&&\s*(whoami|id|uname))",
            r"(`[^`]+`)",
            r"(\$\([^)]+\))",
            r"(>\s*/dev/)",
        ]
    },
    
    # IDOR DETECTION
    'IDOR_DETECTION': {
        'enabled': True,
        'threshold': 5,
        'time_window': 60,
    },
    
    # BOT & SCANNER DETECTION
    'BOT_DETECTION': {
        'enabled': True,
        'suspicious_user_agents': [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit',
            'w3af', 'burp', 'owasp', 'zaproxy', 'acunetix', 'nessus'
        ],
        'request_rate_bot_threshold': 50,
    },
    
    # IGNORED & MONITORED PATHS
    'IGNORED_PATHS': [
        '/', '/health', '/api/config', '/static',
    ],
    
    'MONITORED_PATHS': [
        '/api/user', '/api/search', '/api/comment', '/api/secure-data',
    ],
    
    # ML ANOMALY DETECTION
    'ML_SETTINGS': {
        'training_samples': 1000,
        'anomaly_threshold': 0.7,
        'feature_extraction': [
            'request_size', 'query_param_count', 'header_count',
            'special_char_ratio', 'entropy_score',
        ]
    },
    
    # LOGGING
    'LOGGING': {
        'log_all_requests': True,
        'log_file': 'logs/firewall.log',
        'json_log_file': 'logs/packets.json',
        'max_log_size': 50 * 1024 * 1024,
        'retention_days': 30,
    },
    
    # IP WHITELISTING & BLACKLISTING
    'WHITELIST_IPS': [],
    'BLACKLIST_IPS': [],
    
    # SECURITY HEADERS
    'SECURITY_HEADERS': {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
    },
}