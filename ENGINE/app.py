"""
Adaptive Firewall Simulation - Main Application
"""

import os
import sys
import html  # 🔥 FOR XSS SAFETY
from flask import Flask, request, jsonify, render_template
from datetime import datetime

# Import modules
try:
    from config import FIREWALL_CONFIG
    from firewall import AdaptiveFirewall
    from logger import FirewallLogger
    from detection import ThreatDetector
    from rules import RuleManager
    from ml_detector import MLAnomalyDetector
except ImportError as e:
    print(f"Error: Missing component file: {e}")
    sys.exit(1)

# ============================================================================
# INIT FLASK
# ============================================================================
app = Flask(__name__, template_folder='templates')
app.config['JSON_SORT_KEYS'] = False

# ============================================================================
# GLOBAL FIREWALL COMPONENTS
# ============================================================================
firewall_logger = FirewallLogger()
rule_manager = RuleManager()
threat_detector = ThreatDetector()
ml_detector = MLAnomalyDetector()

adaptive_firewall = AdaptiveFirewall(
    logger=firewall_logger,
    rule_manager=rule_manager,
    threat_detector=threat_detector,
    ml_detector=ml_detector,
    config=FIREWALL_CONFIG
)

# ============================================================================
# 🔥 FIREWALL MIDDLEWARE
# ============================================================================
@app.before_request
def firewall_protection():

    if not FIREWALL_CONFIG['ENABLE_FIREWALL']:
        return None

    # ✅ Allow dashboard & monitoring APIs
    if (
        request.path == '/' or
        request.path.startswith('/static') or
        request.path.startswith('/api/logs') or
        request.path.startswith('/api/stats') or
        request.path.startswith('/api/threat-summary') or
        request.path.startswith('/api/blocked-ips') or
        request.path.startswith('/api/timeline')
    ):
        return None

    decision = adaptive_firewall.process_request(request)

    if decision['blocked']:
        return jsonify({
            'error': 'Access Denied',
            'message': 'Blocked by Adaptive Firewall',
            'reason': decision['reason'],
            'timestamp': datetime.now().isoformat()
        }), 403


# ============================================================================
# FRONTEND
# ============================================================================
@app.route('/')
def index():
    return render_template('dashboard.html')


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(firewall_logger.get_statistics())


@app.route('/api/logs', methods=['GET'])
def get_logs():
    logs = firewall_logger.get_recent_logs(100)
    return jsonify({
        'total': firewall_logger.request_count,
        'logs': logs
    })


@app.route('/api/threat-summary', methods=['GET'])
def get_threat_summary():
    return jsonify(firewall_logger.get_threat_summary())


@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    temp_ips = rule_manager.get_blocked_ips()
    banned_ips = rule_manager.get_banned_ips()

    return jsonify({
        'temporarily_blocked': temp_ips,
        'permanently_banned': banned_ips,
        'total_blocked': len(temp_ips),
        'total_banned': len(banned_ips)
    })


@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    return jsonify(firewall_logger.get_request_timeline())


# ============================================================================
# ADMIN
# ============================================================================
@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    firewall_logger.clear_logs()
    return jsonify({'message': 'Logs cleared'})


@app.route('/api/unblock-ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    rule_manager.unblock_ip(ip)
    firewall_logger.log_event(f"IP {ip} manually unblocked", "ADMIN")
    return jsonify({'message': f'{ip} unblocked'})


# ============================================================================
# VULNERABLE ENDPOINTS (SAFE FOR DEMO)
# ============================================================================

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    return jsonify({
        'query': query,
        'results': [],
        'status': 'Search completed'
    })


@app.route('/api/comment', methods=['POST'])
def comment():
    """Simulated XSS endpoint (SAFE OUTPUT)"""
    data = request.get_json() or {}

    user_input = data.get('text', '')

    # 🔥 ESCAPE HTML (PREVENT EXECUTION)
    safe_output = html.escape(user_input)

    return jsonify({
        'comment': safe_output,
        'status': 'Comment posted'
    })


# ============================================================================
# HEALTH
# ============================================================================
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'firewall': FIREWALL_CONFIG['ENABLE_FIREWALL']
    })


# ============================================================================
# RUN APP
# ============================================================================
if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)

    print("=" * 60)
    print("🛡️ ADAPTIVE FIREWALL RUNNING")
    print("Dashboard: http://127.0.0.1:5000")
    print("=" * 60)

    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)