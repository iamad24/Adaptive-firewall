"""
Rule & Blocking Manager
Manages blocked IPs and firewall rules
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta

class RuleManager:
    """Manages firewall rules and IP blocking"""
    
    def __init__(self):
        self.blocked_ips = {}  # {ip: timestamp}
        self.banned_ips = set()  # Permanently banned
        self.block_count = defaultdict(int)  # Track violations per IP
    
    def add_blocked_ip(self, ip, duration=600, reason='Suspicious activity'):
        """Temporarily block an IP"""
        self.blocked_ips[ip] = {
            'timestamp': time.time(),
            'duration': duration,
            'reason': reason
        }
        
        # Increment block count
        self.block_count[ip] += 1
        
        # Permanent ban after 3 blocks
        if self.block_count[ip] >= 3:
            self.banned_ips.add(ip)
    
    def is_ip_blocked(self, ip):
        """Check if IP is currently blocked"""
        if ip in self.banned_ips:
            return True
        
        if ip in self.blocked_ips:
            block_info = self.blocked_ips[ip]
            elapsed = time.time() - block_info['timestamp']
            
            if elapsed < block_info['duration']:
                return True
            else:
                del self.blocked_ips[ip]
                return False
        
        return False
    
    def unblock_ip(self, ip):
        """Manually unblock an IP"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self.block_count[ip] = max(0, self.block_count[ip] - 1)
    
    def ban_ip(self, ip):
        """Permanently ban an IP"""
        self.banned_ips.add(ip)
    
    def unban_ip(self, ip):
        """Unban an IP"""
        if ip in self.banned_ips:
            self.banned_ips.discard(ip)
    
    def get_blocked_ips(self):
        """Get list of temporarily blocked IPs"""
        current_time = time.time()
        active_blocks = []
        
        for ip, block_info in list(self.blocked_ips.items()):
            elapsed = current_time - block_info['timestamp']
            if elapsed < block_info['duration']:
                active_blocks.append(ip)
            else:
                del self.blocked_ips[ip]
        
        return active_blocks
    
    def get_banned_ips(self):
        """Get list of permanently banned IPs"""
        return list(self.banned_ips)
    
    def cleanup_expired_blocks(self):
        """Remove expired blocks"""
        current_time = time.time()
        expired = []
        
        for ip, block_info in self.blocked_ips.items():
            elapsed = current_time - block_info['timestamp']
            if elapsed >= block_info['duration']:
                expired.append(ip)
        
        for ip in expired:
            del self.blocked_ips[ip]
    
    def get_block_status(self, ip):
        """Get detailed block status for an IP"""
        if ip in self.banned_ips:
            return {
                'status': 'permanently_banned',
                'violations': self.block_count[ip]
            }
        
        if ip in self.blocked_ips:
            block_info = self.blocked_ips[ip]
            elapsed = time.time() - block_info['timestamp']
            remaining = block_info['duration'] - elapsed
            
            return {
                'status': 'temporarily_blocked',
                'remaining_duration': max(0, remaining),
                'reason': block_info['reason'],
                'violations': self.block_count[ip]
            }
        
        return {
            'status': 'allowed',
            'violations': self.block_count[ip]
        }