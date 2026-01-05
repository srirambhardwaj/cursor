"""
Prevention Module
Handles automated prevention actions: IP blocking, rate limiting, MFA triggers, session invalidation
"""

from datetime import datetime, timedelta
from collections import defaultdict
import threading
import json
import os


class PreventionModule:
    """Manages prevention actions and state"""
    
    def __init__(self):
        self.blocked_ips = {}  # {ip: block_until_timestamp}
        self.rate_limits = defaultdict(list)  # {ip: [request_timestamps]}
        self.mfa_triggers = {}  # {ip: trigger_count}
        self.invalidated_sessions = set()  # Set of session IDs
        self.action_history = []  # Audit log
        self.lock = threading.Lock()
        self.max_history = 10000
        
        # Configuration
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max_requests = 30  # max requests per window
        self.block_duration = timedelta(hours=1)  # Default block duration
        self.mfa_threshold = 3  # Trigger MFA after N suspicious events
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            
            block_until = self.blocked_ips[ip]
            if datetime.now() > block_until:
                # Block expired, remove it
                del self.blocked_ips[ip]
                return False
            
            return True
    
    def block_ip(self, ip, duration=None):
        """Block an IP address"""
        if duration is None:
            duration = self.block_duration
        
        with self.lock:
            block_until = datetime.now() + duration
            self.blocked_ips[ip] = block_until
            
            self._log_action('block_ip', ip, {
                'blocked_until': block_until.isoformat(),
                'duration_seconds': duration.total_seconds()
            })
        
        return True
    
    def unblock_ip(self, ip):
        """Manually unblock an IP address"""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self._log_action('unblock_ip', ip, {})
                return True
        return False
    
    def check_rate_limit(self, ip):
        """Check if IP has exceeded rate limit"""
        with self.lock:
            now = datetime.now()
            window_start = now - timedelta(seconds=self.rate_limit_window)
            
            # Clean old requests
            self.rate_limits[ip] = [
                ts for ts in self.rate_limits[ip]
                if ts > window_start
            ]
            
            # Check limit
            request_count = len(self.rate_limits[ip])
            
            if request_count >= self.rate_limit_max_requests:
                # Rate limit exceeded
                self._log_action('rate_limit_exceeded', ip, {
                    'request_count': request_count,
                    'limit': self.rate_limit_max_requests
                })
                return False  # Should be blocked
            
            # Add current request
            self.rate_limits[ip].append(now)
            return True  # Within limit
    
    def get_rate_limit_status(self, ip):
        """Get current rate limit status for an IP"""
        with self.lock:
            now = datetime.now()
            window_start = now - timedelta(seconds=self.rate_limit_window)
            
            # Clean old requests
            self.rate_limits[ip] = [
                ts for ts in self.rate_limits[ip]
                if ts > window_start
            ]
            
            request_count = len(self.rate_limits[ip])
            remaining = max(0, self.rate_limit_max_requests - request_count)
            
            return {
                'current_requests': request_count,
                'limit': self.rate_limit_max_requests,
                'remaining': remaining,
                'window_seconds': self.rate_limit_window
            }
    
    def trigger_mfa(self, ip, reason=None):
        """Trigger MFA requirement for an IP"""
        with self.lock:
            self.mfa_triggers[ip] = self.mfa_triggers.get(ip, 0) + 1
            
            self._log_action('trigger_mfa', ip, {
                'trigger_count': self.mfa_triggers[ip],
                'reason': reason
            })
        
        return True
    
    def should_require_mfa(self, ip):
        """Check if MFA should be required for an IP"""
        with self.lock:
            return self.mfa_triggers.get(ip, 0) >= self.mfa_threshold
    
    def invalidate_session(self, session_id):
        """Invalidate a user session"""
        with self.lock:
            self.invalidated_sessions.add(session_id)
            
            self._log_action('invalidate_session', None, {
                'session_id': session_id
            })
        
        return True
    
    def is_session_valid(self, session_id):
        """Check if a session is still valid"""
        with self.lock:
            return session_id not in self.invalidated_sessions
    
    def execute_action(self, action, ip, event_data=None):
        """
        Execute a prevention action
        
        Args:
            action: Action type ('block_ip', 'rate_limit', 'trigger_mfa', 'invalidate_session', 'allow')
            ip: IP address
            event_data: Additional event data (e.g., session_id)
        
        Returns:
            Dictionary with action result
        """
        result = {
            'action': action,
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'message': ''
        }
        
        # Check if already blocked
        if self.is_ip_blocked(ip) and action != 'unblock_ip':
            result['message'] = 'IP is already blocked'
            result['blocked'] = True
            self._log_action('block_ip', ip, {
                'message': 'IP is already blocked'
            })
            return result
        
        if action == 'block_ip':
            self.block_ip(ip)
            result['success'] = True
            result['message'] = f'IP {ip} blocked'
        
        elif action == 'rate_limit':
            if not self.check_rate_limit(ip):
                # Rate limit exceeded, block IP
                self.block_ip(ip, duration=timedelta(minutes=15))
                result['action'] = 'block_ip'  # Escalated
                result['success'] = True
                result['message'] = f'Rate limit exceeded, IP {ip} blocked'
            else:
                result['success'] = True
                result['message'] = f'Rate limiting applied to {ip}'
                self._log_action('rate_limit', ip, {
                    'message': result['message']
                })
        
        elif action == 'trigger_mfa':
            self.trigger_mfa(ip, reason=event_data.get('reason') if event_data else None)
            result['success'] = True
            result['message'] = f'MFA triggered for {ip}'
            result['mfa_required'] = self.should_require_mfa(ip)
        
        elif action == 'invalidate_session':
            session_id = event_data.get('session_id') if event_data else None
            if session_id:
                self.invalidate_session(session_id)
                result['success'] = True
                result['message'] = f'Session {session_id} invalidated'
            else:
                result['message'] = 'No session_id provided'
        
        elif action == 'allow':
            result['success'] = True
            result['message'] = 'Request allowed'
            self._log_action('allow', ip, {
                'message': result['message']
            })
        
        else:
            result['message'] = f'Unknown action: {action}'

        if result.get('success') and action in {'block_ip', 'rate_limit', 'trigger_mfa', 'invalidate_session', 'allow'}:
            self.save_state()
        
        return result
    
    def _log_action(self, action_type, ip, details):
        """Log prevention action for audit"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action_type,
            'ip': ip,
            'details': details
        }
        
        self.action_history.append(log_entry)
        
        # Keep only recent history
        if len(self.action_history) > self.max_history:
            self.action_history = self.action_history[-self.max_history:]
    
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        with self.lock:
            now = datetime.now()
            active_blocks = {}
            
            for ip, block_until in self.blocked_ips.items():
                if now < block_until:
                    active_blocks[ip] = {
                        'blocked_until': block_until.isoformat(),
                        'remaining_seconds': (block_until - now).total_seconds()
                    }
            
            return active_blocks
    
    def get_action_history(self, limit=100):
        """Get recent action history"""
        with self.lock:
            return self.action_history[-limit:]
    
    def get_statistics(self):
        """Get prevention module statistics"""
        with self.lock:
            return {
                'blocked_ips_count': len([ip for ip, until in self.blocked_ips.items() 
                                         if datetime.now() < until]),
                'rate_limited_ips_count': len(self.rate_limits),
                'mfa_triggered_ips_count': len(self.mfa_triggers),
                'invalidated_sessions_count': len(self.invalidated_sessions),
                'total_actions_logged': len(self.action_history)
            }
    
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        with self.lock:
            now = datetime.now()
            expired_ips = [
                ip for ip, block_until in self.blocked_ips.items()
                if now >= block_until
            ]
            
            for ip in expired_ips:
                del self.blocked_ips[ip]
            
            return len(expired_ips)
    
    def save_state(self, filepath='data/prevention_state.json'):
        """Save prevention state to file"""
        with self.lock:
            state = {
                'blocked_ips': {
                    ip: until.isoformat() 
                    for ip, until in self.blocked_ips.items()
                },
                'mfa_triggers': dict(self.mfa_triggers),
                'invalidated_sessions': list(self.invalidated_sessions),
                'action_history': self.action_history[-self.max_history:],
                'saved_at': datetime.now().isoformat()
            }
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2)
    
    def load_state(self, filepath='data/prevention_state.json'):
        """Load prevention state from file"""
        if not os.path.exists(filepath):
            return False
        
        with self.lock:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            # Restore blocked IPs
            self.blocked_ips = {
                ip: datetime.fromisoformat(until)
                for ip, until in state.get('blocked_ips', {}).items()
                if datetime.fromisoformat(until) > datetime.now()  # Only active blocks
            }
            
            self.mfa_triggers = state.get('mfa_triggers', {})
            self.invalidated_sessions = set(state.get('invalidated_sessions', []))
            self.action_history = state.get('action_history', [])
            
            return True

