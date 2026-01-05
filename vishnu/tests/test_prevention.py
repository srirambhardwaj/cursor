"""
Unit tests for prevention module
"""

import unittest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.prevention import PreventionModule


class TestPreventionModule(unittest.TestCase):
    
    def setUp(self):
        self.prevention = PreventionModule()
    
    def test_block_ip(self):
        """Test IP blocking"""
        test_ip = '10.0.0.100'
        
        # IP should not be blocked initially
        self.assertFalse(self.prevention.is_ip_blocked(test_ip))
        
        # Block IP
        self.prevention.block_ip(test_ip)
        
        # IP should now be blocked
        self.assertTrue(self.prevention.is_ip_blocked(test_ip))
    
    def test_unblock_ip(self):
        """Test IP unblocking"""
        test_ip = '10.0.0.100'
        
        # Block then unblock
        self.prevention.block_ip(test_ip)
        self.assertTrue(self.prevention.is_ip_blocked(test_ip))
        
        self.prevention.unblock_ip(test_ip)
        self.assertFalse(self.prevention.is_ip_blocked(test_ip))
    
    def test_rate_limiting(self):
        """Test rate limiting"""
        test_ip = '10.0.0.100'
        
        # Should be within limit initially
        self.assertTrue(self.prevention.check_rate_limit(test_ip))
        
        # Make many requests quickly
        for _ in range(35):  # More than the limit (30)
            result = self.prevention.check_rate_limit(test_ip)
            if not result:
                break  # Rate limit exceeded
        
        # Should eventually hit rate limit
        self.assertFalse(self.prevention.check_rate_limit(test_ip))
    
    def test_trigger_mfa(self):
        """Test MFA triggering"""
        test_ip = '10.0.0.100'
        
        # Should not require MFA initially
        self.assertFalse(self.prevention.should_require_mfa(test_ip))
        
        # Trigger MFA multiple times
        for _ in range(3):
            self.prevention.trigger_mfa(test_ip)
        
        # Should now require MFA
        self.assertTrue(self.prevention.should_require_mfa(test_ip))
    
    def test_invalidate_session(self):
        """Test session invalidation"""
        session_id = 'session_12345'
        
        # Session should be valid initially
        self.assertTrue(self.prevention.is_session_valid(session_id))
        
        # Invalidate session
        self.prevention.invalidate_session(session_id)
        
        # Session should now be invalid
        self.assertFalse(self.prevention.is_session_valid(session_id))
    
    def test_execute_action(self):
        """Test action execution"""
        test_ip = '10.0.0.100'
        
        # Execute block action
        result = self.prevention.execute_action('block_ip', test_ip)
        self.assertTrue(result['success'])
        self.assertEqual(result['action'], 'block_ip')
        self.assertTrue(self.prevention.is_ip_blocked(test_ip))
        
        # Execute MFA trigger
        result = self.prevention.execute_action('trigger_mfa', test_ip)
        self.assertTrue(result['success'])
        self.assertEqual(result['action'], 'trigger_mfa')
    
    def test_get_blocked_ips(self):
        """Test getting blocked IPs list"""
        test_ips = ['10.0.0.100', '10.0.0.101']
        
        for ip in test_ips:
            self.prevention.block_ip(ip)
        
        blocked = self.prevention.get_blocked_ips()
        self.assertEqual(len(blocked), 2)
        self.assertIn(test_ips[0], blocked)
        self.assertIn(test_ips[1], blocked)
    
    def test_get_statistics(self):
        """Test getting statistics"""
        test_ip = '10.0.0.100'
        
        self.prevention.block_ip(test_ip)
        self.prevention.trigger_mfa(test_ip)
        self.prevention.invalidate_session('session_123')
        
        stats = self.prevention.get_statistics()
        
        self.assertGreaterEqual(stats['blocked_ips_count'], 1)
        self.assertGreaterEqual(stats['mfa_triggered_ips_count'], 1)
        self.assertGreaterEqual(stats['invalidated_sessions_count'], 1)
    
    def test_cleanup_expired_blocks(self):
        """Test cleanup of expired blocks"""
        test_ip = '10.0.0.100'
        
        # Block with very short duration
        self.prevention.block_ip(test_ip, duration=timedelta(seconds=-1))  # Already expired
        
        # Cleanup should remove it
        cleaned = self.prevention.cleanup_expired_blocks()
        self.assertGreaterEqual(cleaned, 0)
        
        # IP should no longer be blocked
        self.assertFalse(self.prevention.is_ip_blocked(test_ip))


if __name__ == '__main__':
    unittest.main()

