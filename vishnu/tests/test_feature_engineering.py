"""
Unit tests for feature engineering module
"""

import unittest
import sys
import os
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_engineering import FeatureEngineer


class TestFeatureEngineering(unittest.TestCase):
    
    def setUp(self):
        self.engineer = FeatureEngineer()
    
    def test_calculate_entropy(self):
        """Test entropy calculation"""
        # High entropy (random string)
        high_entropy = self.engineer.calculate_entropy("abcdefghijklmnopqrstuvwxyz")
        self.assertGreater(high_entropy, 4.0)
        
        # Low entropy (repeated characters)
        low_entropy = self.engineer.calculate_entropy("aaaa")
        self.assertLess(low_entropy, 1.0)
        
        # Empty string
        empty_entropy = self.engineer.calculate_entropy("")
        self.assertEqual(empty_entropy, 0.0)
    
    def test_detect_sql_injection(self):
        """Test SQL injection detection"""
        # SQL injection patterns
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT NULL--"
        ]
        
        for payload in sql_payloads:
            result = self.engineer.detect_sql_injection(payload)
            self.assertEqual(result, 1, f"Should detect SQL injection in: {payload}")
        
        # Normal payload
        normal_payload = "username=admin&password=test123"
        result = self.engineer.detect_sql_injection(normal_payload)
        self.assertEqual(result, 0)
    
    def test_detect_xss(self):
        """Test XSS detection"""
        # XSS patterns
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            result = self.engineer.detect_xss(payload)
            self.assertEqual(result, 1, f"Should detect XSS in: {payload}")
        
        # Normal payload
        normal_payload = "comment=This is a normal comment"
        result = self.engineer.detect_xss(normal_payload)
        self.assertEqual(result, 0)
    
    def test_detect_bot_behavior(self):
        """Test bot behavior detection"""
        # Bot user agents
        bot_agents = [
            "python-requests/2.28.1",
            "curl/7.68.0",
            "Go-http-client/1.1"
        ]
        
        for agent in bot_agents:
            result = self.engineer.detect_bot_behavior(agent)
            self.assertEqual(result, 1.0, f"Should detect bot: {agent}")
        
        # Normal user agents
        normal_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ]
        
        for agent in normal_agents:
            result = self.engineer.detect_bot_behavior(agent)
            self.assertEqual(result, 0.0, f"Should not detect bot: {agent}")
    
    def test_extract_features(self):
        """Test feature extraction from event"""
        event = {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'username': 'admin',
            'method': 'POST',
            'url': '/login',
            'status': 401,
            'user_agent': 'Mozilla/5.0',
            'payload': "username=admin&password=test"
        }
        
        features = self.engineer.extract_features(event, use_history=False)
        
        # Check required features exist
        required_features = [
            'failed_attempts_1m',
            'distinct_usernames_10m',
            'avg_interarrival_seconds',
            'url_entropy',
            'payload_sql_flag',
            'payload_xss_flag',
            'bot_behavior_score',
            'requests_per_minute'
        ]
        
        for feature in required_features:
            self.assertIn(feature, features, f"Missing feature: {feature}")
            self.assertIsInstance(features[feature], (int, float), 
                                f"Feature {feature} should be numeric")
    
    def test_extract_features_batch(self):
        """Test batch feature extraction"""
        events = [
            {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.100',
                'username': 'admin',
                'method': 'POST',
                'url': '/login',
                'status': 401,
                'user_agent': 'Mozilla/5.0',
                'payload': "username=admin&password=test"
            },
            {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.101',
                'username': None,
                'method': 'GET',
                'url': '/home',
                'status': 200,
                'user_agent': 'Mozilla/5.0',
                'payload': None
            }
        ]
        
        features_df = self.engineer.extract_features_batch(events)
        
        self.assertEqual(len(features_df), 2)
        self.assertGreater(len(features_df.columns), 8)


if __name__ == '__main__':
    unittest.main()

