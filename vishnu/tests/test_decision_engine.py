"""
Unit tests for decision engine
"""

import unittest
import sys
import os
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.decision_engine import RuleEngine, HybridDecisionEngine


class TestRuleEngine(unittest.TestCase):
    
    def setUp(self):
        self.rule_engine = RuleEngine()
    
    def test_brute_force_rule(self):
        """Test brute force detection rule"""
        features = {'failed_attempts_1m': 6}  # Above threshold (5)
        event = {'url': '/login', 'status': 401}
        
        result = self.rule_engine.check_brute_force_rule(features, event)
        self.assertTrue(result['triggered'])
        self.assertEqual(result['attack_type'], 'brute_force')
        
        # Below threshold
        features = {'failed_attempts_1m': 3}
        result = self.rule_engine.check_brute_force_rule(features, event)
        self.assertFalse(result['triggered'])
    
    def test_sql_injection_rule(self):
        """Test SQL injection detection rule"""
        features = {}
        event = {'payload': "' OR '1'='1"}
        
        result = self.rule_engine.check_sql_injection_rule(features, event)
        self.assertTrue(result['triggered'])
        self.assertEqual(result['attack_type'], 'sql_injection')
        
        # Normal payload
        event = {'payload': 'username=admin&password=test'}
        result = self.rule_engine.check_sql_injection_rule(features, event)
        self.assertFalse(result['triggered'])
    
    def test_xss_rule(self):
        """Test XSS detection rule"""
        features = {}
        event = {'payload': "<script>alert('XSS')</script>"}
        
        result = self.rule_engine.check_xss_rule(features, event)
        self.assertTrue(result['triggered'])
        self.assertEqual(result['attack_type'], 'xss')
        
        # Normal payload
        event = {'payload': 'comment=Hello world'}
        result = self.rule_engine.check_xss_rule(features, event)
        self.assertFalse(result['triggered'])
    
    def test_credential_stuffing_rule(self):
        """Test credential stuffing detection rule"""
        features = {'distinct_usernames_10m': 12}  # Above threshold (10)
        event = {}
        
        result = self.rule_engine.check_credential_stuffing_rule(features, event)
        self.assertTrue(result['triggered'])
        self.assertEqual(result['attack_type'], 'credential_stuffing')
    
    def test_evaluate_all_rules(self):
        """Test evaluating all rules"""
        features = {
            'failed_attempts_1m': 6,
            'distinct_usernames_10m': 12,
            'bot_behavior_score': 0.9
        }
        event = {'payload': "' OR '1'='1"}
        
        triggered = self.rule_engine.evaluate_all_rules(features, event)
        
        # Should trigger multiple rules
        self.assertGreater(len(triggered), 0)
        
        attack_types = [r['attack_type'] for r in triggered]
        self.assertIn('brute_force', attack_types)
        self.assertIn('sql_injection', attack_types)


class TestHybridDecisionEngine(unittest.TestCase):
    
    def setUp(self):
        # Note: This test requires a trained model
        # In a real scenario, you'd use a mock or ensure model exists
        self.skip_if_no_model()
    
    def skip_if_no_model(self):
        """Skip tests if model doesn't exist"""
        model_path = 'models/best_model.pkl'
        if not os.path.exists(model_path):
            self.skipTest(f"Model not found at {model_path}. Please train model first.")
    
    def test_predict_normal_event(self):
        """Test prediction on normal event"""
        try:
            engine = HybridDecisionEngine()
            
            event = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': '192.168.1.100',
                'username': None,
                'method': 'GET',
                'url': '/home',
                'status': 200,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'payload': None
            }
            
            result = engine.predict(event)
            
            self.assertIn('prediction', result)
            self.assertIn('probabilities', result)
            self.assertIn('action', result)
            self.assertIn('explanation', result)
            
        except FileNotFoundError:
            self.skipTest("Model file not found")


if __name__ == '__main__':
    unittest.main()

