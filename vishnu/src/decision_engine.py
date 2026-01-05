"""
Hybrid Decision Engine
Combines ML predictions with rule-based triggers for final attack classification
"""

import re
import joblib
import os
import numpy as np
from datetime import datetime
import pandas as pd
from src.feature_engineering import FeatureEngineer


class RuleEngine:
    """Rule-based attack detection"""
    
    def __init__(self):
        self.rules_triggered = []
    
    def check_brute_force_rule(self, features, event):
        """Rule: IF failed_attempts_1m > threshold → brute_force"""
        threshold = 5
        if features.get('failed_attempts_1m', 0) > threshold:
            return {
                'triggered': True,
                'attack_type': 'brute_force',
                'rule': f'failed_attempts_1m > {threshold}',
                'value': features.get('failed_attempts_1m', 0)
            }
        return {'triggered': False}
    
    def check_sql_injection_rule(self, features, event):
        """Rule: IF SQLi signature regex matches → sql_injection"""
        payload = event.get('payload', '')
        if not payload:
            return {'triggered': False}
        
        sql_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bor\b.*['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
            r"(\bselect\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"(\bexec\b|\bexecute\b)",
            r"(--|\#|\/\*|\*\/)",
            r"(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
            r"(\badmin\b['\"]?\s*--)"
        ]
        
        payload_lower = str(payload).lower()
        for pattern in sql_patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                return {
                    'triggered': True,
                    'attack_type': 'sql_injection',
                    'rule': 'SQL injection pattern detected',
                    'pattern': pattern
                }
        
        return {'triggered': False}
    
    def check_xss_rule(self, features, event):
        """Rule: IF payload contains <script> or XSS patterns → xss"""
        payload = event.get('payload', '')
        if not payload:
            return {'triggered': False}
        
        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe",
            r"<img.*onerror",
            r"<svg.*onload"
        ]
        
        payload_lower = str(payload).lower()
        for pattern in xss_patterns:
            if re.search(pattern, payload_lower, re.IGNORECASE):
                return {
                    'triggered': True,
                    'attack_type': 'xss',
                    'rule': 'XSS pattern detected',
                    'pattern': pattern
                }
        
        return {'triggered': False}
    
    def check_credential_stuffing_rule(self, features, event):
        """Rule: IF distinct_usernames_10m > threshold → credential_stuffing"""
        threshold = 10
        if features.get('distinct_usernames_10m', 0) > threshold:
            return {
                'triggered': True,
                'attack_type': 'credential_stuffing',
                'rule': f'distinct_usernames_10m > {threshold}',
                'value': features.get('distinct_usernames_10m', 0)
            }
        return {'triggered': False}
    
    def check_bot_traffic_rule(self, features, event):
        """Rule: IF bot_behavior_score > threshold → bot_traffic"""
        threshold = 0.9  # Increased from 0.8 to reduce false positives
        if features.get('bot_behavior_score', 0) > threshold:
            return {
                'triggered': True,
                'attack_type': 'bot_traffic',
                'rule': f'bot_behavior_score > {threshold}',
                'value': features.get('bot_behavior_score', 0)
            }
        return {'triggered': False}
    
    def check_rate_limit_rule(self, features, event):
        """Rule: IF requests_per_minute > threshold → suspicious"""
        threshold = 60  # 60 requests per minute
        if features.get('requests_per_minute', 0) > threshold:
            return {
                'triggered': True,
                'attack_type': 'bot_traffic',  # Could be bot or DDoS
                'rule': f'requests_per_minute > {threshold}',
                'value': features.get('requests_per_minute', 0)
            }
        return {'triggered': False}
    
    def evaluate_all_rules(self, features, event):
        """Evaluate all rules and return triggered ones"""
        self.rules_triggered = []
        
        rules = [
            self.check_brute_force_rule,
            self.check_sql_injection_rule,
            self.check_xss_rule,
            self.check_credential_stuffing_rule,
            self.check_bot_traffic_rule,
            self.check_rate_limit_rule
        ]
        
        for rule_func in rules:
            result = rule_func(features, event)
            if result.get('triggered'):
                self.rules_triggered.append(result)
        
        return self.rules_triggered


class HybridDecisionEngine:
    """Combines ML predictions with rule-based triggers"""
    
    def __init__(self, model_path='models/best_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.label_encoder = None
        self.feature_engineer = FeatureEngineer()
        self.rule_engine = RuleEngine()
        self.class_names = [
            'normal', 'brute_force', 'credential_stuffing',
            'password_spraying', 'sql_injection', 'xss', 'bot_traffic'
        ]
        self.load_model()
    
    def load_model(self):
        """Load the trained ML model and label encoder"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model not found at {self.model_path}. "
                "Please train the model first using ml_trainer.py"
            )
        
        self.model = joblib.load(self.model_path)
        print(f"Model loaded from {self.model_path}")
        
        # Try to load label encoder (needed for XGBoost models)
        encoder_path = os.path.join(os.path.dirname(self.model_path), 'label_encoder.pkl')
        if os.path.exists(encoder_path):
            self.label_encoder = joblib.load(encoder_path)
            print(f"Label encoder loaded from {encoder_path}")
        else:
            print("Warning: Label encoder not found. Assuming model uses string labels.")
    
    def predict(self, event):
        """
        Make hybrid prediction (ML + Rules)
        
        Args:
            event: Dictionary with event data
        
        Returns:
            Dictionary with prediction, probabilities, action, and explanation
        """
        # Extract features
        features = self.feature_engineer.extract_features(event, use_history=True)
        features_df = pd.DataFrame([features])
        
        # Ensure feature order matches training
        expected_features = [
            'failed_attempts_1m', 'distinct_usernames_10m', 'avg_interarrival_seconds',
            'url_entropy', 'payload_sql_flag', 'payload_xss_flag', 'bot_behavior_score',
            'requests_per_minute', 'status_code', 'method_post', 'method_get', 'url_login'
        ]
        
        # Reorder features to match training
        features_df = features_df.reindex(columns=expected_features, fill_value=0)
        
        # ML prediction
        ml_prediction_raw = self.model.predict(features_df)[0]
        ml_probabilities = self.model.predict_proba(features_df)[0]
        
        # Decode prediction if label encoder exists (for XGBoost models)
        if self.label_encoder is not None:
            try:
                # XGBoost returns numeric labels, decode them
                ml_prediction = self.label_encoder.inverse_transform([ml_prediction_raw])[0]
            except (ValueError, IndexError, TypeError):
                # If decoding fails, try to map by index
                try:
                    pred_int = int(ml_prediction_raw)
                    if 0 <= pred_int < len(self.class_names):
                        ml_prediction = self.class_names[pred_int]
                    else:
                        ml_prediction = 'unknown'
                except (ValueError, TypeError):
                    ml_prediction = str(ml_prediction_raw)
        else:
            # No label encoder, assume string labels (Random Forest, Logistic Regression)
            ml_prediction = str(ml_prediction_raw)
        
        # Ensure prediction is in class_names, otherwise set to 'unknown'
        if ml_prediction not in self.class_names:
            ml_prediction = 'unknown'
        
        # Create probability dictionary
        # If we have label encoder, probabilities are in encoded order
        if self.label_encoder is not None and hasattr(self.label_encoder, 'classes_'):
            # Map probabilities to class names using encoder's class order
            encoded_classes = self.label_encoder.classes_
            prob_dict = dict(zip(encoded_classes, ml_probabilities))
        else:
            # Assume probabilities are in the same order as class_names
            prob_dict = dict(zip(self.class_names, ml_probabilities))
        
        # Rule-based evaluation
        triggered_rules = self.rule_engine.evaluate_all_rules(features, event)
        
        # Hybrid decision logic
        final_prediction = ml_prediction
        confidence = max(ml_probabilities)
        
        # If rules strongly indicate an attack, override ML if ML confidence is low
        if triggered_rules:
            rule_attack_types = [r['attack_type'] for r in triggered_rules]
            # If multiple rules agree or ML confidence is low, trust rules
            if len(set(rule_attack_types)) == 1 and confidence < 0.7:
                final_prediction = rule_attack_types[0]
            # If ML and rules agree, increase confidence
            elif ml_prediction in rule_attack_types:
                final_prediction = ml_prediction  # Keep ML prediction but rules confirm it
        
        # Determine prevention action
        action = self._determine_action(final_prediction, features, triggered_rules)
        
        # Get top features (for explainability)
        feature_importance = self._get_top_features(features, ml_probabilities)
        
        # Build explanation
        explanation = {
            'ml_prediction': ml_prediction,
            'ml_confidence': float(confidence),
            'rule_triggers': [r['rule'] for r in triggered_rules],
            'top_features': feature_importance,
            'final_decision': final_prediction,
            'decision_reason': self._get_decision_reason(ml_prediction, triggered_rules, confidence)
        }
        
        return {
            'prediction': final_prediction,
            'probabilities': {k: float(v) for k, v in prob_dict.items()},
            'action': action,
            'explanation': explanation
        }
    
    def _determine_action(self, prediction, features, triggered_rules):
        """Determine prevention action based on prediction and features"""
        if prediction == 'normal':
            return 'allow'
        
        # High severity attacks
        if prediction in ['sql_injection', 'xss']:
            return 'block_ip'
        
        # Brute force - block after multiple attempts
        if prediction == 'brute_force':
            if features.get('failed_attempts_1m', 0) > 10:
                return 'block_ip'
            elif features.get('failed_attempts_1m', 0) > 5:
                return 'trigger_mfa'
            else:
                return 'rate_limit'
        
        # Credential stuffing - block
        if prediction == 'credential_stuffing':
            return 'block_ip'
        
        # Bot traffic - rate limit or block
        if prediction == 'bot_traffic':
            if features.get('requests_per_minute', 0) > 100:
                return 'block_ip'
            else:
                return 'rate_limit'
        
        # Password spraying - trigger MFA
        if prediction == 'password_spraying':
            return 'trigger_mfa'
        
        # Default
        return 'rate_limit'
    
    def _get_top_features(self, features, probabilities):
        """Get top contributing features for explainability"""
        # Simple heuristic: features with high values that correlate with attack
        feature_scores = []
        
        attack_indicators = {
            'failed_attempts_1m': 1.0,
            'distinct_usernames_10m': 0.8,
            'payload_sql_flag': 1.0,
            'payload_xss_flag': 1.0,
            'bot_behavior_score': 0.9,
            'requests_per_minute': 0.7
        }
        
        for feature_name, value in features.items():
            if feature_name in attack_indicators and value > 0:
                score = value * attack_indicators[feature_name]
                feature_scores.append((feature_name, score))
        
        # Sort by score
        feature_scores.sort(key=lambda x: x[1], reverse=True)
        
        return [name for name, _ in feature_scores[:5]]
    
    def _get_decision_reason(self, ml_prediction, triggered_rules, ml_confidence):
        """Generate human-readable decision reason"""
        if triggered_rules and ml_confidence < 0.7:
            return f"Rules detected {triggered_rules[0]['attack_type']}, overriding ML prediction"
        elif triggered_rules and ml_prediction in [r['attack_type'] for r in triggered_rules]:
            return "ML prediction confirmed by rule-based triggers"
        elif ml_confidence > 0.8:
            return f"High confidence ML prediction ({ml_confidence:.2%})"
        else:
            return "ML prediction with moderate confidence"



