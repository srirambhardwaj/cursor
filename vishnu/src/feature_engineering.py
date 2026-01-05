"""
Feature Engineering Module
Extracts features from raw log events for ML model training and inference
"""

import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math


class FeatureEngineer:
    """Extract features from web log events"""
    
    def __init__(self):
        self.event_history = deque(maxlen=5000)  # Use deque with maxlen for efficient history management
        self.ip_stats = defaultdict(lambda: {
            'failed_attempts': [],
            'usernames': set(),
            'requests': deque(maxlen=100),  # Use deque for requests
            'last_request_time': None
        })
        self.max_history_size = 5000  # Reduced from 10k to 5k for better performance
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text or pd.isna(text):
            return 0.0
        
        text = str(text)
        if len(text) == 0:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_sql_injection(self, payload):
        """Detect SQL injection patterns in payload"""
        if not payload or pd.isna(payload):
            return 0
        
        payload = str(payload).lower()
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
        
        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return 1
        
        return 0
    
    def detect_xss(self, payload):
        """Detect XSS patterns in payload"""
        if not payload or pd.isna(payload):
            return 0
        
        payload = str(payload).lower()
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
        
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return 1
        
        return 0
    
    def detect_bot_behavior(self, user_agent):
        """Detect bot behavior from user agent"""
        if not user_agent or pd.isna(user_agent):
            return 0.5  # Unknown
        
        user_agent = str(user_agent).lower()
        
        # Bot indicators
        bot_keywords = [
            'bot', 'crawler', 'spider', 'scraper',
            'python-requests', 'curl', 'wget', 'go-http',
            'googlebot', 'bingbot', 'slurp', 'duckduckbot'
        ]
        
        for keyword in bot_keywords:
            if keyword in user_agent:
                return 1.0
        
        # Human-like browsers
        browser_keywords = [
            'mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera'
        ]
        
        has_browser = any(keyword in user_agent for keyword in browser_keywords)
        return 0.0 if has_browser else 0.5
    
    def update_history(self, event):
        """Update event history for temporal features"""
        # Deque automatically manages maxlen, no need to manually trim
        self.event_history.append(event)
    
    def extract_features(self, event, use_history=True):
        """
        Extract features from a single event
        
        Args:
            event: Dictionary with event data
            use_history: Whether to use historical events for temporal features
        
        Returns:
            Dictionary of feature values
        """
        timestamp = pd.to_datetime(event.get('timestamp', datetime.now()))
        src_ip = event.get('src_ip', '')
        username = event.get('username', '')
        method = event.get('method', '')
        url = event.get('url', '')
        status = event.get('status', 200)
        user_agent = event.get('user_agent', '')
        payload = event.get('payload', '')
        
        # Update IP statistics
        ip_stat = self.ip_stats[src_ip]
        current_time = timestamp
        
        # Failed login attempts in last 1 minute
        failed_attempts_1m = 0
        if use_history and len(self.event_history) > 0:
            one_min_ago = current_time - timedelta(minutes=1)
            # Iterate in reverse for better performance (most recent events first)
            for hist_event in reversed(self.event_history):
                hist_time = pd.to_datetime(hist_event.get('timestamp', datetime.now()))
                if hist_time < one_min_ago:
                    break  # Early exit - older events won't match
                if (hist_event.get('src_ip') == src_ip and
                    hist_event.get('url') == '/login' and
                    hist_event.get('status') in [401, 403]):
                    failed_attempts_1m += 1
        
        # Distinct usernames from this IP in last 10 minutes
        distinct_usernames_10m = 0
        if use_history and len(self.event_history) > 0:
            ten_min_ago = current_time - timedelta(minutes=10)
            usernames_set = set()
            # Iterate in reverse for better performance
            for hist_event in reversed(self.event_history):
                hist_time = pd.to_datetime(hist_event.get('timestamp', datetime.now()))
                if hist_time < ten_min_ago:
                    break  # Early exit
                if (hist_event.get('src_ip') == src_ip and
                    hist_event.get('username')):
                    usernames_set.add(hist_event.get('username'))
            distinct_usernames_10m = len(usernames_set)
        
        # Average inter-arrival time (seconds between requests from this IP)
        avg_interarrival_seconds = 0.0
        if use_history and len(ip_stat['requests']) > 0:
            if ip_stat['last_request_time']:
                time_diff = (current_time - ip_stat['last_request_time']).total_seconds()
                # Average of last 10 inter-arrival times
                recent_times = list(ip_stat['requests'])[-10:]  # Convert deque to list for slicing
                if len(recent_times) > 1:
                    intervals = [recent_times[i] - recent_times[i-1] 
                               for i in range(1, len(recent_times))]
                    avg_interarrival_seconds = np.mean(intervals) if intervals else 0.0
                else:
                    avg_interarrival_seconds = time_diff
            else:
                avg_interarrival_seconds = 0.0
        
        # URL entropy
        url_entropy = self.calculate_entropy(url)
        
        # Payload features
        payload_sql_flag = self.detect_sql_injection(payload)
        payload_xss_flag = self.detect_xss(payload)
        
        # Bot behavior score
        bot_behavior_score = self.detect_bot_behavior(user_agent)
        
        # Requests per minute from this IP
        requests_per_minute = 0.0
        if use_history and len(self.event_history) > 0:
            one_min_ago = current_time - timedelta(minutes=1)
            # Iterate in reverse for better performance
            for hist_event in reversed(self.event_history):
                hist_time = pd.to_datetime(hist_event.get('timestamp', datetime.now()))
                if hist_time < one_min_ago:
                    break  # Early exit
                if hist_event.get('src_ip') == src_ip:
                    requests_per_minute += 1
        
        # Update IP statistics
        ip_stat['requests'].append(current_time.timestamp())  # Deque automatically manages maxlen
        ip_stat['last_request_time'] = current_time
        if username:
            ip_stat['usernames'].add(username)
        
        # Update history
        if use_history:
            self.update_history(event)
        
        # Compile features
        features = {
            'failed_attempts_1m': failed_attempts_1m,
            'distinct_usernames_10m': distinct_usernames_10m,
            'avg_interarrival_seconds': avg_interarrival_seconds,
            'url_entropy': url_entropy,
            'payload_sql_flag': payload_sql_flag,
            'payload_xss_flag': payload_xss_flag,
            'bot_behavior_score': bot_behavior_score,
            'requests_per_minute': requests_per_minute,
            'status_code': status,
            'method_post': 1 if method == 'POST' else 0,
            'method_get': 1 if method == 'GET' else 0,
            'url_login': 1 if '/login' in url.lower() else 0,
        }
        
        return features
    
    def extract_features_batch(self, events):
        """Extract features for a batch of events"""
        features_list = []
        
        for event in events:
            features = self.extract_features(event, use_history=True)
            features_list.append(features)
        
        return pd.DataFrame(features_list)
    
    def reset(self):
        """Reset history and statistics (useful for testing)"""
        self.event_history = deque(maxlen=self.max_history_size)
        self.ip_stats = defaultdict(lambda: {
            'failed_attempts': [],
            'usernames': set(),
            'requests': deque(maxlen=100),
            'last_request_time': None
        })


def load_and_featurize_dataset(csv_path):
    """
    Load dataset from CSV and extract features
    
    Args:
        csv_path: Path to CSV file with events
    
    Returns:
        Tuple of (features_df, labels_series)
    """
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    print("Extracting features...")
    engineer = FeatureEngineer()
    
    # Convert DataFrame rows to dictionaries
    events = df.to_dict('records')
    
    # Extract features
    features_list = []
    total = len(events)
    print(f"Total events to process: {total}")
    for i, event in enumerate(events):
        if i % 500 == 0 or i == total - 1:  # Print every 500 events and at the end
            print(f"Processing event {i+1}/{total} ({(i+1)*100/total:.1f}%)...")
        features = engineer.extract_features(event, use_history=True)
        features_list.append(features)
    
    features_df = pd.DataFrame(features_list)
    labels = df['attack_type']
    
    print(f"Extracted {len(features_df.columns)} features from {len(features_df)} events")
    
    return features_df, labels


if __name__ == '__main__':
    # Test feature extraction
    test_event = {
        'timestamp': datetime.now(),
        'src_ip': '192.168.1.100',
        'username': 'admin',
        'method': 'POST',
        'url': '/login',
        'status': 401,
        'user_agent': 'Mozilla/5.0',
        'payload': "username=admin&password=test"
    }
    
    engineer = FeatureEngineer()
    features = engineer.extract_features(test_event, use_history=False)
    print("\nTest event features:")
    for key, value in features.items():
        print(f"  {key}: {value}")

