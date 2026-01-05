"""
Synthetic Dataset Generator for Web Attack Detection
Generates labeled events for training ML models
"""

import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import json
import os

# Attack type labels
ATTACK_TYPES = [
    'normal',
    'brute_force',
    'credential_stuffing',
    'password_spraying',
    'sql_injection',
    'xss',
    'bot_traffic'
]

# SQL injection patterns
SQL_PATTERNS = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "1' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1--",
    "1' OR '1'='1",
    "admin'/*",
    "' UNION SELECT password FROM users--"
]

# XSS patterns
XSS_PATTERNS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>"
]

# User agents
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

BOT_USER_AGENTS = [
    "python-requests/2.28.1",
    "curl/7.68.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "Mozilla/5.0 (compatible; bingbot/2.0)",
]


def generate_normal_event(base_time, ip_pool, username_pool):
    """Generate a normal/legitimate event"""
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 300)),
        'src_ip': random.choice(ip_pool),
        'username': random.choice(username_pool) if random.random() > 0.3 else None,
        'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
        'url': random.choice(['/home', '/about', '/products', '/contact', '/api/data']),
        'status': random.choice([200, 200, 200, 201, 404, 500]),  # Mostly success
        'user_agent': random.choice(NORMAL_USER_AGENTS),
        'payload': None if random.random() > 0.5 else json.dumps({'key': 'value'})
    }


def generate_brute_force_event(base_time, attacker_ip, target_username):
    """Generate brute-force attack event"""
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 10)),
        'src_ip': attacker_ip,
        'username': target_username,
        'method': 'POST',
        'url': '/login',
        'status': 401,  # Unauthorized
        'user_agent': random.choice(NORMAL_USER_AGENTS),
        'payload': f"username={target_username}&password={random.choice(['123456', 'password', 'admin', 'test'])}"
    }


def generate_credential_stuffing_event(base_time, attacker_ip):
    """Generate credential stuffing attack event"""
    usernames = ['admin', 'user', 'test', 'guest', 'root', 'administrator']
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 5)),
        'src_ip': attacker_ip,
        'username': random.choice(usernames),
        'method': 'POST',
        'url': '/login',
        'status': 401,
        'user_agent': random.choice(NORMAL_USER_AGENTS),
        'payload': f"username={random.choice(usernames)}&password={random.choice(['password123', 'admin123', 'qwerty'])}"
    }


def generate_password_spraying_event(base_time, attacker_ip, username_pool):
    """Generate password spraying attack event"""
    common_password = 'Password123'  # Same password for multiple users
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 5)),
        'src_ip': attacker_ip,
        'username': random.choice(username_pool),
        'method': 'POST',
        'url': '/login',
        'status': 401,
        'user_agent': random.choice(NORMAL_USER_AGENTS),
        'payload': f"username={random.choice(username_pool)}&password={common_password}"
    }


def generate_sql_injection_event(base_time, attacker_ip):
    """Generate SQL injection attack event"""
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 10)),
        'src_ip': attacker_ip,
        'username': None,
        'method': random.choice(['GET', 'POST']),
        'url': random.choice(['/search', '/api/users', '/products', '/login']),
        'status': random.choice([200, 400, 500]),
        'user_agent': random.choice(NORMAL_USER_AGENTS),
        'payload': random.choice(SQL_PATTERNS)
    }


def generate_xss_event(base_time, attacker_ip):
    """Generate XSS attack event"""
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 10)),
        'src_ip': attacker_ip,
        'username': None,
        'method': random.choice(['GET', 'POST']),
        'url': random.choice(['/comment', '/search', '/contact', '/api/submit']),
        'status': random.choice([200, 400]),
        'user_agent': random.choice(NORMAL_USER_AGENTS),
        'payload': random.choice(XSS_PATTERNS)
    }


def generate_bot_traffic_event(base_time, bot_ip):
    """Generate bot traffic event"""
    return {
        'timestamp': base_time + timedelta(seconds=random.randint(1, 2)),
        'src_ip': bot_ip,
        'username': None,
        'method': 'GET',
        'url': random.choice(['/robots.txt', '/sitemap.xml', '/api/data', '/products']),
        'status': random.choice([200, 404]),
        'user_agent': random.choice(BOT_USER_AGENTS),
        'payload': None
    }


def generate_dataset(n_events=10000, output_path='data/dataset.csv'):
    """
    Generate synthetic dataset with labeled attack events
    
    Args:
        n_events: Total number of events to generate
        output_path: Path to save the CSV file
    """
    print(f"Generating {n_events} events...")
    
    # Generate IP pools
    normal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    attacker_ips = [f"10.0.0.{i}" for i in range(1, 20)]
    bot_ips = [f"172.16.0.{i}" for i in range(1, 10)]
    
    # Generate username pools
    normal_usernames = ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'henry']
    target_usernames = ['admin', 'administrator', 'root', 'user', 'test']
    
    events = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Distribution: 60% normal, 40% attacks
    n_normal = int(n_events * 0.6)
    n_attacks = n_events - n_normal
    
    # Attack distribution
    attack_distribution = {
        'brute_force': int(n_attacks * 0.25),
        'credential_stuffing': int(n_attacks * 0.20),
        'password_spraying': int(n_attacks * 0.15),
        'sql_injection': int(n_attacks * 0.15),
        'xss': int(n_attacks * 0.15),
        'bot_traffic': int(n_attacks * 0.10)
    }
    
    # Generate normal events
    print("Generating normal events...")
    for _ in range(n_normal):
        event = generate_normal_event(base_time, normal_ips, normal_usernames)
        event['attack_type'] = 'normal'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 60))
    
    # Generate brute-force attacks
    print("Generating brute-force attacks...")
    attacker_ip = random.choice(attacker_ips)
    target_user = random.choice(target_usernames)
    for _ in range(attack_distribution['brute_force']):
        event = generate_brute_force_event(base_time, attacker_ip, target_user)
        event['attack_type'] = 'brute_force'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 10))
    
    # Generate credential stuffing
    print("Generating credential stuffing attacks...")
    attacker_ip = random.choice(attacker_ips)
    for _ in range(attack_distribution['credential_stuffing']):
        event = generate_credential_stuffing_event(base_time, attacker_ip)
        event['attack_type'] = 'credential_stuffing'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 5))
    
    # Generate password spraying
    print("Generating password spraying attacks...")
    attacker_ip = random.choice(attacker_ips)
    for _ in range(attack_distribution['password_spraying']):
        event = generate_password_spraying_event(base_time, attacker_ip, normal_usernames)
        event['attack_type'] = 'password_spraying'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 5))
    
    # Generate SQL injection
    print("Generating SQL injection attacks...")
    attacker_ip = random.choice(attacker_ips)
    for _ in range(attack_distribution['sql_injection']):
        event = generate_sql_injection_event(base_time, attacker_ip)
        event['attack_type'] = 'sql_injection'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 10))
    
    # Generate XSS
    print("Generating XSS attacks...")
    attacker_ip = random.choice(attacker_ips)
    for _ in range(attack_distribution['xss']):
        event = generate_xss_event(base_time, attacker_ip)
        event['attack_type'] = 'xss'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 10))
    
    # Generate bot traffic
    print("Generating bot traffic...")
    bot_ip = random.choice(bot_ips)
    for _ in range(attack_distribution['bot_traffic']):
        event = generate_bot_traffic_event(base_time, bot_ip)
        event['attack_type'] = 'bot_traffic'
        events.append(event)
        base_time += timedelta(seconds=random.randint(1, 2))
    
    # Convert to DataFrame
    df = pd.DataFrame(events)
    
    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)
    
    # Ensure timestamp is string for CSV
    df['timestamp'] = df['timestamp'].astype(str)
    
    # Save to CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    
    print(f"\nDataset generated successfully!")
    print(f"Total events: {len(df)}")
    print(f"\nAttack type distribution:")
    print(df['attack_type'].value_counts())
    print(f"\nSaved to: {output_path}")
    
    return df


if __name__ == '__main__':
    generate_dataset(n_events=10000, output_path='data/dataset.csv')

