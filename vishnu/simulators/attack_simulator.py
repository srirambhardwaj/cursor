"""
Attack Simulator
Simulates various web attacks for testing the detection system
"""

import requests
import time
import random
from datetime import datetime
import json
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


API_URL = 'http://localhost:5000/api/detect'


def simulate_brute_force(api_url, target_ip='10.0.0.100', target_username='admin', num_attempts=10, verbose=True):
    """Simulate brute-force login attack"""
    requests_sent = 0
    detected = 0
    if verbose:
        print(f"\n{'='*60}")
        print("Simulating Brute-Force Attack")
        print(f"{'='*60}")
        print(f"Target IP: {target_ip}")
        print(f"Target Username: {target_username}")
        print(f"Attempts: {num_attempts}\n")
    
    passwords = ['123456', 'password', 'admin', 'test', 'root', 'qwerty', 'letmein']
    
    # Realistic browser user agents for attack simulation
    realistic_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
    ]
    
    for i in range(num_attempts):
        requests_sent += 1
        event = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': target_ip,
            'username': target_username,
            'method': 'POST',
            'url': '/login',
            'status': 401,  # Unauthorized
            'user_agent': random.choice(realistic_user_agents),
            'payload': f'username={target_username}&password={random.choice(passwords)}'
        }
        
        try:
            response = requests.post(api_url, json=event, timeout=5)
            result = response.json()

            prediction = result.get('prediction', 'unknown')
            if prediction != 'normal':
                detected += 1

            if verbose:
                print(f"Attempt {i+1}: {prediction} - {result.get('action', 'none')}")
                if prediction != 'normal':
                    print(f"  ⚠️  Attack detected! Action: {result.get('action')}")
                    if result.get('prevention_result', {}).get('success'):
                        print(f"  ✓ Prevention action executed")

            time.sleep(0.5)  # Small delay between attempts
        
        except Exception as e:
            if verbose:
                print(f"  ✗ Error: {e}")

    if verbose:
        print(f"\n{'='*60}\n")

    return {
        'attack_type': 'brute_force',
        'requests_sent': requests_sent,
        'detected': detected
    }


def simulate_sql_injection(api_url, attacker_ip='10.0.0.101', num_attempts=5, verbose=True):
    """Simulate SQL injection attacks"""
    requests_sent = 0
    detected = 0
    if verbose:
        print(f"\n{'='*60}")
        print("Simulating SQL Injection Attacks")
        print(f"{'='*60}")
        print(f"Attacker IP: {attacker_ip}")
        print(f"Attempts: {num_attempts}\n")
    
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "1' UNION SELECT NULL--",
        "admin'--",
        "' OR 1=1--"
    ]
    
    # Realistic browser user agents for attack simulation
    realistic_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
    ]
    
    for i, payload in enumerate(sql_payloads[:num_attempts]):
        requests_sent += 1
        event = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': attacker_ip,
            'username': None,
            'method': 'GET',
            'url': '/search',
            'status': 200,
            'user_agent': random.choice(realistic_user_agents),
            'payload': payload
        }
        
        try:
            response = requests.post(api_url, json=event, timeout=5)
            result = response.json()

            prediction = result.get('prediction', 'unknown')
            if prediction != 'normal':
                detected += 1

            if verbose:
                print(f"Attempt {i+1}: {prediction} - {result.get('action', 'none')}")
                print(f"  Payload: {payload[:50]}...")
                if prediction == 'sql_injection':
                    print(f"  ✓ SQL injection detected!")

            time.sleep(0.5)
        
        except Exception as e:
            if verbose:
                print(f"  ✗ Error: {e}")

    if verbose:
        print(f"\n{'='*60}\n")

    return {
        'attack_type': 'sql_injection',
        'requests_sent': requests_sent,
        'detected': detected
    }


def simulate_xss(api_url, attacker_ip='10.0.0.102', num_attempts=5, verbose=True):
    """Simulate XSS attacks"""
    requests_sent = 0
    detected = 0
    if verbose:
        print(f"\n{'='*60}")
        print("Simulating XSS Attacks")
        print(f"{'='*60}")
        print(f"Attacker IP: {attacker_ip}")
        print(f"Attempts: {num_attempts}\n")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>"
    ]
    
    # Realistic browser user agents for attack simulation
    realistic_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
    ]
    
    for i, payload in enumerate(xss_payloads[:num_attempts]):
        requests_sent += 1
        event = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': attacker_ip,
            'username': None,
            'method': 'POST',
            'url': '/comment',
            'status': 200,
            'user_agent': random.choice(realistic_user_agents),
            'payload': payload
        }
        
        try:
            response = requests.post(api_url, json=event, timeout=5)
            result = response.json()

            prediction = result.get('prediction', 'unknown')
            if prediction != 'normal':
                detected += 1

            if verbose:
                print(f"Attempt {i+1}: {prediction} - {result.get('action', 'none')}")
                print(f"  Payload: {payload[:50]}...")
                if prediction == 'xss':
                    print(f"  ✓ XSS detected!")

            time.sleep(0.5)
        
        except Exception as e:
            if verbose:
                print(f"  ✗ Error: {e}")

    if verbose:
        print(f"\n{'='*60}\n")

    return {
        'attack_type': 'xss',
        'requests_sent': requests_sent,
        'detected': detected
    }


def simulate_credential_stuffing(api_url, attacker_ip='10.0.0.103', num_attempts=15, verbose=True):
    """Simulate credential stuffing attack"""
    requests_sent = 0
    detected = 0
    if verbose:
        print(f"\n{'='*60}")
        print("Simulating Credential Stuffing Attack")
        print(f"{'='*60}")
        print(f"Attacker IP: {attacker_ip}")
        print(f"Attempts: {num_attempts}\n")
    
    usernames = ['admin', 'user', 'test', 'guest', 'root', 'administrator', 'alice', 'bob']
    passwords = ['password123', 'admin123', 'qwerty', '123456']
    
    # Realistic browser user agents for attack simulation
    realistic_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
    ]
    
    for i in range(num_attempts):
        requests_sent += 1
        event = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': attacker_ip,
            'username': random.choice(usernames),
            'method': 'POST',
            'url': '/login',
            'status': 401,
            'user_agent': random.choice(realistic_user_agents),
            'payload': f'username={random.choice(usernames)}&password={random.choice(passwords)}'
        }
        
        try:
            response = requests.post(api_url, json=event, timeout=5)
            result = response.json()

            prediction = result.get('prediction', 'unknown')
            if prediction != 'normal':
                detected += 1

            if verbose:
                print(f"Attempt {i+1}: {prediction} - {result.get('action', 'none')}")
                if prediction == 'credential_stuffing':
                    print(f"  ✓ Credential stuffing detected!")

            time.sleep(0.3)  # Faster attempts
        
        except Exception as e:
            if verbose:
                print(f"  ✗ Error: {e}")

    if verbose:
        print(f"\n{'='*60}\n")

    return {
        'attack_type': 'credential_stuffing',
        'requests_sent': requests_sent,
        'detected': detected
    }


def simulate_bot_traffic(api_url, bot_ip='172.16.0.50', num_requests=20, verbose=True):
    """Simulate bot traffic"""
    requests_sent = 0
    detected = 0
    if verbose:
        print(f"\n{'='*60}")
        print("Simulating Bot Traffic")
        print(f"{'='*60}")
        print(f"Bot IP: {bot_ip}")
        print(f"Requests: {num_requests}\n")
    
    bot_user_agents = [
        'python-requests/2.28.1',
        'curl/7.68.0',
        'Go-http-client/1.1',
        'Mozilla/5.0 (compatible; Googlebot/2.1)'
    ]
    
    urls = ['/robots.txt', '/sitemap.xml', '/api/data', '/products']
    
    for i in range(num_requests):
        requests_sent += 1
        event = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': bot_ip,
            'username': None,
            'method': 'GET',
            'url': random.choice(urls),
            'status': 200,
            'user_agent': random.choice(bot_user_agents),
            'payload': None
        }
        
        try:
            response = requests.post(api_url, json=event, timeout=5)
            result = response.json()

            prediction = result.get('prediction', 'unknown')
            if prediction != 'normal':
                detected += 1

            if verbose:
                if i % 5 == 0:  # Print every 5th request
                    print(f"Request {i+1}: {prediction} - {result.get('action', 'none')}")

            time.sleep(0.1)  # Very fast requests
        
        except Exception as e:
            if verbose:
                print(f"  ✗ Error: {e}")

    if verbose:
        print(f"\n{'='*60}\n")

    return {
        'attack_type': 'bot_traffic',
        'requests_sent': requests_sent,
        'detected': detected
    }


def simulate_normal_traffic(api_url, num_requests=10, verbose=True):
    """Simulate normal/legitimate traffic"""
    requests_sent = 0
    detected = 0
    if verbose:
        print(f"\n{'='*60}")
        print("Simulating Normal Traffic")
        print(f"{'='*60}")
        print(f"Requests: {num_requests}\n")
    
    normal_ips = [f'192.168.1.{i}' for i in range(1, 11)]
    urls = ['/home', '/about', '/products', '/contact']
    
    # Realistic browser user agents for attack simulation
    realistic_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
    ]
    
    for i in range(num_requests):
        requests_sent += 1
        event = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': random.choice(normal_ips),
            'username': None,
            'method': random.choice(['GET', 'POST']),
            'url': random.choice(urls),
            'status': 200,
            'user_agent': random.choice(realistic_user_agents),
            'payload': None
        }
        
        try:
            response = requests.post(api_url, json=event, timeout=5)
            result = response.json()

            prediction = result.get('prediction', 'unknown')
            if prediction != 'normal':
                detected += 1

            if verbose:
                if prediction == 'normal':
                    print(f"Request {i+1}: ✓ Normal traffic (correctly classified)")
                else:
                    print(f"Request {i+1}: ⚠️  Classified as {prediction} (false positive?)")

            time.sleep(1)  # Normal user behavior
        
        except Exception as e:
            if verbose:
                print(f"  ✗ Error: {e}")

    if verbose:
        print(f"\n{'='*60}\n")

    return {
        'attack_type': 'normal',
        'requests_sent': requests_sent,
        'detected': detected
    }


def run_full_simulation(api_url=API_URL, verbose=True):
    """Run all attack simulations"""
    if verbose:
        print("\n" + "="*60)
        print("AI Attack Detection System - Full Simulation")
        print("="*60)
        print(f"API URL: {api_url}\n")
    
    # Check if API is available
    try:
        response = requests.get(f"{api_url.replace('/detect', '/health')}", timeout=2)
        if response.status_code != 200:
            if verbose:
                print("⚠️  Warning: API health check failed")
    except Exception as e:
        if verbose:
            print(f"✗ Error: Cannot connect to API at {api_url}")
            print("  Please ensure the Flask server is running (python app.py)")
        return None
    
    # Run simulations
    summaries = []

    summaries.append(simulate_normal_traffic(api_url, num_requests=5, verbose=verbose))
    time.sleep(2)
    
    summaries.append(simulate_brute_force(api_url, num_attempts=8, verbose=verbose))
    time.sleep(2)
    
    summaries.append(simulate_sql_injection(api_url, num_attempts=5, verbose=verbose))
    time.sleep(2)
    
    summaries.append(simulate_xss(api_url, num_attempts=5, verbose=verbose))
    time.sleep(2)
    
    summaries.append(simulate_credential_stuffing(api_url, num_attempts=12, verbose=verbose))
    time.sleep(2)
    
    summaries.append(simulate_bot_traffic(api_url, num_requests=15, verbose=verbose))
    
    if verbose:
        print("\n" + "="*60)
        print("Simulation Complete!")
        print("="*60)
        print("\nCheck the dashboard at http://localhost:5000 to see results")
        print("Check blocked IPs: GET /api/blocked-ips")
        print("Check action history: GET /api/action-history")
        print("="*60 + "\n")

    return summaries


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Attack Simulator for Testing')
    parser.add_argument('--api-url', default=API_URL, help='API endpoint URL')
    parser.add_argument('--attack', choices=['brute_force', 'sql_injection', 'xss', 
                                            'credential_stuffing', 'bot_traffic', 'normal', 'all'],
                       default='all', help='Type of attack to simulate')
    parser.add_argument('--json', action='store_true', help='Output JSON summary only')
    
    args = parser.parse_args()
    
    verbose = not args.json
    summary = None

    if args.attack == 'all':
        summary = run_full_simulation(args.api_url, verbose=verbose)
    elif args.attack == 'brute_force':
        summary = simulate_brute_force(args.api_url, verbose=verbose)
    elif args.attack == 'sql_injection':
        summary = simulate_sql_injection(args.api_url, verbose=verbose)
    elif args.attack == 'xss':
        summary = simulate_xss(args.api_url, verbose=verbose)
    elif args.attack == 'credential_stuffing':
        summary = simulate_credential_stuffing(args.api_url, verbose=verbose)
    elif args.attack == 'bot_traffic':
        summary = simulate_bot_traffic(args.api_url, verbose=verbose)
    elif args.attack == 'normal':
        summary = simulate_normal_traffic(args.api_url, verbose=verbose)

    if args.json:
        if summary is None:
            sys.exit(1)
        print(json.dumps(summary))

