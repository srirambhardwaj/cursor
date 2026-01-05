"""
Main Application Entry Point
Initializes and runs the Flask application with dashboard
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_cors import CORS
import sys
import os
import subprocess
import json
from datetime import datetime

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.api import app, init_components

# Initialize prevention module for dashboard
prevention_module = None


@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/simulation')
def simulation():
    """Simulation page"""
    return render_template('simulation.html')


@app.route('/reports')
def reports():
    """Reports page"""
    return render_template('reports.html')


@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html')


@app.route('/api/simulate/attack', methods=['POST'])
def simulate_attack():
    """Trigger attack simulation"""
    try:
        # Get attack type from request, default to 'brute_force' if not specified
        data = request.get_json() or {}
        attack_type = data.get('attack_type', 'brute_force')
        
        # Map UI attack types to attack_simulator.py arguments
        attack_functions = {
            'brute_force': 'brute_force',
            'sql_injection': 'sql_injection',
            'xss': 'xss',
            'credential_stuffing': 'credential_stuffing',
            'bot_traffic': 'bot_traffic',
            'normal_traffic': 'normal',
            'normal': 'normal',
            'full_simulation': 'all',
            'all': 'all'
        }
        
        if attack_type not in attack_functions:
            return jsonify({
                'status': 'error',
                'message': f'Invalid attack type. Available types: {list(attack_functions.keys())}',
                'timestamp': datetime.utcnow().isoformat()
            }), 400
            
        # Run the simulation in a subprocess to avoid blocking
        # We'll capture the output and return it
        
        
        # Get the path to the attack_simulator.py
        simulator_path = os.path.join(os.path.dirname(__file__), 'simulators', 'attack_simulator.py')
        
        simulator_attack = attack_functions[attack_type]
        api_url = request.host_url.rstrip('/') + '/api/detect'

        result = subprocess.run(
            [
                sys.executable,
                simulator_path,
                '--api-url',
                api_url,
                '--attack',
                simulator_attack,
                '--json'
            ],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return jsonify({
                'status': 'error',
                'attack_type': attack_type,
                'timestamp': datetime.utcnow().isoformat(),
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'message': 'Simulation failed. See stderr/stdout for details.'
            }), 500

        parsed = None
        try:
            parsed = json.loads(result.stdout) if result.stdout else None
        except Exception:
            parsed = None

        results = []
        if isinstance(parsed, list):
            results = parsed
        elif isinstance(parsed, dict):
            results = [parsed]

        totals = {
            'requests_sent': sum((r.get('requests_sent') or 0) for r in results),
            'detected': sum((r.get('detected') or 0) for r in results)
        }

        return jsonify({
            'status': 'success',
            'attack_type': attack_type,
            'timestamp': datetime.utcnow().isoformat(),
            'returncode': result.returncode,
            'results': results,
            **totals
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


@app.route('/api/events/stream')
def events_stream():
    """Server-sent events stream for live updates"""
    # This would typically use Flask-SSE or similar
    # For now, return recent events
    return jsonify({'message': 'Event stream endpoint (to be implemented with SSE)'})


@app.route('/api/reports/summary', methods=['GET'])
def reports_summary():
    """Return summary data for the reports page"""
    try:
        from src.api import recent_events as src_recent_events
        from src.api import prevention_module as src_prevention_module

        range_key = request.args.get('range', '24h')
        now = datetime.utcnow()

        range_to_hours = {
            '1h': 1,
            '24h': 24,
            '7d': 24 * 7,
            '30d': 24 * 30
        }
        hours = range_to_hours.get(range_key, 24)
        start = now.timestamp() - (hours * 3600)

        events = []
        for e in (src_recent_events or []):
            try:
                ts = e.get('timestamp')
                ts_dt = datetime.fromisoformat(ts) if ts else None
                if ts_dt and ts_dt.timestamp() >= start:
                    events.append(e)
            except Exception:
                continue

        attacks = [e for e in events if e.get('prediction') and e.get('prediction') != 'normal']
        unique_ips = len(set([e.get('src_ip') for e in events if e.get('src_ip')]))

        blocked_ips_count = 0
        actions = []
        blocked_actions = 0
        if src_prevention_module is not None:
            try:
                blocked_ips_count = len(src_prevention_module.get_blocked_ips())
            except Exception:
                blocked_ips_count = 0
            try:
                actions = src_prevention_module.get_action_history(limit=50)
                blocked_actions = len([a for a in actions if a.get('action') in {'block_ip', 'unblock_ip'}])
            except Exception:
                actions = []

        detected = len(attacks)
        total_attacks = len(attacks)
        detection_rate = round((detected / total_attacks) * 100, 1) if total_attacks else 0

        # Timeline buckets
        if hours <= 2:  # For 1h or 2h ranges, use 1-minute buckets
            bucket_seconds = 60
            time_format = '%H:%M'
        elif hours <= 48:  # For 24h or 48h ranges, use hourly buckets
            bucket_seconds = 3600
            time_format = '%m-%d %H:00'
        else:
            bucket_seconds = 86400
            time_format = '%m-%d'

        buckets = {}
        for e in events:
            try:
                ts_dt = datetime.fromisoformat(e.get('timestamp'))
                bucket = int(ts_dt.timestamp() // bucket_seconds) * bucket_seconds
                if bucket not in buckets:
                    buckets[bucket] = {'attacks': 0, 'blocked': 0}
                if e.get('prediction') and e.get('prediction') != 'normal':
                    buckets[bucket]['attacks'] += 1
                if e.get('action') == 'block_ip':
                    buckets[bucket]['blocked'] += 1
            except Exception:
                continue

        # Create a full set of labels for the time range to ensure a continuous line
        start_bucket = int(start // bucket_seconds) * bucket_seconds
        end_bucket = int(now.timestamp() // bucket_seconds) * bucket_seconds
        all_buckets = range(start_bucket, end_bucket + bucket_seconds, bucket_seconds)

        timeline_labels = [datetime.fromtimestamp(b).strftime(time_format) for b in all_buckets]
        timeline_attacks = [buckets.get(b, {}).get('attacks', 0) for b in all_buckets]
        timeline_blocked = [buckets.get(b, {}).get('blocked', 0) for b in all_buckets]

        # Distribution by attack type
        dist = {}
        for e in attacks:
            at = e.get('prediction') or 'unknown'
            dist[at] = dist.get(at, 0) + 1
        dist_labels = list(dist.keys())
        dist_values = [dist[k] for k in dist_labels]

        # Top IPs by attack count
        ip_counts = {}
        for e in attacks:
            ip = e.get('src_ip')
            if not ip:
                continue
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        top_ips = [{'ip': ip, 'count': c} for ip, c in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

        return jsonify({
            'kpis': {
                'total_attacks': total_attacks,
                'blocked': blocked_ips_count,
                'detection_rate': detection_rate,
                'unique_ips': unique_ips
            },
            'timeline': {
                'labels': timeline_labels,
                'attacks': timeline_attacks,
                'blocked': timeline_blocked
            },
            'distribution': {
                'labels': dist_labels,
                'values': dist_values
            },
            'top_ips': top_ips,
            'actions': actions,
            'timestamp': now.isoformat()
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


# Initialize on startup
if __name__ == '__main__':
    print("="*60)
    print("AI-Powered Web Attack Detection & Prevention System")
    print("="*60)
    print("\nInitializing system...")
    
    if not init_components():
        print("\n⚠ Warning: Some components failed to initialize.")
        print("The API may not function correctly.")
        print("Please ensure:")
        print("  1. Dataset is generated (run src/data_generator.py)")
        print("  2. Models are trained (run src/ml_trainer.py)")
    
    print("\n" + "="*60)
    print("Starting server...")
    print("="*60)
    print("Dashboard: http://localhost:5000")
    print("API Docs: http://localhost:5000/api/health")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)

