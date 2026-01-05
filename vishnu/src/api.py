"""
Flask REST API for Attack Detection
Provides /api/detect endpoint for real-time attack detection
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import sys
import os
import threading

# Add parent directory to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from src.decision_engine import HybridDecisionEngine
from src.prevention import PreventionModule

# Configure Flask to use templates and static folders from project root
app = Flask(
    __name__,
    template_folder=os.path.join(project_root, 'templates'),
    static_folder=os.path.join(project_root, 'static')
)
CORS(app)  # Enable CORS for frontend

# Initialize components
decision_engine = None
prevention_module = None

# Store recent detection events for dashboard
recent_events = []
max_recent_events = 1000
event_lock = threading.Lock()


def init_components():
    """Initialize decision engine and prevention module"""
    global decision_engine, prevention_module
    
    try:
        decision_engine = HybridDecisionEngine(model_path='models/best_model.pkl')
        prevention_module = PreventionModule()
        prevention_module.load_state()  # Load saved state if exists
        
        print("✓ Components initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Error initializing components: {e}")
        return False


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'model_loaded': decision_engine is not None,
        'prevention_active': prevention_module is not None
    })


@app.route('/api/detect', methods=['POST'])
def detect_attack():
    """
    Main detection endpoint
    
    Request Body:
    {
        "timestamp": "2024-01-15T10:30:00",
        "src_ip": "192.168.1.100",
        "username": "admin",
        "method": "POST",
        "url": "/login",
        "status": 401,
        "user_agent": "Mozilla/5.0",
        "payload": "username=admin&password=test123"
    }
    
    Response:
    {
        "prediction": "brute_force",
        "probabilities": {...},
        "action": "block_ip",
        "explanation": {...},
        "prevention_result": {...}
    }
    """
    if decision_engine is None or prevention_module is None:
        return jsonify({
            'error': 'System not initialized. Please ensure model is trained.'
        }), 500
    
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Validate required fields
        required_fields = ['src_ip', 'method', 'url']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Set default values
        event = {
            'timestamp': data.get('timestamp', datetime.now().isoformat()),
            'src_ip': data['src_ip'],
            'username': data.get('username'),
            'method': data['method'],
            'url': data['url'],
            'status': data.get('status', 200),
            'user_agent': data.get('user_agent', ''),
            'payload': data.get('payload', '')
        }
        
        # Check if IP is already blocked
        if prevention_module.is_ip_blocked(event['src_ip']):
            return jsonify({
                'prediction': 'blocked',
                'probabilities': {},
                'action': 'block_ip',
                'explanation': {
                    'reason': 'IP is currently blocked',
                    'blocked_until': prevention_module.blocked_ips.get(
                        event['src_ip']
                    ).isoformat() if event['src_ip'] in prevention_module.blocked_ips else None
                },
                'prevention_result': {
                    'action': 'block_ip',
                    'success': True,
                    'message': 'IP is already blocked'
                }
            })
        
        # Make prediction
        result = decision_engine.predict(event)
        
        # Execute prevention action
        prevention_result = prevention_module.execute_action(
            result['action'],
            event['src_ip'],
            event_data={'session_id': data.get('session_id')}
        )
        
        result['prevention_result'] = prevention_result
        
        # Add metadata
        result['timestamp'] = datetime.now().isoformat()
        result['event_id'] = data.get('event_id', f"event_{datetime.now().timestamp()}")
        
        # Store event for dashboard (add event details)
        event_data = {
            'timestamp': result['timestamp'],
            'src_ip': event['src_ip'],
            'method': event['method'],
            'url': event['url'],
            'prediction': result['prediction'],
            'action': result['action'],
            'probabilities': result.get('probabilities', {})
        }
        
        # Add to recent events list
        with event_lock:
            recent_events.insert(0, event_data)  # Add to beginning
            # Keep only recent events
            if len(recent_events) > max_recent_events:
                recent_events.pop()  # Remove oldest
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({
            'error': f'Detection error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    if prevention_module is None:
        return jsonify({'error': 'Prevention module not initialized'}), 500
    
    blocked = prevention_module.get_blocked_ips()
    return jsonify({
        'blocked_ips': blocked,
        'count': len(blocked),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/blocked-ips/<ip>', methods=['DELETE'])
def unblock_ip(ip):
    """Unblock an IP address"""
    if prevention_module is None:
        return jsonify({'error': 'Prevention module not initialized'}), 500
    
    success = prevention_module.unblock_ip(ip)
    if success:
        return jsonify({
            'message': f'IP {ip} unblocked',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'message': f'IP {ip} was not blocked',
            'timestamp': datetime.now().isoformat()
        }), 404


@app.route('/api/action-history', methods=['GET'])
def get_action_history():
    """Get prevention action history"""
    if prevention_module is None:
        return jsonify({'error': 'Prevention module not initialized'}), 500
    
    limit = request.args.get('limit', 100, type=int)
    history = prevention_module.get_action_history(limit=limit)
    
    return jsonify({
        'history': history,
        'count': len(history),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get system statistics"""
    if prevention_module is None:
        return jsonify({'error': 'Prevention module not initialized'}), 500
    
    stats = prevention_module.get_statistics()
    stats['timestamp'] = datetime.now().isoformat()
    
    return jsonify(stats)


@app.route('/api/rate-limit-status/<ip>', methods=['GET'])
def get_rate_limit_status(ip):
    """Get rate limit status for an IP"""
    if prevention_module is None:
        return jsonify({'error': 'Prevention module not initialized'}), 500
    
    status = prevention_module.get_rate_limit_status(ip)
    return jsonify(status)


@app.route('/api/recent-events', methods=['GET'])
def get_recent_events():
    """Get recent detection events for dashboard"""
    limit = request.args.get('limit', 50, type=int)
    
    with event_lock:
        events = recent_events[:limit]  # Get most recent events
    
    return jsonify({
        'events': events,
        'count': len(events),
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("Initializing API components...")
    if not init_components():
        print("Failed to initialize. Exiting.")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("AI-Powered Web Attack Detection API")
    print("="*60)
    print("API running on http://localhost:5000")
    print("Endpoints:")
    print("  POST /api/detect - Detect attacks")
    print("  GET  /api/health - Health check")
    print("  GET  /api/blocked-ips - List blocked IPs")
    print("  GET  /api/action-history - Get action history")
    print("  GET  /api/statistics - Get statistics")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)

