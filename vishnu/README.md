# AI-Powered Web Attack Detection & Prevention System

A hybrid AI system for real-time detection and prevention of web application attacks.

## Features

- **Attack Detection**: Brute-force, credential stuffing, password spraying, SQL injection, XSS, bot traffic
- **Real-time Processing**: < 5 second detection latency
- **Automated Prevention**: IP blocking, rate limiting, MFA triggers, session invalidation
- **ML Models**: RandomForest, XGBoost, Logistic Regression
- **Dashboard**: Live monitoring with visual alerts

## Project Structure

```
.
├── data/                    # Generated datasets
├── models/                  # Trained ML models
├── src/
│   ├── data_generator.py   # Synthetic dataset generation
│   ├── feature_engineering.py  # Feature extraction
│   ├── ml_trainer.py        # ML model training
│   ├── decision_engine.py   # Hybrid ML + rules engine
│   ├── prevention.py        # Prevention actions
│   ├── api.py              # Flask REST API
│   └── dashboard.py        # Dashboard routes
├── static/                 # CSS, JS for dashboard
├── templates/              # HTML templates
├── tests/                  # Unit tests
├── simulators/             # Attack simulation scripts
└── app.py                  # Main application entry point
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

1. **Generate Dataset**:
   ```bash
   python src/data_generator.py
   ```

2. **Train Models**:
   ```bash
   python src/ml_trainer.py
   ```

3. **Run Application**:
   ```bash
   python app.py
   ```

4. **Access Dashboard**:
   Open http://localhost:5000 in your browser

5. **Test with Simulator**:
   ```bash
   python simulators/attack_simulator.py
   ```

## API Endpoint

**POST /api/detect**

Request:
```json
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
```

Response:
```json
{
  "prediction": "brute_force",
  "probabilities": {
    "normal": 0.05,
    "brute_force": 0.85,
    "sql_injection": 0.02,
    ...
  },
  "action": "block_ip",
  "explanation": {
    "ml_prediction": "brute_force",
    "rule_triggers": ["failed_attempts_1m > 5"],
    "top_features": ["failed_attempts_1m", "requests_per_minute"]
  }
}
```

## Attack Types

- `normal`: Legitimate traffic
- `brute_force`: Repeated login attempts
- `credential_stuffing`: Bulk credential testing
- `password_spraying`: Single password, multiple users
- `sql_injection`: SQL injection attempts
- `xss`: Cross-site scripting attempts
- `bot_traffic`: Automated bot behavior

