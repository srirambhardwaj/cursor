# Quick Start Guide

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate dataset:**
   ```bash
   python src/data_generator.py
   ```
   This creates `data/dataset.csv` with 10,000 synthetic events.

3. **Train ML models:**
   ```bash
   python src/ml_trainer.py
   ```
   This trains RandomForest, XGBoost, and Logistic Regression models, selects the best one, and saves it to `models/best_model.pkl`.

## Running the System

1. **Start the Flask server:**
   ```bash
   python app.py
   ```

2. **Access the dashboard:**
   Open http://localhost:5000 in your browser

3. **Test with attack simulator:**
   ```bash
   # Run all attack simulations
   python simulators/attack_simulator.py

   # Or run specific attack type
   python simulators/attack_simulator.py --attack brute_force
   python simulators/attack_simulator.py --attack sql_injection
   ```

## API Usage

### Detect Attack

```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T10:30:00",
    "src_ip": "192.168.1.100",
    "username": "admin",
    "method": "POST",
    "url": "/login",
    "status": 401,
    "user_agent": "Mozilla/5.0",
    "payload": "username=admin&password=test123"
  }'
```

### Get Blocked IPs

```bash
curl http://localhost:5000/api/blocked-ips
```

### Get Action History

```bash
curl http://localhost:5000/api/action-history?limit=50
```

### Get Statistics

```bash
curl http://localhost:5000/api/statistics
```

## Testing

Run unit tests:

```bash
python -m pytest tests/
```

Or run specific test file:

```bash
python -m unittest tests/test_feature_engineering.py
python -m unittest tests/test_prevention.py
```

## Project Structure

```
.
├── app.py                 # Main Flask application
├── src/
│   ├── data_generator.py  # Synthetic dataset generation
│   ├── feature_engineering.py  # Feature extraction
│   ├── ml_trainer.py      # ML model training
│   ├── decision_engine.py # Hybrid ML + rules engine
│   ├── prevention.py      # Prevention actions
│   └── api.py            # REST API endpoints
├── templates/
│   └── dashboard.html     # Dashboard UI
├── simulators/
│   └── attack_simulator.py  # Attack simulation scripts
├── tests/                # Unit tests
├── data/                 # Generated datasets
└── models/               # Trained ML models
```

## Troubleshooting

### Model Not Found Error

If you see "Model not found" error:
1. Ensure you've run `python src/ml_trainer.py` to train models
2. Check that `models/best_model.pkl` exists

### Import Errors

If you encounter import errors:
1. Ensure you're running from the project root directory
2. Check that all dependencies are installed: `pip install -r requirements.txt`

### API Connection Errors

If the simulator can't connect to the API:
1. Ensure the Flask server is running: `python app.py`
2. Check that the server is listening on port 5000
3. Verify the API health: `curl http://localhost:5000/api/health`

## Next Steps

- Customize attack detection rules in `src/decision_engine.py`
- Adjust prevention actions in `src/prevention.py`
- Modify feature engineering in `src/feature_engineering.py`
- Add more attack types to the dataset generator
- Deploy to cloud (Vercel, Render, etc.)

