"""
ML Model Training Pipeline
Trains multiple models and selects the best one
"""
import sys
import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_fscore_support, accuracy_score
)
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings('ignore')

# Add project root to Python path so we can import src modules
# This allows us to use "from src.feature_engineering import ..." 
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


class MLTrainer:
    """Train and evaluate ML models for attack detection"""
    
    def __init__(self, models_dir='models'):
        self.models_dir = models_dir
        os.makedirs(models_dir, exist_ok=True)
        self.models = {}
        self.best_model = None
        self.best_model_name = None
        self.best_score = 0.0
        self.feature_names = None
        self.label_encoder = LabelEncoder()  # For encoding string labels to numeric
    
    def train_random_forest(self, X_train, y_train, X_val, y_val):
        """Train Random Forest classifier"""
        print("\nTraining Random Forest...")
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        
        print(f"Random Forest Accuracy: {accuracy:.4f}")
        
        return model, accuracy
    
    def train_xgboost(self, X_train, y_train, X_val, y_val):
        """Train XGBoost classifier"""
        print("\nTraining XGBoost...")
        
        # XGBoost requires numeric labels, so encode string labels
        # Label encoder is already fitted in train_all_models, so just transform
        y_train_encoded = self.label_encoder.transform(y_train)
        y_val_encoded = self.label_encoder.transform(y_val)
        
        model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            eval_metric='mlogloss',
            use_label_encoder=False
        )
        model.fit(X_train, y_train_encoded)
        
        # Evaluate (decode predictions back to original labels)
        y_pred_encoded = model.predict(X_val)
        y_pred = self.label_encoder.inverse_transform(y_pred_encoded)
        accuracy = accuracy_score(y_val, y_pred)
        
        print(f"XGBoost Accuracy: {accuracy:.4f}")
        
        return model, accuracy
    
    def train_logistic_regression(self, X_train, y_train, X_val, y_val):
        """Train Logistic Regression classifier"""
        print("\nTraining Logistic Regression...")
        model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced',
            multi_class='multinomial',
            solver='lbfgs'
        )
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        
        print(f"Logistic Regression Accuracy: {accuracy:.4f}")
        
        return model, accuracy
    
    def evaluate_model(self, model, X_test, y_test, model_name):
        """Comprehensive model evaluation"""
        # Check if model is XGBoost (needs label encoding)
        is_xgboost = model_name.lower() == 'xgboost'
        
        if is_xgboost:
            # XGBoost predictions need to be decoded
            y_pred_encoded = model.predict(X_test)
            y_pred = self.label_encoder.inverse_transform(y_pred_encoded)
        else:
            y_pred = model.predict(X_test)
        
        y_pred_proba = model.predict_proba(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted', zero_division=0
        )
        
        print(f"\n{'='*60}")
        print(f"Evaluation Results for {model_name}")
        print(f"{'='*60}")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1-Score: {f1:.4f}")
        
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, zero_division=0))
        
        print(f"\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'predictions': y_pred,
            'probabilities': y_pred_proba
        }
    
    def train_all_models(self, X_train, y_train, X_val, y_val, X_test, y_test):
        """Train all models and select the best one"""
        print("\n" + "="*60)
        print("Training ML Models")
        print("="*60)
        
        # Fit label encoder on all training labels to ensure consistent encoding
        self.label_encoder.fit(y_train)
        
        results = {}
        
        # Train Random Forest
        rf_model, rf_acc = self.train_random_forest(X_train, y_train, X_val, y_val)
        self.models['random_forest'] = rf_model
        results['random_forest'] = self.evaluate_model(rf_model, X_test, y_test, 'Random Forest')
        
        # Train XGBoost
        xgb_model, xgb_acc = self.train_xgboost(X_train, y_train, X_val, y_val)
        self.models['xgboost'] = xgb_model
        results['xgboost'] = self.evaluate_model(xgb_model, X_test, y_test, 'XGBoost')
        
        # Train Logistic Regression
        lr_model, lr_acc = self.train_logistic_regression(X_train, y_train, X_val, y_val)
        self.models['logistic_regression'] = lr_model
        results['logistic_regression'] = self.evaluate_model(lr_model, X_test, y_test, 'Logistic Regression')
        
        # Select best model based on F1 score
        best_model_name = max(results.keys(), key=lambda k: results[k]['f1'])
        self.best_model = self.models[best_model_name]
        self.best_model_name = best_model_name
        self.best_score = results[best_model_name]['f1']
        
        print(f"\n{'='*60}")
        print(f"Best Model: {best_model_name.upper()} (F1: {self.best_score:.4f})")
        print(f"{'='*60}")
        
        return results
    
    def save_best_model(self, filename='best_model.pkl'):
        """Save the best model to disk"""
        if self.best_model is None:
            raise ValueError("No model has been trained yet")
        
        filepath = os.path.join(self.models_dir, filename)
        joblib.dump(self.best_model, filepath)
        print(f"\nBest model saved to: {filepath}")
        
        # Also save feature names if available
        if self.feature_names is not None:
            feature_filepath = os.path.join(self.models_dir, 'feature_names.pkl')
            joblib.dump(self.feature_names, feature_filepath)
            print(f"Feature names saved to: {feature_filepath}")
        
        # Save label encoder (needed for XGBoost predictions)
        encoder_filepath = os.path.join(self.models_dir, 'label_encoder.pkl')
        joblib.dump(self.label_encoder, encoder_filepath)
        print(f"Label encoder saved to: {encoder_filepath}")
    
    def load_model(self, filename='best_model.pkl'):
        """Load a trained model from disk"""
        filepath = os.path.join(self.models_dir, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        self.best_model = joblib.load(filepath)
        self.best_model_name = filename.replace('.pkl', '')
        print(f"Model loaded from: {filepath}")
        
        # Try to load feature names
        feature_filepath = os.path.join(self.models_dir, 'feature_names.pkl')
        if os.path.exists(feature_filepath):
            self.feature_names = joblib.load(feature_filepath)
        
        # Try to load label encoder
        encoder_filepath = os.path.join(self.models_dir, 'label_encoder.pkl')
        if os.path.exists(encoder_filepath):
            self.label_encoder = joblib.load(encoder_filepath)
        
        return self.best_model


def train_models_from_dataset(dataset_path='data/dataset.csv', test_size=0.2, val_size=0.1):
    """
    Complete training pipeline from dataset
    
    Args:
        dataset_path: Path to CSV dataset
        test_size: Fraction of data for testing
        val_size: Fraction of training data for validation
    """
    from src.feature_engineering import load_and_featurize_dataset
    
    # Load and featurize
    X, y = load_and_featurize_dataset(dataset_path)
    
    # Split data
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    
    val_size_adjusted = val_size / (1 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=val_size_adjusted, random_state=42, stratify=y_temp
    )
    
    print(f"\nData split:")
    print(f"  Training: {len(X_train)} samples")
    print(f"  Validation: {len(X_val)} samples")
    print(f"  Testing: {len(X_test)} samples")
    
    # Train models
    trainer = MLTrainer()
    trainer.feature_names = list(X.columns)
    results = trainer.train_all_models(X_train, y_train, X_val, y_val, X_test, y_test)
    
    # Save best model
    trainer.save_best_model()
    
    # Check if accuracy >= 90%
    best_accuracy = results[trainer.best_model_name]['accuracy']
    if best_accuracy >= 0.90:
        print(f"\n✓ Success: Model accuracy ({best_accuracy:.2%}) meets requirement (≥90%)")
    else:
        print(f"\n⚠ Warning: Model accuracy ({best_accuracy:.2%}) below requirement (≥90%)")
    
    return trainer, results


if __name__ == '__main__':
    import sys
    
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else 'data/dataset.csv'
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        print("Please run data_generator.py first to generate the dataset.")
        sys.exit(1)
    
    train_models_from_dataset(dataset_path)

