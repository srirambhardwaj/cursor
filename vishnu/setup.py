"""
Setup script for AI Attack Detection System
"""

import subprocess
import sys
import os


def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n{'='*60}")
    print(f"{description}")
    print(f"{'='*60}")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return False


def main():
    print("\n" + "="*60)
    print("AI-Powered Web Attack Detection System - Setup")
    print("="*60)
    
    # Step 1: Install dependencies
    if not run_command("pip install -r requirements.txt", "Installing dependencies..."):
        print("Failed to install dependencies. Please install manually.")
        return False
    
    # Step 2: Generate dataset
    if not run_command("python src/data_generator.py", "Generating dataset..."):
        print("Failed to generate dataset.")
        return False
    
    # Step 3: Train models
    if not run_command("python src/ml_trainer.py", "Training ML models..."):
        print("Failed to train models.")
        return False
    
    print("\n" + "="*60)
    print("Setup Complete!")
    print("="*60)
    print("\nNext steps:")
    print("  1. Start the server: python app.py")
    print("  2. Open dashboard: http://localhost:5000")
    print("  3. Run simulations: python simulators/attack_simulator.py")
    print("="*60 + "\n")
    
    return True


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

