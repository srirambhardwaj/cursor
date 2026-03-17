"""
High-Quality Visualization Graphs for IEEE Research Paper
Generates professional academic figures with matplotlib and seaborn
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os
from matplotlib import rcParams

# Set up professional academic styling
plt.style.use('seaborn-v0_8-paper')
rcParams['font.family'] = 'Times New Roman'
rcParams['font.size'] = 12
rcParams['axes.labelsize'] = 12
rcParams['axes.titlesize'] = 14
rcParams['xtick.labelsize'] = 10
rcParams['ytick.labelsize'] = 10
rcParams['legend.fontsize'] = 10
rcParams['figure.titlesize'] = 16

# Create output directory
output_dir = 'paper_figures'
os.makedirs(output_dir, exist_ok=True)

def figure1_model_performance():
    """Figure 1: Model Performance Comparison (Bar Chart)"""
    
    # Data
    models = ['Logistic Regression', 'Random Forest', 'XGBoost']
    accuracy = [0.8160, 0.8770, 0.8805]
    f1_score = [0.7916, 0.8784, 0.8802]
    
    # Create figure
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Set up bar positions
    x = np.arange(len(models))
    width = 0.35
    
    # Create bars with professional colors
    bars1 = ax.bar(x - width/2, accuracy, width, label='Accuracy', 
                   color='#2E86AB', alpha=0.8, edgecolor='#1E5A7A', linewidth=1)
    bars2 = ax.bar(x + width/2, f1_score, width, label='F1-Score', 
                   color='#A23B72', alpha=0.8, edgecolor='#7A2B5A', linewidth=1)
    
    # Add value labels on top of bars
    def add_value_labels(bars):
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.4f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=9, fontweight='bold')
    
    add_value_labels(bars1)
    add_value_labels(bars2)
    
    # Customize plot
    ax.set_xlabel('Machine Learning Models')
    ax.set_ylabel('Performance Metrics')
    ax.set_title('Model Performance Comparison', fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=15, ha='right')
    ax.legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    ax.grid(True, alpha=0.3, axis='y')
    
    # Set y-axis range
    ax.set_ylim(0.75, 0.90)
    
    # Add subtle background
    ax.set_facecolor('#F8F9FA')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/figure1_model_performance.png', 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print("Figure 1: Model Performance Comparison - Generated")

def figure2_latency_analysis():
    """Figure 2: System Latency vs. Traffic Load (Line Chart)"""
    
    # Data
    users = [10, 50, 100, 500, 1000]
    latency = [12, 14, 15, 18, 25]  # in milliseconds
    
    # Create figure
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Create line plot with markers
    line = ax.plot(users, latency, marker='o', linewidth=2.5, markersize=8,
                   color='#2E86AB', markerfacecolor='#A23B72', 
                   markeredgewidth=2, markeredgecolor='#1E5A7A')
    
    # Add SLA threshold line
    ax.axhline(y=50, color='red', linestyle='--', linewidth=2, alpha=0.7,
               label='SLA Threshold (50ms)')
    
    # Add value labels
    for i, (user, lat) in enumerate(zip(users, latency)):
        ax.annotate(f'{lat}ms', (user, lat), textcoords="offset points",
                   xytext=(0,10), ha='center', fontsize=9, fontweight='bold')
    
    # Customize plot
    ax.set_xlabel('Concurrent Users')
    ax.set_ylabel('Average Response Time (ms)')
    ax.set_title('System Latency vs. Traffic Load', fontweight='bold', pad=20)
    ax.legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    ax.grid(True, alpha=0.3)
    
    # Set axis ranges
    ax.set_xlim(0, 1100)
    ax.set_ylim(0, 60)
    
    # Add subtle background
    ax.set_facecolor('#F8F9FA')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/figure2_latency_analysis.png', 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print("Figure 2: System Latency vs. Traffic Load - Generated")

def figure3_attack_mitigation():
    """Figure 3: Attack Mitigation Breakdown (Pie Chart)"""
    
    # Data
    categories = ['Rule Engine Block\n(SQLi/XSS)', 'ML Model Block\n(Anomalies)', 
                  'MFA Challenge\nTriggered', 'False Negatives\n/Missed']
    sizes = [35, 45, 15, 5]
    colors = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D']
    explode = [0, 0.1, 0, 0]  # Explode ML Model Block slice
    
    # Create figure
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Create pie chart
    wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=categories, 
                                      colors=colors, autopct='%1.1f%%',
                                      shadow=True, startangle=90, 
                                      textprops={'fontsize': 10, 'fontweight': 'bold'})
    
    # Customize text properties
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(11)
        autotext.set_fontweight('bold')
    
    # Customize title
    ax.set_title('Attack Mitigation Breakdown (10,000 events)', 
                fontweight='bold', pad=20)
    
    # Ensure equal aspect ratio
    ax.axis('equal')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/figure3_attack_mitigation.png', 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print("Figure 3: Attack Mitigation Breakdown - Generated")

def figure4_confusion_matrix():
    """Figure 4: Confusion Matrix (Heatmap)"""
    
    # Simulated confusion matrix data for 3 classes
    # Rows: True labels, Columns: Predicted labels
    # Classes: [Normal, SQL_Injection, Brute_Force]
    confusion_matrix = np.array([
        [950, 20, 30],    # Normal: 950 correct, 20 predicted as SQLi, 30 as Brute_Force
        [15, 180, 5],     # SQL_Injection: 15 predicted as Normal, 180 correct, 5 as Brute_Force
        [25, 10, 165]     # Brute_Force: 25 predicted as Normal, 10 as SQLi, 165 correct
    ])
    
    class_names = ['Normal', 'SQL_Injection', 'Brute_Force']
    
    # Create figure
    fig, ax = plt.subplots(figsize=(8, 6))
    
    # Create heatmap
    sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names,
                cbar_kws={'label': 'Number of Samples'},
                square=True, linewidths=0.5, linecolor='white',
                annot_kws={'fontsize': 11, 'fontweight': 'bold'})
    
    # Customize plot
    ax.set_xlabel('Predicted Label', fontweight='bold')
    ax.set_ylabel('True Label', fontweight='bold')
    ax.set_title('Confusion Matrix', fontweight='bold', pad=20)
    
    # Add summary statistics
    total_samples = np.sum(confusion_matrix)
    correct_predictions = np.trace(confusion_matrix)
    accuracy = correct_predictions / total_samples
    
    # Add accuracy text
    ax.text(0.5, -0.25, f'Overall Accuracy: {accuracy:.3f} ({correct_predictions}/{total_samples})',
            transform=ax.transAxes, ha='center', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='lightblue', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/figure4_confusion_matrix.png', 
                dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print("Figure 4: Confusion Matrix - Generated")

def main():
    """Generate all figures"""
    print("Generating high-quality IEEE paper figures...")
    print("=" * 50)
    
    # Generate all figures
    figure1_model_performance()
    figure2_latency_analysis()
    figure3_attack_mitigation()
    figure4_confusion_matrix()
    
    print("=" * 50)
    print(f"Graphs generated successfully in /{output_dir}")
    print("\nGenerated files:")
    for i in range(1, 5):
        print(f"  - figure{i}_*.png")

if __name__ == "__main__":
    main()
