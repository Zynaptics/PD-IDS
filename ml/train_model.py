#!/usr/bin/env python3
"""
=============================================================================
WEEK 11 — MACHINE LEARNING DETECTION MODULE
File: ml/train_model.py
=============================================================================

WHAT THIS DOES:
  1. Loads your captured CSV packets
  2. Extracts features from each packet
  3. Labels packets as normal (0) or attack (1) using signature rules
  4. Trains a Random Forest classifier
  5. Evaluates accuracy, precision, recall
  6. Saves the trained model to ml/model.pkl
  7. Generates a performance graph

WHY RANDOM FOREST?
  - Works well on small datasets (your 50-200 captured packets)
  - No need for GPU or huge training data
  - Gives feature importance scores (shows WHICH features matter most)
  - Fast to train and predict
  - Interpretable — you can explain it to your teacher

HOW ML DETECTION WORKS:
  Traditional signature detection:
    if port == 4444: alert()   ← manually written rules

  ML detection:
    model.predict(features)    ← learned from data automatically
    The model figures out the rules itself from examples.

FEATURES WE USE (what we feed into the model):
  1.  Protocol (TCP=6, UDP=17, ICMP=1)
  2.  Source port (normalized 0-1)
  3.  Destination port (normalized 0-1)
  4.  Packet size (normalized)
  5.  SYN flag
  6.  ACK flag
  7.  FIN flag
  8.  RST flag
  9.  PSH flag
  10. Is destination port < 1024 (privileged port)
  11. Is destination port a known bad port
  12. Packet size z-score (how unusual is the size)

RUN:
  python3 ml/train_model.py --csv data/logs/packets.csv
  python3 ml/train_model.py --csv data/logs/attack.csv
  python3 ml/train_model.py --csv data/logs/attack.csv --csv data/logs/packets.csv
=============================================================================
"""

import os
import sys
import csv
import math
import pickle
import argparse
import random
from datetime import datetime

# ── Check dependencies ────────────────────────────────────────
try:
    import numpy as np
except ImportError:
    print("Run: pip3 install numpy --break-system-packages")
    sys.exit(1)

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (classification_report, confusion_matrix,
                                  accuracy_score, precision_score,
                                  recall_score, f1_score)
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("Run: pip3 install scikit-learn --break-system-packages")
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False
    print("WARNING: matplotlib not found. Graphs will be skipped.")
    print("Install: pip3 install matplotlib --break-system-packages")

# ═══════════════════════════════════════════════════════════════
# KNOWN BAD PORTS (used for labeling + feature extraction)
# ═══════════════════════════════════════════════════════════════
BAD_PORTS = {4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080}
LOGIN_PORTS = {22, 23, 21, 3389, 5900}

# ═══════════════════════════════════════════════════════════════
# STEP 1: LOAD CSV
# ═══════════════════════════════════════════════════════════════
def load_csv(paths):
    """
    Load one or more CSV files written by packet_capture_csv.
    Returns list of row dicts.
    """
    rows = []
    for path in paths:
        if not os.path.exists(path):
            print(f"  WARNING: File not found: {path}")
            continue
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            file_rows = list(reader)
            rows.extend(file_rows)
            print(f"  Loaded {len(file_rows):>5} packets from {path}")
    return rows

# ═══════════════════════════════════════════════════════════════
# STEP 2: AUTO-LABEL
# Uses the same signature rules as signature_detection.c to
# label each packet as 0 (normal) or 1 (attack).
# This creates our training labels automatically.
# ═══════════════════════════════════════════════════════════════
def auto_label(row):
    """
    Returns 1 if packet looks like an attack, 0 if normal.
    This mirrors the C detection logic so ML learns the same patterns.
    """
    try:
        proto    = int(row.get('protocol', 0))
        dst_port = int(row.get('dst_port', 0))
        src_port = int(row.get('src_port', 0))
        size     = int(row.get('size', 0))
        syn      = int(row.get('syn', 0))
        ack      = int(row.get('ack', 0))
        fin      = int(row.get('fin', 0))
        rst      = int(row.get('rst', 0))
        psh      = int(row.get('psh', 0))
    except (ValueError, KeyError):
        return 0

    # NULL scan — TCP with no flags
    if proto == 6 and not syn and not ack and not fin and not rst and not psh:
        return 1

    # Known bad port
    if dst_port in BAD_PORTS or src_port in BAD_PORTS:
        return 1

    # Brute force target (SSH/RDP with SYN)
    if proto == 6 and syn and dst_port in LOGIN_PORTS:
        return 1

    # Anomalously large packet
    if size > 5000:
        return 1

    return 0

# ═══════════════════════════════════════════════════════════════
# STEP 3: FEATURE EXTRACTION
# Converts a raw CSV row into a numeric feature vector.
# The ML model only understands numbers, not strings.
# ═══════════════════════════════════════════════════════════════
def extract_features(row, size_mean=512.0, size_std=256.0):
    """
    Extracts 12 numeric features from one packet row.

    Returns numpy array of shape (12,)
    """
    try:
        proto    = int(row.get('protocol', 0))
        dst_port = int(row.get('dst_port', 0))
        src_port = int(row.get('src_port', 0))
        size     = int(row.get('size', 0))
        syn      = int(row.get('syn', 0))
        ack      = int(row.get('ack', 0))
        fin      = int(row.get('fin', 0))
        rst      = int(row.get('rst', 0))
        psh      = int(row.get('psh', 0))
    except (ValueError, KeyError):
        return np.zeros(12)

    # Size z-score: how many std deviations from mean?
    size_z = abs(size - size_mean) / (size_std + 1.0)

    features = [
        proto / 17.0,               # 1. protocol (normalized)
        src_port / 65535.0,         # 2. source port (normalized)
        dst_port / 65535.0,         # 3. destination port (normalized)
        size / 65535.0,             # 4. packet size (normalized)
        float(syn),                 # 5. SYN flag
        float(ack),                 # 6. ACK flag
        float(fin),                 # 7. FIN flag
        float(rst),                 # 8. RST flag
        float(psh),                 # 9. PSH flag
        float(dst_port < 1024),     # 10. privileged port?
        float(dst_port in BAD_PORTS or src_port in BAD_PORTS),  # 11. bad port?
        min(size_z, 10.0) / 10.0,  # 12. size anomaly score (capped at 10)
    ]
    return np.array(features, dtype=np.float32)

# ═══════════════════════════════════════════════════════════════
# STEP 4: AUGMENT DATA
# If we have very few attack samples, we augment (create
# synthetic variations) so the model has enough to learn from.
# ═══════════════════════════════════════════════════════════════
def augment_attacks(rows, target_count=50):
    """
    If fewer than target_count attack packets exist,
    create synthetic variants by adding small random noise.
    """
    attacks = [r for r in rows if auto_label(r) == 1]
    normal  = [r for r in rows if auto_label(r) == 0]

    if len(attacks) == 0:
        # No real attacks — generate some synthetic ones for training
        print("  No real attacks in data — generating synthetic attack samples...")
        synthetic = []
        attack_templates = [
            # NULL scan
            {'protocol':'6','src_port':'60000','dst_port':'22','size':'40',
             'syn':'0','ack':'0','fin':'0','rst':'0','psh':'0',
             'src_ip':'10.0.0.5','dst_ip':'192.168.1.1','timestamp':'0'},
            # Bad port
            {'protocol':'6','src_port':'60001','dst_port':'4444','size':'64',
             'syn':'1','ack':'0','fin':'0','rst':'0','psh':'0',
             'src_ip':'10.0.0.5','dst_ip':'192.168.1.1','timestamp':'0'},
            # Huge packet
            {'protocol':'6','src_port':'60002','dst_port':'80','size':'60000',
             'syn':'1','ack':'0','fin':'0','rst':'0','psh':'0',
             'src_ip':'10.0.0.5','dst_ip':'192.168.1.1','timestamp':'0'},
            # SSH brute force
            {'protocol':'6','src_port':'60003','dst_port':'22','size':'64',
             'syn':'1','ack':'0','fin':'0','rst':'0','psh':'0',
             'src_ip':'172.16.0.10','dst_ip':'192.168.1.1','timestamp':'0'},
        ]
        for _ in range(target_count):
            t = random.choice(attack_templates).copy()
            # Add small variation
            t['src_port'] = str(int(t['src_port']) + random.randint(0, 1000))
            synthetic.append(t)
        attacks = synthetic

    elif len(attacks) < target_count:
        # Augment existing attacks
        extra = []
        while len(attacks) + len(extra) < target_count:
            base = random.choice(attacks).copy()
            extra.append(base)
        attacks = attacks + extra

    return normal + attacks

# ═══════════════════════════════════════════════════════════════
# STEP 5: TRAIN MODEL
# ═══════════════════════════════════════════════════════════════
def train(rows):
    """
    Trains a RandomForestClassifier on the given packet rows.
    Returns (model, scaler, metrics_dict)
    """
    print(f"\n  Building dataset from {len(rows)} packets...")

    # Compute size statistics for z-score feature
    sizes     = [int(r.get('size', 512)) for r in rows]
    size_mean = float(np.mean(sizes))
    size_std  = float(np.std(sizes)) if np.std(sizes) > 0 else 256.0

    # Extract features and labels
    X = np.array([extract_features(r, size_mean, size_std) for r in rows])
    y = np.array([auto_label(r) for r in rows])

    n_attack = int(y.sum())
    n_normal = int(len(y) - n_attack)
    print(f"  Normal packets:  {n_normal}")
    print(f"  Attack packets:  {n_attack}")
    print(f"  Total features:  {X.shape[1]}")

    if n_attack == 0:
        print("\n  WARNING: No attack packets found.")
        print("  Try: python3 ml/train_model.py --csv data/logs/attack.csv")
        print("  Or run: sudo nmap -sN 127.0.0.1 while capturing\n")

    # Split into train/test sets
    # test_size=0.2 means 20% for testing, 80% for training
    if len(X) < 10:
        print("  Too few samples for train/test split — using all for training.")
        X_train, X_test, y_train, y_test = X, X, y, y
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y if n_attack > 1 else None
        )

    # Scale features (mean=0, std=1)
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # Train Random Forest
    # n_estimators=100 means 100 decision trees vote on each prediction
    print("\n  Training Random Forest (100 trees)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced',  # handles imbalanced normal/attack ratio
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    metrics = {
        'accuracy':  acc,
        'precision': prec,
        'recall':    rec,
        'f1':        f1,
        'n_train':   len(X_train),
        'n_test':    len(X_test),
        'n_attack':  n_attack,
        'n_normal':  n_normal,
        'size_mean': size_mean,
        'size_std':  size_std,
    }

    return model, scaler, metrics, X_test, y_test, y_pred

# ═══════════════════════════════════════════════════════════════
# STEP 6: PRINT RESULTS
# ═══════════════════════════════════════════════════════════════
def print_results(metrics, model, y_test, y_pred):
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   ML MODEL TRAINING RESULTS                      ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Training samples:  {metrics['n_train']:<29}║")
    print(f"║  Test samples:      {metrics['n_test']:<29}║")
    print(f"║  Attack packets:    {metrics['n_attack']:<29}║")
    print(f"║  Normal packets:    {metrics['n_normal']:<29}║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Accuracy:          {metrics['accuracy']*100:>5.1f}%                      ║")
    print(f"║  Precision:         {metrics['precision']*100:>5.1f}%                      ║")
    print(f"║  Recall:            {metrics['recall']*100:>5.1f}%                      ║")
    print(f"║  F1 Score:          {metrics['f1']*100:>5.1f}%                      ║")
    print("╠══════════════════════════════════════════════════╣")

    # Feature importance
    feat_names = [
        'Protocol','Src Port','Dst Port','Pkt Size',
        'SYN','ACK','FIN','RST','PSH',
        'Priv Port','Bad Port','Size Z-score'
    ]
    importances = model.feature_importances_
    top3 = sorted(zip(feat_names, importances),
                  key=lambda x: x[1], reverse=True)[:3]
    print("║  Top 3 features:                                 ║")
    for name, imp in top3:
        print(f"║    {name:<20} {imp*100:>5.1f}%                   ║")
    print("╚══════════════════════════════════════════════════╝")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\n  Confusion Matrix:")
    print("                 Predicted Normal  Predicted Attack")
    if cm.shape == (2, 2):
        print(f"  Actual Normal   {cm[0][0]:>14}  {cm[0][1]:>16}")
        print(f"  Actual Attack   {cm[1][0]:>14}  {cm[1][1]:>16}")
    print()

# ═══════════════════════════════════════════════════════════════
# STEP 7: SAVE MODEL
# ═══════════════════════════════════════════════════════════════
def save_model(model, scaler, metrics):
    os.makedirs('ml', exist_ok=True)
    payload = {
        'model':     model,
        'scaler':    scaler,
        'metrics':   metrics,
        'trained_at': datetime.now().isoformat(),
        'feature_names': [
            'protocol','src_port','dst_port','pkt_size',
            'syn','ack','fin','rst','psh',
            'priv_port','bad_port','size_zscore'
        ],
    }
    path = 'ml/model.pkl'
    with open(path, 'wb') as f:
        pickle.dump(payload, f)
    print(f"  Model saved → {path}")
    return path

# ═══════════════════════════════════════════════════════════════
# STEP 8: GENERATE GRAPHS
# ═══════════════════════════════════════════════════════════════
def plot_results(model, metrics, y_test, y_pred):
    if not HAS_PLOT:
        return
    os.makedirs('data/results', exist_ok=True)

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle('D-IDS ML Detection Results — Week 11',
                 fontsize=14, fontweight='bold')

    # ── Chart 1: Performance metrics bar chart ──
    ax1 = axes[0]
    metrics_names  = ['Accuracy','Precision','Recall','F1 Score']
    metrics_values = [
        metrics['accuracy']  * 100,
        metrics['precision'] * 100,
        metrics['recall']    * 100,
        metrics['f1']        * 100,
    ]
    colors = ['#3fb950','#58a6ff','#d29922','#bc8cff']
    bars = ax1.bar(metrics_names, metrics_values,
                   color=colors, edgecolor='#30363d', linewidth=0.5)
    for bar, val in zip(bars, metrics_values):
        ax1.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + 1,
                 f'{val:.1f}%',
                 ha='center', va='bottom', fontsize=11, fontweight='bold')
    ax1.set_ylim(0, 115)
    ax1.set_ylabel('Percentage (%)')
    ax1.set_title('Detection Performance')
    ax1.set_facecolor('#0d1117')
    ax1.tick_params(colors='#8b949e')
    for spine in ax1.spines.values():
        spine.set_color('#30363d')
    ax1.grid(axis='y', alpha=0.3, color='#30363d')

    # ── Chart 2: Feature importance ──
    ax2 = axes[1]
    feat_names = [
        'Protocol','Src Port','Dst Port','Pkt Size',
        'SYN','ACK','FIN','RST','PSH',
        'Priv Port','Bad Port','Size Z'
    ]
    importances = model.feature_importances_
    sorted_idx  = importances.argsort()[::-1][:8]
    ax2.barh(
        [feat_names[i] for i in sorted_idx[::-1]],
        importances[sorted_idx[::-1]] * 100,
        color='#58a6ff', edgecolor='#30363d', linewidth=0.5
    )
    ax2.set_xlabel('Importance (%)')
    ax2.set_title('Feature Importance\n(which features matter most)')
    ax2.set_facecolor('#0d1117')
    ax2.tick_params(colors='#8b949e')
    for spine in ax2.spines.values():
        spine.set_color('#30363d')
    ax2.grid(axis='x', alpha=0.3, color='#30363d')

    # ── Chart 3: Confusion matrix ──
    ax3 = axes[2]
    cm = confusion_matrix(y_test, y_pred)
    if cm.shape == (2, 2):
        im = ax3.imshow(cm, cmap='Blues', aspect='auto')
        ax3.set_xticks([0, 1])
        ax3.set_yticks([0, 1])
        ax3.set_xticklabels(['Normal', 'Attack'], color='#8b949e')
        ax3.set_yticklabels(['Normal', 'Attack'], color='#8b949e')
        ax3.set_xlabel('Predicted', color='#8b949e')
        ax3.set_ylabel('Actual', color='#8b949e')
        ax3.set_title('Confusion Matrix')
        for i in range(2):
            for j in range(2):
                ax3.text(j, i, str(cm[i, j]),
                         ha='center', va='center',
                         fontsize=16, fontweight='bold',
                         color='white' if cm[i,j] > cm.max()/2 else 'black')
    ax3.set_facecolor('#0d1117')
    for spine in ax3.spines.values():
        spine.set_color('#30363d')

    fig.patch.set_facecolor('#0d1117')
    plt.tight_layout()

    out = 'data/results/ml_results.png'
    plt.savefig(out, dpi=150, bbox_inches='tight',
                facecolor='#0d1117')
    plt.close()
    print(f"  Graph saved → {out}")

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='D-IDS ML Trainer — Week 11')
    parser.add_argument('--csv', nargs='+',
                        default=['data/logs/packets.csv'],
                        help='CSV file(s) to train on')
    parser.add_argument('--no-augment', action='store_true',
                        help='Disable data augmentation')
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   D-IDS ML TRAINER — Week 11                     ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # Load data
    rows = load_csv(args.csv)
    if not rows:
        print("\nERROR: No data loaded. Check CSV file paths.\n")
        sys.exit(1)

    # Augment if needed
    if not args.no_augment:
        rows = augment_attacks(rows, target_count=60)
        print(f"  After augmentation: {len(rows)} total samples")

    # Train
    model, scaler, metrics, X_test, y_test, y_pred = train(rows)

    # Print results
    print_results(metrics, model, y_test, y_pred)

    # Save model
    save_model(model, scaler, metrics)

    # Generate graphs
    if HAS_PLOT:
        print("  Generating graphs...")
        plot_results(model, metrics, y_test, y_pred)

    print()
    print("  Next step:")
    print("  python3 ml/ml_detector.py --csv data/logs/packets.csv")
    print()
