#!/usr/bin/env python3
"""
=============================================================================
WEEK 11 — ML DETECTOR
File: ml/ml_detector.py
=============================================================================

WHAT THIS DOES:
  Loads the trained model (ml/model.pkl) and runs it on new packets.
  Combines ML predictions with signature detection results.
  Outputs final threat report.

  This is the INFERENCE step — using the trained model to detect threats
  in packets it has never seen before.

RUN:
  python3 ml/ml_detector.py --csv data/logs/packets.csv
  python3 ml/ml_detector.py --csv data/logs/attack.csv
=============================================================================
"""

import os
import sys
import csv
import pickle
import argparse
import numpy as np
from datetime import datetime

# ── Imports ───────────────────────────────────────────────────
try:
    from sklearn.ensemble import RandomForestClassifier
except ImportError:
    print("Run: pip3 install scikit-learn --break-system-packages")
    sys.exit(1)

# ── Bad ports (must match train_model.py) ─────────────────────
BAD_PORTS   = {4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080}
LOGIN_PORTS = {22, 23, 21, 3389, 5900}

# ═══════════════════════════════════════════════════════════════
# FEATURE EXTRACTION — must match train_model.py exactly
# ═══════════════════════════════════════════════════════════════
def extract_features(row, size_mean=512.0, size_std=256.0):
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

    size_z = abs(size - size_mean) / (size_std + 1.0)

    return np.array([
        proto / 17.0,
        src_port / 65535.0,
        dst_port / 65535.0,
        size / 65535.0,
        float(syn),
        float(ack),
        float(fin),
        float(rst),
        float(psh),
        float(dst_port < 1024),
        float(dst_port in BAD_PORTS or src_port in BAD_PORTS),
        min(size_z, 10.0) / 10.0,
    ], dtype=np.float32)

# ═══════════════════════════════════════════════════════════════
# SIGNATURE DETECTION — same rules as C code
# ═══════════════════════════════════════════════════════════════
def signature_detect(row):
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
        src_ip   = row.get('src_ip', '')
        dst_ip   = row.get('dst_ip', '')
    except (ValueError, KeyError):
        return None

    if proto == 6 and not syn and not ack and not fin and not rst and not psh:
        return {'type':'NULL Scan','level':'MEDIUM',
                'src':src_ip,'dst':dst_ip,'confidence':85,
                'engine':'Signature'}

    if dst_port in BAD_PORTS or src_port in BAD_PORTS:
        port = dst_port if dst_port in BAD_PORTS else src_port
        return {'type':'Suspicious Port','level':'MEDIUM',
                'src':src_ip,'dst':dst_ip,'confidence':75,
                'engine':'Signature',
                'desc':f'Port {port}'}

    if proto == 6 and syn and dst_port in LOGIN_PORTS:
        svc = {22:'SSH',3389:'RDP',21:'FTP',23:'Telnet'}.get(dst_port,'service')
        return {'type':f'Brute Force ({svc})','level':'HIGH',
                'src':src_ip,'dst':dst_ip,'confidence':70,
                'engine':'Signature'}

    if size > 5000:
        return {'type':'Statistical Anomaly','level':'MEDIUM',
                'src':src_ip,'dst':dst_ip,'confidence':65,
                'engine':'Signature'}

    return None

# ═══════════════════════════════════════════════════════════════
# ENSEMBLE: COMBINE SIGNATURE + ML
#
# VOTING RULES:
#   Both detect   → HIGH confidence (two engines agree)
#   Signature only → use signature result as-is
#   ML only        → use ML result with slightly lower confidence
#   Neither        → normal traffic
# ═══════════════════════════════════════════════════════════════
def ensemble_detect(row, model, scaler, size_mean, size_std):
    src_ip = row.get('src_ip', '?')
    dst_ip = row.get('dst_ip', '?')

    # Run signature engine
    sig_result = signature_detect(row)

    # Run ML engine
    features = extract_features(row, size_mean, size_std)
    features_scaled = scaler.transform(features.reshape(1, -1))
    ml_pred  = model.predict(features_scaled)[0]
    ml_proba = model.predict_proba(features_scaled)[0]
    ml_conf  = int(ml_proba[1] * 100)  # probability of being attack

    ml_result = None
    if ml_pred == 1:
        ml_result = {
            'type':       'ML Detected Threat',
            'level':      'HIGH' if ml_conf >= 75 else 'MEDIUM',
            'src':        src_ip,
            'dst':        dst_ip,
            'confidence': ml_conf,
            'engine':     'ML',
        }

    # Ensemble decision
    if sig_result and ml_result:
        # Both fired → boost confidence
        final = sig_result.copy()
        final['confidence'] = min(95, (sig_result['confidence'] + ml_conf) // 2 + 10)
        final['engine']     = 'Signature + ML'
        if final['level'] == 'MEDIUM':
            final['level'] = 'HIGH'
        return final

    elif sig_result:
        sig_result['engine'] = 'Signature'
        return sig_result

    elif ml_result:
        return ml_result

    return None   # no threat

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description='D-IDS ML Detector — Week 11')
    parser.add_argument('--csv',   default='data/logs/packets.csv',
                        help='CSV file to analyze')
    parser.add_argument('--model', default='ml/model.pkl',
                        help='Trained model file')
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   D-IDS ML DETECTOR — Week 11                    ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # Load model
    if not os.path.exists(args.model):
        print(f"ERROR: Model not found: {args.model}")
        print("Train first: python3 ml/train_model.py --csv data/logs/packets.csv")
        sys.exit(1)

    with open(args.model, 'rb') as f:
        payload = pickle.load(f)

    model      = payload['model']
    scaler     = payload['scaler']
    size_mean  = payload['metrics']['size_mean']
    size_std   = payload['metrics']['size_std']
    trained_at = payload.get('trained_at', 'unknown')

    print(f"  Model loaded from : {args.model}")
    print(f"  Trained at        : {trained_at}")
    print(f"  Training accuracy : {payload['metrics']['accuracy']*100:.1f}%")

    # Load CSV
    if not os.path.exists(args.csv):
        print(f"\nERROR: CSV not found: {args.csv}")
        sys.exit(1)

    rows = []
    with open(args.csv, 'r') as f:
        reader = csv.DictReader(f)
        rows   = list(reader)

    print(f"  Packets to analyze: {len(rows)}")
    print()
    print(f"  Running ensemble detection (Signature + ML)...")
    print()

    # Analyze each packet
    threats   = []
    col_w     = 25

    print(f"  {'#':<5} {'TYPE':<25} {'LEVEL':<10} {'CONF':>5} "
          f"{'ENGINE':<18} {'SRC IP'}")
    print(f"  {'─'*5} {'─'*25} {'─'*10} {'─'*5} {'─'*18} {'─'*15}")

    for i, row in enumerate(rows):
        result = ensemble_detect(row, model, scaler, size_mean, size_std)
        if result:
            threats.append(result)
            # Color by level
            color = ('\033[1;31m' if result['level'] == 'CRITICAL' else
                     '\033[0;31m' if result['level'] == 'HIGH'     else
                     '\033[0;33m')
            reset = '\033[0m'
            print(f"  {color}{i+1:<5} "
                  f"{result['type']:<25} "
                  f"{result['level']:<10} "
                  f"{result['confidence']:>4}% "
                  f"{result['engine']:<18} "
                  f"{result['src']}{reset}")

    # Summary
    if not threats:
        print("  No threats detected.")
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   DETECTION SUMMARY                              ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Packets analyzed:    {len(rows):<27}║")
    print(f"║  Threats detected:    {len(threats):<27}║")

    # Count by engine
    sig_only = sum(1 for t in threats if t['engine'] == 'Signature')
    ml_only  = sum(1 for t in threats if t['engine'] == 'ML')
    both     = sum(1 for t in threats if '+' in t['engine'])
    print(f"║  ├── Signature only:  {sig_only:<27}║")
    print(f"║  ├── ML only:         {ml_only:<27}║")
    print(f"║  └── Both (ensemble): {both:<27}║")

    # Count by level
    high     = sum(1 for t in threats if t['level'] in ('HIGH','CRITICAL'))
    medium   = sum(1 for t in threats if t['level'] == 'MEDIUM')
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  High/Critical:       {high:<27}║")
    print(f"║  Medium:              {medium:<27}║")
    det_rate = len(threats)/len(rows)*100 if rows else 0
    print(f"║  Detection rate:      {det_rate:<24.1f}%  ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

if __name__ == '__main__':
    main()
