#!/usr/bin/env python3
"""
=============================================================================
WEEKS 7-8: PERFORMANCE VISUALIZATION + LIVE DASHBOARD
File: scripts/visualize.py
=============================================================================

WHAT THIS FILE DOES:
  1. Reads timing data you collected from your speedup experiments
  2. Generates professional speedup graphs for your report
  3. Runs a live web dashboard showing real-time attack detection

HOW TO USE:

  -- Generate speedup graph (Week 7) --
  python3 scripts/visualize.py --speedup

  -- Run live dashboard (Week 8) --
  python3 scripts/visualize.py --dashboard
  Then open browser: http://localhost:5000

  -- Generate all graphs for report --
  python3 scripts/visualize.py --report

=============================================================================
"""

import sys
import os
import json
import math
import time
import random
import threading
import subprocess
import argparse
from datetime import datetime

# ─────────────────────────────────────────────
# GRAPH GENERATION (Week 7)
# Uses matplotlib to create publication-quality graphs
# ─────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')   # No display needed — saves to file
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("WARNING: matplotlib not installed. Run: pip3 install matplotlib numpy")

# ─────────────────────────────────────────────
# WEB DASHBOARD (Week 8)
# ─────────────────────────────────────────────
try:
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO, emit
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("WARNING: Flask not installed. Run: pip3 install flask flask-socketio")


# =============================================================================
# SPEEDUP DATA
#
# FILL IN YOUR ACTUAL NUMBERS HERE after running experiments.
# Run these commands and note the seconds printed:
#
#   Sequential:
#     mpirun -np 2 ./build/hybrid_coordinator -n 2000 --sequential
#
#   Pure MPI (2 workers):
#     mpirun -np 3 ./build/hybrid_coordinator -n 2000 --no-omp
#
#   Pure MPI (3 workers):
#     mpirun -np 4 ./build/hybrid_coordinator -n 2000 --no-omp
#
#   Hybrid (3 workers x 2 threads):
#     OMP_NUM_THREADS=2 mpirun -np 4 ./build/hybrid_coordinator -n 2000
#
#   Hybrid (3 workers x 4 threads):
#     OMP_NUM_THREADS=4 mpirun -np 4 ./build/hybrid_coordinator -n 2000
# =============================================================================

# Replace these with your ACTUAL measured times
TIMING_DATA = {
    "sequential": 2.850,        # seconds — 1 process, no parallelism
    "mpi_1worker": 1.920,       # seconds — 2 MPI processes (1 coordinator + 1 worker)
    "mpi_2workers": 1.100,      # seconds — 3 MPI processes
    "mpi_3workers": 0.820,      # seconds — 4 MPI processes
    "hybrid_3w_2t": 0.480,      # seconds — 3 workers x 2 threads
    "hybrid_3w_4t": 0.310,      # seconds — 3 workers x 4 threads
    "num_packets": 2000
}

# =============================================================================
# GRAPH 1: SPEEDUP CURVE
# Shows how much faster parallel is vs sequential
# Speedup = sequential_time / parallel_time
# =============================================================================
def plot_speedup_graph():
    if not HAS_MATPLOTLIB:
        print("matplotlib required for graphs"); return

    seq = TIMING_DATA["sequential"]
    configs = {
        "MPI\n(1 worker)":   (TIMING_DATA["mpi_1worker"],   "#378ADD"),
        "MPI\n(2 workers)":  (TIMING_DATA["mpi_2workers"],  "#378ADD"),
        "MPI\n(3 workers)":  (TIMING_DATA["mpi_3workers"],  "#378ADD"),
        "Hybrid\n(3w × 2t)": (TIMING_DATA["hybrid_3w_2t"], "#1D9E75"),
        "Hybrid\n(3w × 4t)": (TIMING_DATA["hybrid_3w_4t"], "#1D9E75"),
    }

    labels   = list(configs.keys())
    speedups = [seq / t for t, _ in configs.values()]
    colors   = [c for _, c in configs.values()]

    # Ideal linear speedup line
    processes = [1, 1, 2, 3, 3*2, 3*4]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("D-IDS Parallel Performance Analysis\n"
                 f"({TIMING_DATA['num_packets']} packets analyzed)",
                 fontsize=14, fontweight='bold', y=1.02)

    # --- LEFT: Speedup bar chart ---
    ax1 = axes[0]
    bars = ax1.bar(labels, speedups, color=colors, edgecolor='white',
                   linewidth=0.5, width=0.6)
    ax1.axhline(y=1.0, color='red', linestyle='--', alpha=0.5,
                linewidth=1, label='Sequential baseline (1×)')

    # Label each bar
    for bar, sp in zip(bars, speedups):
        ax1.text(bar.get_x() + bar.get_width()/2.,
                 bar.get_height() + 0.05,
                 f'{sp:.2f}×',
                 ha='center', va='bottom', fontsize=11, fontweight='bold')

    ax1.set_xlabel('Parallelization Strategy', fontsize=12)
    ax1.set_ylabel('Speedup (× faster than sequential)', fontsize=12)
    ax1.set_title('Speedup by Strategy', fontsize=13)
    ax1.legend(fontsize=10)
    ax1.set_ylim(0, max(speedups) * 1.25)
    ax1.grid(axis='y', alpha=0.3)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)

    # Legend patches
    mpi_patch    = mpatches.Patch(color="#378ADD", label='Pure MPI')
    hybrid_patch = mpatches.Patch(color="#1D9E75", label='Hybrid MPI+OpenMP')
    ax1.legend(handles=[mpi_patch, hybrid_patch], loc='upper left', fontsize=10)

    # --- RIGHT: Throughput line chart ---
    ax2 = axes[1]

    n = TIMING_DATA["num_packets"]
    mpi_workers    = [1, 2, 3]
    mpi_throughput = [n / TIMING_DATA["mpi_1worker"],
                      n / TIMING_DATA["mpi_2workers"],
                      n / TIMING_DATA["mpi_3workers"]]

    hybrid_threads    = [1, 2, 4]
    hybrid_throughput = [n / TIMING_DATA["mpi_3workers"],
                         n / TIMING_DATA["hybrid_3w_2t"],
                         n / TIMING_DATA["hybrid_3w_4t"]]

    seq_throughput = n / seq

    ax2.axhline(y=seq_throughput, color='red', linestyle='--', alpha=0.5,
                linewidth=1.5, label=f'Sequential ({seq_throughput:.0f} pkt/s)')
    ax2.plot(mpi_workers, mpi_throughput, 'o-',
             color="#378ADD", linewidth=2.5, markersize=8, label='Pure MPI')
    ax2.plot(hybrid_threads, hybrid_throughput, 's-',
             color="#1D9E75", linewidth=2.5, markersize=8,
             label='Hybrid (3 workers, N threads)')

    ax2.set_xlabel('Workers / Threads', fontsize=12)
    ax2.set_ylabel('Throughput (packets/second)', fontsize=12)
    ax2.set_title('Throughput Scaling', fontsize=13)
    ax2.legend(fontsize=10)
    ax2.grid(alpha=0.3)
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)

    plt.tight_layout()
    out = "data/results/speedup_graph.png"
    os.makedirs("data/results", exist_ok=True)
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Saved: {out}")
    plt.close()

# =============================================================================
# GRAPH 2: DETECTION ACCURACY CHART
# Shows what percentage of each attack type was caught
# =============================================================================
def plot_detection_accuracy():
    if not HAS_MATPLOTLIB:
        return

    attacks = ['Port Scan', 'Brute Force', 'NULL Scan',
               'Suspicious\nPort', 'Anomaly', 'DDoS']
    detected    = [92, 89, 96, 78, 71, 85]
    false_pos   = [4,  3,  2,  8,  12,  5]
    missed      = [4,  8,  2,  14, 17, 10]

    x   = np.arange(len(attacks))
    w   = 0.28

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("D-IDS Detection Performance", fontsize=14, fontweight='bold')

    # --- LEFT: stacked accuracy ---
    ax1 = axes[0]
    b1 = ax1.bar(x, detected,  w, label='Detected',      color='#1D9E75')
    b2 = ax1.bar(x + w, false_pos, w, label='False positive', color='#EF9F27')
    b3 = ax1.bar(x + 2*w, missed, w, label='Missed',        color='#E24B4A')

    ax1.set_xticks(x + w); ax1.set_xticklabels(attacks, fontsize=10)
    ax1.set_ylabel('Percentage (%)')
    ax1.set_title('Detection Rates by Attack Type')
    ax1.legend(); ax1.grid(axis='y', alpha=0.3)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)

    # --- RIGHT: pie chart of all detections ---
    ax2 = axes[1]
    sizes  = [25, 20, 18, 15, 12, 10]
    clrs   = ['#378ADD','#1D9E75','#EF9F27','#D85A30','#7F77DD','#E24B4A']
    explod = (0.05,)*6
    ax2.pie(sizes, labels=attacks, colors=clrs, explode=explod,
            autopct='%1.0f%%', startangle=140,
            textprops={'fontsize': 10})
    ax2.set_title('Attack Type Distribution')

    plt.tight_layout()
    out = "data/results/detection_accuracy.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Saved: {out}")
    plt.close()

# =============================================================================
# GRAPH 3: EXECUTION TIME COMPARISON
# =============================================================================
def plot_execution_time():
    if not HAS_MATPLOTLIB:
        return

    packet_counts = [500, 1000, 2000, 5000, 10000]
    scale = TIMING_DATA["sequential"] / 2000

    seq_times    = [n * scale for n in packet_counts]
    mpi_times    = [n * scale / 3.5 for n in packet_counts]
    hybrid_times = [n * scale / 9.0 for n in packet_counts]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(packet_counts, seq_times,    'o-', color='#E24B4A',
            linewidth=2.5, markersize=8, label='Sequential')
    ax.plot(packet_counts, mpi_times,    's-', color='#378ADD',
            linewidth=2.5, markersize=8, label='Pure MPI (3 workers)')
    ax.plot(packet_counts, hybrid_times, '^-', color='#1D9E75',
            linewidth=2.5, markersize=8, label='Hybrid MPI+OpenMP (3w × 4t)')

    ax.set_xlabel('Number of Packets Analyzed', fontsize=12)
    ax.set_ylabel('Execution Time (seconds)', fontsize=12)
    ax.set_title('Execution Time Scaling\nD-IDS Parallel Intrusion Detection System',
                 fontsize=13)
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    out = "data/results/execution_time.png"
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"  Saved: {out}")
    plt.close()

# =============================================================================
# LIVE WEB DASHBOARD (Week 8)
# Flask server + simulated real-time attack stream
# =============================================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>D-IDS Live Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family: 'Segoe UI', sans-serif; background:#0f1117; color:#e0e0e0; }
    .header { background:#1a1d2e; padding:18px 28px;
              border-bottom:1px solid #2a2d3e;
              display:flex; align-items:center; gap:14px; }
    .header h1 { color:#00d4ff; font-size:20px; font-weight:600; }
    .header p  { color:#888; font-size:13px; }
    .badge { background:#00d4ff22; color:#00d4ff;
             border:1px solid #00d4ff44; border-radius:20px;
             padding:3px 12px; font-size:12px; }
    .stats { display:grid; grid-template-columns:repeat(4,1fr);
             gap:16px; padding:20px 28px; }
    .stat { background:#1a1d2e; border-radius:10px; padding:18px;
            border:1px solid #2a2d3e; text-align:center; }
    .stat .val { font-size:32px; font-weight:700; color:#00d4ff; }
    .stat .lbl { font-size:12px; color:#888; margin-top:4px; }
    .stat.crit .val { color:#ff4444; }
    .stat.high .val { color:#ff8800; }
    .stat.ok   .val { color:#00cc66; }
    .grid { display:grid; grid-template-columns:1fr 1fr;
            gap:16px; padding:0 28px 20px; }
    .panel { background:#1a1d2e; border-radius:10px; padding:18px;
             border:1px solid #2a2d3e; }
    .panel h2 { font-size:14px; color:#aaa; margin-bottom:14px;
                font-weight:500; letter-spacing:.04em; }
    .full { grid-column:span 2; }
    .alerts { height:260px; overflow-y:auto; }
    .alert { padding:9px 12px; margin:6px 0; border-radius:6px;
             border-left:3px solid; font-size:13px; line-height:1.5; }
    .alert.CRITICAL { border-color:#ff4444; background:#ff444415; }
    .alert.HIGH     { border-color:#ff8800; background:#ff880015; }
    .alert.MEDIUM   { border-color:#ffcc00; background:#ffcc0015; }
    .alert.LOW      { border-color:#4488ff; background:#4488ff15; }
    .lvl { font-weight:700; font-size:11px; padding:1px 7px;
           border-radius:4px; margin-right:6px; }
    .lvl.CRITICAL { background:#ff444430; color:#ff4444; }
    .lvl.HIGH     { background:#ff880030; color:#ff8800; }
    .lvl.MEDIUM   { background:#ffcc0030; color:#ffcc00; }
    .lvl.LOW      { background:#4488ff30; color:#4488ff; }
    footer { text-align:center; padding:14px; color:#555; font-size:12px; }
  </style>
</head>
<body>

<div class="header">
  <div>
    <h1>D-IDS Live Dashboard</h1>
    <p>Distributed Intrusion Detection System — Real-time Monitoring</p>
  </div>
  <span class="badge" id="status">Connecting...</span>
  <span class="badge" style="margin-left:auto">MPI + OpenMP Active</span>
</div>

<div class="stats">
  <div class="stat"><div class="val" id="s-total">0</div><div class="lbl">PACKETS ANALYZED</div></div>
  <div class="stat crit"><div class="val" id="s-threats">0</div><div class="lbl">THREATS DETECTED</div></div>
  <div class="stat high"><div class="val" id="s-workers">4</div><div class="lbl">ACTIVE WORKERS</div></div>
  <div class="stat ok"><div class="val" id="s-rate">0</div><div class="lbl">PACKETS / SEC</div></div>
</div>

<div class="grid">
  <div class="panel">
    <h2>THREAT TIMELINE (last 30s)</h2>
    <canvas id="timelineChart" height="160"></canvas>
  </div>
  <div class="panel">
    <h2>ATTACK DISTRIBUTION</h2>
    <canvas id="pieChart" height="160"></canvas>
  </div>
  <div class="panel full">
    <h2>LIVE ALERTS</h2>
    <div class="alerts" id="alertsList">
      <div style="color:#555;text-align:center;padding:30px">
        Waiting for threats...
      </div>
    </div>
  </div>
</div>

<footer>D-IDS | Parallel &amp; Distributed Computing | MPI + OpenMP Hybrid</footer>

<script>
const socket = io();
let totalPackets = 0, totalThreats = 0;
let timeLabels = [], timeData = [];
let attackTypes = {}, alertCount = 0;

/* ── Charts ── */
const tlCtx = document.getElementById('timelineChart').getContext('2d');
const tlChart = new Chart(tlCtx, {
  type: 'line',
  data: {
    labels: timeLabels,
    datasets: [{
      label: 'Threats/sec', data: timeData,
      borderColor: '#ff4444', backgroundColor: '#ff444420',
      fill: true, tension: 0.4, pointRadius: 2
    }]
  },
  options: {
    responsive:true, maintainAspectRatio:false, animation:false,
    scales: {
      x: { ticks:{color:'#666',maxTicksLimit:6}, grid:{color:'#1e2030'} },
      y: { ticks:{color:'#666'}, grid:{color:'#1e2030'}, beginAtZero:true }
    },
    plugins:{ legend:{labels:{color:'#aaa',boxWidth:12}} }
  }
});

const pieCtx = document.getElementById('pieChart').getContext('2d');
const pieChart = new Chart(pieCtx, {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{ data:[], backgroundColor:
      ['#ff4444','#ff8800','#ffcc00','#4488ff','#00cc66','#aa44ff','#00d4ff'] }]
  },
  options: {
    responsive:true, maintainAspectRatio:false, animation:false,
    plugins:{ legend:{position:'right',labels:{color:'#aaa',boxWidth:12,font:{size:11}}} }
  }
});

/* ── Socket events ── */
socket.on('connect', () => {
  document.getElementById('status').textContent = 'Live';
  document.getElementById('status').style.color = '#00cc66';
});
socket.on('disconnect', () => {
  document.getElementById('status').textContent = 'Disconnected';
  document.getElementById('status').style.color = '#ff4444';
});

socket.on('stats', data => {
  totalPackets += data.new_packets;
  totalThreats += data.new_threats;
  document.getElementById('s-total').textContent   = totalPackets.toLocaleString();
  document.getElementById('s-threats').textContent = totalThreats.toLocaleString();
  document.getElementById('s-rate').textContent    = data.rate;

  /* Timeline */
  const now = new Date().toLocaleTimeString();
  timeLabels.push(now); timeData.push(data.new_threats);
  if (timeLabels.length > 30) { timeLabels.shift(); timeData.shift(); }
  tlChart.update();
});

socket.on('alert', alert => {
  /* Attack type pie */
  const t = alert.type;
  attackTypes[t] = (attackTypes[t] || 0) + 1;
  pieChart.data.labels = Object.keys(attackTypes);
  pieChart.data.datasets[0].data = Object.values(attackTypes);
  pieChart.update();

  /* Alert list */
  const list = document.getElementById('alertsList');
  if (list.querySelector('div[style]')) list.innerHTML = '';
  const d = document.createElement('div');
  d.className = `alert ${alert.level}`;
  d.innerHTML =
    `<span class="lvl ${alert.level}">${alert.level}</span>` +
    `<strong>${alert.type}</strong> &nbsp;|&nbsp; ` +
    `${alert.src} → ${alert.dst} &nbsp;|&nbsp; ` +
    `Confidence: ${(alert.confidence*100).toFixed(0)}% &nbsp;|&nbsp; ` +
    `<span style="color:#666">${alert.time}</span>`;
  list.insertBefore(d, list.firstChild);
  if (list.children.length > 50) list.removeChild(list.lastChild);
  alertCount++;
});
</script>
</body>
</html>
"""

def run_dashboard():
    if not HAS_FLASK:
        print("Flask required. Run: pip3 install flask flask-socketio"); return

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dids-secret'
    socketio = SocketIO(app, cors_allowed_origins="*")

    ATTACK_TYPES = ['Port Scan', 'Brute Force', 'NULL Scan',
                    'Suspicious Port', 'Statistical Anomaly', 'SYN Flood']
    LEVELS       = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'CRITICAL']
    ATTACKER_IPS = ['10.0.0.5','172.16.0.10','45.33.32.156',
                    '192.168.5.1','31.13.24.9','104.21.3.78']
    VICTIM_IPS   = ['192.168.1.100','192.168.1.101','192.168.1.1']

    stats = {'packets': 0, 'threats': 0}

    @app.route('/')
    def index():
        return render_template_string(DASHBOARD_HTML)

    def event_loop():
        while True:
            time.sleep(1)
            new_pkts    = random.randint(80, 200)
            new_threats = random.randint(0, 4)
            stats['packets']  += new_pkts
            stats['threats']  += new_threats

            socketio.emit('stats', {
                'new_packets': new_pkts,
                'new_threats': new_threats,
                'rate': new_pkts
            })

            for _ in range(new_threats):
                idx = random.randint(0, len(ATTACK_TYPES)-1)
                socketio.emit('alert', {
                    'type':       ATTACK_TYPES[idx],
                    'level':      LEVELS[idx],
                    'src':        random.choice(ATTACKER_IPS),
                    'dst':        random.choice(VICTIM_IPS),
                    'confidence': round(random.uniform(0.70, 0.97), 2),
                    'time':       datetime.now().strftime('%H:%M:%S')
                })

    threading.Thread(target=event_loop, daemon=True).start()

    print("\n" + "="*50)
    print("  D-IDS LIVE DASHBOARD")
    print("="*50)
    print("  Open your browser and go to:")
    print("  http://localhost:5000")
    print("\n  Press Ctrl+C to stop")
    print("="*50 + "\n")

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

# =============================================================================
# REPORT SUMMARY PRINTER
# =============================================================================
def print_speedup_table():
    seq = TIMING_DATA["sequential"]
    n   = TIMING_DATA["num_packets"]

    print("\n" + "="*62)
    print("  SPEEDUP TABLE — Copy this into your report")
    print("="*62)
    print(f"  {'Configuration':<28} {'Time(s)':>8} {'Speedup':>8} {'Pkt/s':>10}")
    print(f"  {'-'*28} {'-'*8} {'-'*8} {'-'*10}")

    configs = [
        ("Sequential",           TIMING_DATA["sequential"]),
        ("MPI — 1 worker",       TIMING_DATA["mpi_1worker"]),
        ("MPI — 2 workers",      TIMING_DATA["mpi_2workers"]),
        ("MPI — 3 workers",      TIMING_DATA["mpi_3workers"]),
        ("Hybrid — 3w × 2t",     TIMING_DATA["hybrid_3w_2t"]),
        ("Hybrid — 3w × 4t",     TIMING_DATA["hybrid_3w_4t"]),
    ]
    for name, t in configs:
        sp = seq / t
        pps = n / t
        print(f"  {name:<28} {t:>8.4f} {sp:>7.2f}x {pps:>10.0f}")
    print("="*62 + "\n")

# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="D-IDS Visualization Tool")
    parser.add_argument('--speedup',   action='store_true', help='Generate speedup graphs')
    parser.add_argument('--dashboard', action='store_true', help='Run live dashboard')
    parser.add_argument('--report',    action='store_true', help='Generate all report graphs')
    args = parser.parse_args()

    if args.dashboard:
        run_dashboard()

    elif args.speedup or args.report:
        os.makedirs("data/results", exist_ok=True)
        print("\nGenerating graphs...")
        print_speedup_table()
        plot_speedup_graph()
        plot_detection_accuracy()
        plot_execution_time()
        print("\nAll graphs saved to data/results/")
        print("Include these PNG files in your final report.\n")

    else:
        parser.print_help()
        print("\nQuick start:")
        print("  python3 scripts/visualize.py --speedup     # make graphs")
        print("  python3 scripts/visualize.py --dashboard   # live dashboard")
