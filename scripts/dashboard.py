#!/usr/bin/env python3
"""
=============================================================================
WEEK 10 — COMPLETE D-IDS DASHBOARD
File: scripts/dashboard.py
=============================================================================

WHAT THIS FILE DOES:
  Full web dashboard that shows:
    Tab 1 — Live Monitor   : real packet alerts, threat timeline, attack pie
    Tab 2 — Speedup        : bar charts comparing sequential vs MPI vs hybrid
    Tab 3 — Top Attackers  : table of most active attacker IPs
    Tab 4 — Report         : download full PDF/text report

TWO DATA MODES:
  1. Real CSV mode  — reads your actual captured packets.csv
     python3 scripts/dashboard.py --csv data/logs/packets.csv

  2. Simulated mode — generates realistic fake traffic (default)
     python3 scripts/dashboard.py

HOW TO RUN:
  python3 scripts/dashboard.py
  python3 scripts/dashboard.py --csv data/logs/packets.csv
  python3 scripts/dashboard.py --csv data/logs/attack.csv --port 5000

OPEN BROWSER:
  http://localhost:5000

STOP:
  Ctrl+C
=============================================================================
"""

import os
import io
import csv
import sys
import time
import random
import threading
import argparse
from datetime import datetime
from collections import defaultdict

# ── Flask ──────────────────────────────────────────────────────
try:
    from flask import Flask, render_template_string, jsonify, send_file
    from flask_socketio import SocketIO
except ImportError:
    print("\nERROR: Flask not installed.")
    print("Run: pip3 install flask flask-socketio --break-system-packages\n")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
# SPEEDUP DATA
# Replace these numbers with your ACTUAL measured times after
# running the speedup experiment commands shown below.
#
# HOW TO GET REAL NUMBERS:
#   Sequential:
#     mpirun --oversubscribe -np 2 ./build/coordinator_real -n 2000 --sequential
#   MPI 1 worker:
#     mpirun --oversubscribe -np 2 ./build/coordinator_real -n 2000
#   MPI 2 workers:
#     mpirun --oversubscribe -np 3 ./build/coordinator_real -n 2000
#   MPI 3 workers:
#     mpirun --oversubscribe -np 4 ./build/coordinator_real -n 2000
#   Hybrid 3w x 2t:
#     OMP_NUM_THREADS=2 mpirun --oversubscribe -np 4 ./build/coordinator_real -n 2000
#   Hybrid 3w x 4t:
#     OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 ./build/coordinator_real -n 2000
# ══════════════════════════════════════════════════════════════
SPEEDUP = {
    'labels': [
        'Sequential',
        'MPI\n1 worker',
        'MPI\n2 workers',
        'MPI\n3 workers',
        'Hybrid\n3w × 2t',
        'Hybrid\n3w × 4t',
    ],
    'times':   [2.850, 1.920, 1.100, 0.820, 0.480, 0.310],
    'packets': 2000,
}

# ══════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════
state = {
    'total_packets': 0,
    'total_threats': 0,
    'critical':      0,
    'high':          0,
    'medium':        0,
    'low':           0,
    'start_time':    time.time(),
    'alerts':        [],               # newest first, max 100
    'attack_counts': defaultdict(int), # { 'Port Scan': 5, ... }
    'src_ip_counts': defaultdict(int), # { '10.0.0.5': 12, ... }
    'timeline':      [],               # [ {time, threats, packets}, ... ]
    'data_mode':     'Simulated',
}
state_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════
# DETECTION — runs on real CSV rows
# ══════════════════════════════════════════════════════════════
def detect_threat(row):
    """
    Runs basic detection on one CSV row.
    Returns a threat dict or None if traffic looks normal.

    CSV columns:
      timestamp, src_ip, src_port, dst_ip, dst_port,
      protocol, size, syn, ack, fin, rst, psh
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
        src_ip   = row.get('src_ip', '0.0.0.0')
        dst_ip   = row.get('dst_ip', '0.0.0.0')
    except (ValueError, KeyError):
        return None

    # ── NULL scan: TCP with zero flags ──
    if proto == 6 and not syn and not ack and not fin and not rst and not psh:
        return {
            'type':       'NULL Scan',
            'level':      'MEDIUM',
            'src':        src_ip,
            'dst':        dst_ip,
            'confidence': 85,
            'desc':       f'TCP NULL scan → {dst_ip}:{dst_port}',
        }

    # ── Suspicious / malware ports ──
    bad_ports = {4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080}
    if dst_port in bad_ports or src_port in bad_ports:
        port = dst_port if dst_port in bad_ports else src_port
        return {
            'type':       'Suspicious Port',
            'level':      'MEDIUM',
            'src':        src_ip,
            'dst':        dst_ip,
            'confidence': 75,
            'desc':       f'Known malware port {port}: {src_ip} → {dst_ip}',
        }

    # ── Brute force SSH / RDP ──
    if proto == 6 and syn and dst_port in {22, 3389, 21, 23}:
        svc = {22:'SSH', 3389:'RDP', 21:'FTP', 23:'Telnet'}.get(dst_port, 'service')
        return {
            'type':       f'Brute Force ({svc})',
            'level':      'HIGH',
            'src':        src_ip,
            'dst':        dst_ip,
            'confidence': 70,
            'desc':       f'{svc} connection attempt from {src_ip}',
        }

    # ── Anomalous oversized packet ──
    if size > 5000:
        return {
            'type':       'Statistical Anomaly',
            'level':      'MEDIUM',
            'src':        src_ip,
            'dst':        dst_ip,
            'confidence': 65,
            'desc':       f'Oversized packet ({size} B) from {src_ip}',
        }

    return None   # normal traffic

def register_threat(threat):
    """Add a detected threat to global state."""
    lvl = threat['level']
    state['total_threats'] += 1
    if   lvl == 'CRITICAL': state['critical'] += 1
    elif lvl == 'HIGH':     state['high']     += 1
    elif lvl == 'MEDIUM':   state['medium']   += 1
    else:                   state['low']       += 1

    state['attack_counts'][threat['type']] += 1
    state['src_ip_counts'][threat['src']]  += 1

    alert = {**threat, 'time': datetime.now().strftime('%H:%M:%S')}
    state['alerts'].insert(0, alert)
    if len(state['alerts']) > 100:
        state['alerts'].pop()

    return alert

# ══════════════════════════════════════════════════════════════
# BACKGROUND THREAD — REAL CSV MODE
# Re-reads the CSV every 3 seconds in batches of 10 packets.
# Simulates a live stream by replaying the file in a loop.
# ══════════════════════════════════════════════════════════════
def csv_loop(csv_path):
    # Load all rows once
    rows = []
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except FileNotFoundError:
        print(f"\n  ERROR: File not found: {csv_path}")
        print("  Falling back to simulated mode.\n")
        simulate_loop()
        return

    if not rows:
        print(f"\n  WARNING: {csv_path} is empty. Falling back to simulated mode.\n")
        simulate_loop()
        return

    print(f"\n  Loaded {len(rows)} real packets from {csv_path}")
    state['data_mode'] = f'Real CSV ({len(rows)} packets)'

    idx       = 0
    BATCH     = 10   # packets per cycle

    while True:
        time.sleep(3)   # update every 3 seconds

        batch = []
        for _ in range(BATCH):
            batch.append(rows[idx % len(rows)])
            idx += 1

        new_threats = 0
        new_alerts  = []

        with state_lock:
            state['total_packets'] += len(batch)
            for row in batch:
                threat = detect_threat(row)
                if threat:
                    alert = register_threat(threat)
                    new_alerts.append(alert)
                    new_threats += 1

            elapsed = max(time.time() - state['start_time'], 1)
            rate    = int(state['total_packets'] / elapsed)

            state['timeline'].append({
                'time':    datetime.now().strftime('%H:%M:%S'),
                'threats': new_threats,
                'packets': len(batch),
            })
            if len(state['timeline']) > 20:
                state['timeline'].pop(0)

            snap = _snapshot(rate, len(batch), new_threats)

        # Emit to browser
        socketio.emit('stats', snap)
        for alert in new_alerts:
            socketio.emit('alert', alert)

# ══════════════════════════════════════════════════════════════
# BACKGROUND THREAD — SIMULATED MODE (default)
# Generates realistic-looking mixed traffic with random attacks.
# ══════════════════════════════════════════════════════════════
ATTACK_TYPES = ['Port Scan','Brute Force','NULL Scan',
                'Suspicious Port','SYN Flood','Statistical Anomaly']
LEVELS       = ['HIGH','HIGH','MEDIUM','MEDIUM','CRITICAL','MEDIUM']
ATTACKER_IPS = ['10.0.0.5','172.16.0.10','45.33.32.156',
                '192.168.5.1','31.13.24.9','104.21.3.78']
VICTIM_IPS   = ['192.168.1.100','192.168.1.101','192.168.1.1']

def simulate_loop():
    state['data_mode'] = 'Simulated'
    while True:
        time.sleep(3)

        new_pkts    = random.randint(120, 280)
        new_threats = random.randint(0, 3)
        new_alerts  = []

        with state_lock:
            state['total_packets'] += new_pkts
            for _ in range(new_threats):
                idx    = random.randint(0, len(ATTACK_TYPES)-1)
                threat = {
                    'type':       ATTACK_TYPES[idx],
                    'level':      LEVELS[idx],
                    'src':        random.choice(ATTACKER_IPS),
                    'dst':        random.choice(VICTIM_IPS),
                    'confidence': random.randint(70, 97),
                    'desc':       f'{ATTACK_TYPES[idx]} detected',
                }
                alert = register_threat(threat)
                new_alerts.append(alert)

            elapsed = max(time.time() - state['start_time'], 1)
            rate    = int(state['total_packets'] / elapsed)

            state['timeline'].append({
                'time':    datetime.now().strftime('%H:%M:%S'),
                'threats': new_threats,
                'packets': new_pkts,
            })
            if len(state['timeline']) > 20:
                state['timeline'].pop(0)

            snap = _snapshot(rate, new_pkts, new_threats)

        socketio.emit('stats', snap)
        for alert in new_alerts:
            socketio.emit('alert', alert)

def _snapshot(rate, new_pkts, new_threats):
    """Build a stats snapshot dict to send to the browser."""
    top = dict(
        sorted(state['src_ip_counts'].items(),
               key=lambda x: x[1], reverse=True)[:6]
    )
    return {
        'total_packets':  state['total_packets'],
        'total_threats':  state['total_threats'],
        'critical':       state['critical'],
        'high':           state['high'],
        'medium':         state['medium'],
        'rate':           rate,
        'new_pkts':       new_pkts,
        'new_threats':    new_threats,
        'attack_counts':  dict(state['attack_counts']),
        'top_attackers':  top,
        'data_mode':      state['data_mode'],
    }

# ══════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════════════════════
def make_report():
    """
    Generates a text report. If fpdf2 is installed, makes a real PDF.
    Install fpdf2 with: pip3 install fpdf2 --break-system-packages
    """
    lines = []
    sep   = '=' * 52

    lines += [
        sep,
        '  D-IDS SECURITY REPORT',
        sep,
        f'  Generated : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'  Data mode : {state["data_mode"]}',
        '',
        '  TRAFFIC SUMMARY',
        '-' * 52,
        f'  Total packets analyzed : {state["total_packets"]}',
        f'  Threats detected       : {state["total_threats"]}',
        f'    Critical             : {state["critical"]}',
        f'    High                 : {state["high"]}',
        f'    Medium               : {state["medium"]}',
        f'    Low                  : {state["low"]}',
        '',
        '  ATTACK BREAKDOWN',
        '-' * 52,
    ]
    for k, v in sorted(state['attack_counts'].items(),
                        key=lambda x: x[1], reverse=True):
        lines.append(f'  {k:<35} {v:>5} occurrences')

    lines += [
        '',
        '  TOP ATTACKING IPs',
        '-' * 52,
    ]
    for ip, cnt in sorted(state['src_ip_counts'].items(),
                           key=lambda x: x[1], reverse=True)[:10]:
        lines.append(f'  {ip:<22} {cnt:>5} packets')

    lines += [
        '',
        '  RECENT ALERTS (last 20)',
        '-' * 52,
    ]
    for a in state['alerts'][:20]:
        lines.append(
            f'  [{a["time"]}]  {a["level"]:<8}  '
            f'{a["type"]:<25}  {a["src"]} → {a["dst"]}'
        )

    # Speedup table
    seq = SPEEDUP['times'][0]
    n   = SPEEDUP['packets']
    cfgs = ['Sequential','MPI 1w','MPI 2w','MPI 3w','Hybrid 3w×2t','Hybrid 3w×4t']
    lines += [
        '',
        '  PERFORMANCE / SPEEDUP TABLE',
        '-' * 52,
        f'  {"Config":<20} {"Time(s)":>7}  {"Speedup":>8}  {"Pkt/s":>8}',
        f'  {"-"*20} {"-"*7}  {"-"*8}  {"-"*8}',
    ]
    for cfg, t in zip(cfgs, SPEEDUP['times']):
        lines.append(
            f'  {cfg:<20} {t:>7.3f}  {seq/t:>7.2f}x  {n/t:>8.0f}'
        )

    lines += ['', sep, '  END OF REPORT', sep, '']
    content = '\n'.join(lines)

    # Try real PDF first
    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Courier', size=10)
        for line in lines:
            pdf.cell(0, 5, line, ln=True)
        buf = io.BytesIO()
        pdf.output(buf)
        buf.seek(0)
        return buf, 'application/pdf', 'dids_report.pdf'
    except ImportError:
        pass

    # Fall back to plain text
    buf = io.BytesIO(content.encode())
    return buf, 'text/plain', 'dids_report.txt'

# ══════════════════════════════════════════════════════════════
# FLASK APP + ROUTES
# ══════════════════════════════════════════════════════════════
app     = Flask(__name__)
app.config['SECRET_KEY'] = 'dids-week10'
socketio = SocketIO(app, cors_allowed_origins='*')

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/speedup')
def api_speedup():
    seq = SPEEDUP['times'][0]
    n   = SPEEDUP['packets']
    return jsonify({
        'labels':     SPEEDUP['labels'],
        'times':      SPEEDUP['times'],
        'speedups':   [round(seq/t, 2) for t in SPEEDUP['times']],
        'throughput': [round(n/t)      for t in SPEEDUP['times']],
        'packets':    n,
    })

@app.route('/api/state')
def api_state():
    with state_lock:
        top = dict(sorted(state['src_ip_counts'].items(),
                          key=lambda x: x[1], reverse=True)[:10])
        return jsonify({
            'total_packets':  state['total_packets'],
            'total_threats':  state['total_threats'],
            'critical':       state['critical'],
            'high':           state['high'],
            'medium':         state['medium'],
            'attack_counts':  dict(state['attack_counts']),
            'top_attackers':  top,
            'timeline':       state['timeline'],
            'alerts':         state['alerts'][:20],
            'data_mode':      state['data_mode'],
        })

@app.route('/api/report')
def api_report():
    with state_lock:
        buf, mime, fname = make_report()
    return send_file(buf, mimetype=mime,
                     as_attachment=True,
                     download_name=fname)

@socketio.on('connect')
def on_connect():
    with state_lock:
        socketio.emit('init', {
            'alerts':        state['alerts'][:20],
            'attack_counts': dict(state['attack_counts']),
            'timeline':      state['timeline'],
            'data_mode':     state['data_mode'],
        })

# ══════════════════════════════════════════════════════════════
# DASHBOARD HTML
# ══════════════════════════════════════════════════════════════
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>D-IDS Dashboard — Week 10</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<style>
/* ── Reset ── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

/* ── Variables ── */
:root{
  --bg:     #0d1117;
  --surf:   #161b22;
  --surf2:  #1c2128;
  --border: #30363d;
  --text:   #c9d1d9;
  --muted:  #8b949e;
  --blue:   #58a6ff;
  --green:  #3fb950;
  --orange: #d29922;
  --red:    #f85149;
  --yellow: #e3b341;
  --purple: #bc8cff;
}

html,body{
  min-height:100%;
  font-size:14px;
  font-family:'Segoe UI',system-ui,sans-serif;
  background:var(--bg);
  color:var(--text);
  overflow-x:hidden;
}

/* ── Header ── */
.header{
  background:var(--surf);
  border-bottom:1px solid var(--border);
  padding:12px 24px;
  display:flex;
  align-items:center;
  gap:12px;
  position:sticky;
  top:0;
  z-index:20;
}
.header h1{font-size:15px;font-weight:600;color:var(--blue)}
.header p {font-size:11px;color:var(--muted);margin-top:2px}
.live-dot{
  width:8px;height:8px;border-radius:50%;
  background:var(--green);flex-shrink:0;
  animation:pulse 2s ease-in-out infinite;
}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{
  font-size:11px;
  background:var(--surf2);
  border:1px solid var(--border);
  border-radius:10px;
  padding:3px 10px;
  color:var(--muted);
  white-space:nowrap;
}
.btn{
  font-size:12px;font-weight:600;
  background:var(--blue);color:#0d1117;
  border:none;border-radius:8px;
  padding:5px 14px;cursor:pointer;
}
.btn:hover{opacity:0.85}
.btn.red{background:var(--red);color:#fff}

/* ── Tabs ── */
.tabs{
  display:flex;
  background:var(--surf);
  border-bottom:1px solid var(--border);
  padding:0 24px;
  gap:0;
}
.tab{
  padding:10px 18px;
  font-size:13px;
  cursor:pointer;
  color:var(--muted);
  border-bottom:2px solid transparent;
  transition:all .15s;
  user-select:none;
}
.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab:hover:not(.active){color:var(--text)}
.tab-panel{display:none;padding-bottom:20px}
.tab-panel.active{display:block}

/* ── Stat cards ── */
.stats{
  display:grid;
  grid-template-columns:repeat(5,1fr);
  gap:10px;
  padding:14px 24px;
}
.stat{
  background:var(--surf);
  border:1px solid var(--border);
  border-radius:8px;
  padding:14px;
  text-align:center;
}
.stat .val{
  font-size:28px;
  font-weight:700;
  line-height:1.2;
  color:var(--blue);
}
.stat .lbl{
  font-size:10px;
  color:var(--muted);
  margin-top:4px;
  text-transform:uppercase;
  letter-spacing:.05em;
}
.stat.c-red    .val{color:var(--red)}
.stat.c-orange .val{color:var(--orange)}
.stat.c-yellow .val{color:var(--yellow)}
.stat.c-green  .val{color:var(--green)}

/* ── Grid layouts ── */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0 24px 12px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;padding:0 24px 12px}
.span2{grid-column:span 2}

/* ── Panel ── */
.panel{
  background:var(--surf);
  border:1px solid var(--border);
  border-radius:8px;
  padding:16px;
}
.panel h2{
  font-size:11px;
  color:var(--muted);
  font-weight:500;
  letter-spacing:.05em;
  text-transform:uppercase;
  margin-bottom:12px;
}

/* ── Chart containers — FIXED height, no zoom ── */
.chart-box{
  position:relative;
  height:175px;   /* fixed — prevents Chart.js zoom bug */
  width:100%;
}
.chart-box.tall{height:220px}
.chart-box.short{height:140px}

/* ── Alerts ── */
.alerts-list{
  height:210px;
  overflow-y:auto;
  display:flex;
  flex-direction:column;
  gap:5px;
}
.alerts-list::-webkit-scrollbar{width:3px}
.alerts-list::-webkit-scrollbar-thumb{
  background:var(--border);border-radius:2px}

.alert-row{
  display:grid;
  grid-template-columns:78px 1fr auto;
  gap:8px;
  align-items:center;
  padding:7px 10px;
  border-radius:5px;
  border-left:3px solid;
  font-size:12px;
  line-height:1.4;
}
.alert-row.CRITICAL{border-color:var(--red);   background:rgba(248,81,73,.07)}
.alert-row.HIGH    {border-color:var(--orange); background:rgba(210,153,34,.07)}
.alert-row.MEDIUM  {border-color:var(--yellow); background:rgba(227,179,65,.07)}
.alert-row.LOW     {border-color:var(--blue);   background:rgba(88,166,255,.07)}

.lvl-badge{
  font-size:10px;font-weight:600;
  padding:2px 6px;border-radius:3px;
  text-align:center;
}
.CRITICAL .lvl-badge{background:rgba(248,81,73,.2); color:var(--red)}
.HIGH     .lvl-badge{background:rgba(210,153,34,.2);color:var(--orange)}
.MEDIUM   .lvl-badge{background:rgba(227,179,65,.2);color:var(--yellow)}
.LOW      .lvl-badge{background:rgba(88,166,255,.2);color:var(--blue)}

.alert-info strong{color:#e6edf3;font-size:12px}
.alert-info .route{color:var(--muted);font-size:11px;margin-top:1px}
.alert-time{color:var(--muted);font-size:11px;white-space:nowrap}
.empty{text-align:center;color:var(--muted);padding:30px 0;font-size:13px}

/* ── Tables ── */
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{
  color:var(--muted);font-size:10px;font-weight:500;
  text-transform:uppercase;letter-spacing:.04em;
  padding:5px 8px;text-align:left;
  border-bottom:1px solid var(--border);
}
.tbl td{
  padding:6px 8px;
  border-bottom:1px solid rgba(48,54,61,.4);
  vertical-align:middle;
}
.tbl tr:last-child td{border-bottom:none}
.bar-wrap{display:flex;align-items:center;gap:6px}
.bar-fill{height:6px;border-radius:3px;background:var(--red);min-width:2px;transition:width .3s}

footer{
  text-align:center;padding:12px;
  color:var(--muted);font-size:11px;
  border-top:1px solid var(--border);
}
</style>
</head>
<body>

<!-- ════════ HEADER ════════ -->
<div class="header">
  <div class="live-dot"></div>
  <div>
    <h1>D-IDS Full Dashboard</h1>
    <p>Distributed Intrusion Detection — MPI + OpenMP Hybrid</p>
  </div>
  <div class="hdr-right">
    <span class="badge" id="mode-badge">Connecting...</span>
    <span class="badge">Week 10</span>
    <button class="btn" onclick="location.href='/api/report'">
      Download Report
    </button>
  </div>
</div>

<!-- ════════ TABS ════════ -->
<div class="tabs">
  <div class="tab active"  onclick="showTab('live',    this)">Live Monitor</div>
  <div class="tab"         onclick="showTab('speedup', this)">Speedup Analysis</div>
  <div class="tab"         onclick="showTab('attack',  this)">Top Attackers</div>
</div>

<!-- ══════════════════════════════
     TAB 1 — LIVE MONITOR
     ══════════════════════════════ -->
<div class="tab-panel active" id="tab-live">

  <!-- Stat cards -->
  <div class="stats">
    <div class="stat">
      <div class="val" id="s-total">0</div>
      <div class="lbl">Packets</div>
    </div>
    <div class="stat c-red">
      <div class="val" id="s-threats">0</div>
      <div class="lbl">Threats</div>
    </div>
    <div class="stat c-red">
      <div class="val" id="s-critical">0</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat c-orange">
      <div class="val" id="s-high">0</div>
      <div class="lbl">High</div>
    </div>
    <div class="stat c-green">
      <div class="val" id="s-rate">0</div>
      <div class="lbl">Pkt / sec</div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="g2">
    <div class="panel">
      <h2>Threat timeline (last 15 updates)</h2>
      <div class="chart-box">
        <canvas id="timelineChart"></canvas>
      </div>
    </div>
    <div class="panel">
      <h2>Attack type distribution</h2>
      <div class="chart-box">
        <canvas id="pieChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Alerts -->
  <div style="padding:0 24px 12px">
    <div class="panel">
      <h2>Live alerts</h2>
      <div class="alerts-list" id="alertsList">
        <div class="empty">Waiting for threats...</div>
      </div>
    </div>
  </div>

</div><!-- /tab-live -->


<!-- ══════════════════════════════
     TAB 2 — SPEEDUP ANALYSIS
     ══════════════════════════════ -->
<div class="tab-panel" id="tab-speedup">

  <div style="padding:14px 24px 0">
    <div class="panel">
      <h2>Speedup — Sequential vs Pure MPI vs Hybrid MPI+OpenMP</h2>
      <div class="chart-box tall">
        <canvas id="speedupChart"></canvas>
      </div>
    </div>
  </div>

  <div class="g2" style="padding-top:12px">
    <div class="panel">
      <h2>Execution time (seconds) — lower is better</h2>
      <div class="chart-box">
        <canvas id="timeChart"></canvas>
      </div>
    </div>
    <div class="panel">
      <h2>Throughput (packets / second) — higher is better</h2>
      <div class="chart-box">
        <canvas id="throughputChart"></canvas>
      </div>
    </div>
  </div>

  <div style="padding:0 24px 12px">
    <div class="panel">
      <h2>Speedup table</h2>
      <table class="tbl" id="speedupTable">
        <thead>
          <tr>
            <th>Configuration</th>
            <th>Time (s)</th>
            <th>Speedup</th>
            <th>Throughput (pkt/s)</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

</div><!-- /tab-speedup -->


<!-- ══════════════════════════════
     TAB 3 — TOP ATTACKERS
     ══════════════════════════════ -->
<div class="tab-panel" id="tab-attack">

  <div class="g2" style="padding-top:14px">

    <div class="panel">
      <h2>Top attacking IP addresses</h2>
      <table class="tbl" id="attackerTable">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Packets</th>
            <th>Activity</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="3" class="empty">No data yet</td></tr>
        </tbody>
      </table>
    </div>

    <div class="panel">
      <h2>Attack type breakdown</h2>
      <table class="tbl" id="attackTypeTable">
        <thead>
          <tr>
            <th>Attack Type</th>
            <th>Count</th>
            <th>Share</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="3" class="empty">No data yet</td></tr>
        </tbody>
      </table>
    </div>

  </div>
</div><!-- /tab-attack -->

<footer>
  D-IDS &nbsp;|&nbsp; Parallel &amp; Distributed Computing
  &nbsp;|&nbsp; MPI + OpenMP Hybrid
</footer>


<!-- ════════════════════════════════════════════
     JAVASCRIPT
     ════════════════════════════════════════════ -->
<script>
/* ── Chart.js global: disable ALL animations → stops the zoom/jump bug ── */
Chart.defaults.animation            = false;
Chart.defaults.responsive           = true;
Chart.defaults.maintainAspectRatio  = false;   /* respect fixed container height */

const GRID  = 'rgba(48,54,61,0.7)';
const TICK  = '#8b949e';
const PIE_C = ['#f85149','#d29922','#e3b341',
               '#58a6ff','#3fb950','#bc8cff','#79c0ff'];

const baseScales = {
  x:{ grid:{color:GRID}, ticks:{color:TICK, font:{size:11}, maxTicksLimit:8} },
  y:{ grid:{color:GRID}, ticks:{color:TICK, font:{size:11}}, beginAtZero:true }
};
const baseTip = {
  backgroundColor:'#1c2128', borderColor:'#30363d', borderWidth:1,
  titleColor:'#c9d1d9', bodyColor:'#8b949e'
};

/* ══ Timeline chart (line) ══ */
const tlChart = new Chart(
  document.getElementById('timelineChart').getContext('2d'), {
  type: 'line',
  data: {
    labels: [],
    datasets:[{
      label:'Threats', data:[],
      borderColor:'#f85149',
      backgroundColor:'rgba(248,81,73,0.10)',
      borderWidth:2, pointRadius:3, fill:true, tension:0.3
    }]
  },
  options:{
    animation:false, responsive:true, maintainAspectRatio:false,
    plugins:{ legend:{display:false}, tooltip:{...baseTip} },
    scales:{ ...baseScales, y:{ ...baseScales.y, suggestedMax:6 } }
  }
});

/* ══ Pie chart (doughnut) ══ */
const pieChart = new Chart(
  document.getElementById('pieChart').getContext('2d'), {
  type: 'doughnut',
  data: { labels:[], datasets:[{
    data:[], backgroundColor:PIE_C,
    borderColor:'#161b22', borderWidth:2
  }]},
  options:{
    animation:false, responsive:true, maintainAspectRatio:false,
    plugins:{
      legend:{
        position:'right',
        labels:{ color:TICK, font:{size:11}, boxWidth:12, padding:8 }
      },
      tooltip:{...baseTip}
    }
  }
});

/* ══ Speedup charts (built on demand when tab is opened) ══ */
let spCharts = null;

function buildSpeedupCharts(d) {
  if (spCharts) return;   /* build once only */

  const barOpts = (ylabel, cbFn) => ({
    animation:false, responsive:true, maintainAspectRatio:false,
    plugins:{ legend:{display:false}, tooltip:{...baseTip} },
    scales:{
      x:{ grid:{color:GRID}, ticks:{color:TICK, font:{size:10}} },
      y:{ grid:{color:GRID}, ticks:{color:TICK, font:{size:11},
            callback: cbFn }, beginAtZero:true }
    }
  });

  const colors = d.labels.map(l =>
    l.includes('Hybrid')
      ? 'rgba(63,185,80,0.70)'
      : l === 'Sequential'
        ? 'rgba(248,81,73,0.60)'
        : 'rgba(88,166,255,0.70)'
  );
  const borders = d.labels.map(l =>
    l.includes('Hybrid') ? '#3fb950'
    : l === 'Sequential' ? '#f85149'
    : '#58a6ff'
  );

  /* Speedup bar */
  spCharts = new Chart(
    document.getElementById('speedupChart').getContext('2d'), {
    type:'bar',
    data:{ labels:d.labels, datasets:[{
      label:'Speedup', data:d.speedups,
      backgroundColor:colors, borderColor:borders,
      borderWidth:1, borderRadius:4
    }]},
    options: barOpts('Speedup', v => v+'×')
  });

  /* Time bar */
  new Chart(document.getElementById('timeChart').getContext('2d'), {
    type:'bar',
    data:{ labels:d.labels, datasets:[{
      label:'Time (s)', data:d.times,
      backgroundColor:'rgba(210,153,34,0.65)',
      borderColor:'#d29922', borderWidth:1, borderRadius:4
    }]},
    options: barOpts('Seconds', v => v+'s')
  });

  /* Throughput bar */
  new Chart(document.getElementById('throughputChart').getContext('2d'), {
    type:'bar',
    data:{ labels:d.labels, datasets:[{
      label:'Pkt/s', data:d.throughput,
      backgroundColor:colors, borderColor:borders,
      borderWidth:1, borderRadius:4
    }]},
    options: barOpts('Pkt/s', v => v)
  });

  /* Table */
  const seq   = d.times[0];
  const tbody = document.querySelector('#speedupTable tbody');
  tbody.innerHTML = '';
  d.labels.forEach((lbl, i) => {
    const sp  = (seq / d.times[i]).toFixed(2);
    const pps = Math.round(d.packets / d.times[i]).toLocaleString();
    const color =
      lbl.includes('Hybrid')     ? 'var(--green)'  :
      lbl === 'Sequential'       ? 'var(--red)'     :
                                   'var(--blue)';
    const tr = document.createElement('tr');
    tr.innerHTML =
      `<td style="color:${color};font-weight:500">${lbl.replace(/\\n/g,' ')}</td>` +
      `<td>${d.times[i].toFixed(3)} s</td>` +
      `<td><strong style="color:${color}">${sp}×</strong></td>` +
      `<td>${pps}</td>`;
    tbody.appendChild(tr);
  });
}

/* ══ Tab switcher ══ */
function showTab(name, el) {
  document.querySelectorAll('.tab-panel')
          .forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab')
          .forEach(t => t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  el.classList.add('active');

  if (name === 'speedup') {
    fetch('/api/speedup')
      .then(r => r.json())
      .then(buildSpeedupCharts);
  }
  if (name === 'attack') {
    fetch('/api/state')
      .then(r => r.json())
      .then(d => {
        updateAttackerTable(d.top_attackers);
        updateAttackTypeTable(d.attack_counts);
      });
  }
}

/* ══ Alert helpers ══ */
function addAlert(a) {
  const list = document.getElementById('alertsList');
  const empty = list.querySelector('.empty');
  if (empty) empty.remove();

  const el = document.createElement('div');
  el.className = `alert-row ${a.level}`;
  el.innerHTML =
    `<span class="lvl-badge">${a.level}</span>` +
    `<div class="alert-info">` +
      `<strong>${a.type}</strong>` +
      `<div class="route">${a.src} &rarr; ${a.dst}</div>` +
    `</div>` +
    `<span class="alert-time">${a.time}</span>`;

  list.insertBefore(el, list.firstChild);
  /* keep max 40 rows */
  while (list.children.length > 40) list.removeChild(list.lastChild);
}

/* ══ Attacker table ══ */
function updateAttackerTable(top) {
  const entries = Object.entries(top).sort((a,b)=>b[1]-a[1]).slice(0,8);
  if (!entries.length) return;
  const max = entries[0][1];
  const tbody = document.querySelector('#attackerTable tbody');
  tbody.innerHTML = '';
  entries.forEach(([ip, cnt]) => {
    const pct = Math.round(cnt/max*100);
    const tr  = document.createElement('tr');
    tr.innerHTML =
      `<td style="font-family:monospace;color:var(--red)">${ip}</td>` +
      `<td>${cnt}</td>` +
      `<td><div class="bar-wrap">` +
        `<div class="bar-fill" style="width:${pct}px"></div>` +
        `<span style="color:var(--muted);font-size:11px">${pct}%</span>` +
      `</div></td>`;
    tbody.appendChild(tr);
  });
}

/* ══ Attack type table ══ */
function updateAttackTypeTable(counts) {
  const entries = Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) return;
  const total = entries.reduce((s,[,v])=>s+v, 0);
  const tbody = document.querySelector('#attackTypeTable tbody');
  tbody.innerHTML = '';
  entries.forEach(([type, cnt]) => {
    const pct = total ? Math.round(cnt/total*100) : 0;
    const tr  = document.createElement('tr');
    tr.innerHTML =
      `<td>${type}</td>` +
      `<td>${cnt}</td>` +
      `<td style="color:var(--muted)">${pct}%</td>`;
    tbody.appendChild(tr);
  });
}

/* ══ Socket.IO ══ */
const socket = io({ transports:['websocket','polling'] });

socket.on('connect', () => {
  document.getElementById('mode-badge').textContent = 'Live';
  document.getElementById('mode-badge').style.color = 'var(--green)';
});
socket.on('disconnect', () => {
  document.getElementById('mode-badge').textContent = 'Disconnected';
  document.getElementById('mode-badge').style.color = 'var(--red)';
});

/* Restore state on page load / reconnect */
socket.on('init', d => {
  if (d.data_mode)
    document.getElementById('mode-badge').textContent = d.data_mode;

  /* Replay existing alerts */
  if (d.alerts) d.alerts.slice().reverse().forEach(addAlert);

  /* Restore pie */
  if (d.attack_counts && Object.keys(d.attack_counts).length) {
    pieChart.data.labels = Object.keys(d.attack_counts);
    pieChart.data.datasets[0].data = Object.values(d.attack_counts);
    pieChart.update('none');
  }

  /* Restore timeline */
  if (d.timeline) {
    d.timeline.forEach(t => {
      tlChart.data.labels.push(t.time);
      tlChart.data.datasets[0].data.push(t.threats);
    });
    tlChart.update('none');
  }
});

/* Live stats update (every 3 seconds) */
socket.on('stats', d => {
  document.getElementById('s-total').textContent    = d.total_packets.toLocaleString();
  document.getElementById('s-threats').textContent  = d.total_threats.toLocaleString();
  document.getElementById('s-critical').textContent = d.critical.toLocaleString();
  document.getElementById('s-high').textContent     = d.high.toLocaleString();
  document.getElementById('s-rate').textContent     = d.rate;

  if (d.data_mode)
    document.getElementById('mode-badge').textContent = d.data_mode;

  /* Timeline — keep last 15 points */
  const now = new Date().toLocaleTimeString('en-US',
    {hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
  tlChart.data.labels.push(now);
  tlChart.data.datasets[0].data.push(d.new_threats);
  if (tlChart.data.labels.length > 15) {
    tlChart.data.labels.shift();
    tlChart.data.datasets[0].data.shift();
  }
  tlChart.update('none');   /* 'none' = instant, no animation */

  /* Pie */
  if (d.attack_counts && Object.keys(d.attack_counts).length) {
    pieChart.data.labels = Object.keys(d.attack_counts);
    pieChart.data.datasets[0].data = Object.values(d.attack_counts);
    pieChart.update('none');
  }
});

/* Individual alert */
socket.on('alert', addAlert);
</script>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='D-IDS Week 10 Dashboard')
    parser.add_argument('--csv',  help='Path to captured packets CSV file')
    parser.add_argument('--port', type=int, default=5000, help='Port (default 5000)')
    args = parser.parse_args()

    # Start background data thread
    if args.csv:
        print(f"\n  Mode: Real CSV  →  {args.csv}")
        t = threading.Thread(target=csv_loop, args=(args.csv,), daemon=True)
    else:
        print("\n  Mode: Simulated data")
        print("  Tip:  Use --csv data/logs/packets.csv for real captured packets")
        t = threading.Thread(target=simulate_loop, daemon=True)
    t.start()

    print(f"\n{'='*50}")
    print(f"  D-IDS DASHBOARD — Week 10")
    print(f"{'='*50}")
    print(f"  Open browser : http://localhost:{args.port}")
    print(f"  Tabs         : Live Monitor | Speedup | Top Attackers")
    print(f"  Report       : click 'Download Report' button")
    print(f"  Stop         : Ctrl+C")
    print(f"{'='*50}\n")

    socketio.run(app, host='0.0.0.0', port=args.port,
                 debug=False, use_reloader=False)
