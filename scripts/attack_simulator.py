#!/usr/bin/env python3
"""
=============================================================================
WEEK 11 — ATTACK SIMULATOR
File: scripts/attack_simulator.py
=============================================================================

WHAT THIS DOES:
  Generates a realistic CSV file containing a mix of:
    - Normal HTTP/HTTPS/DNS traffic  (60%)
    - Port scan attempts             (15%)
    - SSH brute force attempts       (10%)
    - NULL scan (stealth probe)      (5%)
    - Suspicious port traffic        (5%)
    - DDoS-like flood packets        (3%)
    - Anomalous oversized packets    (2%)

WHY DO WE NEED THIS?
  Your real captured traffic (ping + DNS) has no attacks.
  To test and demo the detection system properly you need
  attack traffic. This script creates it without needing
  to actually attack anything — it just writes a CSV file
  with realistic-looking attack packets.

  Think of it like a flight simulator — same training,
  no real risk.

RUN:
  python3 scripts/attack_simulator.py
  python3 scripts/attack_simulator.py -n 500 -o data/logs/simulated.csv

THEN ANALYZE:
  python3 ml/ml_detector.py --csv data/logs/simulated.csv
  mpirun --oversubscribe -np 4 ./build/coordinator_real --file data/logs/simulated.csv
  python3 scripts/dashboard.py --csv data/logs/simulated.csv
=============================================================================
"""

import csv
import random
import time
import os
import argparse
from datetime import datetime

# ── IP pools ──────────────────────────────────────────────────
ATTACKER_IPS = [
    '10.0.0.5',       # internal attacker
    '172.16.0.10',    # another internal
    '45.33.32.156',   # external (Shodan scanner)
    '192.168.5.1',    # rogue device
    '31.13.24.9',     # external threat actor
    '104.21.3.78',    # cloud-based attacker
]

VICTIM_IPS = [
    '192.168.1.100',
    '192.168.1.101',
    '192.168.1.1',    # router
    '192.168.1.10',   # server
]

NORMAL_SRC_IPS = [
    '192.168.1.50',
    '192.168.1.51',
    '192.168.1.52',
    '192.168.1.200',
]

EXTERNAL_IPS = [
    '8.8.8.8',        # Google DNS
    '1.1.1.1',        # Cloudflare
    '93.184.216.34',  # example.com
    '151.101.1.140',  # Fastly CDN
]

BAD_PORTS    = [4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080]
COMMON_PORTS = [80, 443, 53, 25, 110, 143, 8080]

# ── Packet builders ───────────────────────────────────────────

def make_normal(ts):
    """Normal HTTP/HTTPS/DNS traffic."""
    src = random.choice(NORMAL_SRC_IPS)
    dst = random.choice(EXTERNAL_IPS)
    proto = random.choice([6, 6, 6, 17])   # mostly TCP
    if proto == 17:                          # DNS
        return {
            'timestamp': ts, 'src_ip': src,
            'src_port': random.randint(32000, 60000),
            'dst_ip': '8.8.8.8', 'dst_port': 53,
            'protocol': 17, 'size': random.randint(40, 120),
            'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
        }
    # TCP HTTP/HTTPS
    dst_port = random.choice([80, 443, 8080])
    is_syn   = random.random() < 0.2
    return {
        'timestamp': ts, 'src_ip': src,
        'src_port': random.randint(32000, 60000),
        'dst_ip': dst, 'dst_port': dst_port,
        'protocol': 6, 'size': random.randint(64, 1400),
        'syn': 1 if is_syn else 0,
        'ack': 0 if is_syn else 1,
        'fin': 0, 'rst': 0, 'psh': random.randint(0, 1),
    }

def make_port_scan(ts, src_ip, dst_ip, port):
    """TCP SYN to sequential ports — classic nmap scan."""
    return {
        'timestamp': ts, 'src_ip': src_ip,
        'src_port': random.randint(40000, 65000),
        'dst_ip': dst_ip, 'dst_port': port,
        'protocol': 6, 'size': 40,
        'syn': 1, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
    }

def make_null_scan(ts, src_ip, dst_ip, port):
    """TCP packet with no flags — stealth probe (nmap -sN)."""
    return {
        'timestamp': ts, 'src_ip': src_ip,
        'src_port': random.randint(40000, 65000),
        'dst_ip': dst_ip, 'dst_port': port,
        'protocol': 6, 'size': 40,
        'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
    }

def make_brute_force(ts, src_ip, dst_ip, port=22):
    """Rapid SSH/RDP connection attempts."""
    return {
        'timestamp': ts, 'src_ip': src_ip,
        'src_port': random.randint(40000, 65000),
        'dst_ip': dst_ip, 'dst_port': port,
        'protocol': 6, 'size': 64,
        'syn': 1, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
    }

def make_bad_port(ts, src_ip, dst_ip):
    """Traffic to known malware/RAT ports."""
    port = random.choice(BAD_PORTS)
    return {
        'timestamp': ts, 'src_ip': src_ip,
        'src_port': random.randint(40000, 65000),
        'dst_ip': dst_ip, 'dst_port': port,
        'protocol': 6, 'size': random.randint(64, 256),
        'syn': 1, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
    }

def make_ddos(ts, src_ip, dst_ip):
    """High-volume UDP flood."""
    return {
        'timestamp': ts, 'src_ip': src_ip,
        'src_port': random.randint(1024, 65535),
        'dst_ip': dst_ip, 'dst_port': random.randint(1, 1024),
        'protocol': 17, 'size': random.randint(500, 1500),
        'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
    }

def make_oversized(ts, src_ip, dst_ip):
    """Anomalously large packet — possible buffer overflow attempt."""
    return {
        'timestamp': ts, 'src_ip': src_ip,
        'src_port': random.randint(40000, 65000),
        'dst_ip': dst_ip,
        'dst_port': random.randint(1, 1024),
        'protocol': 6,
        'size': random.randint(6000, 65000),
        'syn': 1, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0,
    }

# ── CSV writer ─────────────────────────────────────────────────
FIELDNAMES = [
    'timestamp','src_ip','src_port','dst_ip','dst_port',
    'protocol','size','syn','ack','fin','rst','psh'
]

def write_csv(packets, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(packets)

# ── Generator ──────────────────────────────────────────────────
def generate(n, seed=42):
    """
    Generate n packets with realistic attack mix.
    Returns list of packet dicts.
    """
    random.seed(seed)
    packets  = []
    ts       = int(time.time()) - n  # start from n seconds ago

    # Pre-pick attackers for this run
    scanner     = random.choice(ATTACKER_IPS)
    bruteforcer = random.choice([ip for ip in ATTACKER_IPS if ip != scanner])
    null_scanner= random.choice([ip for ip in ATTACKER_IPS
                                  if ip not in (scanner, bruteforcer)])

    scan_port   = 1     # port scan starts at port 1
    brute_count = 0

    counts = {
        'normal': 0, 'port_scan': 0, 'null_scan': 0,
        'brute_force': 0, 'bad_port': 0,
        'ddos': 0, 'oversized': 0,
    }

    print(f"\n  Generating {n} packets...")
    print(f"  Scanner IP:      {scanner}")
    print(f"  Brute forcer IP: {bruteforcer}")
    print(f"  NULL scanner IP: {null_scanner}")
    print()

    for i in range(n):
        ts += 1
        victim = random.choice(VICTIM_IPS)
        r      = random.random()

        if r < 0.60:
            # 60% normal traffic
            packets.append(make_normal(ts))
            counts['normal'] += 1

        elif r < 0.75:
            # 15% port scan
            packets.append(make_port_scan(ts, scanner, victim, scan_port))
            scan_port += 1
            if scan_port > 1024:
                scan_port = 1
            counts['port_scan'] += 1

        elif r < 0.85:
            # 10% brute force
            port = random.choice([22, 3389, 21])
            packets.append(make_brute_force(ts, bruteforcer, victim, port))
            brute_count += 1
            counts['brute_force'] += 1

        elif r < 0.90:
            # 5% NULL scan
            packets.append(make_null_scan(ts, null_scanner, victim,
                                          random.randint(1, 1024)))
            counts['null_scan'] += 1

        elif r < 0.95:
            # 5% bad port
            packets.append(make_bad_port(ts,
                           random.choice(ATTACKER_IPS), victim))
            counts['bad_port'] += 1

        elif r < 0.98:
            # 3% DDoS
            packets.append(make_ddos(ts,
                           random.choice(ATTACKER_IPS), victim))
            counts['ddos'] += 1

        else:
            # 2% oversized
            packets.append(make_oversized(ts,
                           random.choice(ATTACKER_IPS), victim))
            counts['oversized'] += 1

    # Shuffle so attacks are not all at the end
    random.shuffle(packets)

    # Re-assign sequential timestamps after shuffle
    base_ts = int(time.time()) - n
    for i, p in enumerate(packets):
        p['timestamp'] = base_ts + i

    return packets, counts

# ── Main ───────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='D-IDS Attack Simulator — Week 11')
    parser.add_argument('-n', type=int, default=300,
                        help='Number of packets to generate (default: 300)')
    parser.add_argument('-o', default='data/logs/simulated.csv',
                        help='Output CSV path')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   D-IDS ATTACK SIMULATOR — Week 11               ║")
    print("╚══════════════════════════════════════════════════╝")

    packets, counts = generate(args.n, args.seed)
    write_csv(packets, args.o)

    total_attacks = sum(v for k, v in counts.items() if k != 'normal')

    print(f"  Output file : {args.o}")
    print()
    print("  PACKET BREAKDOWN:")
    print(f"  {'Normal traffic':<25} {counts['normal']:>5}"
          f"  ({counts['normal']/args.n*100:.0f}%)")
    print(f"  {'Port scan':<25} {counts['port_scan']:>5}"
          f"  ({counts['port_scan']/args.n*100:.0f}%)")
    print(f"  {'Brute force':<25} {counts['brute_force']:>5}"
          f"  ({counts['brute_force']/args.n*100:.0f}%)")
    print(f"  {'NULL scan':<25} {counts['null_scan']:>5}"
          f"  ({counts['null_scan']/args.n*100:.0f}%)")
    print(f"  {'Bad port':<25} {counts['bad_port']:>5}"
          f"  ({counts['bad_port']/args.n*100:.0f}%)")
    print(f"  {'DDoS flood':<25} {counts['ddos']:>5}"
          f"  ({counts['ddos']/args.n*100:.0f}%)")
    print(f"  {'Oversized packet':<25} {counts['oversized']:>5}"
          f"  ({counts['oversized']/args.n*100:.0f}%)")
    print(f"  {'─'*35}")
    print(f"  {'TOTAL ATTACKS':<25} {total_attacks:>5}"
          f"  ({total_attacks/args.n*100:.0f}%)")
    print()
    print("  NEXT STEPS:")
    print(f"  1. python3 ml/train_model.py   --csv {args.o}")
    print(f"  2. python3 ml/ml_detector.py   --csv {args.o}")
    print(f"  3. mpirun --oversubscribe -np 4 ./build/coordinator_real"
          f" --file {args.o}")
    print(f"  4. python3 scripts/dashboard.py --csv {args.o}")
    print()
