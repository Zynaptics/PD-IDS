#!/usr/bin/env python3
"""
=============================================================================
WEEK 12 — PERFORMANCE BENCHMARK
File: tests/benchmark.py
=============================================================================

WHAT THIS DOES:
  Runs the coordinator with increasing packet counts and worker counts.
  Records timing for each combination.
  Generates a proper speedup graph saved to data/results/speedup.png
  Prints a clean table you can copy into your report.

RUN:
  python3 tests/benchmark.py
  python3 tests/benchmark.py --packets 500 1000 2000 5000
=============================================================================
"""

import os
import sys
import subprocess
import time
import argparse

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False
    print("WARNING: matplotlib not found. Table only, no graph.")
    print("Install: pip3 install matplotlib --break-system-packages")

# ══════════════════════════════════════════════════════════════
# RUN ONE EXPERIMENT
# ══════════════════════════════════════════════════════════════
def run_experiment(csv_path, np_count, omp_threads=1):
    """
    Runs coordinator_real with given settings.
    Returns elapsed time in seconds, or None on failure.
    """
    env = os.environ.copy()
    env['OMP_NUM_THREADS'] = str(omp_threads)

    cmd = [
        'mpirun', '--oversubscribe',
        '-np', str(np_count),
        './build/coordinator_real',
        '--file', csv_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        output = result.stdout + result.stderr

        # Parse "Time:" from coordinator output
        for line in output.split('\n'):
            if 'Time:' in line:
                parts = line.split()
                for p in parts:
                    try:
                        val = float(p)
                        if 0 < val < 1000:
                            return val
                    except ValueError:
                        continue
    except subprocess.TimeoutExpired:
        print("  TIMEOUT")
    except Exception as e:
        print(f"  ERROR: {e}")

    return None

# ══════════════════════════════════════════════════════════════
# GENERATE TEST DATA
# ══════════════════════════════════════════════════════════════
def ensure_csv(n):
    path = f'data/logs/bench_{n}.csv'
    if not os.path.exists(path):
        print(f"  Generating {n} packets...")
        subprocess.run(
            ['python3', 'scripts/attack_simulator.py',
             '-n', str(n), '-o', path],
            capture_output=True
        )
    return path

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description='D-IDS Benchmark — Week 12')
    parser.add_argument('--packets', nargs='+', type=int,
                        default=[500, 1000, 2000, 5000],
                        help='Packet counts to test')
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   D-IDS PERFORMANCE BENCHMARK — Week 12          ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    if not os.path.exists('build/coordinator_real'):
        print("ERROR: build/coordinator_real not found.")
        print("Compile: mpicc -O2 -fopenmp -o build/coordinator_real "
              "central/coordinator_real.c -lm")
        sys.exit(1)

    os.makedirs('data/logs', exist_ok=True)
    os.makedirs('data/results', exist_ok=True)

    # Configurations to test
    configs = [
        ('Sequential\n(1 proc)',  2, 1,  'seq'),
        ('MPI\n2 workers',        3, 1,  'mpi2'),
        ('MPI\n3 workers',        4, 1,  'mpi3'),
        ('Hybrid\n3w × 2t',       4, 2,  'hyb2'),
        ('Hybrid\n3w × 4t',       4, 4,  'hyb4'),
    ]

    # Store results: results[config_key][n_packets] = time
    results = {c[3]: {} for c in configs}

    packet_counts = args.packets

    # Run all experiments
    print(f"  Testing {len(configs)} configurations × "
          f"{len(packet_counts)} packet counts...")
    print(f"  Total runs: {len(configs) * len(packet_counts)}")
    print()

    for n in packet_counts:
        csv_path = ensure_csv(n)
        print(f"  Packets: {n}")

        for label, np_count, omp, key in configs:
            clean_label = label.replace('\n', ' ')
            print(f"    {clean_label:<25} ", end='', flush=True)
            t = run_experiment(csv_path, np_count, omp)
            if t is not None:
                results[key][n] = t
                pps = n / t
                print(f"{t:.4f}s  ({pps:.0f} pkt/s)")
            else:
                results[key][n] = None
                print("FAILED")
        print()

    # Print summary table
    print()
    print("═" * 70)
    print("  SPEEDUP TABLE (copy into your report)")
    print("═" * 70)

    # Header
    header = f"  {'Config':<20}"
    for n in packet_counts:
        header += f"  {n:>8} pkts"
    print(header)
    print(f"  {'-'*20}" + f"  {'-'*10}" * len(packet_counts))

    for label, np_count, omp, key in configs:
        clean = label.replace('\n', ' ')
        row   = f"  {clean:<20}"
        for n in packet_counts:
            t = results[key].get(n)
            if t is not None:
                row += f"  {t:>8.4f}s"
            else:
                row += f"  {'N/A':>9}"
        print(row)

    print()
    print("  SPEEDUP vs SEQUENTIAL:")
    print(f"  {'-'*20}" + f"  {'-'*10}" * len(packet_counts))

    for label, np_count, omp, key in configs:
        if key == 'seq':
            continue
        clean = label.replace('\n', ' ')
        row   = f"  {clean:<20}"
        for n in packet_counts:
            t_seq = results['seq'].get(n)
            t     = results[key].get(n)
            if t_seq and t and t > 0:
                sp = t_seq / t
                row += f"  {sp:>8.2f}x"
            else:
                row += f"  {'N/A':>9}"
        print(row)

    print("═" * 70)

    # Generate graph
    if not HAS_PLOT:
        print("\nInstall matplotlib to get graphs:")
        print("pip3 install matplotlib --break-system-packages")
        return

    print("\n  Generating speedup graph...")

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor('#0d1117')
    fig.suptitle('D-IDS Performance Benchmark — Week 12',
                 fontsize=14, fontweight='bold', color='#c9d1d9')

    COLORS = {
        'seq':  '#f85149',
        'mpi2': '#58a6ff',
        'mpi3': '#79c0ff',
        'hyb2': '#56d364',
        'hyb4': '#3fb950',
    }
    LABELS = {
        'seq':  'Sequential',
        'mpi2': 'MPI 2 workers',
        'mpi3': 'MPI 3 workers',
        'hyb2': 'Hybrid 3w×2t',
        'hyb4': 'Hybrid 3w×4t',
    }

    # ── Left: Execution time ──
    ax1 = axes[0]
    ax1.set_facecolor('#161b22')
    for label, np_count, omp, key in configs:
        xs = []
        ys = []
        for n in packet_counts:
            t = results[key].get(n)
            if t is not None:
                xs.append(n)
                ys.append(t)
        if xs:
            ax1.plot(xs, ys, 'o-',
                     color=COLORS[key],
                     label=LABELS[key],
                     linewidth=2,
                     markersize=6)

    ax1.set_xlabel('Packet Count', color='#8b949e', fontsize=11)
    ax1.set_ylabel('Time (seconds)', color='#8b949e', fontsize=11)
    ax1.set_title('Execution Time', color='#c9d1d9', fontsize=12)
    ax1.tick_params(colors='#8b949e')
    ax1.grid(alpha=0.3, color='#30363d')
    ax1.legend(fontsize=10, facecolor='#1c2128',
               labelcolor='#c9d1d9', edgecolor='#30363d')
    for spine in ax1.spines.values():
        spine.set_color('#30363d')

    # ── Right: Speedup vs sequential ──
    ax2 = axes[1]
    ax2.set_facecolor('#161b22')

    for label, np_count, omp, key in configs:
        if key == 'seq':
            continue
        xs = []
        ys = []
        for n in packet_counts:
            t_seq = results['seq'].get(n)
            t     = results[key].get(n)
            if t_seq and t and t > 0:
                xs.append(n)
                ys.append(t_seq / t)
        if xs:
            ax2.plot(xs, ys, 's-',
                     color=COLORS[key],
                     label=LABELS[key],
                     linewidth=2,
                     markersize=6)

    # Ideal speedup line
    if packet_counts:
        ax2.axhline(y=1.0, color='#f85149',
                    linestyle='--', alpha=0.5,
                    linewidth=1, label='Sequential (1×)')

    ax2.set_xlabel('Packet Count', color='#8b949e', fontsize=11)
    ax2.set_ylabel('Speedup (× faster than sequential)',
                   color='#8b949e', fontsize=11)
    ax2.set_title('Speedup vs Sequential', color='#c9d1d9', fontsize=12)
    ax2.tick_params(colors='#8b949e')
    ax2.grid(alpha=0.3, color='#30363d')
    ax2.legend(fontsize=10, facecolor='#1c2128',
               labelcolor='#c9d1d9', edgecolor='#30363d')
    for spine in ax2.spines.values():
        spine.set_color('#30363d')

    plt.tight_layout()
    out = 'data/results/speedup_benchmark.png'
    plt.savefig(out, dpi=150, bbox_inches='tight',
                facecolor='#0d1117')
    plt.close()
    print(f"  Graph saved → {out}")
    print()
    print("  Include this graph in your report!")
    print()

if __name__ == '__main__':
    main()
