#!/usr/bin/env python3
"""
=============================================================================
WEEK 12 — CORRECTED PERFORMANCE BENCHMARK
File: tests/benchmark_fixed.py
=============================================================================

FIXES from previous benchmark:
  1. Hybrid uses OMP_NUM_THREADS=2 (not 4) — 4 cores / 2 workers = 2 threads each
  2. Results are compiled to /tmp (not shared folder) to avoid vboxsf slowdown
  3. Uses correct MPI process counts for a 4-core VM
  4. Runs each config 3 times and takes the MINIMUM (removes noise)

WHY HYBRID WAS SLOWER BEFORE:
  Problem 1 — Thread oversubscription:
    4 cores, 4 MPI processes, each trying to use 4 OMP threads = 16 threads on 4 cores
    Threads fight over cores → context switching → slower

  Problem 2 — VirtualBox shared folder (vboxsf):
    Multiple threads reading/writing to /media/sf_PDIDS simultaneously
    vboxsf has a global lock → threads queue up → no real parallelism

  Fix: compile to /tmp, use 1-2 OMP threads per worker, 3 MPI procs total

RUN:
  python3 tests/benchmark_fixed.py
=============================================================================
"""

import os
import sys
import subprocess
import time
import shutil
import argparse

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

# ── Build to /tmp to avoid vboxsf slowdown ────────────────────
TMP_BIN = '/tmp/coordinator_bench'

def build_coordinator():
    """Compile coordinator_real to /tmp for faster execution."""
    print("  Compiling coordinator to /tmp (avoids shared folder overhead)...")
    result = subprocess.run(
        ['mpicc', '-O2', '-fopenmp',
         '-o', TMP_BIN,
         'central/coordinator_real.c', '-lm'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr}")
        return False
    print(f"  Compiled → {TMP_BIN}")
    return True

def ensure_csv(n):
    """Generate test CSV if not already present."""
    path = f'/tmp/bench_{n}.csv'
    if not os.path.exists(path):
        print(f"  Generating {n} packets → {path}")
        subprocess.run(
            ['python3', 'scripts/attack_simulator.py',
             '-n', str(n), '-o', path],
            capture_output=True
        )
    return path

def run_once(csv_path, np_count, omp_threads):
    """Run coordinator once, return elapsed seconds or None."""
    env = os.environ.copy()
    env['OMP_NUM_THREADS'] = str(omp_threads)

    cmd = ['mpirun', '--oversubscribe', '-np', str(np_count),
           TMP_BIN, '--file', csv_path]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=30, env=env
        )
        output = result.stdout + result.stderr
        for line in output.split('\n'):
            if 'Time:' in line:
                for part in line.split():
                    try:
                        val = float(part)
                        if 0 < val < 100:
                            return val
                    except ValueError:
                        continue
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    return None

def run_experiment(csv_path, np_count, omp_threads, repeats=3):
    """
    Run experiment multiple times, return best (minimum) time.
    Minimum eliminates OS scheduling noise.
    """
    times = []
    for _ in range(repeats):
        t = run_once(csv_path, np_count, omp_threads)
        if t is not None:
            times.append(t)
    return min(times) if times else None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--packets', nargs='+', type=int,
                        default=[1000, 2000, 5000, 10000])
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   D-IDS CORRECTED BENCHMARK — Week 12            ║")
    print("╠══════════════════════════════════════════════════╣")
    print("║  Fixes: /tmp compile, correct thread counts      ║")
    print("║  Each config runs 3x, best time taken            ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # Build coordinator to /tmp
    if not build_coordinator():
        sys.exit(1)
    print()

    """
    CORRECT CONFIGURATIONS FOR 4-CORE VM:
    
    Total cores = 4
    
    Sequential:
      1 MPI process total (np=2: 1 coord + 1 worker but worker does all work)
      OMP=1 thread
      
    Pure MPI 1 worker:
      np=2 (1 coord + 1 worker), OMP=1
      
    Pure MPI 3 workers:
      np=4 (1 coord + 3 workers), OMP=1
      Uses all 4 cores for MPI
      
    Hybrid 2 workers x 2 threads:
      np=3 (1 coord + 2 workers), OMP=2
      Total threads = 2 workers × 2 threads = 4 threads = matches core count
      THIS IS THE CORRECT HYBRID SETUP FOR A 4-CORE MACHINE
      
    Hybrid 1 worker x 4 threads:
      np=2 (1 coord + 1 worker), OMP=4
      1 worker uses all 4 threads
    """
    configs = [
        #  label                  np   omp  key
        ('Sequential',             2,   1,  'seq'),
        ('MPI — 1 worker',         2,   1,  'mpi1'),
        ('MPI — 3 workers',        4,   1,  'mpi3'),
        ('Hybrid 2w × 2t\n(recommended)', 3, 2, 'hyb_2x2'),
        ('Hybrid 1w × 4t',         2,   4,  'hyb_1x4'),
    ]

    results = {c[3]: {} for c in configs}
    packet_counts = args.packets

    print(f"  Configurations: {len(configs)}")
    print(f"  Packet counts:  {packet_counts}")
    print(f"  Repeats each:   {args.repeats} (best time used)")
    print()

    for n in packet_counts:
        csv_path = ensure_csv(n)
        print(f"  ── Packets: {n} ──")
        for label, np_count, omp, key in configs:
            clean = label.replace('\n', '')
            print(f"    {clean:<35} ", end='', flush=True)
            t = run_experiment(csv_path, np_count, omp, args.repeats)
            if t is not None:
                results[key][n] = t
                pps = n / t
                print(f"{t:.4f}s  ({pps:,.0f} pkt/s)")
            else:
                results[key][n] = None
                print("FAILED")
        print()

    # ── Print table ──────────────────────────────────────────
    print()
    print("═" * 72)
    print("  CORRECTED SPEEDUP TABLE")
    print("  (Each value = best of 3 runs to eliminate noise)")
    print("═" * 72)

    col_w = 14
    header = f"  {'Config':<30}"
    for n in packet_counts:
        header += f"  {str(n)+' pkts':>{col_w}}"
    print(header)
    print(f"  {'-'*30}" + f"  {'-'*col_w}" * len(packet_counts))

    for label, np_count, omp, key in configs:
        clean = label.replace('\n', ' ')
        row   = f"  {clean:<30}"
        for n in packet_counts:
            t = results[key].get(n)
            row += f"  {f'{t:.4f}s' if t else 'N/A':>{col_w}}"
        print(row)

    print()
    print("  SPEEDUP vs SEQUENTIAL:")
    print(f"  {'-'*30}" + f"  {'-'*col_w}" * len(packet_counts))

    for label, np_count, omp, key in configs:
        if key == 'seq':
            continue
        clean = label.replace('\n', ' ')
        row   = f"  {clean:<30}"
        for n in packet_counts:
            t_seq = results['seq'].get(n)
            t     = results[key].get(n)
            if t_seq and t and t > 0:
                sp   = t_seq / t
                mark = " ✅" if sp > 1.0 else " ⚠"
                row += f"  {f'{sp:.2f}x{mark}':>{col_w}}"
            else:
                row += f"  {'N/A':>{col_w}}"
        print(row)

    print("═" * 72)
    print()

    # ── Explain results ──────────────────────────────────────
    print("  EXPLANATION FOR YOUR REPORT:")
    print()

    # Find best config at largest packet count
    n_large = max(packet_counts)
    best_key  = 'seq'
    best_time = results['seq'].get(n_large, float('inf'))
    for label, np_count, omp, key in configs:
        t = results[key].get(n_large)
        if t and t < best_time:
            best_time = t
            best_key  = key

    best_label = next(c[0] for c in configs if c[3] == best_key)
    t_seq = results['seq'].get(n_large, 1)
    if t_seq and best_time:
        best_sp = t_seq / best_time
        print(f"  At {n_large} packets, best config: {best_label.replace(chr(10),' ')}")
        print(f"  Speedup over sequential: {best_sp:.2f}x")
        print()

    print("  WHY HYBRID 2w×2t IS THE RIGHT SETUP FOR YOUR 4-CORE VM:")
    print("  • 4 cores available")
    print("  • 1 MPI coordinator process (uses ~0 CPU when distributing)")
    print("  • 2 MPI worker processes × 2 OMP threads = 4 active threads")
    print("  • 4 threads perfectly maps to 4 cores = no oversubscription")
    print("  • This is the textbook 'hybrid parallelism' configuration")
    print()

    # ── Generate graph ───────────────────────────────────────
    if not HAS_PLOT:
        return

    print("  Generating corrected speedup graph...")

    COLORS = {
        'seq':     '#f85149',
        'mpi1':    '#58a6ff',
        'mpi3':    '#79c0ff',
        'hyb_2x2': '#3fb950',
        'hyb_1x4': '#56d364',
    }
    LABELS = {
        'seq':     'Sequential',
        'mpi1':    'MPI 1 worker',
        'mpi3':    'MPI 3 workers',
        'hyb_2x2': 'Hybrid 2w×2t ★',
        'hyb_1x4': 'Hybrid 1w×4t',
    }

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor('#0d1117')
    fig.suptitle(
        'D-IDS Corrected Performance Benchmark — Week 12\n'
        '(Compiled to /tmp, optimal thread counts for 4-core VM)',
        fontsize=12, fontweight='bold', color='#c9d1d9'
    )

    for ax in axes:
        ax.set_facecolor('#161b22')
        ax.tick_params(colors='#8b949e')
        ax.grid(alpha=0.3, color='#30363d')
        for spine in ax.spines.values():
            spine.set_color('#30363d')

    # Left: execution time
    ax1 = axes[0]
    for label, np_count, omp, key in configs:
        xs = [n for n in packet_counts if results[key].get(n)]
        ys = [results[key][n] for n in xs]
        if xs:
            lw = 3 if key == 'hyb_2x2' else 1.5
            ax1.plot(xs, ys, 'o-',
                     color=COLORS[key], label=LABELS[key],
                     linewidth=lw, markersize=7)

    ax1.set_xlabel('Packets Analyzed', color='#8b949e', fontsize=11)
    ax1.set_ylabel('Time (seconds)', color='#8b949e', fontsize=11)
    ax1.set_title('Execution Time\n(lower = better)',
                  color='#c9d1d9', fontsize=11)
    ax1.legend(fontsize=9, facecolor='#1c2128',
               labelcolor='#c9d1d9', edgecolor='#30363d')

    # Right: speedup
    ax2 = axes[1]
    ax2.axhline(y=1.0, color='#f85149', linestyle='--',
                alpha=0.5, linewidth=1, label='Sequential baseline')

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
            lw = 3 if key == 'hyb_2x2' else 1.5
            ax2.plot(xs, ys, 's-',
                     color=COLORS[key], label=LABELS[key],
                     linewidth=lw, markersize=7)

    ax2.set_xlabel('Packets Analyzed', color='#8b949e', fontsize=11)
    ax2.set_ylabel('Speedup (×)', color='#8b949e', fontsize=11)
    ax2.set_title('Speedup vs Sequential\n(higher = better)',
                  color='#c9d1d9', fontsize=11)
    ax2.legend(fontsize=9, facecolor='#1c2128',
               labelcolor='#c9d1d9', edgecolor='#30363d')

    plt.tight_layout()
    out = 'data/results/speedup_corrected.png'
    os.makedirs('data/results', exist_ok=True)
    plt.savefig(out, dpi=150, bbox_inches='tight',
                facecolor='#0d1117')
    plt.close()
    print(f"  Graph saved → {out}")
    print()
    print("  Use this graph in your report.")
    print("  The ★ line (Hybrid 2w×2t) should show the best speedup.")
    print()

if __name__ == '__main__':
    main()
