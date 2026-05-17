#!/bin/bash
# =============================================================================
# WEEK 11 — RUN ALL SCRIPT
# File: scripts/run_all.sh
# =============================================================================
#
# WHAT THIS DOES:
#   Runs the ENTIRE D-IDS pipeline in the correct order:
#
#   Step 1 — Generate simulated attack traffic
#   Step 2 — Train ML model on that traffic
#   Step 3 — Run ML detector (Python)
#   Step 4 — Run MPI+OpenMP coordinator (C) on same data
#   Step 5 — Compare results
#   Step 6 — Launch dashboard
#
# WHY THIS SCRIPT?
#   For your demo/presentation you want to show the WHOLE system
#   working with ONE command. This is that command.
#
# HOW TO RUN:
#   chmod +x scripts/run_all.sh
#   ./scripts/run_all.sh
#
#   With real captured packets:
#   ./scripts/run_all.sh --real data/logs/packets.csv
#
#   Skip dashboard (just run analysis):
#   ./scripts/run_all.sh --no-dashboard
#
# =============================================================================

set -e   # stop on any error

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Defaults ──────────────────────────────────────────────────
CSV_FILE="data/logs/simulated.csv"
USE_REAL=0
SKIP_DASHBOARD=0
N_PACKETS=300
MPI_NP=4
OMP_THREADS=4

# ── Parse arguments ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --real)
            USE_REAL=1
            CSV_FILE="$2"
            shift 2
            ;;
        --no-dashboard)
            SKIP_DASHBOARD=1
            shift
            ;;
        -n)
            N_PACKETS="$2"
            shift 2
            ;;
        -h|--help)
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "  --real <file.csv>   Use real captured CSV instead of simulated"
            echo "  --no-dashboard      Skip launching the dashboard"
            echo "  -n <count>          Number of simulated packets (default: 300)"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Helper functions ──────────────────────────────────────────
banner() {
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${BLUE}║  $1$(printf '%*s' $((46 - ${#1})) '')║${RESET}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

step() {
    echo -e "${BOLD}${CYAN}[STEP $1]${RESET} $2"
}

ok() {
    echo -e "  ${GREEN}✅ $1${RESET}"
}

info() {
    echo -e "  ${YELLOW}ℹ  $1${RESET}"
}

fail() {
    echo -e "  ${RED}❌ $1${RESET}"
    exit 1
}

check_file() {
    if [ ! -f "$1" ]; then
        fail "File not found: $1"
    fi
}

check_binary() {
    if [ ! -f "$1" ]; then
        fail "Binary not found: $1 — did you run make?"
    fi
}

# ── Header ────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${BLUE}"
echo "  ██████╗       ██╗██████╗ ███████╗"
echo "  ██╔══██╗      ██║██╔══██╗██╔════╝"
echo "  ██║  ██║      ██║██║  ██║███████╗"
echo "  ██║  ██║      ██║██║  ██║╚════██║"
echo "  ██████╔╝      ██║██████╔╝███████║"
echo "  ╚═════╝       ╚═╝╚═════╝ ╚══════╝"
echo -e "${RESET}"
echo -e "  ${BOLD}Distributed Intrusion Detection System${RESET}"
echo -e "  ${YELLOW}Week 11 — Complete Pipeline Demo${RESET}"
echo ""
echo -e "  ${CYAN}MPI workers:   $((MPI_NP - 1))${RESET}"
echo -e "  ${CYAN}OMP threads:   $OMP_THREADS${RESET}"
echo -e "  ${CYAN}Data source:   $([ $USE_REAL -eq 1 ] && echo "$CSV_FILE" || echo "Simulated ($N_PACKETS packets)")${RESET}"
echo ""

# ── Check we are in the right directory ──────────────────────
if [ ! -f "Makefile" ]; then
    fail "Run this from /media/sf_PDIDS (your project root)"
fi

mkdir -p build data/logs data/results ml

# ═══════════════════════════════════════════════════════════════
# STEP 1 — COMPILE (if binaries missing)
# ═══════════════════════════════════════════════════════════════
banner "STEP 1 — Compiling"
step 1 "Checking compiled binaries..."

NEED_COMPILE=0
[ ! -f "build/packet_capture_csv"  ] && NEED_COMPILE=1
[ ! -f "build/packet_bridge"       ] && NEED_COMPILE=1
[ ! -f "build/coordinator_real"    ] && NEED_COMPILE=1
[ ! -f "build/signature_detection" ] && NEED_COMPILE=1

if [ $NEED_COMPILE -eq 1 ]; then
    info "Some binaries missing — compiling..."

    if [ ! -f "build/packet_capture_csv" ]; then
        gcc -O2 -o build/packet_capture_csv \
            sensor/packet_capture_csv.c -lpcap -lm 2>/dev/null \
            && ok "packet_capture_csv compiled" \
            || info "packet_capture_csv skipped (needs libpcap)"
    fi

    if [ ! -f "build/packet_bridge" ]; then
        gcc -O2 -o build/packet_bridge sensor/packet_bridge.c \
            && ok "packet_bridge compiled" \
            || fail "packet_bridge failed to compile"
    fi

    if [ ! -f "build/signature_detection" ]; then
        gcc -O2 -o build/signature_detection \
            central/signature_detection.c -lm \
            && ok "signature_detection compiled" \
            || fail "signature_detection failed to compile"
    fi

    if [ ! -f "build/coordinator_real" ]; then
        mpicc -O2 -fopenmp -o build/coordinator_real \
            central/coordinator_real.c -lm \
            && ok "coordinator_real compiled" \
            || fail "coordinator_real failed to compile"
    fi
else
    ok "All binaries already compiled"
fi

# ═══════════════════════════════════════════════════════════════
# STEP 2 — GET DATA
# ═══════════════════════════════════════════════════════════════
banner "STEP 2 — Preparing packet data"

if [ $USE_REAL -eq 1 ]; then
    step 2 "Using real captured CSV: $CSV_FILE"
    check_file "$CSV_FILE"
    LINES=$(wc -l < "$CSV_FILE")
    ok "Found $CSV_FILE ($((LINES-1)) packets)"
else
    step 2 "Generating $N_PACKETS simulated attack packets..."
    python3 scripts/attack_simulator.py -n $N_PACKETS -o "$CSV_FILE"
    check_file "$CSV_FILE"
    ok "Simulated CSV created: $CSV_FILE"
fi

# ═══════════════════════════════════════════════════════════════
# STEP 3 — PACKET BRIDGE (verify CSV)
# ═══════════════════════════════════════════════════════════════
banner "STEP 3 — Verifying packets via bridge"
step 3 "Reading CSV through packet_bridge..."

./build/packet_bridge --read "$CSV_FILE" | tail -20
ok "CSV verified by packet_bridge"

# ═══════════════════════════════════════════════════════════════
# STEP 4 — SIGNATURE DETECTION (standalone test)
# ═══════════════════════════════════════════════════════════════
banner "STEP 4 — Signature Detection Engine Test"
step 4 "Running signature detection unit tests..."

./build/signature_detection
ok "Signature detection tests passed"

# ═══════════════════════════════════════════════════════════════
# STEP 5 — ML: TRAIN
# ═══════════════════════════════════════════════════════════════
banner "STEP 5 — ML Model Training"
step 5 "Training Random Forest model on $CSV_FILE..."

python3 ml/train_model.py --csv "$CSV_FILE"

check_file "ml/model.pkl"
ok "Model saved to ml/model.pkl"

if [ -f "data/results/ml_results.png" ]; then
    ok "ML graph saved to data/results/ml_results.png"
fi

# ═══════════════════════════════════════════════════════════════
# STEP 6 — ML: DETECT
# ═══════════════════════════════════════════════════════════════
banner "STEP 6 — ML Detection (Signature + ML Ensemble)"
step 6 "Running ensemble detector on $CSV_FILE..."

python3 ml/ml_detector.py --csv "$CSV_FILE"
ok "ML detection complete"

# ═══════════════════════════════════════════════════════════════
# STEP 7 — MPI+OpenMP COORDINATOR
# ═══════════════════════════════════════════════════════════════
banner "STEP 7 — MPI + OpenMP Parallel Analysis"
step 7 "Running hybrid coordinator ($((MPI_NP-1)) workers × $OMP_THREADS threads)..."

OMP_NUM_THREADS=$OMP_THREADS \
    mpirun --oversubscribe -np $MPI_NP \
    ./build/coordinator_real \
    --file "$CSV_FILE"

ok "MPI+OpenMP analysis complete"

# ═══════════════════════════════════════════════════════════════
# STEP 8 — SPEEDUP EXPERIMENT
# ═══════════════════════════════════════════════════════════════
banner "STEP 8 — Speedup Experiment"
step 8 "Running with different worker counts..."

echo ""
echo -e "  ${CYAN}Sequential (1 process, no parallelism):${RESET}"
mpirun --oversubscribe -np 2 ./build/coordinator_real \
    --file "$CSV_FILE" 2>/dev/null \
    | grep "Time:"

echo ""
echo -e "  ${CYAN}Pure MPI (2 workers):${RESET}"
mpirun --oversubscribe -np 3 ./build/coordinator_real \
    --file "$CSV_FILE" 2>/dev/null \
    | grep "Time:"

echo ""
echo -e "  ${CYAN}Hybrid MPI+OpenMP (3 workers × 4 threads):${RESET}"
OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 \
    ./build/coordinator_real \
    --file "$CSV_FILE" 2>/dev/null \
    | grep "Time:"

echo ""
ok "Speedup experiment complete — copy the times to your report"

# ═══════════════════════════════════════════════════════════════
# STEP 9 — DASHBOARD
# ═══════════════════════════════════════════════════════════════
banner "STEP 9 — Live Dashboard"

if [ $SKIP_DASHBOARD -eq 1 ]; then
    info "Dashboard skipped (--no-dashboard flag)"
else
    step 9 "Launching web dashboard..."
    echo ""
    echo -e "  ${GREEN}${BOLD}Open your browser: http://localhost:5000${RESET}"
    echo ""
    echo -e "  ${YELLOW}Press Ctrl+C to stop the dashboard${RESET}"
    echo ""

    python3 scripts/dashboard.py --csv "$CSV_FILE"
fi

# ═══════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════
banner "ALL STEPS COMPLETE"
echo -e "  ${GREEN}${BOLD}Week 11 full pipeline ran successfully!${RESET}"
echo ""
echo -e "  ${CYAN}Files generated:${RESET}"
echo -e "  ├── $CSV_FILE"
[ -f "ml/model.pkl"                ] && echo -e "  ├── ml/model.pkl"
[ -f "data/results/ml_results.png" ] && echo -e "  ├── data/results/ml_results.png"
echo ""
echo -e "  ${CYAN}For your report:${RESET}"
echo -e "  • Copy the timing numbers from Step 8 into your speedup table"
echo -e "  • Include data/results/ml_results.png in your ML section"
echo -e "  • Take a screenshot of the dashboard for your presentation"
echo ""
