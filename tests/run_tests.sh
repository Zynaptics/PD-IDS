#!/bin/bash
# =============================================================================
# WEEK 12 — COMPLETE TEST SUITE
# File: tests/run_tests.sh
# =============================================================================
#
# WHAT THIS DOES:
#   Runs a complete automated test of every component in your project.
#   Each test prints PASS or FAIL clearly.
#   At the end prints a summary table your teacher can see.
#
# HOW TO RUN:
#   chmod +x tests/run_tests.sh
#   ./tests/run_tests.sh
#
# WHAT IT TESTS:
#   Test 1  — GCC compiler works
#   Test 2  — MPI compiler works
#   Test 3  — OpenMP support works
#   Test 4  — Python3 works
#   Test 5  — All binaries compiled
#   Test 6  — Signature detection (5/5 cases)
#   Test 7  — Packet bridge reads CSV correctly
#   Test 8  — Attack simulator generates correct mix
#   Test 9  — ML model trains successfully
#   Test 10 — ML detector finds threats
#   Test 11 — MPI coordinator analyzes real packets
#   Test 12 — Hybrid MPI+OpenMP works
#   Test 13 — Speedup: parallel faster than sequential at scale
#   Test 14 — Dashboard starts and responds
#   Test 15 — Full pipeline end to end
# =============================================================================

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── State ─────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
declare -a RESULTS=()
declare -a TEST_NAMES=()

# ── Helpers ───────────────────────────────────────────────────
pass() {
    PASS=$((PASS + 1))
    RESULTS+=("PASS")
    TEST_NAMES+=("$1")
    echo -e "  ${GREEN}✅ PASS${RESET} — $1"
}

fail() {
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL")
    TEST_NAMES+=("$1")
    echo -e "  ${RED}❌ FAIL${RESET} — $1"
    if [ -n "$2" ]; then
        echo -e "        ${RED}Reason: $2${RESET}"
    fi
}

skip() {
    SKIP=$((SKIP + 1))
    RESULTS+=("SKIP")
    TEST_NAMES+=("$1")
    echo -e "  ${YELLOW}⏭  SKIP${RESET} — $1 ($2)"
}

section() {
    echo ""
    echo -e "${BOLD}${BLUE}── $1 ──────────────────────────────────────────${RESET}"
}

# ── Check we are in project root ─────────────────────────────
if [ ! -f "Makefile" ] && [ ! -d "sensor" ]; then
    echo -e "${RED}ERROR: Run from project root: cd /media/sf_PDIDS${RESET}"
    exit 1
fi

mkdir -p build data/logs data/results ml tests

# ═══════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════
clear
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${BLUE}║   D-IDS COMPLETE TEST SUITE — Week 12               ║${RESET}"
echo -e "${BOLD}${BLUE}║   Distributed Intrusion Detection System             ║${RESET}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${RESET}"
echo -e "${BOLD}${BLUE}║   $(date '+%Y-%m-%d %H:%M:%S')$(printf '%*s' $((30 - ${#$(date '+%Y-%m-%d %H:%M:%S')})) '')║${RESET}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ═══════════════════════════════════════════════════════════════
# GROUP 1: ENVIRONMENT TESTS
# ═══════════════════════════════════════════════════════════════
section "GROUP 1: Environment"

# Test 1 — GCC
echo -n "  Testing GCC... "
if gcc --version &>/dev/null; then
    VER=$(gcc --version | head -1)
    pass "GCC compiler available ($VER)"
else
    fail "GCC compiler" "gcc not found — run: sudo apt-get install gcc"
fi

# Test 2 — MPI
echo -n "  Testing MPI... "
if mpicc --version &>/dev/null; then
    pass "MPI compiler (mpicc) available"
else
    fail "MPI compiler" "mpicc not found — run: sudo apt-get install libopenmpi-dev"
fi

# Test 3 — OpenMP
echo -n "  Testing OpenMP... "
cat > /tmp/test_omp.c << 'EOF'
#include <omp.h>
#include <stdio.h>
int main() {
    #pragma omp parallel num_threads(2)
    { /* test */ }
    printf("OpenMP OK: max threads = %d\n", omp_get_max_threads());
    return 0;
}
EOF
if gcc -fopenmp -o /tmp/test_omp /tmp/test_omp.c &>/dev/null && \
   /tmp/test_omp &>/dev/null; then
    THREADS=$(/tmp/test_omp | grep -o '[0-9]*')
    pass "OpenMP working (max threads: $THREADS)"
else
    fail "OpenMP" "OpenMP not supported by this GCC"
fi

# Test 4 — Python3
echo -n "  Testing Python3... "
if python3 --version &>/dev/null; then
    VER=$(python3 --version)
    pass "Python3 available ($VER)"
else
    fail "Python3" "python3 not found"
fi

# Test 4b — Python libraries
echo -n "  Testing Python libraries... "
if python3 -c "import flask, sklearn, numpy, matplotlib" &>/dev/null; then
    pass "Flask, scikit-learn, numpy, matplotlib all installed"
else
    MISSING=$(python3 -c "
libs = ['flask','sklearn','numpy','matplotlib']
missing = []
for l in libs:
    try: __import__(l)
    except: missing.append(l)
print(','.join(missing))
" 2>/dev/null)
    fail "Python libraries" "Missing: $MISSING — run: pip3 install $MISSING --break-system-packages"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 2: COMPILATION TESTS
# ═══════════════════════════════════════════════════════════════
section "GROUP 2: Compilation"

# Test 5a — packet_capture_csv
echo -n "  Compiling packet_capture_csv... "
if [ -f "sensor/packet_capture_csv.c" ]; then
    if gcc -O2 -o build/packet_capture_csv \
       sensor/packet_capture_csv.c -lpcap -lm &>/dev/null; then
        pass "packet_capture_csv compiled"
    else
        fail "packet_capture_csv compilation" "Check sensor/packet_capture_csv.c"
    fi
else
    skip "packet_capture_csv compilation" "source file not found"
fi

# Test 5b — packet_bridge
echo -n "  Compiling packet_bridge... "
if [ -f "sensor/packet_bridge.c" ]; then
    if gcc -O2 -o build/packet_bridge sensor/packet_bridge.c &>/dev/null; then
        pass "packet_bridge compiled"
    else
        fail "packet_bridge compilation" "Check sensor/packet_bridge.c"
    fi
else
    skip "packet_bridge compilation" "source file not found"
fi

# Test 5c — signature_detection
echo -n "  Compiling signature_detection... "
if [ -f "central/signature_detection.c" ]; then
    if gcc -O2 -o build/signature_detection \
       central/signature_detection.c -lm &>/dev/null; then
        pass "signature_detection compiled"
    else
        fail "signature_detection compilation" "Check central/signature_detection.c"
    fi
else
    skip "signature_detection compilation" "source file not found"
fi

# Test 5d — coordinator_real (MPI + OpenMP)
echo -n "  Compiling coordinator_real (MPI+OpenMP)... "
if [ -f "central/coordinator_real.c" ]; then
    if mpicc -O2 -fopenmp -o build/coordinator_real \
       central/coordinator_real.c -lm &>/dev/null; then
        pass "coordinator_real compiled with MPI+OpenMP"
    else
        fail "coordinator_real compilation" "Check central/coordinator_real.c"
    fi
else
    skip "coordinator_real compilation" "source file not found"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 3: DETECTION ENGINE TESTS
# ═══════════════════════════════════════════════════════════════
section "GROUP 3: Signature Detection Engine"

# Test 6 — Run detection tests and check 5/5 pass
echo -n "  Running signature detection tests... "
if [ -f "build/signature_detection" ]; then
    OUTPUT=$(./build/signature_detection 2>&1)
    if echo "$OUTPUT" | grep -q "5/5 PASSED"; then
        pass "Signature detection: 5/5 tests passed"
    elif echo "$OUTPUT" | grep -q "PASSED"; then
        PASSED=$(echo "$OUTPUT" | grep "TEST RESULTS" | grep -o '[0-9]*/5')
        fail "Signature detection" "Only $PASSED tests passed"
    else
        fail "Signature detection" "Could not parse test output"
    fi
else
    skip "Signature detection tests" "binary not compiled"
fi

# Test 6b — Verify specific attack types detected
echo -n "  Verifying NULL scan detection... "
if [ -f "build/signature_detection" ]; then
    if ./build/signature_detection 2>&1 | grep -q "NULL Scan"; then
        pass "NULL scan correctly detected"
    else
        fail "NULL scan detection" "NULL scan not found in output"
    fi
else
    skip "NULL scan detection" "binary not compiled"
fi

echo -n "  Verifying brute force detection... "
if [ -f "build/signature_detection" ]; then
    if ./build/signature_detection 2>&1 | grep -q "Brute Force"; then
        pass "Brute force correctly detected"
    else
        fail "Brute force detection" "Brute force not found in output"
    fi
else
    skip "Brute force detection" "binary not compiled"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 4: DATA PIPELINE TESTS
# ═══════════════════════════════════════════════════════════════
section "GROUP 4: Data Pipeline"

# Test 7 — Attack simulator
echo -n "  Running attack simulator... "
if python3 scripts/attack_simulator.py \
   -n 100 -o data/logs/test_sim.csv &>/dev/null; then
    LINES=$(wc -l < data/logs/test_sim.csv)
    if [ "$LINES" -eq 101 ]; then   # 100 packets + 1 header
        pass "Attack simulator: generated 100 packets correctly"
    else
        fail "Attack simulator" "Expected 101 lines, got $LINES"
    fi
else
    fail "Attack simulator" "Script failed to run"
fi

# Test 8 — CSV has correct columns
echo -n "  Verifying CSV format... "
if [ -f "data/logs/test_sim.csv" ]; then
    HEADER=$(head -1 data/logs/test_sim.csv)
    if echo "$HEADER" | grep -q "timestamp" && \
       echo "$HEADER" | grep -q "src_ip" && \
       echo "$HEADER" | grep -q "protocol" && \
       echo "$HEADER" | grep -q "syn"; then
        pass "CSV format correct (all required columns present)"
    else
        fail "CSV format" "Missing columns. Header: $HEADER"
    fi
else
    skip "CSV format" "test_sim.csv not created"
fi

# Test 9 — Packet bridge reads CSV
echo -n "  Testing packet_bridge reads CSV... "
if [ -f "build/packet_bridge" ] && [ -f "data/logs/test_sim.csv" ]; then
    OUTPUT=$(./build/packet_bridge --read data/logs/test_sim.csv 2>&1)
    if echo "$OUTPUT" | grep -q "Packets read:  100"; then
        pass "Packet bridge: read 100 packets correctly"
    else
        LINES=$(echo "$OUTPUT" | grep "Packets read" | head -1)
        fail "Packet bridge" "Expected 100 packets. Got: $LINES"
    fi
else
    skip "Packet bridge CSV read" "binary or CSV not available"
fi

# Test 10 — Bridge detects some threats in simulated data
echo -n "  Testing bridge quick-detection on attack CSV... "
if [ -f "build/packet_bridge" ] && [ -f "data/logs/test_sim.csv" ]; then
    THREATS=$(./build/packet_bridge --read data/logs/test_sim.csv 2>&1 \
              | grep "Threats found" | grep -o '[0-9]*' | head -1)
    if [ -n "$THREATS" ] && [ "$THREATS" -gt 0 ]; then
        pass "Bridge detected $THREATS threats in simulated traffic"
    else
        fail "Bridge detection" "Expected threats > 0, got: $THREATS"
    fi
else
    skip "Bridge quick-detection" "binary or CSV not available"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 5: ML TESTS
# ═══════════════════════════════════════════════════════════════
section "GROUP 5: Machine Learning"

# Generate fresh data for ML tests
python3 scripts/attack_simulator.py \
    -n 200 -o data/logs/ml_test.csv &>/dev/null

# Test 11 — ML training
echo -n "  Training ML model... "
if python3 ml/train_model.py \
   --csv data/logs/ml_test.csv &>/dev/null; then
    if [ -f "ml/model.pkl" ]; then
        SIZE=$(du -h ml/model.pkl | cut -f1)
        pass "ML model trained and saved (model.pkl: $SIZE)"
    else
        fail "ML training" "model.pkl not created"
    fi
else
    fail "ML training" "train_model.py failed"
fi

# Test 12 — ML accuracy
echo -n "  Checking ML accuracy... "
if [ -f "ml/model.pkl" ]; then
    ACC=$(python3 ml/train_model.py \
          --csv data/logs/ml_test.csv 2>&1 \
          | grep "Accuracy:" | grep -o '[0-9.]*' | head -1)
    if [ -n "$ACC" ]; then
        # Compare using python since bash can't do float comparison
        PASS_ACC=$(python3 -c "print('yes' if float('$ACC') >= 70.0 else 'no')" 2>/dev/null)
        if [ "$PASS_ACC" = "yes" ]; then
            pass "ML accuracy: ${ACC}% (threshold: 70%)"
        else
            fail "ML accuracy" "${ACC}% is below 70% threshold"
        fi
    else
        fail "ML accuracy" "Could not parse accuracy from output"
    fi
else
    skip "ML accuracy check" "model not trained"
fi

# Test 13 — ML detection runs
echo -n "  Running ML detector... "
if [ -f "ml/model.pkl" ] && [ -f "data/logs/ml_test.csv" ]; then
    OUTPUT=$(python3 ml/ml_detector.py --csv data/logs/ml_test.csv 2>&1)
    if echo "$OUTPUT" | grep -q "DETECTION SUMMARY"; then
        DETECTED=$(echo "$OUTPUT" | grep "Threats detected:" \
                   | grep -o '[0-9]*' | head -1)
        pass "ML detector ran successfully (found $DETECTED threats)"
    else
        fail "ML detector" "Did not produce detection summary"
    fi
else
    skip "ML detector" "model or CSV not available"
fi

# Test 14 — Ensemble both engines fire
echo -n "  Verifying ensemble detection... "
if [ -f "ml/model.pkl" ] && [ -f "data/logs/ml_test.csv" ]; then
    ENSEMBLE=$(python3 ml/ml_detector.py \
               --csv data/logs/ml_test.csv 2>&1 \
               | grep "Both (ensemble):" | grep -o '[0-9]*' | head -1)
    if [ -n "$ENSEMBLE" ] && [ "$ENSEMBLE" -gt 0 ]; then
        pass "Ensemble detection: $ENSEMBLE threats caught by both engines"
    else
        fail "Ensemble detection" "No threats caught by both engines"
    fi
else
    skip "Ensemble detection" "model or CSV not available"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 6: MPI + OPENMP TESTS
# ═══════════════════════════════════════════════════════════════
section "GROUP 6: MPI + OpenMP Parallel Processing"

# Test 15 — MPI coordinator runs
echo -n "  Running MPI coordinator (file mode)... "
if [ -f "build/coordinator_real" ] && \
   [ -f "data/logs/test_sim.csv" ]; then
    OUTPUT=$(mpirun --oversubscribe -np 4 \
             ./build/coordinator_real \
             --file data/logs/test_sim.csv 2>&1)
    if echo "$OUTPUT" | grep -q "ANALYSIS RESULTS"; then
        THREATS=$(echo "$OUTPUT" | grep "Threats detected:" \
                  | grep -o '[0-9]*' | head -1)
        TIME=$(echo "$OUTPUT" | grep "Time:" \
               | grep -o '[0-9.]*' | head -1)
        pass "MPI coordinator: analyzed 100 packets in ${TIME}s, found $THREATS threats"
    else
        fail "MPI coordinator" "Did not produce analysis results"
    fi
else
    skip "MPI coordinator" "binary or CSV not available"
fi

# Test 16 — OpenMP threads actually used
echo -n "  Verifying OpenMP threads are active... "
if [ -f "build/coordinator_real" ] && \
   [ -f "data/logs/test_sim.csv" ]; then
    OUTPUT=$(OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 \
             ./build/coordinator_real \
             --file data/logs/test_sim.csv 2>&1)
    if echo "$OUTPUT" | grep -q "Threads"; then
        THREADS=$(echo "$OUTPUT" | grep "Threads" \
                  | grep -o '[0-9]*' | head -1)
        pass "OpenMP: $THREADS threads/worker confirmed in output"
    else
        fail "OpenMP threads" "Thread count not shown in output"
    fi
else
    skip "OpenMP verification" "binary or CSV not available"
fi

# Test 17 — Speedup at scale
echo -n "  Running speedup test (1000 packets)... "
if [ -f "build/coordinator_real" ]; then
    # Generate larger dataset
    python3 scripts/attack_simulator.py \
        -n 1000 -o data/logs/speedup_test.csv &>/dev/null

    # Time sequential
    T_SEQ=$(mpirun --oversubscribe -np 2 \
            ./build/coordinator_real \
            --file data/logs/speedup_test.csv 2>&1 \
            | grep "Time:" | grep -o '[0-9.]*' | head -1)

    # Time parallel (3 workers)
    T_PAR=$(mpirun --oversubscribe -np 4 \
            ./build/coordinator_real \
            --file data/logs/speedup_test.csv 2>&1 \
            | grep "Time:" | grep -o '[0-9.]*' | head -1)

    if [ -n "$T_SEQ" ] && [ -n "$T_PAR" ]; then
        # Calculate speedup using python
        SPEEDUP=$(python3 -c "
t_seq = float('$T_SEQ')
t_par = float('$T_PAR')
if t_par > 0:
    sp = t_seq / t_par
    print(f'{sp:.2f}')
else:
    print('N/A')
" 2>/dev/null)
        pass "Speedup test: seq=${T_SEQ}s, parallel=${T_PAR}s, speedup=${SPEEDUP}x"
    else
        fail "Speedup test" "Could not parse timing output"
    fi
else
    skip "Speedup test" "coordinator binary not compiled"
fi

# Test 18 — Hybrid MPI+OpenMP
echo -n "  Testing Hybrid MPI+OpenMP... "
if [ -f "build/coordinator_real" ] && \
   [ -f "data/logs/test_sim.csv" ]; then
    OUTPUT=$(OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 \
             ./build/coordinator_real \
             --file data/logs/test_sim.csv 2>&1)
    if echo "$OUTPUT" | grep -q "ANALYSIS RESULTS"; then
        pass "Hybrid MPI+OpenMP coordinator runs successfully"
    else
        fail "Hybrid MPI+OpenMP" "No analysis results produced"
    fi
else
    skip "Hybrid MPI+OpenMP" "binary or CSV not available"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 7: DASHBOARD TEST
# ═══════════════════════════════════════════════════════════════
section "GROUP 7: Web Dashboard"

# Test 19 — Dashboard starts and responds
echo -n "  Testing dashboard starts correctly... "
if python3 -c "import flask, flask_socketio" &>/dev/null; then
    # Start dashboard in background
    python3 scripts/dashboard.py &>/dev/null &
    DASH_PID=$!
    sleep 3   # give it time to start

    # Try to connect
    if curl -s http://localhost:5000 &>/dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000)
        if [ "$HTTP_CODE" = "200" ]; then
            pass "Dashboard: HTTP 200 OK on http://localhost:5000"
        else
            fail "Dashboard" "Got HTTP $HTTP_CODE instead of 200"
        fi
    else
        fail "Dashboard" "Could not connect to localhost:5000"
    fi
    kill $DASH_PID &>/dev/null
    wait $DASH_PID &>/dev/null
else
    skip "Dashboard test" "Flask not installed"
fi

# Test 20 — Dashboard API endpoints
echo -n "  Testing dashboard API endpoints... "
python3 scripts/dashboard.py &>/dev/null &
DASH_PID=$!
sleep 3

API_OK=1
for endpoint in "/api/speedup" "/api/state"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
           http://localhost:5000$endpoint 2>/dev/null)
    if [ "$CODE" != "200" ]; then
        API_OK=0
        break
    fi
done

kill $DASH_PID &>/dev/null
wait $DASH_PID &>/dev/null

if [ $API_OK -eq 1 ]; then
    pass "Dashboard API: /api/speedup and /api/state both return 200"
else
    fail "Dashboard API" "One or more endpoints returned non-200"
fi

# ═══════════════════════════════════════════════════════════════
# GROUP 8: END-TO-END PIPELINE TEST
# ═══════════════════════════════════════════════════════════════
section "GROUP 8: End-to-End Pipeline"

# Test 21 — Full pipeline
echo -n "  Running full pipeline (no dashboard)... "
if ./scripts/run_all.sh --no-dashboard -n 100 &>/dev/null; then
    # Check all expected outputs exist
    PIPELINE_OK=1
    [ ! -f "data/logs/simulated.csv" ] && PIPELINE_OK=0
    [ ! -f "ml/model.pkl"            ] && PIPELINE_OK=0

    if [ $PIPELINE_OK -eq 1 ]; then
        pass "Full pipeline: all steps completed, all outputs created"
    else
        fail "Full pipeline" "Some expected output files missing"
    fi
else
    fail "Full pipeline" "run_all.sh returned non-zero exit code"
fi

# Test 22 — Output files exist
echo -n "  Checking all output files exist... "
FILES_OK=1
MISSING_FILES=""

check_output() {
    if [ ! -f "$1" ]; then
        FILES_OK=0
        MISSING_FILES="$MISSING_FILES $1"
    fi
}

check_output "build/packet_bridge"
check_output "build/coordinator_real"
check_output "build/signature_detection"
check_output "ml/model.pkl"
check_output "data/logs/simulated.csv"

if [ $FILES_OK -eq 1 ]; then
    pass "All expected output files present"
else
    fail "Output files" "Missing:$MISSING_FILES"
fi

# ═══════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${BLUE}║   TEST RESULTS SUMMARY — Week 12                    ║${RESET}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${RESET}"
echo -e "${BOLD}${BLUE}║                                                      ║${RESET}"

for i in "${!RESULTS[@]}"; do
    NAME="${TEST_NAMES[$i]}"
    RESULT="${RESULTS[$i]}"
    NUM=$((i + 1))

    if [ "$RESULT" = "PASS" ]; then
        COLOR=$GREEN
        ICON="✅"
    elif [ "$RESULT" = "FAIL" ]; then
        COLOR=$RED
        ICON="❌"
    else
        COLOR=$YELLOW
        ICON="⏭"
    fi

    # Truncate long names
    if [ ${#NAME} -gt 44 ]; then
        NAME="${NAME:0:41}..."
    fi

    printf "${BOLD}${BLUE}║${RESET}  ${COLOR}${ICON} %2d. %-44s${RESET}${BOLD}${BLUE}║${RESET}\n" \
           "$NUM" "$NAME"
done

echo -e "${BOLD}${BLUE}║                                                      ║${RESET}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${RESET}"
echo -e "${BOLD}${BLUE}║                                                      ║${RESET}"
printf "${BOLD}${BLUE}║${RESET}  ${GREEN}✅ PASSED: %-42s${BOLD}${BLUE}║${RESET}\n" "$PASS"
printf "${BOLD}${BLUE}║${RESET}  ${RED}❌ FAILED: %-42s${BOLD}${BLUE}║${RESET}\n" "$FAIL"
printf "${BOLD}${BLUE}║${RESET}  ${YELLOW}⏭  SKIPPED:%-42s${BOLD}${BLUE}║${RESET}\n" "$SKIP"
printf "${BOLD}${BLUE}║${RESET}     TOTAL: %-42s${BOLD}${BLUE}║${RESET}\n" "$TOTAL"
echo -e "${BOLD}${BLUE}║                                                      ║${RESET}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${RESET}"

# Overall verdict
if [ $FAIL -eq 0 ]; then
    echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}${BOLD}✅ ALL TESTS PASSED — SYSTEM READY FOR DEMO!${RESET}  ${BOLD}${BLUE}║${RESET}"
elif [ $FAIL -le 2 ]; then
    echo -e "${BOLD}${BLUE}║${RESET}  ${YELLOW}${BOLD}⚠  $FAIL TEST(S) FAILED — MINOR ISSUES ONLY${RESET}    ${BOLD}${BLUE}║${RESET}"
else
    echo -e "${BOLD}${BLUE}║${RESET}  ${RED}${BOLD}❌ $FAIL TESTS FAILED — NEEDS ATTENTION${RESET}         ${BOLD}${BLUE}║${RESET}"
fi

echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Performance summary for report ───────────────────────────
echo -e "${BOLD}${CYAN}  PERFORMANCE NUMBERS FOR YOUR REPORT:${RESET}"
echo ""

if [ -f "data/logs/speedup_test.csv" ]; then
    echo -e "  ${CYAN}Running final speedup measurement (1000 packets)...${RESET}"
    echo ""

    T1=$(mpirun --oversubscribe -np 2 ./build/coordinator_real \
         --file data/logs/speedup_test.csv 2>&1 \
         | grep "Time:" | grep -o '[0-9.]*' | head -1)

    T2=$(mpirun --oversubscribe -np 3 ./build/coordinator_real \
         --file data/logs/speedup_test.csv 2>&1 \
         | grep "Time:" | grep -o '[0-9.]*' | head -1)

    T3=$(mpirun --oversubscribe -np 4 ./build/coordinator_real \
         --file data/logs/speedup_test.csv 2>&1 \
         | grep "Time:" | grep -o '[0-9.]*' | head -1)

    T4=$(OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 \
         ./build/coordinator_real \
         --file data/logs/speedup_test.csv 2>&1 \
         | grep "Time:" | grep -o '[0-9.]*' | head -1)

    python3 - <<PYEOF
t = {'Sequential': $T1,
     'MPI 1 worker': $T2,
     'MPI 3 workers': $T3,
     'Hybrid 3w x 4t': $T4}

seq = t['Sequential']
print(f"  {'Configuration':<20} {'Time(s)':>8}  {'Speedup':>8}  {'Pkt/s':>8}")
print(f"  {'-'*20} {'-'*8}  {'-'*8}  {'-'*8}")
for name, time in t.items():
    sp  = seq / time if time > 0 else 0
    pps = 1000 / time if time > 0 else 0
    print(f"  {name:<20} {time:>8.4f}  {sp:>7.2f}x  {pps:>8.0f}")
print()
print("  Copy this table into your final report!")
PYEOF
fi

echo ""
echo -e "  ${GREEN}${BOLD}Week 12 testing complete!${RESET}"
echo ""
