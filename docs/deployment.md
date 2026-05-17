# DISTRIBUTED INTRUSION DETECTION SYSTEM
## Deployment and Operations Guide
### Course: Parallel and Distributed Computing

---

## TABLE OF CONTENTS

1. System Requirements
2. Environment Setup
3. Compilation Instructions
4. Running Each Component
5. Full Pipeline Execution
6. Configuration Reference
7. Troubleshooting

---

## 1. SYSTEM REQUIREMENTS

### 1.1 Hardware Requirements

| Resource     | Minimum         | Recommended     |
|--------------|-----------------|-----------------|
| CPU Cores    | 2               | 4 or more       |
| RAM          | 2 GB            | 4 GB            |
| Disk Space   | 500 MB          | 2 GB            |
| Network      | Any interface   | eth0 or wlan0   |

### 1.2 Software Requirements

| Package              | Version  | Purpose                        |
|----------------------|----------|--------------------------------|
| Ubuntu / Debian      | 20.04+   | Operating system               |
| GCC                  | 9+       | C compiler                     |
| OpenMPI              | 4.x      | MPI implementation             |
| libpcap-dev          | 1.9+     | Packet capture library         |
| Python3              | 3.8+     | Dashboard and ML modules       |
| pip3                 | 21+      | Python package manager         |
| Flask                | 2.x+     | Web framework                  |
| Flask-SocketIO       | 5.x      | WebSocket support              |
| scikit-learn         | 1.x      | Machine learning               |
| numpy                | 1.21+    | Numerical computation          |
| matplotlib           | 3.5+     | Graph generation               |

---

## 2. ENVIRONMENT SETUP

### 2.1 Install System Packages

Run the following command once to install all required system packages:

```bash
sudo apt-get update && sudo apt-get install -y \
    gcc \
    build-essential \
    libopenmpi-dev \
    openmpi-bin \
    libpcap-dev \
    zlib1g-dev \
    python3 \
    python3-pip \
    make \
    tcpdump \
    net-tools
```

### 2.2 Install Python Libraries

```bash
pip3 install flask flask-socketio flask-cors \
             scikit-learn numpy matplotlib pandas \
             --break-system-packages
```

For PDF report generation (optional):

```bash
pip3 install fpdf2 --break-system-packages
```

### 2.3 Verify Installation

Check each tool is available:

```bash
gcc --version
mpicc --version
mpirun --version
python3 --version
python3 -c "import flask, sklearn, numpy, matplotlib; print('All OK')"
```

### 2.4 Create Project Directory Structure

```bash
cd /media/sf_PDIDS
mkdir -p build data/logs data/results ml docs tests
```

---

## 3. COMPILATION INSTRUCTIONS

All compilation commands are run from the project root directory
(/media/sf_PDIDS).

### 3.1 Compile Packet Capture Sensor

```bash
gcc -O2 -o build/packet_capture_csv \
    sensor/packet_capture_csv.c \
    -lpcap -lm
```

Flags:
  -O2      Enable optimization level 2
  -lpcap   Link the libpcap packet capture library
  -lm      Link the math library

### 3.2 Compile Packet Bridge

```bash
gcc -O2 -o build/packet_bridge \
    sensor/packet_bridge.c
```

No special libraries required. The bridge only reads CSV files and
manages TCP socket connections using standard POSIX socket API.

### 3.3 Compile Signature Detection (standalone test)

```bash
gcc -O2 -o build/signature_detection \
    central/signature_detection.c \
    -lm
```

### 3.4 Compile MPI Coordinator

```bash
mpicc -O2 -fopenmp -o build/coordinator_real \
    central/coordinator_real.c \
    -lm
```

Flags:
  mpicc      MPI compiler wrapper (substitutes for gcc, adds MPI paths)
  -fopenmp   Enable OpenMP thread-level parallelism
  -lm        Link the math library

### 3.5 Compile All at Once

```bash
make all
```

Or individually:

```bash
make week1    # test programs
make week2    # packet capture
make week3    # signature detection
make week4    # basic MPI coordinator
```

---

## 4. RUNNING EACH COMPONENT

### 4.1 Capture Real Network Packets

Requires root privileges because raw socket access is restricted.

```bash
# Capture 100 packets from loopback interface, save to CSV
sudo ./build/packet_capture_csv -i lo -n 100 -o data/logs/packets.csv

# Capture from ethernet interface
sudo ./build/packet_capture_csv -i eth0 -n 500 -o data/logs/packets.csv

# Capture unlimited packets until Ctrl+C
sudo ./build/packet_capture_csv -i lo -o data/logs/packets.csv
```

To generate traffic for capture, open a second terminal and run:

```bash
ping 127.0.0.1
```

Or for attack-like traffic:

```bash
sudo apt-get install -y nmap
nmap -sN 127.0.0.1       # NULL scan
nmap -sS 127.0.0.1       # SYN scan
```

### 4.2 Read and Verify a CSV File

No root privileges required.

```bash
./build/packet_bridge --read data/logs/packets.csv
```

Expected output: a table of all packets with quick threat annotations.

### 4.3 Run Signature Detection Unit Tests

```bash
./build/signature_detection
```

Expected output: 5 test cases, all showing PASS.

### 4.4 Generate Simulated Attack Traffic

```bash
# Default: 300 packets
python3 scripts/attack_simulator.py

# Custom count and output path
python3 scripts/attack_simulator.py -n 1000 -o data/logs/simulated.csv
```

### 4.5 Train the ML Model

```bash
# Train on real captured CSV
python3 ml/train_model.py --csv data/logs/packets.csv

# Train on simulated attack CSV
python3 ml/train_model.py --csv data/logs/simulated.csv

# Train on multiple files combined
python3 ml/train_model.py --csv data/logs/packets.csv data/logs/simulated.csv
```

### 4.6 Run ML Detection

```bash
python3 ml/ml_detector.py --csv data/logs/packets.csv
```

The model must be trained before running the detector. The detector
reads ml/model.pkl automatically.

### 4.7 Run MPI Coordinator (File Mode)

```bash
# 3 workers, 4 OMP threads each
OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 \
    ./build/coordinator_real \
    --file data/logs/packets.csv
```

Adjust -np based on available CPU cores:
  -np 2 = 1 coordinator + 1 worker
  -np 4 = 1 coordinator + 3 workers
  -np 5 = 1 coordinator + 4 workers (use --oversubscribe on a 4-core VM)

### 4.8 Run MPI Coordinator (Socket Mode - Two Terminals)

Terminal 1 (no root required):
```bash
./build/packet_bridge --serve data/logs/packets.csv
```

Terminal 2:
```bash
OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 \
    ./build/coordinator_real \
    --socket localhost:9999
```

### 4.9 Run the Web Dashboard

Simulated data mode:
```bash
python3 scripts/dashboard.py
```

Real CSV data mode:
```bash
python3 scripts/dashboard.py --csv data/logs/simulated.csv
```

Custom port:
```bash
python3 scripts/dashboard.py --csv data/logs/simulated.csv --port 8080
```

Open browser and navigate to: http://localhost:5000

Press Ctrl+C to stop the dashboard.

---

## 5. FULL PIPELINE EXECUTION

### 5.1 Automated Pipeline (Recommended for Demo)

```bash
chmod +x scripts/run_all.sh
./scripts/run_all.sh
```

This runs all 9 steps in sequence:
  Step 1: Compile all binaries
  Step 2: Generate simulated attack traffic
  Step 3: Verify CSV via packet bridge
  Step 4: Run signature detection tests
  Step 5: Train ML model
  Step 6: Run ML ensemble detection
  Step 7: Run MPI+OpenMP coordinator
  Step 8: Run speedup experiment
  Step 9: Launch web dashboard

### 5.2 Pipeline with Real Captured Data

```bash
# First capture real packets (requires sudo)
sudo ./build/packet_capture_csv -i lo -n 200 -o data/logs/real.csv

# Then run pipeline on real data
./scripts/run_all.sh --real data/logs/real.csv

# Or run pipeline without dashboard (faster for testing)
./scripts/run_all.sh --real data/logs/real.csv --no-dashboard
```

### 5.3 Run Full Test Suite

```bash
chmod +x tests/run_tests.sh
./tests/run_tests.sh
```

Expected output: summary table showing PASS/FAIL for all 22 tests.

### 5.4 Run Performance Benchmark

```bash
python3 tests/benchmark_fixed.py
```

This tests 5 configurations at 4 different packet counts (1000, 2000,
5000, 10000), runs each 3 times, and reports the best time. A speedup
graph is saved to data/results/speedup_corrected.png.

---

## 6. CONFIGURATION REFERENCE

### 6.1 MPI Configuration

The number of MPI processes is controlled by the -np flag:

```bash
mpirun --oversubscribe -np <N> ./build/coordinator_real --file <csv>
```

Recommended values for a 4-core VM:
  -np 2: 1 coordinator + 1 worker (baseline parallel)
  -np 4: 1 coordinator + 3 workers (optimal for 4 cores)
  -np 5: 1 coordinator + 4 workers (oversubscribed, use with caution)

The --oversubscribe flag is required when requesting more MPI processes
than available CPU cores. Without it, MPI will refuse to run if N
exceeds the detected slot count.

### 6.2 OpenMP Configuration

The number of OpenMP threads per worker is set via environment variable:

```bash
OMP_NUM_THREADS=4 mpirun --oversubscribe -np 4 ./build/coordinator_real ...
```

Recommended for a 4-core VM:
  OMP_NUM_THREADS=1: No thread-level parallelism (pure MPI mode)
  OMP_NUM_THREADS=2: 2 threads per worker (recommended with 2 workers)
  OMP_NUM_THREADS=4: 4 threads per worker (use with 1 worker only)

Rule of thumb: MPI_workers x OMP_threads should not exceed total core count.

### 6.3 Batch Size

The packet batch size is defined in coordinator_real.c:

```c
#define BATCH_SIZE 100
```

Increase for better MPI efficiency with large datasets.
Decrease for more responsive load balancing with small datasets.
Recompile after changing: mpicc -O2 -fopenmp -o build/coordinator_real ...

### 6.4 Detection Thresholds

Thresholds are defined in coordinator_real.c and signature_detection.c:

Port scan:    20 unique ports in 60 seconds
Brute force:  30 connection attempts in 60 seconds
Anomaly:      Z-score > 2.0 (moderate) or > 3.0 (severe)

---

## 7. TROUBLESHOOTING

### Problem: "No such file or directory" when running binaries

Cause: Binary not compiled yet, or compiled to wrong location.
Fix:
```bash
cd /media/sf_PDIDS
mkdir -p build
gcc -O2 -o build/coordinator_real central/coordinator_real.c ...
```

### Problem: "Permission denied" when running compiled binary

Cause: VirtualBox shared folder (vboxsf) does not support execute permission.
Fix: Compile to /tmp instead:
```bash
gcc -O2 -o /tmp/coordinator central/coordinator_real.c -lm
mpirun --oversubscribe -np 4 /tmp/coordinator --file data/logs/packets.csv
```

### Problem: "There are not enough slots" from mpirun

Cause: Requested more MPI processes than available cores.
Fix: Add --oversubscribe flag:
```bash
mpirun --oversubscribe -np 9 ./build/coordinator_real ...
```

### Problem: pcap.h not found during compilation

Cause: libpcap development headers not installed.
Fix:
```bash
sudo apt-get install libpcap-dev
```

### Problem: mpicc command not found

Cause: OpenMPI not installed.
Fix:
```bash
sudo apt-get install libopenmpi-dev openmpi-bin
```

### Problem: Dashboard shows "Disconnected" in browser

Cause: Flask-SocketIO not installed, or wrong port.
Fix:
```bash
pip3 install flask-socketio --break-system-packages
python3 scripts/dashboard.py --port 5001
```

### Problem: "No module named sklearn"

Cause: scikit-learn not installed.
Fix:
```bash
pip3 install scikit-learn --break-system-packages
```

### Problem: ML model file not found (ml/model.pkl)

Cause: Model has not been trained yet.
Fix:
```bash
python3 ml/train_model.py --csv data/logs/packets.csv
```

### Problem: Packet capture captures 0 packets

Cause: No traffic on the selected interface.
Fix: Open a second terminal and generate traffic:
```bash
ping 127.0.0.1          # for loopback interface
curl http://example.com  # for ethernet interface
```

---

*Document version: 1.0*
*Prepared for: Parallel and Distributed Computing — Final Project*
