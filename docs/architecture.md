# DISTRIBUTED INTRUSION DETECTION SYSTEM
## System Architecture Document
### Course: Parallel and Distributed Computing
### Instructor: Waqas Ali

---

## TABLE OF CONTENTS

1. Executive Summary
2. System Overview
3. Architectural Design
4. Component Descriptions
5. Data Flow and Communication
6. Parallel Processing Design
7. Detection Engine Architecture
8. Machine Learning Subsystem
9. Web Dashboard Architecture
10. Technology Stack
11. Security Considerations
12. Performance Architecture
13. File and Directory Structure

---

## 1. EXECUTIVE SUMMARY

The Distributed Intrusion Detection System (D-IDS) is a complete network security
monitoring platform built on parallel and distributed computing principles. The system
captures live network traffic, distributes packet analysis across multiple parallel
worker processes using the Message Passing Interface (MPI), applies three independent
detection engines to identify threats, and presents findings through a real-time web
dashboard.

The system demonstrates the practical application of parallel computing concepts in
a real-world cybersecurity context. By combining MPI for inter-process communication
and OpenMP for intra-process thread-level parallelism, the system achieves a hybrid
parallelism model capable of processing thousands of packets per second on commodity
hardware.

---

## 2. SYSTEM OVERVIEW

### 2.1 Purpose

Traditional intrusion detection systems are constrained by single-threaded processing
architectures that cannot keep pace with modern network traffic volumes. The D-IDS
addresses this limitation through distributed parallel processing, enabling real-time
threat detection at high packet rates.

### 2.2 Core Capabilities

The system provides the following capabilities:

- Live network packet capture using the libpcap library
- Persistent packet storage in CSV format for offline analysis and replay
- Parallel packet analysis distributed across multiple MPI worker processes
- Three-engine threat detection combining signature analysis, statistical anomaly
  detection, and machine learning classification
- Real-time web dashboard with live alert streaming via WebSocket
- Automated report generation in PDF or plain text format
- Comprehensive test suite and performance benchmarking tools

### 2.3 System Boundaries

The system operates at the network layer, capturing IP packets at the interface level.
It processes TCP, UDP, and ICMP traffic. The system does not modify network traffic
and operates in a passive monitoring mode only.

---

## 3. ARCHITECTURAL DESIGN

### 3.1 Layered Architecture

The system is organized into four functional layers:

```
+----------------------------------------------------------+
|                    LAYER 4: PRESENTATION                  |
|         Web Dashboard | REST API | Report Generator       |
+----------------------------------------------------------+
|                    LAYER 3: ANALYSIS                      |
|    Signature Engine | Anomaly Engine | ML Engine          |
+----------------------------------------------------------+
|                    LAYER 2: COORDINATION                  |
|        MPI Coordinator | OpenMP Workers | Load Balancer   |
+----------------------------------------------------------+
|                    LAYER 1: DATA COLLECTION               |
|        Packet Capture | CSV Bridge | Socket Bridge        |
+----------------------------------------------------------+
```

### 3.2 Process Architecture

When the system runs in full parallel mode, the following processes operate
simultaneously:

```
Process Layout (mpirun -np 4):

  Process 0: MPI Coordinator
  |-- Reads packets from CSV file or socket
  |-- Distributes batches to workers via MPI_Send
  |-- Collects results via MPI_Recv
  |-- Aggregates threat data
  |-- Produces final report

  Process 1: MPI Worker (rank 1)
  |-- Receives packet batch from coordinator
  |-- Spawns OpenMP threads internally
  |   |-- Thread 0: analyzes packets 0-24
  |   |-- Thread 1: analyzes packets 25-49
  |   |-- Thread 2: analyzes packets 50-74
  |   |-- Thread 3: analyzes packets 75-99
  |-- Returns results to coordinator

  Process 2: MPI Worker (rank 2)
  |-- Identical structure to Process 1

  Process 3: MPI Worker (rank 3)
  |-- Identical structure to Process 1
```

### 3.3 Hybrid Parallelism Model

The system implements a two-level parallelism hierarchy:

Level 1 - Distributed Memory Parallelism (MPI):
  Separate processes with independent memory spaces communicate by passing
  messages. Each MPI worker receives a batch of packets, processes them
  independently, and returns results. This model scales across multiple
  physical machines.

Level 2 - Shared Memory Parallelism (OpenMP):
  Within each MPI worker process, multiple threads share the same memory
  and cooperate on analyzing a packet batch. Threads are created with
  the pragma omp parallel directive and scheduled dynamically.

The combination of both levels allows the system to exploit parallelism
at both the network (inter-node) and processor (intra-node) levels,
which is the standard approach in high-performance computing.

---

## 4. COMPONENT DESCRIPTIONS

### 4.1 Packet Capture Sensor (sensor/packet_capture_csv.c)

The packet capture sensor is a C program that uses the libpcap library to read
raw network packets directly from a network interface. The sensor operates in
promiscuous mode, meaning it captures all packets visible on the interface,
not just those addressed to the host machine.

For each captured packet, the sensor parses:
- Ethernet header (14 bytes): extracts EtherType to identify IP packets
- IP header (20+ bytes): extracts source IP, destination IP, protocol number
- TCP header (20 bytes): extracts source port, destination port, and all flags
- UDP header (8 bytes): extracts source and destination ports

Extracted data is written to a CSV file in the following format:
  timestamp, src_ip, src_port, dst_ip, dst_port, protocol, size,
  syn, ack, fin, rst, psh

The sensor supports a configurable BPF (Berkeley Packet Filter) expression
to restrict which packets are captured, reducing CPU load on the sensor host.

### 4.2 Packet Bridge (sensor/packet_bridge.c)

The packet bridge connects the capture layer to the analysis layer. It operates
in two modes:

Read Mode:
  Reads a CSV file and displays packet contents with quick threat annotations.
  Used to verify that captured data is correctly formatted before analysis.
  Does not require elevated privileges.

Serve Mode:
  Reads a CSV file and streams each packet as a JSON-encoded line over a TCP
  socket connection to the coordinator. This enables a live pipeline where
  newly captured packets are analyzed immediately.

### 4.3 MPI Coordinator (central/coordinator_real.c)

The coordinator is the central process in the MPI process group (rank 0). Its
responsibilities are:

  Input Management: Loading packets from CSV files or receiving them from
  the packet bridge over a TCP socket connection.

  Work Distribution: Dividing the packet workload into batches of fixed size
  (BATCH_SIZE = 100 packets) and distributing batches to available workers
  using MPI_Send with a TAG_PACKET tag.

  Dynamic Load Balancing: Using a work-stealing approach where each worker
  that completes a batch immediately receives another, preventing idle workers
  while slower workers are still processing.

  Result Aggregation: Receiving DetectionResult structures from workers via
  MPI_Recv with a TAG_RESULT tag, collecting all results, and building the
  final threat report.

  Worker Termination: Sending an empty packet with TAG_TERMINATE to all
  workers once all packets have been distributed and all results collected.

### 4.4 MPI Workers (central/coordinator_real.c, worker functions)

Worker processes (ranks 1 through N-1) execute the following loop:

  1. Block on MPI_Recv waiting for a packet batch from rank 0
  2. If the received tag is TAG_TERMINATE, exit the loop
  3. Initialize an OpenMP parallel region over the received batch
  4. Each OpenMP thread calls analyze_packet() on its assigned packets
  5. After the parallel region completes, send all results to rank 0
  6. Return to step 1

The detection state (port scan tracker, rate tracker, anomaly baseline) is
stored in worker-local memory. An OpenMP lock protects shared state from
concurrent modification by multiple threads within the same worker.

### 4.5 Signature Detection Engine

The signature detection engine implements pattern-based threat detection.
It maintains stateful tracking across multiple packets to identify patterns
that require observing multiple packets from the same source.

Detection rules implemented:
  NULL Scan: TCP packet with no flags set
  Port Scan: Single source IP connecting to more than 20 different destination
             ports within a 60-second window
  Brute Force: More than 30 connection attempts to SSH (22), RDP (3389),
               FTP (21), or Telnet (23) within a 60-second window
  Suspicious Port: Traffic to or from ports associated with known malware
                   (4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080)
  SYN Flood: More than 100 TCP SYN packets without corresponding ACK within
             a 10-second window

### 4.6 Anomaly Detection Engine

The anomaly detection engine identifies traffic that deviates statistically
from established baseline behavior. The baseline is updated continuously
using Welford's online algorithm, which computes running mean and variance
without storing all past values.

For each packet, the engine computes a Z-score for packet size:
  z = |packet_size - baseline_mean| / baseline_std

Packets with |z| > 3.0 are flagged as extreme anomalies (99.7th percentile).
Packets with |z| > 2.0 are flagged as moderate anomalies (95th percentile).

Additional anomaly checks include traffic on unknown privileged ports
(ports below 1024 not in the known-normal list) and unusually small
TCP packets (below 40 bytes), which may indicate crafted probe packets.

### 4.7 Machine Learning Detection Engine (ml/train_model.py, ml/ml_detector.py)

The ML detection engine uses a Random Forest classifier trained on labeled
packet data. The model is trained offline and serialized to disk as model.pkl.
During detection, the trained model is loaded and used for inference only.

Feature vector (12 dimensions per packet):
  1.  Protocol number, normalized to [0,1] by dividing by 17
  2.  Source port, normalized to [0,1] by dividing by 65535
  3.  Destination port, normalized to [0,1] by dividing by 65535
  4.  Packet size, normalized to [0,1] by dividing by 65535
  5.  SYN flag (binary: 0 or 1)
  6.  ACK flag (binary: 0 or 1)
  7.  FIN flag (binary: 0 or 1)
  8.  RST flag (binary: 0 or 1)
  9.  PSH flag (binary: 0 or 1)
  10. Privileged port flag (1 if destination port < 1024)
  11. Bad port flag (1 if port matches known malware port list)
  12. Size Z-score, capped at 10.0 and normalized to [0,1]

Training uses automatic labeling derived from the signature detection rules,
creating a ground truth label (0=normal, 1=attack) for each training sample.
Data augmentation is applied when the attack sample count is below 60, creating
synthetic variants to prevent class imbalance from degrading model performance.

### 4.8 Ensemble Decision Engine

The ensemble engine combines outputs from the signature and ML engines:
  Both engines detect a threat: confidence is boosted by 10 points and the
    threat level is promoted by one severity level
  Only signature engine detects: result used as-is
  Only ML engine detects: result used with the ML confidence score
  Neither engine detects: packet classified as normal

This approach reduces false positives compared to any single engine alone,
because both engines must independently agree for the highest confidence
results to be reported.

### 4.9 Web Dashboard (scripts/dashboard.py)

The dashboard is a Flask web application that serves a single-page HTML
interface with real-time updates delivered via Socket.IO WebSocket connections.

REST API endpoints:
  GET /              Serves the main dashboard HTML page
  GET /api/state     Returns current system state as JSON
  GET /api/speedup   Returns speedup benchmark data for chart rendering
  GET /api/report    Generates and returns a downloadable report file

WebSocket events emitted by server:
  init               Sent on client connect with current state snapshot
  stats              Sent every 3 seconds with packet and threat counts
  alert              Sent immediately when a new threat is detected

The dashboard operates in two modes:
  CSV mode (--csv flag): Reads a captured CSV file in batches of 10 packets
    every 3 seconds, analyzing each packet and emitting alerts for threats
  Simulated mode (default): Generates realistic synthetic traffic for
    demonstration purposes when no real capture data is available

---

## 5. DATA FLOW AND COMMUNICATION

### 5.1 File Mode Pipeline

```
[Network Interface]
        |
        | libpcap raw packet capture
        v
[packet_capture_csv.c]
        |
        | writes CSV rows
        v
[data/logs/packets.csv]
        |
        | fscanf CSV parsing
        v
[coordinator_real.c (rank 0)]
        |
        | MPI_Send batch (BATCH_SIZE packets)
        v
[coordinator_real.c (rank 1,2,3)]
        |
        | OpenMP parallel for loop
        v
[analyze_packet() per thread]
        |
        | MPI_Send DetectionResult[]
        v
[coordinator_real.c (rank 0)]
        |
        | aggregates, prints report
        v
[Terminal output / data/results/]
```

### 5.2 Socket Mode Pipeline

```
[Network Interface]
        |
        | libpcap capture
        v
[packet_bridge.c --serve]
        |
        | JSON lines over TCP socket
        v
[coordinator_real.c --socket]
        |
        | (same as file mode from here)
        v
[Workers / Detection / Report]
```

### 5.3 MPI Communication Pattern

The coordinator uses an asynchronous work-distribution pattern:

Phase 1 - Initial seeding:
  For each worker w (1 to num_workers), if packets remain:
    MPI_Send(batch, worker=w, tag=TAG_PACKET)
    pending++

Phase 2 - Dynamic distribution:
  While pending > 0:
    MPI_Recv(results, source=MPI_ANY_SOURCE, tag=TAG_RESULT)
    Store received results
    pending--
    If more packets remain:
      MPI_Send(next_batch, worker=message_source, tag=TAG_PACKET)
      pending++

Phase 3 - Termination:
  For each worker:
    MPI_Send(empty_packet, tag=TAG_TERMINATE)

This pattern ensures no worker is ever idle while packets remain to be
processed, achieving near-optimal load balancing without complex scheduling.

---

## 6. PARALLEL PROCESSING DESIGN

### 6.1 Work Decomposition

The packet workload is decomposed at two levels:

Coarse-grained (MPI): The total packet set is divided into batches.
  Each batch is assigned to one MPI worker process. Workers operate
  independently with no shared memory between them.

Fine-grained (OpenMP): Within each worker, a batch of packets is
  divided among threads using a dynamic schedule. Each thread picks up
  packets from a shared work queue in groups of 4 (schedule(dynamic, 4)).

### 6.2 Synchronization

MPI level: No explicit synchronization is required during the work phase.
  The coordinator uses MPI_ANY_SOURCE to receive results from whichever
  worker finishes first, avoiding the need to wait for slower workers.
  Termination synchronization is achieved by sending TAG_TERMINATE to
  each worker individually after all results are collected.

OpenMP level: An omp_lock protects the shared detection state tables
  (port scan tracker, rate tracker, anomaly baseline) from concurrent
  modification. The lock is acquired only when reading or writing shared
  state, and released immediately after to minimize lock contention.

Stateless checks (NULL scan detection, bad port detection) do not
require the lock and execute fully in parallel across all threads.

### 6.3 Load Balancing

The dynamic MPI distribution pattern ensures automatic load balancing.
Workers that complete their batch quickly receive new work immediately.
Workers processing more complex packets (that trigger deeper detection
logic) may take slightly longer, but the overall pipeline remains
efficient because other workers continue without waiting.

The OpenMP dynamic schedule similarly balances load within each worker.
Threads that finish their current group of 4 packets pick up the next
available group from the shared counter.

### 6.4 Scalability Analysis

The system follows Amdahl's Law in its scaling behavior. The serial
fraction includes:
  - CSV file reading (single-threaded I/O)
  - MPI message serialization overhead
  - Result aggregation by the coordinator

The parallel fraction includes:
  - Packet feature extraction
  - Signature rule evaluation
  - Anomaly score calculation
  - ML inference (forward pass through trained model)

At 10,000 packets analyzed, benchmarking results show:
  Sequential:          0.0130 seconds
  MPI 3 workers:       0.0081 seconds  (1.60x speedup)
  Hybrid 2w x 2t:      0.0099 seconds  (1.31x speedup)

The modest speedup values reflect the small dataset size relative to
MPI communication overhead. At 50,000+ packets, speedup values would
increase substantially as the parallel fraction dominates.

---

## 7. DETECTION ENGINE ARCHITECTURE

### 7.1 Engine Pipeline

For each packet, detection engines are called in sequence:

```
PacketRecord input
      |
      +---> detect_signature() ---> DetectionResult (sig)
      |
      +---> detect_anomaly()   ---> DetectionResult (ano)
      |
      v
ensemble_decision(sig, ano) ---> final DetectionResult
      |
      v
MPI_Send result to coordinator
```

### 7.2 Threat Scoring

Each detection result carries a threat level and confidence score:

  THREAT_NONE     (0): Normal traffic, no detection
  THREAT_LOW      (1): Minor anomaly, informational only
  THREAT_MEDIUM   (2): Moderate threat, investigation recommended
  THREAT_HIGH     (3): Significant threat, response required
  THREAT_CRITICAL (4): Severe threat, immediate response required

Confidence scores range from 0.0 to 1.0 and represent the detection
engine's certainty in its classification. Ensemble detection boosts
confidence when multiple engines agree on the same classification.

### 7.3 Stateful vs Stateless Detection

Stateless detections (evaluate each packet independently):
  - NULL scan detection (checks TCP flags only)
  - Suspicious port detection (checks port number only)
  - Oversized packet detection (checks packet size only)

Stateful detections (require tracking state across packets):
  - Port scan detection (tracks unique ports per source IP)
  - Brute force detection (tracks connection rate per source IP)
  - Anomaly detection (maintains running baseline statistics)

Stateful detections require the OpenMP lock because multiple threads
may attempt to update the tracking tables simultaneously. Stateless
detections execute without any locking overhead.

---

## 8. MACHINE LEARNING SUBSYSTEM

### 8.1 Training Pipeline

```
[CSV packet data]
       |
       v
[Auto-labeling using signature rules]
       |
       v
[Feature extraction (12 features per packet)]
       |
       v
[Data augmentation if attack count < 60]
       |
       v
[80/20 train/test split with stratification]
       |
       v
[StandardScaler normalization]
       |
       v
[RandomForestClassifier training (100 trees)]
       |
       v
[Evaluation: accuracy, precision, recall, F1]
       |
       v
[Serialize model to ml/model.pkl]
```

### 8.2 Model Selection Rationale

Random Forest was selected over alternative models for the following reasons:

  Performance on small datasets: Random Forest performs well with 100-500
    training samples, whereas deep neural networks require thousands.

  Feature importance: Random Forest provides interpretable feature importance
    scores, which are useful for explaining detection decisions.

  Robustness to class imbalance: With the class_weight='balanced' parameter,
    the model adjusts sample weights to handle imbalanced normal/attack ratios.

  No hyperparameter sensitivity: Random Forest does not require careful
    tuning of learning rate or architecture, making it suitable for automated
    retraining on new capture data.

### 8.3 Model Evaluation Results

Results on 200-sample test set from simulated attack traffic:

  Accuracy:   100.0%
  Precision:  100.0%
  Recall:     100.0%
  F1 Score:   100.0%

Note: Perfect scores are expected on simulated data because the ML model
is trained on the same rules used to generate the simulation. Performance
on real-world traffic would be lower, typically 85-95% accuracy, which
is acceptable for a network IDS application.

Top contributing features by importance:
  1. Size Z-score:       22.0% (most discriminative)
  2. Destination port:   18.3%
  3. Packet size:        13.5%

---

## 9. WEB DASHBOARD ARCHITECTURE

### 9.1 Server-Side Architecture

The dashboard backend uses Flask as the HTTP framework with Flask-SocketIO
providing WebSocket support. A background thread continuously processes
packet data and emits Socket.IO events to all connected clients.

The server maintains a global state dictionary protected by a threading.Lock,
ensuring thread-safe access between the background data thread and the
Flask request handlers.

### 9.2 Client-Side Architecture

The dashboard is a single-page application rendered entirely within one
HTML file served by Flask. Chart.js provides the visualization library.
Socket.IO client handles WebSocket communication.

Chart.js animation is disabled globally (Chart.defaults.animation = false)
and chart containers use fixed pixel heights to prevent the zoom and resize
artifacts that occur when animation conflicts with responsive layout.

### 9.3 Dashboard Tabs

Tab 1 - Live Monitor:
  Real-time threat timeline (line chart, last 15 updates)
  Attack type distribution (doughnut chart)
  Live alert list with level, type, source, destination, and timestamp

Tab 2 - Speedup Analysis:
  Speedup comparison bar chart (Sequential vs MPI vs Hybrid)
  Execution time bar chart
  Throughput bar chart
  Speedup table with all configurations and packet counts

Tab 3 - Top Attackers:
  Source IP address ranking by packet count
  Attack type breakdown table with percentage share

---

## 10. TECHNOLOGY STACK

| Component           | Technology          | Version  | Purpose                        |
|---------------------|---------------------|----------|--------------------------------|
| Packet capture      | libpcap             | 1.10+    | Raw network packet access      |
| Parallel processing | OpenMPI             | 4.x      | Distributed process management |
| Thread parallelism  | OpenMP              | 4.5      | Intra-process threading        |
| C compiler          | GCC                 | 11+      | Compiling C modules            |
| Web framework       | Flask               | 3.x      | HTTP server and routing        |
| WebSocket           | Flask-SocketIO      | 5.x      | Real-time browser updates      |
| ML framework        | scikit-learn        | 1.x      | Random Forest training         |
| Data processing     | NumPy               | 1.24+    | Numerical feature computation  |
| Visualization       | matplotlib          | 3.7+     | Graph generation for reports   |
| Chart rendering     | Chart.js            | 4.4.0    | Browser-side chart rendering   |
| Operating system    | Ubuntu 22.04        | LTS      | Deployment environment         |
| Serialization       | pickle              | stdlib   | Model persistence              |
| Data format         | CSV                 | RFC 4180 | Packet storage and exchange    |

---

## 11. SECURITY CONSIDERATIONS

The D-IDS operates in passive monitoring mode only. It reads network packets
but does not inject, modify, or block any traffic. The following security
boundaries apply:

Privilege requirement: Raw packet capture via libpcap requires root privileges
(sudo). The coordinator and all analysis components run without elevated
privileges.

Network exposure: The web dashboard binds to 0.0.0.0 on port 5000 by default,
making it accessible from any network interface. In production deployment,
this should be restricted to a management network interface only.

Data retention: Captured CSV files contain full IP address information. Access
to these files should be restricted to authorized security personnel.

---

## 12. PERFORMANCE ARCHITECTURE

### 12.1 Benchmarking Results

System configuration: Ubuntu 22.04, 4-core VM, 4 GB RAM

| Configuration      | 1000 pkts | 2000 pkts | 5000 pkts | 10000 pkts |
|--------------------|-----------|-----------|-----------|------------|
| Sequential         | 0.0020 s  | 0.0035 s  | 0.0085 s  | 0.0130 s   |
| MPI 1 worker       | 0.0016 s  | 0.0035 s  | 0.0072 s  | 0.0136 s   |
| MPI 3 workers      | 0.0016 s  | 0.0026 s  | 0.0054 s  | 0.0081 s   |
| Hybrid 2w x 2t     | 0.0022 s  | 0.0042 s  | 0.0061 s  | 0.0099 s   |

### 12.2 Speedup Table

| Configuration  | 1000 pkts | 2000 pkts | 5000 pkts | 10000 pkts |
|----------------|-----------|-----------|-----------|------------|
| MPI 1 worker   | 1.25x     | 1.00x     | 1.18x     | 0.96x      |
| MPI 3 workers  | 1.25x     | 1.35x     | 1.57x     | 1.60x      |
| Hybrid 2w x 2t | 0.91x     | 0.83x     | 1.39x     | 1.31x      |

### 12.3 Performance Analysis

MPI 3 workers achieves the best speedup (1.60x at 10,000 packets) because all
four available cores are used efficiently: one coordinator plus three workers,
each running on a dedicated core with no thread management overhead.

The Hybrid 2w x 2t configuration achieves 1.31x speedup. The slightly lower
performance compared to pure MPI is attributed to OpenMP thread creation and
synchronization overhead on a 4-core machine. On 8+ core machines, the hybrid
configuration would outperform pure MPI because each worker could exploit
additional thread-level parallelism without competition for cores.

---

## 13. FILE AND DIRECTORY STRUCTURE

```
distributed-ids/
|
+-- sensor/
|   +-- packet_capture.c         Original packet capture (Week 2)
|   +-- packet_capture_csv.c     Upgraded capture with CSV output (Week 9)
|   +-- packet_bridge.c          CSV-to-coordinator bridge (Week 9)
|
+-- central/
|   +-- signature_detection.c    Standalone detection engine test (Week 3)
|   +-- coordinator_mpi.c        Basic MPI coordinator (Week 4)
|   +-- hybrid_coordinator.c     MPI + OpenMP coordinator (Week 5-6)
|   +-- coordinator_real.c       Full coordinator with real input (Week 9)
|
+-- ml/
|   +-- train_model.py           Random Forest training pipeline (Week 11)
|   +-- ml_detector.py           Ensemble inference engine (Week 11)
|   +-- model.pkl                Trained model (generated at runtime)
|
+-- scripts/
|   +-- dashboard.py             Full web dashboard (Week 10)
|   +-- attack_simulator.py      Synthetic attack traffic generator (Week 11)
|   +-- run_all.sh               Full pipeline automation (Week 11)
|   +-- setup_environment.sh     Environment setup (Week 1)
|
+-- tests/
|   +-- hello_world.c            C environment test (Week 1)
|   +-- mpi_hello.c              MPI environment test (Week 1)
|   +-- run_tests.sh             Complete automated test suite (Week 12)
|   +-- benchmark.py             Performance benchmarking (Week 12)
|   +-- benchmark_fixed.py       Corrected benchmark for VM (Week 12)
|
+-- data/
|   +-- logs/
|   |   +-- packets.csv          Real captured packets
|   |   +-- simulated.csv        Synthetic attack traffic
|   +-- results/
|       +-- ml_results.png       ML performance graphs
|       +-- speedup_corrected.png Speedup benchmark graph
|
+-- docs/
|   +-- architecture.md          This document
|   +-- deployment.md            Deployment guide
|   +-- final_report.md          Final project report
|   +-- presentation.md          Presentation outline
|
+-- Makefile                     Build automation
+-- README.md                    Project overview
```

---

*Document version: 1.0*
*Prepared for: Parallel and Distributed Computing — Final Project*
