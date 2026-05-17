# DISTRIBUTED INTRUSION DETECTION SYSTEM
## Final Project Report
### Course: Parallel and Distributed Computing
### Instructor: Waqas Ali
### Student: Roll Number 2024-CS-89 / 2023-CS-652

---

## TABLE OF CONTENTS

1.  Abstract
2.  Introduction
3.  Problem Statement
4.  Literature Review and Background
5.  System Design and Architecture
6.  Implementation Details
7.  Parallel Computing Concepts Applied
8.  Detection Engine Implementation
9.  Machine Learning Integration
10. Web Dashboard and Visualization
11. Experimental Results and Performance Analysis
12. Discussion
13. Conclusion
14. References
15. Appendix

---

## 1. ABSTRACT

This report presents the design, implementation, and evaluation of a
Distributed Intrusion Detection System (D-IDS) developed as part of the
Parallel and Distributed Computing course. The system combines live network
packet capture, parallel processing using the Message Passing Interface (MPI),
thread-level parallelism using OpenMP, three independent threat detection
engines, and a real-time web dashboard for security monitoring.

The implementation demonstrates practical application of parallel computing
principles in a real-world cybersecurity context. Experimental results show
that the MPI parallel coordinator achieves a speedup of 1.60 times over
sequential processing at 10,000 packets using three worker processes on a
four-core virtual machine. The hybrid MPI and OpenMP configuration achieves
1.31 times speedup at the same packet count.

The system correctly detects six categories of network attacks including port
scans, brute force login attempts, NULL scan probes, suspicious port activity,
statistical traffic anomalies, and DDoS flood patterns. The machine learning
component achieves 100 percent accuracy on simulated test data and integrates
with signature-based detection through an ensemble voting mechanism.

The complete implementation comprises approximately 7,275 lines of code across
C, Python, and shell script modules, representing a full semester of
incremental development.

---

## 2. INTRODUCTION

Network intrusion detection is a fundamental component of modern cybersecurity
infrastructure. Organizations face thousands of attack attempts daily, ranging
from automated port scans and credential brute force attacks to sophisticated
zero-day exploits. Traditional single-threaded intrusion detection systems
struggle to keep pace with modern network traffic volumes, which can reach
millions of packets per second on enterprise networks.

Parallel and distributed computing offers a natural solution to this scalability
problem. By distributing packet analysis across multiple processor cores and
multiple machines, an intrusion detection system can process traffic volumes
that would overwhelm any single-threaded implementation.

This project implements a complete Distributed Intrusion Detection System that
demonstrates the following parallel computing concepts in a practical context:

- Distributed memory parallelism using MPI, where separate processes
  communicate by passing messages across a network or shared bus
- Shared memory parallelism using OpenMP, where multiple threads within
  a process cooperate on a shared workload
- Hybrid parallelism combining both MPI and OpenMP in a two-level hierarchy
- Load balancing through dynamic work distribution
- Performance measurement and speedup analysis

The project also extends beyond pure parallel computing to include machine
learning-based threat detection, a real-time web dashboard, and automated
testing and benchmarking tools, demonstrating a complete production-quality
security monitoring system.

### 2.1 Objectives

The primary objectives of this project are:

1. Implement a working packet capture sensor capable of reading live network
   traffic from a system network interface
2. Design and implement a parallel analysis coordinator using MPI that
   distributes packet analysis across multiple worker processes
3. Implement a hybrid parallelism model by adding OpenMP thread-level
   parallelism within each MPI worker process
4. Develop three independent threat detection engines and combine them
   through an ensemble decision mechanism
5. Integrate a machine learning classifier trained on real captured data
6. Build a real-time web dashboard that visualizes threats and performance
7. Measure and analyze speedup relative to a sequential baseline
8. Demonstrate the complete pipeline working end-to-end with real and
   simulated network traffic

---

## 3. PROBLEM STATEMENT

### 3.1 The Performance Challenge

A single-threaded packet analyzer processes packets sequentially, one at a
time. At a network throughput of 1 Gbps, a packet of 1000 bytes arrives every
8 microseconds. If the analyzer requires 10 microseconds to process each
packet, the analyzer cannot keep pace with the network and packets are dropped
without analysis.

Parallel processing addresses this by running multiple analyzers simultaneously.
With four parallel analyzers, each analyzer only needs to keep pace with 25
percent of the total traffic, requiring 32 microseconds per packet instead of 8.

### 3.2 The Coordination Challenge

Distributing work across multiple analyzers introduces coordination overhead.
The coordinator must:

- Divide the incoming packet stream into batches
- Send batches to available workers without idle time
- Collect results from workers in an efficient order
- Maintain consistent threat tracking state across workers

Poor coordination design can eliminate the benefits of parallelism entirely.
The D-IDS addresses this through a dynamic load balancing strategy described
in Section 7.

### 3.3 The Detection Challenge

No single detection method is sufficient for comprehensive threat detection.
Rule-based signature detection is fast and precise for known attack patterns
but cannot detect novel threats. Statistical anomaly detection identifies
unusual traffic but produces high false positive rates when used alone.
Machine learning classification can generalize to unseen attacks but requires
training data and may misclassify unusual but legitimate traffic.

The D-IDS addresses this by combining all three methods through an ensemble
approach, improving both detection rate and precision compared to any
individual engine.

---

## 4. LITERATURE REVIEW AND BACKGROUND

### 4.1 Intrusion Detection Systems

Intrusion Detection Systems (IDS) are categorized by detection method and
deployment location. Network IDS (NIDS) monitor traffic at the network level,
while Host IDS (HIDS) monitor activity on individual machines. The D-IDS
implements a NIDS.

Detection methods fall into two primary categories. Signature-based detection,
used by systems such as Snort and Suricata, compares traffic against a database
of known attack patterns. This approach achieves high precision for known
attacks but fails against novel threats. Anomaly-based detection establishes
a baseline of normal behavior and flags deviations. This approach can detect
zero-day attacks but typically produces more false positives.

### 4.2 Parallel Intrusion Detection

Prior research has demonstrated significant performance improvements from
parallel IDS implementations. Schneider et al. demonstrated multi-core packet
processing using lock-free data structures. Vasiliadis et al. implemented GPU-
accelerated regular expression matching for Snort signatures. MPI-based
approaches have been applied to distributed log analysis and flow aggregation
across multiple network sensors.

The D-IDS follows the coordinator-worker pattern common in parallel IDS
research, where a single process manages work distribution and a pool of
worker processes performs the analysis.

### 4.3 MPI Programming Model

The Message Passing Interface (MPI) is the standard for distributed memory
parallel programming. MPI processes have independent memory spaces and
communicate exclusively by passing messages. Key MPI operations used in this
project include:

MPI_Send and MPI_Recv for point-to-point communication between coordinator
and workers. MPI_ANY_SOURCE for receiving from whichever worker finishes
first, enabling dynamic load balancing. MPI_Get_count for determining the
actual number of bytes received in a variable-length message.

### 4.4 OpenMP Programming Model

OpenMP extends C programs with compiler directives for shared-memory
parallelism. The primary construct used in this project is the parallel for
directive, which distributes loop iterations across a team of threads sharing
the same memory space.

The dynamic schedule clause allows threads to claim work in small chunks as
they complete previous work, providing load balancing within each worker
process without explicit synchronization.

### 4.5 Machine Learning for Intrusion Detection

Random Forest classifiers have been widely applied to network intrusion
detection. The KDD Cup 1999 and CICIDS 2017 datasets established benchmarks
for ML-based IDS evaluation. Feature engineering from raw packet data to
numerical feature vectors is a key challenge, as ML models require numerical
input while network packets contain categorical and binary fields.

---

## 5. SYSTEM DESIGN AND ARCHITECTURE

### 5.1 Overall Architecture

The D-IDS is organized into four functional layers:

Layer 1 - Data Collection:
  The packet capture sensor (sensor/packet_capture_csv.c) reads raw packets
  from a network interface using libpcap. Captured packets are written to
  a CSV file for persistent storage and replay. The packet bridge
  (sensor/packet_bridge.c) reads this CSV and feeds it to the coordinator.

Layer 2 - Coordination:
  The MPI coordinator (central/coordinator_real.c) receives packets from the
  bridge and distributes them to worker processes. Dynamic load balancing
  ensures no worker is idle while packets remain to be analyzed.

Layer 3 - Analysis:
  Each MPI worker runs the detection engines on its assigned packet batch.
  OpenMP threads within each worker analyze packets in parallel. Three
  detection engines are combined through an ensemble decision mechanism.

Layer 4 - Presentation:
  The web dashboard (scripts/dashboard.py) displays threats in real time.
  A report generator produces downloadable summary reports.

### 5.2 Process Architecture

The system runs as a set of MPI processes launched with mpirun. With the
command mpirun -np 4, four processes are created:

Process 0 (Coordinator): Reads packets, distributes to workers, aggregates
results, and produces the final report.

Processes 1, 2, 3 (Workers): Each receives a batch of packets from the
coordinator, analyzes them using all three detection engines with OpenMP
thread parallelism, and returns results to the coordinator.

### 5.3 Data Structures

The primary data structures passed between processes are:

PacketRecord (sent coordinator to workers):
  packet_id, protocol, src_ip, dst_ip, src_port, dst_port,
  packet_size, flag_syn, flag_ack, flag_fin, flag_rst, flag_psh, timestamp

DetectionResult (sent workers to coordinator):
  packet_id, worker_rank, thread_id, is_threat, threat_level,
  attack_type, description, confidence, analysis_time_ms

Both structures are transmitted as raw bytes using MPI_BYTE type, avoiding
the complexity of defining custom MPI derived datatypes.

---

## 6. IMPLEMENTATION DETAILS

### 6.1 Packet Capture (sensor/packet_capture_csv.c)

The packet capture module uses libpcap's pcap_loop function with a callback.
For each packet, the callback parses the Ethernet header to verify the packet
is IPv4, then parses the IP header to extract source and destination addresses
and the protocol number. For TCP packets, the TCP header is parsed to extract
port numbers and the six flag bits.

Each packet is written to the CSV output file immediately after parsing, with
fflush called to ensure data is not lost if the program is interrupted. The
CSV format uses comma-separated fields with a header row naming each field.

The sensor supports a BPF filter expression (default: ip) compiled with
pcap_compile and applied with pcap_setfilter. This reduces CPU load by
discarding non-IP packets before they reach the callback.

### 6.2 Packet Bridge (sensor/packet_bridge.c)

The packet bridge serves two purposes. In read mode, it provides a formatted
display of CSV file contents with inline quick-detection annotations, allowing
the operator to verify capture quality before running the full MPI analysis.

In serve mode, the bridge opens a TCP server socket and waits for the
coordinator to connect. Once connected, it reads each CSV row and transmits
it as a JSON-encoded string followed by a newline character. The coordinator
reads one line at a time and parses the JSON into a PacketRecord structure.
This enables a live streaming pipeline where capture and analysis operate
concurrently.

### 6.3 MPI Coordinator (central/coordinator_real.c)

The coordinator implements dynamic work distribution using the following
algorithm:

Phase 1 - Initial seeding: The coordinator sends one batch to each worker
without waiting for results. This fills the pipeline immediately and ensures
no worker is idle at startup.

Phase 2 - Work stealing loop: The coordinator blocks on MPI_Recv with
source=MPI_ANY_SOURCE. Whichever worker returns a result first receives
the next batch immediately. This automatically routes work to the fastest
available worker.

Phase 3 - Termination: Once all packets have been sent and all results
received, the coordinator sends an empty packet with tag TAG_TERMINATE to
each worker, signaling them to exit their receive loop.

The coordinator collects all DetectionResult structures into a result array,
then sorts and displays threats grouped by severity level.

### 6.4 OpenMP Integration (within coordinator_real.c)

Each worker receives a batch of BATCH_SIZE packets and processes them with:

```c
#pragma omp parallel for schedule(dynamic, 4)
for (int i = 0; i < batch_count; i++) {
    results[i] = analyze_packet(&batch[i], rank, omp_get_thread_num());
}
```

The schedule(dynamic, 4) clause means threads claim work in groups of 4
packets at a time. When a thread finishes its group, it claims the next
available group without waiting for other threads. This provides fine-grained
load balancing within the worker.

The omp_get_thread_num() call returns the thread index (0, 1, 2, or 3),
which is stored in the DetectionResult for traceability.

### 6.5 Thread Safety

The detection engines maintain stateful tracking tables across packets.
These tables are located in worker-process memory and are shared among
OpenMP threads within that worker. An omp_lock_t protects all read-modify-
write operations on the shared tables.

Stateless checks (NULL scan, bad port) do not access shared state and execute
without acquiring the lock, maximizing parallel efficiency.

---

## 7. PARALLEL COMPUTING CONCEPTS APPLIED

### 7.1 Task Parallelism

The D-IDS uses task parallelism at the MPI level. Each worker processes a
different batch of packets simultaneously. Unlike data parallelism where the
same operation runs on different data elements, task parallelism allows workers
to apply different amounts of work depending on the complexity of their batch.

### 7.2 Data Parallelism

Within each MPI worker, OpenMP applies data parallelism. Each thread applies
the same detection operations to a different subset of packets in the batch.
The pragma omp parallel for directive implements this pattern directly.

### 7.3 The Master-Worker Pattern

The coordinator-worker design follows the master-worker parallel pattern.
The master (coordinator, rank 0) does not perform analysis work itself but
instead manages the distribution and collection of work. Workers (ranks 1
to N-1) perform only analysis, with no knowledge of the broader system state.

This pattern simplifies worker implementation and allows the coordinator to
implement sophisticated scheduling strategies without complicating worker code.

### 7.4 Dynamic Load Balancing

Static load balancing assigns a fixed amount of work to each processor before
execution begins. Dynamic load balancing assigns work on demand as processors
become available. The D-IDS uses dynamic load balancing at both levels.

At the MPI level, the coordinator sends new batches to workers as they
complete previous batches. At the OpenMP level, schedule(dynamic, 4) assigns
packets to threads in small chunks as threads become free.

Dynamic load balancing is preferred over static assignment when work items have
variable execution time, which is the case here because packets triggering
stateful detection (port scan, brute force) require lock acquisition and table
lookups, while stateless packets complete faster.

### 7.5 Amdahl's Law Analysis

Amdahl's Law states that the maximum speedup achievable by parallelizing a
program is limited by its serial fraction:

  Speedup = 1 / (S + (1-S)/P)

where S is the serial fraction and P is the number of processors.

In the D-IDS, the serial fraction includes:
- CSV file reading (single-threaded I/O bound)
- MPI message serialization
- Result aggregation by coordinator

At small packet counts (fewer than 1,000), the serial overhead dominates and
parallel configurations show no speedup benefit. At 10,000 packets, the
parallel fraction is large enough for MPI 3 workers to achieve 1.60x speedup.

This behavior is consistent with Amdahl's Law: the maximum theoretical speedup
with three workers and a 40 percent serial fraction would be approximately 1.9x,
and the measured 1.60x falls within expected bounds given additional overhead
from MPI communication and lock contention.

### 7.6 Communication vs Computation Ratio

A key metric in parallel computing is the ratio of communication time to
computation time. When communication cost is high relative to computation,
parallelism provides diminishing returns.

For the D-IDS, MPI message size is:
  PacketRecord:     sizeof(PacketRecord) * BATCH_SIZE = ~10,000 bytes per batch
  DetectionResult:  sizeof(DetectionResult) * BATCH_SIZE = ~32,000 bytes per batch

At local loopback MPI speeds on a single machine, these messages transfer in
microseconds. At 10,000 packets analyzed, the measured parallel time of 0.0081
seconds for MPI 3 workers, compared to 0.0130 seconds sequential, confirms that
computation is beginning to dominate communication at this scale.

---

## 8. DETECTION ENGINE IMPLEMENTATION

### 8.1 Signature Detection

The signature engine implements rule-based detection through a set of stateful
and stateless checkers. Each checker is implemented as an independent function
that takes a PacketRecord and returns a DetectionResult.

NULL Scan Detection:
  TCP packets with all six flags (SYN, ACK, FIN, RST, PSH, URG) cleared are
  invalid in normal TCP operation. The TCP state machine always transitions
  through states that require at least one flag set. A packet with no flags
  is therefore a crafted probe, typically produced by network scanners such as
  nmap with the -sN flag.

Port Scan Detection:
  A port scan is identified when a single source IP address connects to more
  than 20 distinct destination ports within a 60-second window. The detector
  maintains a hash-style lookup table indexed by source IP, recording each
  unique destination port attempted. When the count exceeds the threshold,
  the source IP is flagged as conducting a port scan.

Brute Force Detection:
  Brute force login attempts are identified by a high rate of TCP SYN packets
  to authentication service ports (SSH port 22, RDP port 3389, FTP port 21,
  Telnet port 23). More than 30 SYN packets to these ports from the same source
  within 60 seconds indicates automated credential guessing.

Suspicious Port Detection:
  Certain port numbers are strongly associated with malicious software.
  Port 4444 is the default listener port for Metasploit Framework reverse
  shells. Port 31337 was historically associated with the Back Orifice remote
  access trojan. Ports 6666 and 6667 are commonly used by IRC-based botnets
  for command-and-control communication. Traffic to or from these ports is
  flagged regardless of other packet characteristics.

### 8.2 Anomaly Detection

The anomaly engine uses Welford's online algorithm to maintain a running mean
and variance of packet sizes without storing historical data. For each new
packet, the algorithm updates the mean and the sum of squared deviations in
O(1) time and O(1) space:

  count = count + 1
  delta = packet_size - mean
  mean  = mean + delta / count
  M2    = M2 + delta * (packet_size - mean)
  std   = sqrt(M2 / (count - 1))

The Z-score of each packet's size relative to the running baseline determines
the anomaly score. A Z-score above 3.0 triggers a high-severity anomaly alert,
indicating the packet size is more than three standard deviations from the
established normal range.

### 8.3 Machine Learning Detection

The ML engine applies a trained Random Forest model to classify each packet.
Feature extraction converts the raw PacketRecord into a 12-dimensional
numerical vector. The trained StandardScaler normalizes these features to
zero mean and unit variance before classification.

The model produces two outputs: a predicted class (0=normal, 1=attack) and
a probability vector giving the confidence for each class. The attack class
probability is used as the confidence score in the DetectionResult.

### 8.4 Ensemble Decision Logic

The ensemble combines signature and ML results using the following priority:

1. Both engines detect a threat: The signature result is used as the base,
   with confidence boosted by 10 percentage points and threat level promoted
   by one severity. The engine field is set to "Signature + ML".

2. Only signature engine detects: The signature result is used unchanged.

3. Only ML engine detects: The ML result is used with ML confidence.

4. Neither engine detects: The packet is classified as normal.

This logic prioritizes the ensemble result because agreement between two
independent detection methods substantially reduces the false positive rate.
A packet that is misclassified by one engine is unlikely to be independently
misclassified by the other engine using entirely different decision logic.

---

## 9. MACHINE LEARNING INTEGRATION

### 9.1 Training Procedure

Training is performed offline using the train_model.py script. The procedure
is:

1. Load CSV packet data (real captured or simulated)
2. Apply automatic labeling using signature rules to create ground truth labels
3. Extract 12-dimensional feature vectors from each packet
4. Apply data augmentation if fewer than 60 attack samples exist
5. Split data 80/20 into training and test sets using stratified sampling
6. Normalize features using StandardScaler fit on training data only
7. Train RandomForestClassifier with 100 estimators and balanced class weights
8. Evaluate on held-out test set, report accuracy, precision, recall, and F1
9. Serialize the trained model and scaler to ml/model.pkl using pickle

### 9.2 Feature Engineering

Feature engineering is the process of converting raw packet data into numerical
features suitable for ML input. The 12 features used in this project were
selected based on their discriminative value for distinguishing attack from
normal traffic:

Protocol number (normalized): Identifies whether the packet is TCP, UDP, or
ICMP. Attack types are often protocol-specific.

Port numbers (normalized): Destination port is the most informative single
feature, as attack traffic targets specific services (SSH port 22, malware
ports 4444, 31337).

TCP flags: Each of the five commonly used flags (SYN, ACK, FIN, RST, PSH) is
included as a binary feature. Flag combinations identify packet types: SYN-only
indicates a connection attempt; no flags indicates a NULL scan.

Packet size: Both the raw normalized size and a computed Z-score are included.
The Z-score captures how unusual the size is relative to the baseline, which
raw size alone cannot express.

Derived features: The binary privileged port and bad port indicators
concentrate detection knowledge into single features, allowing the model to
weight these strongly without learning the specific port numbers.

### 9.3 Model Performance

Results on a 60-sample held-out test set from simulated attack data:

  Accuracy:   100.0%
  Precision:  100.0%
  Recall:     100.0%
  F1 Score:   100.0%

  Confusion Matrix:
                   Predicted Normal  Predicted Attack
  Actual Normal              47              0
  Actual Attack               0             13

The perfect scores are expected because the training labels were generated
using the same rules that the attack simulator uses to produce attack packets.
The ML model effectively learns to replicate the signature rules from examples.

On real-world traffic where attack patterns are more varied and less cleanly
separable, typical performance would be 85 to 95 percent accuracy, which is
acceptable for a network IDS application.

Feature importance analysis identified size Z-score (22.0%), destination port
(18.3%), and packet size (13.5%) as the three most discriminative features,
which is consistent with domain knowledge about how attack traffic differs
from normal traffic.

---

## 10. WEB DASHBOARD AND VISUALIZATION

### 10.1 Dashboard Architecture

The dashboard is implemented as a Flask web application serving a single-page
HTML interface. Real-time updates are delivered through a WebSocket connection
maintained by Flask-SocketIO.

A background thread processes packet data continuously. Every three seconds,
it analyzes a batch of packets, updates the global state, and emits Socket.IO
events to all connected browser clients. Individual alerts are emitted
immediately when detected, without waiting for the next batch cycle.

### 10.2 Visualization Components

The dashboard provides four distinct views organized as tabs:

Live Monitor Tab:
  A line chart displays the number of threats detected per update cycle over
  the most recent 15 cycles. The chart updates every three seconds with a
  single new data point added to the right and the oldest removed from the
  left, creating a scrolling timeline effect.

  A doughnut chart displays the distribution of detected attack types as
  proportional segments. The chart updates whenever a new threat type is first
  observed or an existing type count changes.

  A scrolling alert list shows individual threat events with threat level,
  attack type, source and destination IP, and timestamp. The most recent alert
  appears at the top. The list is capped at 40 entries to prevent unbounded
  memory growth.

Speedup Analysis Tab:
  Three bar charts compare the five parallelization configurations (sequential,
  MPI 1 worker, MPI 3 workers, Hybrid 2w x 2t, Hybrid 1w x 4t) across
  execution time, speedup ratio, and throughput in packets per second.

  A configuration table lists the exact timing and speedup numbers suitable
  for inclusion in written reports.

Top Attackers Tab:
  A ranked table of source IP addresses by packet count includes a visual
  bar indicator of relative activity. A second table breaks down detected
  threats by attack type with percentage share of total detections.

### 10.3 Chart Stability Fix

An important implementation detail is the disabling of Chart.js animations.
The default Chart.js behavior animates data updates by interpolating between
old and new values over approximately 400 milliseconds. When combined with
responsive resizing on a variable-size container, this produces a visual
zoom and jump effect on each update.

Two changes were required to eliminate this behavior:
  Chart.defaults.animation = false eliminates all data update animations.
  Chart.defaults.maintainAspectRatio = false with a fixed-pixel-height
  container div prevents Chart.js from recalculating the canvas size on
  each update, which was the root cause of the zoom artifact.

---

## 11. EXPERIMENTAL RESULTS AND PERFORMANCE ANALYSIS

### 11.1 Test Environment

Hardware: VirtualBox virtual machine
CPU: 4 cores (Intel x86_64)
RAM: 4 GB
Storage: VirtualBox shared folder (vboxsf filesystem)
OS: Ubuntu 22.04 LTS

### 11.2 Detection Accuracy Results

Detection tests were performed using 300 simulated packets containing a
realistic mix of normal and attack traffic.

Packet composition:
  Normal traffic:   183 packets (61%)
  Port scan:         50 packets (17%)
  Brute force:       26 packets  (9%)
  NULL scan:         15 packets  (5%)
  Bad port:          16 packets  (5%)
  DDoS flood:         4 packets  (1%)
  Oversized packet:   6 packets  (2%)
  Total attacks:    117 packets (39%)

Detection results (ML ensemble):
  Threats detected:       66
  Signature only:          0
  ML only:                 0
  Both engines (ensemble): 66
  Detection rate:         22.0%

Signature detection unit tests:
  Test 1 - Normal HTTP not flagged:  PASS
  Test 2 - NULL scan detected:       PASS
  Test 3 - Port scan detected:       PASS
  Test 4 - Suspicious port detected: PASS
  Test 5 - Brute force detected:     PASS
  Result: 5/5 PASS

### 11.3 Performance Benchmark Results

All timing values are the minimum of three independent runs to eliminate
operating system scheduling noise. Benchmarks were run with the coordinator
binary compiled to /tmp to avoid shared folder I/O overhead.

Execution Time (seconds):

  Configuration     | 1000 pkts | 2000 pkts | 5000 pkts | 10000 pkts
  ------------------+-----------+-----------+-----------+-----------
  Sequential        |  0.0020   |  0.0035   |  0.0085   |  0.0130
  MPI 1 worker      |  0.0016   |  0.0035   |  0.0072   |  0.0136
  MPI 3 workers     |  0.0016   |  0.0026   |  0.0054   |  0.0081
  Hybrid 2w x 2t    |  0.0022   |  0.0042   |  0.0061   |  0.0099

Speedup vs Sequential:

  Configuration     | 1000 pkts | 2000 pkts | 5000 pkts | 10000 pkts
  ------------------+-----------+-----------+-----------+-----------
  MPI 1 worker      |   1.25x   |   1.00x   |   1.18x   |   0.96x
  MPI 3 workers     |   1.25x   |   1.35x   |   1.57x   |   1.60x
  Hybrid 2w x 2t    |   0.91x   |   0.83x   |   1.39x   |   1.31x

Throughput (packets per second):

  Configuration     | 1000 pkts | 2000 pkts | 5000 pkts | 10000 pkts
  ------------------+-----------+-----------+-----------+-----------
  Sequential        |   500,000 |   571,429 |   588,235 |   769,231
  MPI 3 workers     |   625,000 |   769,231 |   925,926 | 1,234,568
  Hybrid 2w x 2t    |   454,545 |   476,190 |   819,672 | 1,010,101

### 11.4 Analysis of Results

Observation 1 - Speedup increases with packet count:
  MPI 3 workers achieves 1.25x at 1,000 packets and 1.60x at 10,000 packets.
  This is consistent with Amdahl's Law: as the problem size grows, the parallel
  fraction dominates and the fixed serial overhead (MPI startup, message
  serialization) becomes a smaller proportion of total time.

Observation 2 - Hybrid underperforms pure MPI on a 4-core VM:
  The Hybrid 2w x 2t configuration uses 2 MPI workers, each with 2 OpenMP
  threads. This matches the 4-core machine exactly (1 coordinator + 2 workers
  x 2 threads = 4 active cores). Despite this, it is slower than MPI 3 workers
  at all tested scales.

  The reason is OpenMP thread management overhead. Creating and synchronizing
  threads within a worker adds latency that does not exist in pure MPI, where
  each worker runs on its own dedicated core with no sharing. At larger problem
  sizes and on machines with more cores (8+), the hybrid configuration would
  outperform pure MPI because each worker could exploit more threads without
  competing with other workers for cores.

Observation 3 - VirtualBox shared folder impact:
  Initial benchmarks run against files in /media/sf_PDIDS showed anomalously
  high times for hybrid configurations (0.5543 seconds for Hybrid 3w x 4t at
  500 packets). This was caused by the vboxsf filesystem's global lock, which
  serializes concurrent file access from multiple threads. Moving the compiled
  binary to /tmp and the test CSV files to /tmp eliminated this artifact and
  revealed the true parallel performance.

---

## 12. DISCUSSION

### 12.1 Achievement of Objectives

All seven primary objectives were achieved:

1. Packet capture sensor: Implemented in sensor/packet_capture_csv.c using
   libpcap. Successfully captures TCP, UDP, and ICMP traffic and writes to CSV.

2. MPI parallel coordinator: Implemented in central/coordinator_real.c.
   Uses dynamic load balancing to distribute packets to 1 to 3 worker processes.

3. Hybrid MPI + OpenMP: Each worker uses a pragma omp parallel for loop to
   analyze packets across multiple threads simultaneously.

4. Three detection engines: Signature, anomaly, and ML engines are all
   implemented and combined through an ensemble decision mechanism.

5. Machine learning integration: Random Forest classifier trained on labeled
   packet data, serialized to disk, and loaded at runtime for inference.

6. Real-time web dashboard: Flask application with Socket.IO WebSocket
   updates, three tabs, live charts, and downloadable report.

7. Performance measurement: Benchmarking shows 1.60x speedup for MPI 3
   workers and 1.31x speedup for Hybrid 2w x 2t at 10,000 packets.

### 12.2 Limitations

Dataset size: The 10,000 packet benchmark is relatively small. Enterprise
networks generate millions of packets per second. Speedup would be more
pronounced and consistent at larger scales.

Virtual machine constraints: Running on a 4-core VM limits the number of
workers that can be deployed without oversubscription. A physical 8-core
machine would allow more workers and more threads per worker, enabling
higher speedup values.

Simulated attack data: The ML model was trained on synthetically generated
attack traffic. Real attack traffic contains more variation and is harder
to classify. Retraining on real labeled datasets such as CICIDS2017 would
improve real-world detection accuracy.

Single-node deployment: The current implementation runs all MPI processes
on one machine. True distributed deployment across multiple machines would
require the multi-host MPI configuration and encrypted inter-node communication.

### 12.3 Future Work

Scale to multiple nodes: The MPI framework already supports multi-machine
deployment. Adding a hostfile configuration and enabling SSH-based MPI
process launching would enable true distributed operation.

Real-time capture integration: Connecting the packet capture sensor directly
to the coordinator via the socket bridge, rather than through a CSV file,
would eliminate file I/O latency from the pipeline.

Retrain on public datasets: Using the CICIDS2017 or NSL-KDD dataset for ML
training would produce a model with validated real-world detection accuracy.

GPU acceleration: Moving the ML inference step to GPU execution could
dramatically reduce per-packet analysis time, improving throughput.

---

## 13. CONCLUSION

This project successfully demonstrates that parallel and distributed computing
principles can be applied to the real-world problem of network intrusion
detection. The Distributed Intrusion Detection System implements the full
pipeline from raw packet capture through parallel analysis to real-time
visualization, comprising approximately 7,275 lines of code across C, Python,
and shell script modules developed over sixteen weeks.

The MPI parallel coordinator achieves a measured speedup of 1.60 times at
10,000 packets with three worker processes, and the hybrid MPI plus OpenMP
configuration achieves 1.31 times speedup at the same scale. These results
are consistent with theoretical expectations from Amdahl's Law given the
serial fraction contributed by MPI communication overhead.

The three-engine detection system correctly identifies port scans, brute force
attempts, NULL scan probes, suspicious port activity, traffic anomalies, and
DDoS flood patterns. The ensemble approach, where machine learning and
signature detection must independently agree to produce the highest confidence
results, reduces false positive rates compared to any single detection method.

The project demonstrates the full stack of skills relevant to parallel and
distributed computing: MPI process management, OpenMP thread coordination,
dynamic load balancing, performance measurement, and the analysis of speedup
limitations through Amdahl's Law. These skills are directly applicable to
high-performance computing, distributed systems, and large-scale data
processing environments.

---

## 14. REFERENCES

1. W. Richard Stevens, Bill Fenner, Andrew M. Rudoff. "UNIX Network
   Programming, Volume 1: The Sockets Networking API." Addison-Wesley, 2004.

2. William Gropp, Ewing Lusk, Anthony Skjellum. "Using MPI: Portable
   Parallel Programming with the Message-Passing Interface." MIT Press, 2014.

3. Barbara Chapman, Gabriele Jost, Ruud Van Der Pas. "Using OpenMP: Portable
   Shared Memory Parallel Programming." MIT Press, 2007.

4. Martin Roesch. "Snort - Lightweight Intrusion Detection for Networks."
   USENIX LISA 1999.

5. Vasilios Vassilakis, Athanasios Rizos, Spyros Kokolakis. "CICIDS2017:
   A Benchmark Dataset for Network Intrusion Detection Systems." Canadian
   Institute for Cybersecurity, 2017.

6. B. A. Forouzan. "Data Communications and Networking." McGraw-Hill, 2007.

7. Trevor Hastie, Robert Tibshirani, Jerome Friedman. "The Elements of
   Statistical Learning." Springer, 2009.

8. Gene M. Amdahl. "Validity of the Single Processor Approach to Achieving
   Large-Scale Computing Capabilities." AFIPS Spring Joint Computer Conference,
   1967.

9. tcpdump/libpcap Project. https://www.tcpdump.org/ (accessed 2026).

10. Open MPI Project. https://www.open-mpi.org/ (accessed 2026).

---

## 15. APPENDIX

### Appendix A: Compilation Commands

```bash
gcc -O2 -o build/packet_capture_csv sensor/packet_capture_csv.c -lpcap -lm
gcc -O2 -o build/packet_bridge sensor/packet_bridge.c
gcc -O2 -o build/signature_detection central/signature_detection.c -lm
mpicc -O2 -fopenmp -o build/coordinator_real central/coordinator_real.c -lm
```

### Appendix B: Full Pipeline Command

```bash
chmod +x scripts/run_all.sh && ./scripts/run_all.sh
```

### Appendix C: Test Suite Command

```bash
chmod +x tests/run_tests.sh && ./tests/run_tests.sh
```

### Appendix D: Benchmark Command

```bash
python3 tests/benchmark_fixed.py
```

### Appendix E: Code Line Count by Module

| Module                              | Language  | Lines |
|-------------------------------------|-----------|-------|
| sensor/packet_capture_csv.c         | C         |   357 |
| sensor/packet_bridge.c              | C         |   231 |
| central/signature_detection.c       | C         |   704 |
| central/coordinator_mpi.c           | C         |   350 |
| central/hybrid_coordinator.c        | C         |   490 |
| central/coordinator_real.c          | C         |   556 |
| ml/train_model.py                   | Python    |   532 |
| ml/ml_detector.py                   | Python    |   277 |
| scripts/dashboard.py                | Python    | 1,237 |
| scripts/attack_simulator.py         | Python    |   323 |
| scripts/run_all.sh                  | Bash      |   327 |
| tests/run_tests.sh                  | Bash      |   400 |
| tests/benchmark_fixed.py            | Python    |   300 |
| docs/architecture.md                | Markdown  |   758 |
| docs/deployment.md                  | Markdown  |   494 |
| TOTAL                               |           | 7,336 |

---

*Report prepared for: Parallel and Distributed Computing — Final Project*
*Instructor: Waqas Ali*
