# PROJECT PROPOSAL
## Distributed Intrusion Detection System Using MPI and OpenMP
### Course: Parallel and Distributed Computing
### Instructor: Waqas Ali
### Student Name: ZAinab Batool
### Roll Number: 2024-CS-89 / 2023-CS-652
### Date: 

---

## TABLE OF CONTENTS

1. Problem Statement
2. Background and Motivation
3. Sequential Baseline Algorithm
4. Proposed Parallelization Strategy
5. Expected Speedup Analysis Using Amdahl's Law
6. Expected Outcomes
7. Implementation Timeline
8. Tools and Technologies
9. References

---

## 1. PROBLEM STATEMENT

### 1.1 The Core Problem

Network intrusion detection is the process of monitoring network traffic
to identify malicious activity such as port scans, brute force login
attempts, denial-of-service attacks, and unauthorized access attempts.
Organizations deploy Intrusion Detection Systems (IDS) at network
boundaries to analyze every packet passing through the network and raise
alerts when suspicious activity is identified.

The fundamental challenge facing modern IDS solutions is one of throughput.
Network speeds have increased dramatically over the past decade. Enterprise
networks routinely operate at 1 Gbps, and data center interconnects operate
at 10 Gbps or higher. At 1 Gbps with an average packet size of 1000 bytes,
a new packet arrives every 8 microseconds. A sequential IDS that requires
10 to 15 microseconds to analyze each packet simply cannot keep pace with
the network, resulting in packets passing unanalyzed and potential attacks
going undetected.

To quantify this limitation: a sequential IDS processing 1,000 packets per
second on a single core would require 10 seconds to process 10,000 packets.
During that 10 seconds of analysis backlog, an attacker conducting an
automated port scan could complete a full scan of all 65,535 ports and
begin exploiting discovered vulnerabilities before any alert is raised.

### 1.2 Why Parallelism is the Solution

The packet analysis problem is inherently parallelizable. Each packet can
be analyzed independently of most other packets. There is no requirement
that packet 500 be analyzed before packet 501. This property, known as
data parallelism, means that multiple processors can analyze different
packets simultaneously without interfering with each other.

By distributing the packet analysis workload across multiple processor
cores using parallel computing techniques, it becomes possible to multiply
the throughput of the IDS proportionally to the number of cores available.
A four-core parallel IDS could theoretically analyze four packets
simultaneously, quadrupling throughput compared to the sequential baseline.

This project proposes the design and implementation of a Distributed
Intrusion Detection System (D-IDS) that applies MPI and OpenMP parallel
computing techniques to achieve significantly higher packet analysis
throughput than a sequential IDS implementation.

### 1.3 Real-World Relevance

Commercial IDS products such as Snort and Suricata already employ
multi-threaded processing for exactly this reason. Academic research
on parallel IDS dates to at least 2003 (Aldwairi et al.) and has
produced implementations using GPU acceleration, FPGA offloading, and
multi-core CPU parallelism. This project implements the MPI plus OpenMP
approach, which is directly applicable to commodity server hardware
without specialized accelerator cards.

---

## 2. BACKGROUND AND MOTIVATION

### 2.1 How Sequential IDS Works

A sequential IDS operates a continuous loop: capture a packet, extract
its header fields (source IP, destination IP, ports, protocol, flags),
compare those fields against a database of known attack signatures, check
for statistical anomalies, and record any threats detected. The loop then
immediately repeats for the next packet.

The bottleneck in this model is the analysis step. Comparing a packet
against hundreds of signature rules, computing statistical deviation scores,
and running machine learning inference are all computationally expensive
operations that must complete before the next packet can be processed.

### 2.2 The Gap Between Capture Rate and Analysis Rate

If a network is delivering packets faster than the IDS can analyze them,
one of two things happens: either packets are dropped (lost) without
analysis, or packets accumulate in a buffer until the buffer overflows
and packets are dropped. Either outcome means some packets are never
analyzed and any attacks they contain go undetected.

Parallel processing closes this gap by running multiple analysis pipelines
simultaneously, each handling a different subset of the incoming packet
stream. With N parallel analyzers, the system can process N packets in
the same time a sequential system processes one packet.

### 2.3 MPI and OpenMP as the Parallelization Framework

Two complementary parallel programming models are proposed for this project:

Message Passing Interface (MPI): MPI enables parallelism across multiple
independent processes, each with its own memory space. Processes communicate
by explicitly sending and receiving messages. MPI is the standard for
distributed memory parallel computing and scales from multi-core single
machines to clusters of hundreds of nodes.

OpenMP: OpenMP enables parallelism within a single process through compiler
directives that instruct the compiler to distribute loop iterations across
multiple threads sharing the same memory. OpenMP is the standard for
shared memory parallelism on multi-core processors.

The proposed system uses both in a hybrid configuration: MPI handles
coarse-grained distribution of packet batches between processes, and OpenMP
handles fine-grained parallelism within each process across threads.

---

## 3. SEQUENTIAL BASELINE ALGORITHM

### 3.1 Overview

The sequential baseline represents the simplest possible correct
implementation of the IDS: a single process, single thread loop that
analyzes packets one at a time. This baseline will be used as the
reference point for measuring speedup achieved by the parallel implementation.

### 3.2 Sequential Pseudocode

```
ALGORITHM: Sequential Packet Analysis

INPUT:  packets[]  -- array of N captured network packets
OUTPUT: threats[]  -- array of detected threats

FOR i = 0 TO N-1:

    packet = packets[i]

    // Step 1: Signature Detection
    sig_result = run_signature_detection(packet)
    //   Check: does packet have TCP with no flags? (NULL scan)
    //   Check: has this IP tried more than 20 ports? (port scan)
    //   Check: more than 30 SSH attempts in 60 seconds? (brute force)
    //   Check: traffic to known malware port? (suspicious port)

    // Step 2: Anomaly Detection
    ano_result = run_anomaly_detection(packet)
    //   Compute Z-score of packet size vs running baseline
    //   Z-score = |size - mean| / std_deviation
    //   Z > 3.0 = severe anomaly

    // Step 3: Ensemble Decision
    IF sig_result.is_threat AND ano_result.is_threat:
        final.confidence = sig_result.confidence + 10  // both agree
        final.level      = PROMOTE(sig_result.level)
    ELSE IF sig_result.is_threat:
        final = sig_result
    ELSE IF ano_result.is_threat:
        final = ano_result
    ELSE:
        final.is_threat = FALSE

    // Step 4: Record result
    IF final.is_threat:
        threats[threat_count++] = final

END FOR

RETURN threats
```

### 3.3 Actual Sequential C Code

The following is the C implementation of the sequential baseline. This
version uses no MPI, no OpenMP, and no threading of any kind. It processes
packets strictly one at a time in a single loop:

```c
/*
 * sequential_ids.c
 * Sequential baseline -- processes packets one at a time.
 * No parallelism. Used as reference for speedup measurement.
 *
 * Compile: gcc -O2 -o sequential_ids sequential_ids.c -lm
 * Run:     ./sequential_ids -n 10000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>

#define MAX_PACKETS     50000
#define MAX_TRACKED_IPS 500
#define MAX_PORTS       200

#define THREAT_NONE     0
#define THREAT_MEDIUM   2
#define THREAT_HIGH     3
#define THREAT_CRITICAL 4

/* Packet structure */
typedef struct {
    int      packet_id;
    int      protocol;
    char     src_ip[16];
    char     dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_size;
    int      flag_syn;
    int      flag_ack;
    int      flag_fin;
    int      flag_rst;
    int      flag_psh;
} Packet;

/* Detection result */
typedef struct {
    int    packet_id;
    int    is_threat;
    int    threat_level;
    char   attack_type[64];
    char   description[256];
    double confidence;
} DetectionResult;

/* Tracking state for stateful detections */
typedef struct {
    char     ip[16];
    uint16_t ports[MAX_PORTS];
    int      port_count;
    long     first_seen;
} ScanState;

typedef struct {
    char ip[16];
    int  count;
    long window_start;
} RateState;

/* Global state */
static ScanState scan_state[MAX_TRACKED_IPS];
static int       scan_count = 0;
static RateState rate_state[MAX_TRACKED_IPS];
static int       rate_count = 0;
static double    base_mean  = 512.0;
static double    base_std   = 256.0;
static long      base_n     = 0;
static double    base_m2    = 0.0;

/* Known malware ports */
static uint16_t BAD_PORTS[] = {
    4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080, 0
};

/* -------------------------------------------------------
 * Helper: find or create tracking entry for an IP
 * ------------------------------------------------------- */
ScanState* get_scan(const char* ip) {
    for (int i = 0; i < scan_count; i++)
        if (!strcmp(scan_state[i].ip, ip)) return &scan_state[i];
    if (scan_count >= MAX_TRACKED_IPS) return NULL;
    ScanState* s = &scan_state[scan_count++];
    strncpy(s->ip, ip, 15);
    s->port_count = 0;
    s->first_seen = time(NULL);
    return s;
}

RateState* get_rate(const char* ip) {
    for (int i = 0; i < rate_count; i++)
        if (!strcmp(rate_state[i].ip, ip)) return &rate_state[i];
    if (rate_count >= MAX_TRACKED_IPS) return NULL;
    RateState* s = &rate_state[rate_count++];
    strncpy(s->ip, ip, 15);
    s->count = 0;
    s->window_start = time(NULL);
    return s;
}

/* -------------------------------------------------------
 * Signature detection
 * Checks each packet against known attack patterns.
 * No parallelism -- one packet at a time, sequentially.
 * ------------------------------------------------------- */
int detect_signature(const Packet* p, DetectionResult* r) {

    /* Check 1: NULL scan -- TCP with zero flags */
    if (p->protocol == 6 &&
        !p->flag_syn && !p->flag_ack &&
        !p->flag_fin && !p->flag_rst && !p->flag_psh) {
        r->is_threat    = 1;
        r->threat_level = THREAT_MEDIUM;
        r->confidence   = 0.85;
        strcpy(r->attack_type, "NULL Scan");
        snprintf(r->description, 256,
                 "TCP NULL scan from %s to %s:%d",
                 p->src_ip, p->dst_ip, p->dst_port);
        return 1;
    }

    /* Check 2: Known bad port */
    for (int i = 0; BAD_PORTS[i]; i++) {
        if (p->dst_port == BAD_PORTS[i] ||
            p->src_port == BAD_PORTS[i]) {
            r->is_threat    = 1;
            r->threat_level = THREAT_MEDIUM;
            r->confidence   = 0.75;
            strcpy(r->attack_type, "Suspicious Port");
            snprintf(r->description, 256,
                     "Traffic on malware port %d: %s -> %s",
                     BAD_PORTS[i], p->src_ip, p->dst_ip);
            return 1;
        }
    }

    /* Check 3: Port scan */
    if (p->protocol == 6 && p->flag_syn) {
        ScanState* s = get_scan(p->src_ip);
        if (s) {
            long now = time(NULL);
            if (now - s->first_seen > 60) {
                s->port_count = 0;
                s->first_seen = now;
            }
            int found = 0;
            for (int i = 0; i < s->port_count; i++)
                if (s->ports[i] == p->dst_port) { found = 1; break; }
            if (!found && s->port_count < MAX_PORTS)
                s->ports[s->port_count++] = p->dst_port;
            if (s->port_count > 20) {
                r->is_threat    = 1;
                r->threat_level = THREAT_HIGH;
                r->confidence   = 0.88;
                strcpy(r->attack_type, "Port Scan");
                snprintf(r->description, 256,
                         "%s scanned %d ports on %s",
                         p->src_ip, s->port_count, p->dst_ip);
                return 1;
            }
        }
    }

    /* Check 4: Brute force */
    if (p->protocol == 6 && p->flag_syn &&
        (p->dst_port == 22   || p->dst_port == 3389 ||
         p->dst_port == 21   || p->dst_port == 23)) {
        RateState* rs = get_rate(p->src_ip);
        if (rs) {
            long now = time(NULL);
            if (now - rs->window_start > 60) {
                rs->count = 0;
                rs->window_start = now;
            }
            rs->count++;
            if (rs->count > 30) {
                r->is_threat    = 1;
                r->threat_level = THREAT_HIGH;
                r->confidence   = 0.90;
                strcpy(r->attack_type, "Brute Force");
                snprintf(r->description, 256,
                         "%s made %d login attempts to %s",
                         p->src_ip, rs->count, p->dst_ip);
                return 1;
            }
        }
    }

    return 0;  /* No threat detected */
}

/* -------------------------------------------------------
 * Anomaly detection
 * Uses Welford online algorithm for running statistics.
 * Computes Z-score for each packet's size.
 * ------------------------------------------------------- */
int detect_anomaly(const Packet* p, DetectionResult* r) {

    double score = 0.0;
    char   reasons[200] = "";

    /* Z-score of packet size */
    double z = fabs((double)p->packet_size - base_mean)
               / (base_std + 1.0);
    if (z > 3.0) { score += 40.0; strncat(reasons, "extreme size; ", 190); }
    else if (z > 2.0) { score += 20.0; strncat(reasons, "unusual size; ", 190); }

    /* Tiny TCP packet check */
    if (p->protocol == 6 && p->packet_size < 40) {
        score += 20.0;
        strncat(reasons, "tiny TCP; ", 190);
    }

    /* Update running baseline using Welford algorithm */
    base_n++;
    double old_mean = base_mean;
    base_mean += ((double)p->packet_size - old_mean) / base_n;
    base_m2   += ((double)p->packet_size - old_mean)
                * ((double)p->packet_size - base_mean);
    if (base_n > 1) {
        double new_std = sqrt(base_m2 / (base_n - 1));
        base_std = (new_std < 10.0) ? 10.0 : new_std;
    }

    if (score >= 40.0) {
        r->is_threat    = 1;
        r->threat_level = THREAT_HIGH;
        r->confidence   = score / 100.0;
        strcpy(r->attack_type, "Anomaly");
        snprintf(r->description, 256,
                 "Statistical anomaly from %s: %s(%.0f)",
                 p->src_ip, reasons, score);
        return 1;
    }

    return 0;
}

/* -------------------------------------------------------
 * Analyze one packet using both engines
 * This is the function that will later be parallelized.
 * Currently called sequentially for each packet.
 * ------------------------------------------------------- */
DetectionResult analyze_packet(const Packet* p) {

    DetectionResult result;
    memset(&result, 0, sizeof(result));
    result.packet_id = p->packet_id;
    result.is_threat = 0;
    strcpy(result.attack_type, "Normal");

    DetectionResult sig, ano;
    memset(&sig, 0, sizeof(sig));
    memset(&ano, 0, sizeof(ano));

    int sig_hit = detect_signature(p, &sig);
    int ano_hit = detect_anomaly(p, &ano);

    /* Ensemble: both agree gives highest confidence */
    if (sig_hit && ano_hit) {
        result         = sig;
        result.confidence = (sig.confidence * 100 + 10) / 100.0;
        if (result.threat_level < THREAT_CRITICAL)
            result.threat_level++;
    } else if (sig_hit) {
        result = sig;
    } else if (ano_hit) {
        result = ano;
    }

    result.packet_id = p->packet_id;
    return result;
}

/* -------------------------------------------------------
 * Generate test packets (simulates captured network data)
 * ------------------------------------------------------- */
void generate_packets(Packet* pkts, int n) {
    srand(42);
    const char* atk[] = {
        "10.0.0.5","172.16.0.10","45.33.32.156","192.168.5.1"
    };
    const char* vic[] = {
        "192.168.1.100","192.168.1.101","192.168.1.1"
    };

    for (int i = 0; i < n; i++) {
        Packet* p = &pkts[i];
        memset(p, 0, sizeof(*p));
        p->packet_id = i + 1;
        int s = rand() % 10;

        if (s < 5) {
            /* Normal traffic */
            strcpy(p->src_ip, "192.168.1.50");
            strcpy(p->dst_ip, "8.8.8.8");
            p->protocol    = (rand() % 2) ? 6 : 17;
            p->dst_port    = (uint16_t[]){80,443,53,25}[rand()%4];
            p->flag_ack    = 1;
            p->packet_size = 200 + rand() % 800;
        } else if (s < 7) {
            /* Port scan */
            strcpy(p->src_ip, atk[0]);
            strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol    = 6;
            p->dst_port    = (i * 17 + 7) % 1024;
            p->flag_syn    = 1;
            p->packet_size = 40;
        } else if (s < 8) {
            /* Brute force SSH */
            strcpy(p->src_ip, atk[1]);
            strcpy(p->dst_ip, vic[0]);
            p->protocol    = 6;
            p->dst_port    = 22;
            p->flag_syn    = 1;
            p->packet_size = 64;
        } else if (s < 9) {
            /* NULL scan */
            strcpy(p->src_ip, atk[2]);
            strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol    = 6;
            p->dst_port    = rand() % 1024;
            p->packet_size = 40;
            /* all flags 0 */
        } else {
            /* Suspicious port */
            strcpy(p->src_ip, atk[rand()%4]);
            strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol    = 6;
            p->dst_port    = (uint16_t[]){4444,6667,31337}[rand()%3];
            p->flag_syn    = 1;
            p->packet_size = 64;
        }
    }
}

/* -------------------------------------------------------
 * MAIN: Sequential analysis loop
 *
 * This is the core of the sequential baseline.
 * Every packet is analyzed one by one in a simple for loop.
 * No MPI. No OpenMP. No threads. Purely sequential.
 * ------------------------------------------------------- */
int main(int argc, char* argv[]) {

    int n = 10000;  /* Default: 10,000 packets */
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-n") && i+1 < argc)
            n = atoi(argv[++i]);

    printf("\n");
    printf("D-IDS SEQUENTIAL BASELINE\n");
    printf("==========================\n");
    printf("Packets to analyze: %d\n\n", n);

    /* Allocate memory */
    Packet* packets = malloc(n * sizeof(Packet));
    DetectionResult* results = malloc(n * sizeof(DetectionResult));

    /* Generate test data */
    generate_packets(packets, n);

    /* ===================================================
     * SEQUENTIAL ANALYSIS LOOP
     *
     * This is the part that will be parallelized.
     * Currently: one packet analyzed at a time.
     * After parallelization: N packets analyzed at once.
     * =================================================== */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int threat_count = 0;
    for (int i = 0; i < n; i++) {
        results[i] = analyze_packet(&packets[i]);
        if (results[i].is_threat) {
            threat_count++;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec  - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    /* Report */
    printf("RESULTS:\n");
    printf("  Packets analyzed: %d\n", n);
    printf("  Threats detected: %d\n", threat_count);
    printf("  Detection rate:   %.1f%%\n",
           (double)threat_count / n * 100);
    printf("  Time (sequential): %.4f seconds\n", elapsed);
    printf("  Throughput:        %.0f packets/second\n", n / elapsed);
    printf("\n");
    printf("NOTE: This is the sequential baseline.\n");
    printf("The parallel version using MPI and OpenMP\n");
    printf("is expected to reduce this time by 1.8x to 2.2x.\n\n");

    free(packets);
    free(results);
    return 0;
}
```

### 3.4 Complexity Analysis of Sequential Baseline

Time complexity of the sequential loop: O(N * C)
  N = number of packets
  C = average cost to analyze one packet

C includes:
  - Signature engine: O(S) where S is the number of signatures (constant)
  - Anomaly engine: O(1) per packet (Welford algorithm is O(1) update)
  - Tracking table lookup: O(T) where T is tracked IP count (at most 500)

Overall: O(N) linear in packet count. Doubling N doubles execution time.

This linear relationship means parallelism provides direct proportional
benefit: with P workers each handling N/P packets, execution time reduces
to O(N/P * C) plus communication overhead.

---

## 4. PROPOSED PARALLELIZATION STRATEGY

### 4.1 Overall Approach: Coordinator-Worker with Hybrid Parallelism

The proposed parallel implementation uses a two-level parallelism hierarchy:

Level 1 (MPI): A coordinator process distributes packets to worker processes.
Each worker is an independent MPI process with its own memory space.
Workers communicate with the coordinator only, never with each other.

Level 2 (OpenMP): Within each MPI worker process, an OpenMP parallel for
loop distributes packets among threads. Threads share the worker's memory
and cooperate on analyzing the batch received from the coordinator.

This combination is called hybrid MPI+OpenMP parallelism and is the standard
approach for high-performance computing on modern multi-core clusters.

### 4.2 MPI Coordinator-Worker Design

```
PROPOSED MPI ARCHITECTURE:

Process 0 (Coordinator):
    Load all packets from input source
    PHASE 1 -- Seed all workers:
        FOR each worker w:
            MPI_Send(batch_of_100_packets, destination=w)
    PHASE 2 -- Dynamic distribution:
        WHILE unprocessed packets remain OR results outstanding:
            MPI_Recv(results, source=MPI_ANY_SOURCE)
            Store received results
            IF more packets remain:
                MPI_Send(next_batch, destination=result_sender)
    PHASE 3 -- Terminate:
        FOR each worker w:
            MPI_Send(empty_packet_signal, destination=w, tag=TERMINATE)
    Aggregate and report all results

Process 1..N (Workers):
    LOOP:
        MPI_Recv(batch, source=0)
        IF received tag == TERMINATE: EXIT LOOP
        #pragma omp parallel for schedule(dynamic, 4)
        FOR each packet in batch:
            results[i] = analyze_packet(packet)
        MPI_Send(results, destination=0)
```

Key design decisions:

Dynamic distribution (MPI_ANY_SOURCE): The coordinator receives results
from whichever worker finishes first, then immediately assigns that worker
more work. This prevents any worker from sitting idle while faster workers
receive a disproportionate share of packets, achieving near-optimal load
balancing automatically.

Batch size of 100 packets: Sending 100 packets per MPI message amortizes
the fixed cost of each MPI_Send/MPI_Recv call across 100 units of work.
Sending one packet per message would produce excessive communication
overhead. Sending 10,000 packets per message would reduce load balancing
flexibility.

### 4.3 OpenMP Thread Parallelism Within Workers

Within each worker, the packet analysis loop is parallelized with a single
OpenMP directive:

```c
/* Proposed parallel analysis within each MPI worker */
#pragma omp parallel for schedule(dynamic, 4)
for (int i = 0; i < batch_count; i++) {
    results[i] = analyze_packet(&batch[i]);
}
/* All threads join here before results are sent back */
```

The schedule(dynamic, 4) clause assigns packets to threads in groups of 4.
As each thread completes its group, it claims the next available group without
waiting for other threads. This provides fine-grained load balancing at the
thread level, complementing the coarse-grained load balancing at the MPI level.

### 4.4 Thread Safety Considerations

The analyze_packet function accesses shared tracking tables (port scan tracker,
rate tracker, anomaly baseline). These tables must be protected from concurrent
modification by multiple threads.

The proposed solution uses an OpenMP lock (omp_lock_t) that is acquired before
any read-modify-write operation on shared tables and released immediately after.
Stateless checks (NULL scan, bad port check) do not require the lock and can
execute fully in parallel.

This design minimizes lock contention by limiting locked regions to the minimum
necessary operations, allowing the majority of analysis work to proceed without
synchronization.

### 4.5 Input Pipeline

Packets will be supplied to the coordinator through two mechanisms:

File mode: Packets captured by a sensor program using the libpcap library
are written to a CSV file. The coordinator reads this file at startup and
distributes packets from it. This mode is suitable for offline analysis and
testing.

Socket mode: A sensor program captures packets continuously and streams them
as JSON-encoded lines over a TCP socket connection to the coordinator. The
coordinator reads packets from the socket in real time. This mode enables
continuous live monitoring without buffering the full capture to disk.

---

## 5. EXPECTED SPEEDUP ANALYSIS USING AMDAHL'S LAW

### 5.1 Amdahl's Law

Amdahl's Law gives the theoretical maximum speedup achievable by
parallelizing a program:

    Speedup(P) = 1 / ( S + (1 - S) / P )

Where:
    S = the serial fraction (proportion of execution time that cannot
        be parallelized, regardless of how many processors are used)
    P = the number of parallel processors (MPI workers or cores)
    (1 - S) = the parallel fraction

### 5.2 Identifying the Serial and Parallel Fractions

Serial fraction components in the D-IDS coordinator:
  - CSV file reading or socket I/O (single-threaded, I/O bound)
  - MPI message serialization and transmission
  - Result collection and threat report generation

These operations cannot be distributed across workers because they require
coordinated access to shared input/output resources.

Parallel fraction components (can be parallelized):
  - Packet feature extraction
  - Signature rule evaluation against each packet
  - Anomaly Z-score computation
  - ML model inference (if integrated)

Estimated serial fraction: 30 to 40 percent
This estimate is based on the proportion of time spent in I/O and
communication operations relative to pure computation, as measured in
similar parallel IDS research (Aldwairi et al., 2003).

### 5.3 Speedup Calculations

Using S = 0.35 (35 percent serial fraction) as the central estimate:

With P = 2 workers (3 MPI processes total: 1 coordinator + 2 workers):

    Speedup(2) = 1 / (0.35 + 0.65/2)
               = 1 / (0.35 + 0.325)
               = 1 / 0.675
               = 1.48x

With P = 3 workers (4 MPI processes total):

    Speedup(3) = 1 / (0.35 + 0.65/3)
               = 1 / (0.35 + 0.217)
               = 1 / 0.567
               = 1.76x

With P = 4 workers (5 MPI processes total):

    Speedup(4) = 1 / (0.35 + 0.65/4)
               = 1 / (0.35 + 0.163)
               = 1 / 0.513
               = 1.95x

Sensitivity analysis (varying the serial fraction estimate):

    Serial fraction | P=2 workers | P=3 workers | P=4 workers
    ----------------+-------------+-------------+-------------
    S = 0.30        |   1.54x     |   1.87x     |   2.11x
    S = 0.35        |   1.48x     |   1.76x     |   1.95x
    S = 0.40        |   1.43x     |   1.67x     |   1.82x

### 5.4 Expected Execution Time

Measured sequential baseline execution time for 10,000 packets:
  Approximately 0.013 seconds on the target 4-core virtual machine.

Expected parallel execution time with 3 MPI workers:
  0.013 / 1.76 = approximately 0.0074 seconds

Expected parallel execution time with OpenMP (4 threads, 1 worker):
  If OpenMP achieves 1.5x speedup within one worker:
  0.013 / 1.5 = approximately 0.0087 seconds

Expected parallel execution time with hybrid (2 workers x 2 threads):
  Combined theoretical speedup approximately 1.8x to 2.2x:
  0.013 / 2.0 = approximately 0.0065 seconds

### 5.5 Throughput Projections

Sequential baseline:
    10,000 packets / 0.013 seconds = 769,231 packets per second

Expected with MPI 3 workers:
    10,000 packets / 0.0074 seconds = approximately 1,350,000 packets/second

Expected with hybrid MPI+OpenMP:
    10,000 packets / 0.0065 seconds = approximately 1,540,000 packets/second

### 5.6 Limitations of the Prediction

Amdahl's Law provides theoretical maximum speedup under ideal conditions.
Actual measured speedup will be lower due to:
  - MPI message latency (not modeled in Amdahl's Law)
  - OpenMP thread creation and synchronization overhead
  - Lock contention on shared detection state tables
  - Memory bandwidth saturation on shared-memory systems
  - Operating system scheduling overhead on virtual machines

The predicted speedup of 1.76x to 2.2x should therefore be treated as
an upper bound. A realistic expectation accounting for these overheads
would be 1.4x to 1.8x speedup on the 4-core target machine.

---

## 6. EXPECTED OUTCOMES

### 6.1 Functional Outcomes

By the end of the implementation the following capabilities will be
demonstrated:

1. A working packet capture sensor that reads live traffic from a network
   interface using libpcap and writes captured packets to a structured
   CSV file for analysis.

2. An MPI parallel coordinator implementing dynamic load-balanced distribution
   of packet batches to 1 to 4 worker processes running simultaneously.

3. OpenMP thread parallelism within each MPI worker using the parallel for
   directive with dynamic scheduling.

4. Three detection engines: signature-based, statistical anomaly-based, and
   optionally machine learning-based, combined through an ensemble voting
   mechanism.

5. A real-time web dashboard displaying detected threats, packet statistics,
   and performance metrics in a browser interface.

6. A performance benchmark comparing sequential, pure MPI, pure OpenMP, and
   hybrid configurations across multiple packet counts.

### 6.2 Performance Outcomes

Expected speedup at 10,000 packets:
  MPI 3 workers vs sequential:    1.6x to 1.9x
  Hybrid MPI+OpenMP vs sequential: 1.4x to 2.2x (depends on thread count)

Expected throughput:
  Sequential baseline:  approximately 750,000 packets per second
  Parallel (MPI):       approximately 1,200,000 to 1,500,000 packets per second

### 6.3 Academic Outcomes

The implementation will demonstrate the following parallel computing concepts
from the course curriculum:

  - MPI point-to-point communication (MPI_Send, MPI_Recv)
  - Dynamic load balancing using MPI_ANY_SOURCE
  - OpenMP parallel loops with dynamic scheduling
  - Hybrid MPI+OpenMP two-level parallelism
  - Thread safety and mutual exclusion using omp_lock_t
  - Speedup measurement and Amdahl's Law validation
  - Performance analysis and bottleneck identification

---

## 7. IMPLEMENTATION TIMELINE

| Week | Focus                     | Planned Tasks                                          |
|------|---------------------------|--------------------------------------------------------|
| 1    | Environment setup         | Install GCC, MPI, libpcap, Python; verify all tools    |
| 2    | Packet capture            | Implement libpcap sensor, CSV output, BPF filter       |
| 3    | Signature detection       | Implement 5 detection rules, unit tests                |
| 4    | Basic MPI                 | Implement coordinator-worker, measure initial speedup  |
| 5    | OpenMP integration        | Add parallel for within workers, measure thread speedup|
| 6    | Anomaly detection         | Implement Welford baseline, Z-score analysis           |
| 7    | ML detection (optional)   | Train Random Forest on captured data                   |
| 8    | Ensemble decision engine  | Combine all three engines, validate detection accuracy |
| 9    | Data pipeline             | Connect capture to coordinator via file and socket     |
| 10   | Web dashboard             | Flask server, Socket.IO, real-time charts              |
| 11   | Attack simulation         | Build simulator for demo traffic; run ML training      |
| 12   | Testing and benchmarking  | 22-test suite; speedup benchmark across packet counts  |
| 13   | Architecture documentation| Write architecture document and deployment guide       |
| 14   | Final report              | Write 30-page report with results and analysis         |
| 15   | Presentation preparation  | Build slide deck; rehearse demo                        |
| 16   | Final presentation        | Live demo and Q&A                                      |

---

## 8. TOOLS AND TECHNOLOGIES

| Component          | Technology     | Justification                                         |
|--------------------|----------------|-------------------------------------------------------|
| C compiler         | GCC 11+        | Standard, -fopenmp flag enables OpenMP                |
| MPI implementation | OpenMPI 4.x    | Industry standard, widely deployed                    |
| Thread parallelism | OpenMP 4.5     | Integrated with GCC, no separate library needed       |
| Packet capture     | libpcap        | Standard for network packet access on Linux           |
| Web framework      | Flask (Python) | Lightweight, simple WebSocket integration             |
| Real-time updates  | Flask-SocketIO | Enables push notifications to browser clients         |
| ML framework       | scikit-learn   | Simple API, Random Forest included, no GPU required   |
| Visualization      | Chart.js       | Client-side charts, no server-side rendering needed   |
| Operating system   | Ubuntu 22.04   | Native libpcap and OpenMPI package support            |

---

## 9. REFERENCES

1. Aldwairi, M., Conte, T., and Franzon, P. "Configurable string matching
   hardware for speeding up intrusion detection." ACM SIGARCH Computer
   Architecture News, 2003.

2. Gropp, W., Lusk, E., and Skjellum, A. "Using MPI: Portable Parallel
   Programming with the Message-Passing Interface." MIT Press, 2014.

3. Chapman, B., Jost, G., and Van Der Pas, R. "Using OpenMP: Portable
   Shared Memory Parallel Programming." MIT Press, 2007.

4. Amdahl, G. M. "Validity of the single processor approach to achieving
   large-scale computing capabilities." AFIPS Spring Joint Computer
   Conference, 1967.

5. Roesch, M. "Snort - Lightweight Intrusion Detection for Networks."
   USENIX LISA, 1999.

6. tcpdump/libpcap Project. https://www.tcpdump.org/

7. Open MPI Project. https://www.open-mpi.org/

---

*Proposal submitted for: Parallel and Distributed Computing*
*Instructor: Waqas Ali*
*Student Roll Number: 2024-CS-89 / 2023-CS-652*
