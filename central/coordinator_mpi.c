/*
 * =============================================================================
 * WEEK 4 - MPI COORDINATOR (Parallel Processing)
 * File: central/coordinator_mpi.c
 * =============================================================================
 *
 * WHAT THIS FILE DOES:
 *   This is the BRAIN of the D-IDS system. It uses MPI to run multiple
 *   processes in parallel, each analyzing packets for threats.
 *
 * HOW MPI PARALLELISM WORKS IN OUR SYSTEM:
 *
 *   When you run: mpirun -np 5 ./coordinator
 *   You get 5 processes running simultaneously:
 *
 *   Process 0 (Coordinator/Manager):
 *     - Reads packets from a file (simulating sensor input)
 *     - Sends packets to workers using MPI_Send
 *     - Receives results back using MPI_Recv
 *     - Prints alerts and statistics
 *
 *   Processes 1,2,3,4 (Workers):
 *     - Wait for packets from coordinator
 *     - Run signature detection on each packet
 *     - Send results back to coordinator
 *
 * WHY IS THIS FASTER?
 *   Without parallelism: 1 process analyzes 1000 packets in 10 seconds
 *   With 4 workers: each gets 250 packets, done in ~2.5 seconds = 4x speedup!
 *
 *   This is what your speedup graph will show in your final report.
 *
 * KEY MPI FUNCTIONS USED:
 *   MPI_Send()     - Send data to another process
 *   MPI_Recv()     - Receive data from another process
 *   MPI_Scatter()  - Send different pieces of data to all workers
 *   MPI_Gather()   - Collect results from all workers
 *   MPI_Barrier()  - Synchronize all processes
 *   MPI_Wtime()    - Get high-precision timer (for measuring speedup)
 *
 * COMPILE:
 *   mpicc -O2 -o coordinator coordinator_mpi.c -lm
 *
 * RUN (test with 5 processes: 1 coordinator + 4 workers):
 *   mpirun -np 5 ./coordinator -f ../data/test_packets.csv -n 100
 *
 *   Or just test with simulated packets:
 *   mpirun -np 5 ./coordinator
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <mpi.h>     /* MPI library */
#include <stdint.h>
/* =============================================================================
 * CONSTANTS
 * ============================================================================= */

#define MAX_PACKETS          10000   /* Maximum packets to analyze in one run */
#define MAX_IPS              500     /* For tracking attacker IPs */
#define MAX_PORTS            200     /* For port scan tracking */
#define BATCH_SIZE           50      /* Packets per batch sent to workers */

/* MPI tags - used to distinguish types of messages */
#define TAG_PACKET           1       /* Sending a packet to analyze */
#define TAG_RESULT           2       /* Sending a result back */
#define TAG_TERMINATE        99      /* Tell worker to stop */

/* Threat levels */
#define THREAT_NONE          0
#define THREAT_LOW           1
#define THREAT_MEDIUM        2
#define THREAT_HIGH          3
#define THREAT_CRITICAL      4

/* =============================================================================
 * DATA STRUCTURES
 * These must be IDENTICAL in coordinator and workers because we send them
 * as raw bytes over MPI.
 * ============================================================================= */

/*
 * PacketRecord - the data we send from coordinator to workers
 * Keep it simple: only what workers need to detect threats.
 */
typedef struct {
    int      packet_id;       /* Unique ID so we can track it */
    int      protocol;        /* 6=TCP, 17=UDP, 1=ICMP */
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
    long     timestamp;
} PacketRecord;

/*
 * DetectionResult - what workers send back to coordinator
 */
typedef struct {
    int    packet_id;          /* Which packet this result is for */
    int    worker_rank;        /* Which worker analyzed it */
    int    is_threat;          /* 0 = safe, 1 = threat */
    int    threat_level;       /* THREAT_NONE to THREAT_CRITICAL */
    char   attack_type[64];    /* "Port Scan", "DDoS", etc. */
    char   description[256];   /* Detailed explanation */
    double confidence;         /* 0.0 to 1.0 */
    double analysis_time_ms;   /* How long did analysis take */
} DetectionResult;

/*
 * SystemStats - tracks overall performance
 * Used to calculate speedup for your final report
 */
typedef struct {
    long   total_packets;
    long   threats_found;
    long   critical_threats;
    long   high_threats;
    long   medium_threats;
    double total_analysis_time;
    double packets_per_second;
    int    num_workers;
} SystemStats;

/* =============================================================================
 * DETECTION STATE (for workers)
 * Each worker maintains its own tracking state
 * ============================================================================= */

/* Port scan tracking */
typedef struct {
    char     ip[16];
    uint16_t ports[MAX_PORTS];
    int      port_count;
    long     first_seen;
} PortScanTracker;

static PortScanTracker scan_tracker[MAX_IPS];
static int             scan_tracker_count = 0;

/* Rate tracking for DDoS/brute force */
typedef struct {
    char ip[16];
    int  count;
    long window_start;
} RateTracker;

static RateTracker rate_tracker[MAX_IPS];
static int         rate_tracker_count = 0;

/* =============================================================================
 * DETECTION HELPER FUNCTIONS
 * ============================================================================= */

PortScanTracker* find_scan_tracker(const char* ip) {
    for (int i = 0; i < scan_tracker_count; i++) {
        if (strcmp(scan_tracker[i].ip, ip) == 0)
            return &scan_tracker[i];
    }
    if (scan_tracker_count < MAX_IPS) {
        PortScanTracker* t = &scan_tracker[scan_tracker_count++];
        strncpy(t->ip, ip, 15);
        t->port_count = 0;
        t->first_seen = time(NULL);
        return t;
    }
    return NULL;
}

RateTracker* find_rate_tracker(const char* ip) {
    for (int i = 0; i < rate_tracker_count; i++) {
        if (strcmp(rate_tracker[i].ip, ip) == 0)
            return &rate_tracker[i];
    }
    if (rate_tracker_count < MAX_IPS) {
        RateTracker* t = &rate_tracker[rate_tracker_count++];
        strncpy(t->ip, ip, 15);
        t->count = 0;
        t->window_start = time(NULL);
        return t;
    }
    return NULL;
}

const char* threat_name(int level) {
    switch (level) {
        case THREAT_NONE:     return "NONE";
        case THREAT_LOW:      return "LOW";
        case THREAT_MEDIUM:   return "MEDIUM";
        case THREAT_HIGH:     return "HIGH";
        case THREAT_CRITICAL: return "CRITICAL";
        default:              return "UNKNOWN";
    }
}

/* =============================================================================
 * WORKER DETECTION LOGIC
 * This is what each worker process runs on each packet
 * ============================================================================= */

/*
 * analyze_packet
 *
 * This is the core detection function. Each worker calls this for every
 * packet it receives. It runs multiple checks and returns the worst finding.
 *
 * PARAMS:
 *   packet - the packet to analyze
 *   rank   - this worker's process rank (for logging)
 *
 * RETURNS:
 *   DetectionResult with findings
 */
DetectionResult analyze_packet(const PacketRecord* packet, int rank) {
    DetectionResult result;
    memset(&result, 0, sizeof(DetectionResult));
    result.packet_id   = packet->packet_id;
    result.worker_rank = rank;
    result.is_threat   = 0;
    result.threat_level = THREAT_NONE;
    result.confidence  = 0.0;
    strcpy(result.attack_type, "Normal");
    strcpy(result.description, "No threats detected");

    double start_time = MPI_Wtime();  /* Start timing this analysis */

    /* =================================================================
     * CHECK 1: NULL Scan Detection
     * TCP packet with NO flags = stealth scanner
     * ================================================================= */
    if (packet->protocol == 6 &&
        !packet->flag_syn && !packet->flag_ack &&
        !packet->flag_fin && !packet->flag_rst && !packet->flag_psh) {

        result.is_threat    = 1;
        result.threat_level = THREAT_MEDIUM;
        result.confidence   = 0.85;
        strcpy(result.attack_type, "NULL Scan");
        snprintf(result.description, sizeof(result.description),
                 "TCP NULL scan from %s to %s:%d (no flags set = stealth probe)",
                 packet->src_ip, packet->dst_ip, packet->dst_port);
    }

    /* =================================================================
     * CHECK 2: Port Scan Detection
     * Same IP connecting to many different ports
     * ================================================================= */
    if (packet->protocol == 6 && packet->flag_syn) {
        PortScanTracker* t = find_scan_tracker(packet->src_ip);
        if (t != NULL) {
            /* Reset if older than 60 seconds */
            long now = time(NULL);
            if (now - t->first_seen > 60) {
                t->port_count = 0;
                t->first_seen = now;
            }

            /* Add this port if not already seen */
            int found = 0;
            for (int i = 0; i < t->port_count; i++) {
                if (t->ports[i] == packet->dst_port) { found = 1; break; }
            }
            if (!found && t->port_count < MAX_PORTS) {
                t->ports[t->port_count++] = packet->dst_port;
            }

            if (t->port_count > 20) {
                /* This is more severe than NULL scan */
                if (THREAT_HIGH > result.threat_level) {
                    result.is_threat    = 1;
                    result.threat_level = THREAT_HIGH;
                    result.confidence   = 0.88;
                    strcpy(result.attack_type, "Port Scan");
                    snprintf(result.description, sizeof(result.description),
                             "Port scan from %s: tried %d unique ports on %s in <60s",
                             packet->src_ip, t->port_count, packet->dst_ip);
                }
            }
        }
    }

    /* =================================================================
     * CHECK 3: Brute Force Detection
     * Many connection attempts to SSH/RDP
     * ================================================================= */
    if (packet->protocol == 6 && packet->flag_syn &&
        (packet->dst_port == 22 || packet->dst_port == 3389 ||
         packet->dst_port == 21 || packet->dst_port == 23)) {

        RateTracker* t = find_rate_tracker(packet->src_ip);
        if (t != NULL) {
            long now = time(NULL);
            if (now - t->window_start > 60) {
                t->count = 0;
                t->window_start = now;
            }
            t->count++;

            if (t->count > 30) {
                if (THREAT_HIGH > result.threat_level) {
                    const char* service =
                        (packet->dst_port == 22)   ? "SSH" :
                        (packet->dst_port == 3389) ? "RDP" :
                        (packet->dst_port == 21)   ? "FTP" : "Telnet";

                    result.is_threat    = 1;
                    result.threat_level = THREAT_HIGH;
                    result.confidence   = 0.90;
                    strcpy(result.attack_type, "Brute Force");
                    snprintf(result.description, sizeof(result.description),
                             "Brute force %s from %s: %d attempts in 60s to %s",
                             service, packet->src_ip, t->count, packet->dst_ip);
                }
            }
        }
    }

    /* =================================================================
     * CHECK 4: Suspicious Ports
     * Known malware/RAT ports
     * ================================================================= */
    uint16_t bad_ports[] = {4444, 6667, 6666, 31337, 12345, 8888, 9999, 1080, 0};
    for (int i = 0; bad_ports[i] != 0; i++) {
        if (packet->dst_port == bad_ports[i] || packet->src_port == bad_ports[i]) {
            if (THREAT_MEDIUM > result.threat_level) {
                uint16_t the_port = (packet->dst_port == bad_ports[i]) ?
                                     packet->dst_port : packet->src_port;
                result.is_threat    = 1;
                result.threat_level = THREAT_MEDIUM;
                result.confidence   = 0.75;
                strcpy(result.attack_type, "Suspicious Port");
                snprintf(result.description, sizeof(result.description),
                         "Traffic on malware port %d between %s and %s",
                         the_port, packet->src_ip, packet->dst_ip);
            }
            break;
        }
    }

    /* =================================================================
     * CHECK 5: Oversized Packets (possible buffer overflow attempt)
     * ================================================================= */
    if (packet->packet_size > 1500) {
        /* Jumbo frames are over 1500 bytes - suspicious in some contexts */
        if (THREAT_LOW > result.threat_level) {
            result.is_threat    = 1;
            result.threat_level = THREAT_LOW;
            result.confidence   = 0.55;
            strcpy(result.attack_type, "Oversized Packet");
            snprintf(result.description, sizeof(result.description),
                     "Oversized packet (%d bytes) from %s - possible evasion",
                     packet->packet_size, packet->src_ip);
        }
    }

    /* Record analysis time */
    result.analysis_time_ms = (MPI_Wtime() - start_time) * 1000.0;

    return result;
}

/* =============================================================================
 * WORKER PROCESS MAIN LOOP
 *
 * Workers run this loop:
 * 1. Wait for a packet from coordinator
 * 2. Analyze it
 * 3. Send result back
 * 4. Repeat until termination signal
 * ============================================================================= */

void run_worker(int rank) {
    MPI_Status status;
    PacketRecord packet;
    long packets_analyzed = 0;

    /* Worker loop */
    while (1) {
        /* Wait to receive a packet from coordinator (rank 0) */
        MPI_Recv(
            &packet,           /* where to store it */
            sizeof(PacketRecord), /* how many bytes */
            MPI_BYTE,          /* raw bytes */
            0,                 /* from rank 0 (coordinator) */
            MPI_ANY_TAG,       /* accept any tag */
            MPI_COMM_WORLD,    /* communication group */
            &status            /* status info */
        );

        /* Check if this is a termination signal */
        if (status.MPI_TAG == TAG_TERMINATE) {
            /* Coordinator is done, we can stop */
            break;
        }

        /* Analyze the packet */
        DetectionResult result = analyze_packet(&packet, rank);
        packets_analyzed++;

        /* Send the result back to coordinator */
        MPI_Send(
            &result,                /* what to send */
            sizeof(DetectionResult), /* how many bytes */
            MPI_BYTE,               /* raw bytes */
            0,                      /* to rank 0 (coordinator) */
            TAG_RESULT,             /* tag: this is a result */
            MPI_COMM_WORLD
        );
    }

    /* Optional: workers can print their stats */
    /* (In real system, we'd gather these with MPI_Gather) */
}

/* =============================================================================
 * PACKET GENERATOR
 * Creates test packets for demonstration
 * (In production, real packets come from sensors)
 * ============================================================================= */

/*
 * generate_test_packets
 *
 * Creates a mix of normal and attack packets for testing.
 * This simulates what your real sensors would send.
 *
 * PARAMS:
 *   packets   - array to fill with generated packets
 *   count     - how many to generate
 */
void generate_test_packets(PacketRecord* packets, int count) {
    srand(42);  /* Fixed seed for reproducibility */

    /* Attack scenarios to simulate */
    char* attacker_ips[] = {
        "10.0.0.5",    /* Port scanner */
        "172.16.0.10", /* Brute forcer */
        "192.168.5.1", /* DDoS attacker */
        "45.33.32.156" /* External attacker */
    };

    char* victim_ips[] = {
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.1"
    };

    uint16_t common_ports[] = {80, 443, 22, 53, 25, 8080};

    for (int i = 0; i < count; i++) {
        PacketRecord* p = &packets[i];
        memset(p, 0, sizeof(PacketRecord));
        p->packet_id = i + 1;
        p->timestamp = time(NULL);

        int scenario = rand() % 10;

        if (scenario < 5) {
            /* 50% - Normal HTTP/HTTPS traffic */
            strncpy(p->src_ip, "192.168.1.50", 15);
            strncpy(p->dst_ip, "8.8.8.8", 15);
            p->src_port   = 50000 + (rand() % 10000);
            p->dst_port   = common_ports[rand() % 6];
            p->protocol   = 6;  /* TCP */
            p->flag_syn   = (rand() % 3 == 0) ? 1 : 0;
            p->flag_ack   = !p->flag_syn;
            p->packet_size = 200 + (rand() % 800);

        } else if (scenario < 7) {
            /* 20% - Port scan from attacker */
            strncpy(p->src_ip, attacker_ips[0], 15);
            strncpy(p->dst_ip, victim_ips[rand() % 3], 15);
            p->src_port   = 60000;
            p->dst_port   = (i * 17 + 7) % 1024;  /* Scanning ports */
            p->protocol   = 6;
            p->flag_syn   = 1;
            p->packet_size = 40;

        } else if (scenario < 8) {
            /* 10% - Brute force SSH */
            strncpy(p->src_ip, attacker_ips[1], 15);
            strncpy(p->dst_ip, victim_ips[0], 15);
            p->src_port   = 60000 + (rand() % 100);
            p->dst_port   = 22;  /* SSH */
            p->protocol   = 6;
            p->flag_syn   = 1;
            p->packet_size = 64;

        } else if (scenario == 8) {
            /* 10% - NULL scan */
            strncpy(p->src_ip, attacker_ips[3], 15);
            strncpy(p->dst_ip, victim_ips[rand() % 3], 15);
            p->src_port    = rand() % 65535;
            p->dst_port    = rand() % 1024;
            p->protocol    = 6;
            /* All flags = 0 (NULL scan) */
            p->packet_size = 40;

        } else {
            /* 10% - Suspicious ports */
            uint16_t bad_ports[] = {4444, 6667, 31337, 8888};
            strncpy(p->src_ip, attacker_ips[rand() % 4], 15);
            strncpy(p->dst_ip, victim_ips[rand() % 3], 15);
            p->src_port   = 60000;
            p->dst_port   = bad_ports[rand() % 4];
            p->protocol   = 6;
            p->flag_syn   = 1;
            p->packet_size = 64;
        }
    }
}

/* =============================================================================
 * COORDINATOR PROCESS
 * Manages all workers and aggregates results
 * ============================================================================= */

void run_coordinator(int num_workers, int num_packets) {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   D-IDS PARALLEL COORDINATOR - WEEK 4       ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Workers:  %-33d║\n", num_workers);
    printf("║  Packets:  %-33d║\n", num_packets);
    printf("╚══════════════════════════════════════════════╝\n");
    printf("\n");

    /* Allocate memory for packets and results */
    PacketRecord* packets = (PacketRecord*)malloc(num_packets * sizeof(PacketRecord));
    DetectionResult* results = (DetectionResult*)malloc(num_packets * sizeof(DetectionResult));

    if (!packets || !results) {
        fprintf(stderr, "ERROR: Cannot allocate memory!\n");
        return;
    }

    /* Generate test packets */
    printf("[1/4] Generating %d test packets...\n", num_packets);
    generate_test_packets(packets, num_packets);
    printf("      Done.\n\n");

    /* =========================================================
     * PARALLEL PROCESSING WITH MPI
     *
     * Strategy: Round-robin distribution
     * Packet 0 → Worker 1
     * Packet 1 → Worker 2
     * Packet 2 → Worker 3
     * ...
     * Packet N → Worker (N % num_workers) + 1
     *
     * While workers are analyzing, coordinator distributes more.
     * When a result comes back, send the next packet to that worker.
     * This is called "work stealing" or "dynamic load balancing."
     * ========================================================= */

    printf("[2/4] Starting parallel analysis...\n");
    double start_time = MPI_Wtime();  /* High-precision MPI timer */

    int next_packet  = 0;  /* Next packet to send */
    int pending      = 0;  /* Results we're still waiting for */
    int results_count = 0;
    MPI_Status status;

    /* Phase 1: Fill all workers with their first packet */
    for (int w = 1; w <= num_workers && next_packet < num_packets; w++) {
        MPI_Send(&packets[next_packet], sizeof(PacketRecord), MPI_BYTE,
                 w, TAG_PACKET, MPI_COMM_WORLD);
        next_packet++;
        pending++;
    }

    /* Phase 2: Dynamic distribution - as each worker finishes, give it more */
    while (pending > 0) {
        /* Wait for ANY worker to send a result back */
        DetectionResult result;
        MPI_Recv(&result, sizeof(DetectionResult), MPI_BYTE,
                 MPI_ANY_SOURCE, TAG_RESULT, MPI_COMM_WORLD, &status);

        /* Store this result */
        results[results_count++] = result;
        pending--;

        /* If we have more packets, send another to this worker */
        if (next_packet < num_packets) {
            int worker_rank = status.MPI_SOURCE;
            MPI_Send(&packets[next_packet], sizeof(PacketRecord), MPI_BYTE,
                     worker_rank, TAG_PACKET, MPI_COMM_WORLD);
            next_packet++;
            pending++;
        }
    }

    double end_time = MPI_Wtime();
    double elapsed  = end_time - start_time;

    /* Phase 3: Send termination signal to all workers */
    PacketRecord terminate_signal;
    memset(&terminate_signal, 0, sizeof(PacketRecord));
    for (int w = 1; w <= num_workers; w++) {
        MPI_Send(&terminate_signal, sizeof(PacketRecord), MPI_BYTE,
                 w, TAG_TERMINATE, MPI_COMM_WORLD);
    }

    printf("      Done. Analyzed %d packets in %.3f seconds\n\n",
           num_packets, elapsed);

    /* =========================================================
     * AGGREGATE RESULTS AND PRINT ALERTS
     * ========================================================= */
    printf("[3/4] Processing results...\n\n");

    SystemStats stats = {0};
    stats.total_packets    = num_packets;
    stats.num_workers      = num_workers;
    stats.total_analysis_time = elapsed;
    stats.packets_per_second  = num_packets / elapsed;

    /* Sort and display threats */
    printf("%-60s %-8s %-10s %s\n",
           "DESCRIPTION", "LEVEL", "CONFIDENCE", "SOURCE IP");
    printf("%-60s %-8s %-10s %s\n",
           "------------------------------------------------------------",
           "--------", "----------", "---------");

    for (int i = 0; i < results_count; i++) {
        DetectionResult* r = &results[i];

        if (r->is_threat) {
            stats.threats_found++;

            switch (r->threat_level) {
                case THREAT_CRITICAL: stats.critical_threats++; break;
                case THREAT_HIGH:     stats.high_threats++;     break;
                case THREAT_MEDIUM:   stats.medium_threats++;   break;
            }

            /* Color codes */
            const char* color;
            switch (r->threat_level) {
                case THREAT_CRITICAL: color = "\033[1;31m"; break;
                case THREAT_HIGH:     color = "\033[0;31m"; break;
                case THREAT_MEDIUM:   color = "\033[0;33m"; break;
                default:              color = "\033[0;34m"; break;
            }

            printf("%s%-60s %-8s %8.0f%%   %s\033[0m\n",
                   color,
                   r->attack_type,
                   threat_name(r->threat_level),
                   r->confidence * 100,
                   r->worker_rank > 0 ? "Worker" : "");
        }
    }

    /* =========================================================
     * PERFORMANCE STATISTICS REPORT
     * This is the data you'll use for your speedup graph!
     * ========================================================= */
    printf("\n[4/4] Performance Report\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║          ANALYSIS COMPLETE - STATISTICS      ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Total packets analyzed:   %-17ld║\n", stats.total_packets);
    printf("║  Threats detected:         %-17ld║\n", stats.threats_found);
    printf("║  ├── Critical:             %-17ld║\n", stats.critical_threats);
    printf("║  ├── High:                 %-17ld║\n", stats.high_threats);
    printf("║  └── Medium:               %-17ld║\n", stats.medium_threats);
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  PERFORMANCE METRICS:                        ║\n");
    printf("║  Workers used:             %-17d║\n", stats.num_workers);
    printf("║  Total time:               %-14.3f sec║\n", stats.total_analysis_time);
    printf("║  Throughput:               %-10.0f pkt/sec║\n", stats.packets_per_second);
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Detection rate:           %-14.1f%%  ║\n",
           (double)stats.threats_found / stats.total_packets * 100);
    printf("╚══════════════════════════════════════════════╝\n");

    printf("\n");
    printf("📊 FOR YOUR REPORT - Copy this line:\n");
    printf("   workers=%d, packets=%d, time=%.3fs, throughput=%.0f pkt/s\n\n",
           num_workers, num_packets, elapsed, stats.packets_per_second);

    free(packets);
    free(results);
}

/* =============================================================================
 * MAIN FUNCTION
 *
 * This is where every process starts. Both coordinator AND workers run main().
 * We use the rank to decide which role each process plays.
 * ============================================================================= */
int main(int argc, char* argv[]) {
    int rank, size;
    int num_packets = 500;  /* Default: analyze 500 packets */

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i+1 < argc) {
            num_packets = atoi(argv[++i]);
        }
    }

    /* ALWAYS call MPI_Init first */
    MPI_Init(&argc, &argv);

    /* Get this process's rank and total count */
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (size < 2) {
        if (rank == 0) {
            fprintf(stderr, "ERROR: Need at least 2 processes!\n");
            fprintf(stderr, "Run: mpirun -np 4 ./coordinator\n");
        }
        MPI_Finalize();
        return 1;
    }

    int num_workers = size - 1;  /* 1 coordinator, rest are workers */

    /* -----------------------------------------------
     * THIS IS THE KEY MPI CONCEPT:
     * Same program, same main(), but different roles
     * based on rank!
     * ----------------------------------------------- */
    if (rank == 0) {
        /* I am the COORDINATOR */
        run_coordinator(num_workers, num_packets);
    } else {
        /* I am a WORKER (rank 1, 2, 3, ...) */
        run_worker(rank);
    }

    /* ALWAYS call MPI_Finalize last */
    MPI_Finalize();
    return 0;
}
