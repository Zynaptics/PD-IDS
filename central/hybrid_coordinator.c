/*
 * =============================================================================
 * WEEKS 5-6: HYBRID MPI + OpenMP COORDINATOR
 * File: central/hybrid_coordinator.c
 * =============================================================================
 *
 * WHAT IS HYBRID PARALLELISM?
 *
 *   LEVEL 1 — MPI (between processes):
 *     Process 0 = Coordinator
 *     Process 1,2,3 = Workers (talk via MPI_Send/MPI_Recv)
 *     Each process has its OWN separate memory
 *
 *   LEVEL 2 — OpenMP (within each worker process):
 *     Each worker spawns multiple THREADS internally
 *     Threads SHARE memory inside the worker
 *     Split the packet batch with #pragma omp parallel for
 *
 *   VISUAL:
 *   [Coordinator rank=0]
 *        | MPI_Send batch
 *   ┌────▼────┐  ┌─────────┐  ┌─────────┐
 *   │Worker 1 │  │Worker 2 │  │Worker 3 │  <- MPI processes
 *   │Thread 0 │  │Thread 0 │  │Thread 0 │  <- OpenMP threads
 *   │Thread 1 │  │Thread 1 │  │Thread 1 │    inside each worker
 *   │Thread 2 │  │Thread 2 │  │Thread 2 │
 *   │Thread 3 │  │Thread 3 │  │Thread 3 │
 *   └─────────┘  └─────────┘  └─────────┘
 *
 * WEEK 6 ADDITION: ANOMALY DETECTION
 *   Statistical baseline tracking using Welford online algorithm.
 *   Z-score analysis flags packets that deviate from normal traffic.
 *
 * COMPILE:
 *   mpicc -O2 -fopenmp -o build/hybrid_coordinator central/hybrid_coordinator.c -lm
 *
 * RUN:
 *   OMP_NUM_THREADS=4 mpirun -np 4 ./build/hybrid_coordinator -n 1000
 *
 * SPEEDUP EXPERIMENT (for your report):
 *   Sequential:  mpirun -np 2 ./build/hybrid_coordinator -n 2000 --sequential
 *   Pure MPI:    mpirun -np 4 ./build/hybrid_coordinator -n 2000 --no-omp
 *   Hybrid:      OMP_NUM_THREADS=4 mpirun -np 4 ./build/hybrid_coordinator -n 2000
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <mpi.h>
#include <omp.h>

/* =============================================================================
 * CONSTANTS
 * ============================================================================= */
#define MAX_PACKETS        20000
#define MAX_TRACKED_IPS    500
#define MAX_TRACKED_PORTS  200
#define BATCH_SIZE         100

#define THREAT_NONE        0
#define THREAT_LOW         1
#define THREAT_MEDIUM      2
#define THREAT_HIGH        3
#define THREAT_CRITICAL    4

#define MODE_SEQUENTIAL    0
#define MODE_MPI_ONLY      1
#define MODE_HYBRID        2

/* =============================================================================
 * DATA STRUCTURES
 * ============================================================================= */
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
    long     timestamp;
} PacketRecord;

typedef struct {
    int    packet_id;
    int    worker_rank;
    int    thread_id;
    int    is_threat;
    int    threat_level;
    char   attack_type[64];
    char   description[256];
    double confidence;
    double analysis_time_ms;
} DetectionResult;

/* Anomaly detection baseline */
typedef struct {
    double   size_mean;
    double   size_std;
    long     sample_count;
    double   size_m2;        /* For Welford variance */
    uint16_t common_ports[12];
    int      common_port_count;
} TrafficBaseline;

static TrafficBaseline baseline = {
    .size_mean         = 512.0,
    .size_std          = 256.0,
    .sample_count      = 0,
    .size_m2           = 0.0,
    .common_ports      = {80,443,22,53,25,8080,110,143,3306,5432,21,23},
    .common_port_count = 12
};

/* Port scan tracking */
typedef struct {
    char     ip[16];
    uint16_t ports[MAX_TRACKED_PORTS];
    int      port_count;
    long     first_seen;
} PortScanState;

typedef struct {
    char ip[16];
    int  count;
    long window_start;
} RateState;

static PortScanState scan_state[MAX_TRACKED_IPS];
static int           scan_state_count = 0;
static RateState     rate_state[MAX_TRACKED_IPS];
static int           rate_state_count = 0;

/* OpenMP lock — protects shared tracking state */
static omp_lock_t state_lock;

/* =============================================================================
 * HELPERS
 * ============================================================================= */
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

PortScanState* get_scan_state(const char* ip) {
    for (int i = 0; i < scan_state_count; i++)
        if (strcmp(scan_state[i].ip, ip) == 0) return &scan_state[i];
    if (scan_state_count >= MAX_TRACKED_IPS) return NULL;
    PortScanState* s = &scan_state[scan_state_count++];
    strncpy(s->ip, ip, 15);
    s->port_count = 0;
    s->first_seen = time(NULL);
    return s;
}

RateState* get_rate_state(const char* ip) {
    for (int i = 0; i < rate_state_count; i++)
        if (strcmp(rate_state[i].ip, ip) == 0) return &rate_state[i];
    if (rate_state_count >= MAX_TRACKED_IPS) return NULL;
    RateState* s = &rate_state[rate_state_count++];
    strncpy(s->ip, ip, 15);
    s->count = 0;
    s->window_start = time(NULL);
    return s;
}

/* =============================================================================
 * ENGINE 1: SIGNATURE DETECTION
 * ============================================================================= */
int detect_signature(const PacketRecord* p, DetectionResult* r) {

    /* NULL scan — no shared state, thread-safe */
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

    /* Suspicious ports — no shared state, thread-safe */
    uint16_t bad[] = {4444,6667,6666,31337,12345,8888,9999,1080,0};
    for (int i = 0; bad[i]; i++) {
        if (p->dst_port == bad[i] || p->src_port == bad[i]) {
            r->is_threat    = 1;
            r->threat_level = THREAT_MEDIUM;
            r->confidence   = 0.75;
            strcpy(r->attack_type, "Suspicious Port");
            snprintf(r->description, 256,
                     "Malware port %d: %s to %s",
                     bad[i], p->src_ip, p->dst_ip);
            return 1;
        }
    }

    /* Port scan + brute force — needs shared state, use lock */
    omp_set_lock(&state_lock);

    if (p->protocol == 6 && p->flag_syn) {
        PortScanState* s = get_scan_state(p->src_ip);
        if (s) {
            long now = time(NULL);
            if (now - s->first_seen > 60) { s->port_count = 0; s->first_seen = now; }
            int found = 0;
            for (int i = 0; i < s->port_count; i++)
                if (s->ports[i] == p->dst_port) { found = 1; break; }
            if (!found && s->port_count < MAX_TRACKED_PORTS)
                s->ports[s->port_count++] = p->dst_port;
            if (s->port_count > 20) {
                int cnt = s->port_count;
                omp_unset_lock(&state_lock);
                r->is_threat    = 1;
                r->threat_level = THREAT_HIGH;
                r->confidence   = 0.88;
                strcpy(r->attack_type, "Port Scan");
                snprintf(r->description, 256,
                         "%s scanned %d ports on %s",
                         p->src_ip, cnt, p->dst_ip);
                return 1;
            }
        }

        if (p->dst_port == 22 || p->dst_port == 3389 ||
            p->dst_port == 21 || p->dst_port == 23) {
            RateState* rs = get_rate_state(p->src_ip);
            if (rs) {
                long now = time(NULL);
                if (now - rs->window_start > 60) { rs->count = 0; rs->window_start = now; }
                rs->count++;
                if (rs->count > 30) {
                    int cnt = rs->count;
                    omp_unset_lock(&state_lock);
                    const char* svc = p->dst_port==22?"SSH":p->dst_port==3389?"RDP":"FTP";
                    r->is_threat    = 1;
                    r->threat_level = THREAT_HIGH;
                    r->confidence   = 0.90;
                    strcpy(r->attack_type, "Brute Force");
                    snprintf(r->description, 256,
                             "%s brute forcing %s on %s (%d attempts)",
                             p->src_ip, svc, p->dst_ip, cnt);
                    return 1;
                }
            }
        }
    }

    omp_unset_lock(&state_lock);
    return 0;
}

/* =============================================================================
 * ENGINE 2: ANOMALY DETECTION (Week 6)
 *
 * Uses Z-score: how many standard deviations from the mean?
 * |z| > 2 = unusual, |z| > 3 = very unusual
 *
 * Updates baseline online using Welford's algorithm:
 *   mean  = mean + (new_val - mean) / count
 *   M2    = M2 + (new_val - old_mean) * (new_val - new_mean)
 *   std   = sqrt(M2 / count)
 * ============================================================================= */
int detect_anomaly(const PacketRecord* p, DetectionResult* r) {
    double score = 0.0;
    char   reasons[200] = "";

    /* Z-score on packet size */
    double z = fabs((double)p->packet_size - baseline.size_mean)
               / (baseline.size_std + 1.0);
    if (z > 3.0) { score += 40.0; strncat(reasons, "extreme size; ", 190); }
    else if (z > 2.0) { score += 20.0; strncat(reasons, "unusual size; ", 190); }

    /* Unknown privileged port */
    int port_ok = 0;
    for (int i = 0; i < baseline.common_port_count; i++)
        if (p->dst_port == baseline.common_ports[i]) { port_ok = 1; break; }
    if (!port_ok && p->dst_port > 0 && p->dst_port < 1024) {
        score += 15.0;
        strncat(reasons, "unknown port; ", 190);
    }

    /* Tiny TCP packet */
    if (p->protocol == 6 && p->packet_size < 40) {
        score += 20.0;
        strncat(reasons, "tiny TCP; ", 190);
    }

    /* Update baseline with Welford online algorithm */
    omp_set_lock(&state_lock);
    baseline.sample_count++;
    double old_mean = baseline.size_mean;
    baseline.size_mean += ((double)p->packet_size - old_mean) / baseline.sample_count;
    baseline.size_m2   += ((double)p->packet_size - old_mean)
                        * ((double)p->packet_size - baseline.size_mean);
    if (baseline.sample_count > 1) {
        double new_std = sqrt(baseline.size_m2 / (baseline.sample_count - 1));
        baseline.size_std = (new_std < 10.0) ? 10.0 : new_std;
    }
    omp_unset_lock(&state_lock);

    if (score >= 55.0) {
        r->is_threat    = 1;
        r->threat_level = THREAT_HIGH;
        r->confidence   = score / 100.0;
        strcpy(r->attack_type, "Statistical Anomaly");
        snprintf(r->description, 256,
                 "Anomaly from %s: %s(score=%.0f)", p->src_ip, reasons, score);
        return 1;
    } else if (score >= 30.0) {
        r->is_threat    = 1;
        r->threat_level = THREAT_MEDIUM;
        r->confidence   = score / 100.0;
        strcpy(r->attack_type, "Mild Anomaly");
        snprintf(r->description, 256,
                 "Unusual traffic from %s: %s(score=%.0f)", p->src_ip, reasons, score);
        return 1;
    }
    return 0;
}

/* =============================================================================
 * COMBINED ANALYSIS — called by each OpenMP thread
 * ============================================================================= */
DetectionResult analyze_packet(const PacketRecord* p, int rank, int tid) {
    DetectionResult r;
    memset(&r, 0, sizeof(r));
    r.packet_id    = p->packet_id;
    r.worker_rank  = rank;
    r.thread_id    = tid;
    strcpy(r.attack_type, "Normal");
    strcpy(r.description,  "No threat");

    double t0 = MPI_Wtime();

    DetectionResult sig = r, ano = r;
    int sig_hit = detect_signature(p, &sig);
    int ano_hit = detect_anomaly(p, &ano);

    if (sig_hit && sig.threat_level >= ano.threat_level) r = sig;
    else if (ano_hit) r = ano;

    r.packet_id   = p->packet_id;
    r.worker_rank = rank;
    r.thread_id   = tid;
    r.analysis_time_ms = (MPI_Wtime() - t0) * 1000.0;
    return r;
}

/* =============================================================================
 * WORKER — HYBRID VERSION
 * Receives batches from coordinator, processes with OpenMP threads
 * ============================================================================= */
void run_worker(int rank, int num_threads) {
    omp_init_lock(&state_lock);
    omp_set_num_threads(num_threads);

    PacketRecord    batch[BATCH_SIZE];
    DetectionResult results[BATCH_SIZE];
    MPI_Status      status;

    while (1) {
        MPI_Recv(batch, BATCH_SIZE * sizeof(PacketRecord),
                 MPI_BYTE, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

        if (status.MPI_TAG == 99) break;

        int bc;
        MPI_Get_count(&status, MPI_BYTE, &bc);
        bc /= sizeof(PacketRecord);

        /*
         * KEY OPENMP LINE:
         * This splits the loop across num_threads threads automatically.
         * Each thread picks up 4 packets at a time (dynamic scheduling).
         * omp_get_thread_num() tells each thread its own ID (0,1,2,3).
         */
        #pragma omp parallel for schedule(dynamic, 4)
        for (int i = 0; i < bc; i++) {
            results[i] = analyze_packet(&batch[i], rank, omp_get_thread_num());
        }

        MPI_Send(results, bc * sizeof(DetectionResult),
                 MPI_BYTE, 0, 2, MPI_COMM_WORLD);
    }

    omp_destroy_lock(&state_lock);
}

/* =============================================================================
 * PACKET GENERATOR
 * ============================================================================= */
void generate_packets(PacketRecord* packets, int count) {
    srand(42);
    const char* atk[] = {"10.0.0.5","172.16.0.10","45.33.32.156","192.168.5.1"};
    const char* vic[] = {"192.168.1.100","192.168.1.101","192.168.1.1"};

    for (int i = 0; i < count; i++) {
        PacketRecord* p = &packets[i];
        memset(p, 0, sizeof(*p));
        p->packet_id = i + 1;
        p->timestamp = time(NULL);
        int s = rand() % 10;

        if (s < 4) {
            strcpy(p->src_ip, "192.168.1.50"); strcpy(p->dst_ip, "8.8.8.8");
            p->protocol = (rand()%2)?6:17;
            p->dst_port = (uint16_t[]){80,443,53,25}[rand()%4];
            p->flag_ack = 1; p->packet_size = 200 + rand()%800;
        } else if (s < 6) {
            strcpy(p->src_ip, atk[0]); strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol = 6; p->dst_port = (i*17+7)%1024;
            p->flag_syn = 1; p->packet_size = 40;
        } else if (s < 7) {
            strcpy(p->src_ip, atk[1]); strcpy(p->dst_ip, vic[0]);
            p->protocol = 6; p->dst_port = 22;
            p->flag_syn = 1; p->packet_size = 64;
        } else if (s < 8) {
            strcpy(p->src_ip, atk[2]); strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol = 6; p->dst_port = rand()%1024;
            p->packet_size = 40; /* all flags 0 = NULL scan */
        } else if (s < 9) {
            strcpy(p->src_ip, atk[rand()%4]); strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol = 6;
            p->dst_port = (uint16_t[]){4444,6667,31337,8888}[rand()%4];
            p->flag_syn = 1; p->packet_size = 64;
        } else {
            strcpy(p->src_ip, atk[rand()%4]); strcpy(p->dst_ip, vic[rand()%3]);
            p->protocol = 6; p->dst_port = rand()%1024;
            p->packet_size = 5000 + rand()%60000; /* anomalous huge packet */
            p->flag_syn = 1;
        }
    }
}

/* =============================================================================
 * COORDINATOR
 * ============================================================================= */
double run_coordinator(int num_workers, int num_packets, int num_threads, int mode) {
    PacketRecord*    packets = malloc(num_packets * sizeof(PacketRecord));
    DetectionResult* results = malloc(num_packets * sizeof(DetectionResult));
    generate_packets(packets, num_packets);

    double start = MPI_Wtime();
    int results_count = 0;

    if (mode == MODE_SEQUENTIAL) {
        omp_init_lock(&state_lock);
        for (int i = 0; i < num_packets; i++)
            results[results_count++] = analyze_packet(&packets[i], 0, 0);
        omp_destroy_lock(&state_lock);
    } else {
        int next = 0, pending = 0;
        MPI_Status status;

        /* Send first batch to each worker */
        for (int w = 1; w <= num_workers && next < num_packets; w++) {
            int bs = (next + BATCH_SIZE <= num_packets) ? BATCH_SIZE : num_packets - next;
            MPI_Send(&packets[next], bs * sizeof(PacketRecord),
                     MPI_BYTE, w, 1, MPI_COMM_WORLD);
            next += bs; pending++;
        }

        /* Dynamic load balancing */
        while (pending > 0) {
            DetectionResult br[BATCH_SIZE];
            MPI_Recv(br, BATCH_SIZE * sizeof(DetectionResult),
                     MPI_BYTE, MPI_ANY_SOURCE, 2, MPI_COMM_WORLD, &status);
            int got; MPI_Get_count(&status, MPI_BYTE, &got);
            got /= sizeof(DetectionResult);
            for (int i = 0; i < got; i++) results[results_count++] = br[i];
            pending--;
            if (next < num_packets) {
                int bs = (next + BATCH_SIZE <= num_packets) ? BATCH_SIZE : num_packets - next;
                MPI_Send(&packets[next], bs * sizeof(PacketRecord),
                         MPI_BYTE, status.MPI_SOURCE, 1, MPI_COMM_WORLD);
                next += bs; pending++;
            }
        }

        PacketRecord term = {0};
        for (int w = 1; w <= num_workers; w++)
            MPI_Send(&term, sizeof(PacketRecord), MPI_BYTE, w, 99, MPI_COMM_WORLD);
    }

    double elapsed = MPI_Wtime() - start;

    /* Count threats for report */
    int threats = 0, high = 0, medium = 0;
    for (int i = 0; i < results_count; i++) {
        if (results[i].is_threat) {
            threats++;
            if (results[i].threat_level >= THREAT_HIGH) high++;
            else medium++;
        }
    }

    printf("  Time: %7.4f sec | Throughput: %8.0f pkt/s | Threats: %d (H=%d M=%d)\n",
           elapsed, num_packets / elapsed, threats, high, medium);

    free(packets); free(results);
    return elapsed;
}

/* =============================================================================
 * MAIN
 * ============================================================================= */
int main(int argc, char* argv[]) {
    int provided;
    MPI_Init_thread(&argc, &argv, MPI_THREAD_FUNNELED, &provided);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    int num_packets = 2000;
    int num_threads = omp_get_max_threads();
    int mode        = MODE_HYBRID;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i+1 < argc) num_packets = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i+1 < argc) num_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sequential")) mode = MODE_SEQUENTIAL;
        else if (!strcmp(argv[i], "--no-omp")) { mode = MODE_MPI_ONLY; num_threads = 1; }
    }

    int num_workers = (mode == MODE_SEQUENTIAL) ? 0 : size - 1;

    if (rank == 0) {
        printf("\n╔══════════════════════════════════════════════════╗\n");
        printf(  "║   D-IDS HYBRID MPI+OpenMP — Weeks 5-6           ║\n");
        printf(  "╠══════════════════════════════════════════════════╣\n");
        printf(  "║  Mode: %-41s║\n",
               mode==MODE_SEQUENTIAL ? "Sequential (no parallelism)" :
               mode==MODE_MPI_ONLY   ? "Pure MPI (no OpenMP)" :
                                       "Hybrid MPI + OpenMP");
        printf(  "║  MPI workers:     %-30d║\n", num_workers);
        printf(  "║  OpenMP threads:  %-30d║\n", num_threads);
        printf(  "║  Packets:         %-30d║\n", num_packets);
        printf(  "╚══════════════════════════════════════════════════╝\n\n");

        if (mode == MODE_SEQUENTIAL) {
            /* Tell workers to terminate immediately */
            PacketRecord term = {0};
            for (int w = 1; w < size; w++)
                MPI_Send(&term, sizeof(PacketRecord), MPI_BYTE, w, 99, MPI_COMM_WORLD);
        }

        double elapsed = run_coordinator(num_workers, num_packets, num_threads, mode);
        printf("\n  >> Copy to your speedup table: %.4f seconds\n\n", elapsed);

    } else {
        /* Worker process */
        MPI_Status status;
        PacketRecord dummy;
        if (mode == MODE_SEQUENTIAL) {
            MPI_Recv(&dummy, sizeof(PacketRecord), MPI_BYTE, 0, 99, MPI_COMM_WORLD, &status);
        } else {
            run_worker(rank, num_threads);
        }
    }

    MPI_Finalize();
    return 0;
}
