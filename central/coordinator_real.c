/*
 * =============================================================================
 * WEEK 9 — COORDINATOR WITH REAL INPUT SUPPORT
 * File: central/coordinator_real.c
 * =============================================================================
 *
 * This extends the Week 4 coordinator to accept REAL packets from:
 *   --file <path>            read from CSV written by packet_bridge
 *   --socket <host:port>     connect to live packet_bridge socket stream
 *   (no flag)                fall back to generated test packets
 *
 * COMPILE:
 *   mpicc -O2 -fopenmp -o build/coordinator central/coordinator_real.c -lm
 *
 * RUN EXAMPLES:
 *   File mode:   mpirun -np 4 ./build/coordinator --file data/logs/packets.csv
 *   Socket mode: mpirun -np 4 ./build/coordinator --socket localhost:9999
 *   Test mode:   mpirun -np 4 ./build/coordinator -n 500
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <mpi.h>
#include <omp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */
#define MAX_PACKETS      50000
#define BATCH_SIZE       100
#define MAX_TRACKED_IPS  500
#define MAX_PORTS        200
#define THREAT_NONE      0
#define THREAT_LOW       1
#define THREAT_MEDIUM    2
#define THREAT_HIGH      3
#define THREAT_CRITICAL  4

/* Input modes */
#define INPUT_GENERATED  0
#define INPUT_FILE       1
#define INPUT_SOCKET     2

/* ============================================================
 * DATA STRUCTURES (same as hybrid_coordinator.c)
 * ============================================================ */
typedef struct {
    int      packet_id;
    int      protocol;
    char     src_ip[16];
    char     dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t packet_size;
    int      flag_syn, flag_ack, flag_fin, flag_rst, flag_psh;
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

/* Tracking state */
typedef struct { char ip[16]; uint16_t ports[MAX_PORTS]; int cnt; long first; } ScanState;
typedef struct { char ip[16]; int cnt; long start; } RateState;
static ScanState scan_st[MAX_TRACKED_IPS]; static int scan_cnt = 0;
static RateState rate_st[MAX_TRACKED_IPS]; static int rate_cnt = 0;
static omp_lock_t state_lock;

/* Anomaly baseline */
static double base_mean = 512.0, base_std = 256.0, base_m2 = 0.0;
static long   base_n    = 0;

/* ============================================================
 * HELPERS
 * ============================================================ */
const char* threat_name(int l) {
    return l==THREAT_CRITICAL?"CRITICAL":l==THREAT_HIGH?"HIGH":
           l==THREAT_MEDIUM?"MEDIUM":l==THREAT_LOW?"LOW":"NONE";
}

ScanState* get_scan(const char* ip) {
    for (int i=0;i<scan_cnt;i++) if(!strcmp(scan_st[i].ip,ip)) return &scan_st[i];
    if (scan_cnt>=MAX_TRACKED_IPS) return NULL;
    ScanState* s=&scan_st[scan_cnt++]; strncpy(s->ip,ip,15);
    s->cnt=0; s->first=time(NULL); return s;
}
RateState* get_rate(const char* ip) {
    for (int i=0;i<rate_cnt;i++) if(!strcmp(rate_st[i].ip,ip)) return &rate_st[i];
    if (rate_cnt>=MAX_TRACKED_IPS) return NULL;
    RateState* s=&rate_st[rate_cnt++]; strncpy(s->ip,ip,15);
    s->cnt=0; s->start=time(NULL); return s;
}

/* ============================================================
 * CSV READER — load real packets from file
 * ============================================================ */
int load_packets_from_csv(const char* path, PacketRecord* packets,
                           int max_count) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open CSV: %s\n", path);
        return 0;
    }

    /* Skip header */
    char header[256];
    if (!fgets(header, sizeof(header), f)) { fclose(f); return 0; }

    int count = 0;
    long ts; char src[16],dst[16];
    int sp,dp,proto,size,syn,ack,fin,rst,psh;

    while (count < max_count &&
           fscanf(f, "%ld,%15[^,],%d,%15[^,],%d,%d,%d,%d,%d,%d,%d,%d\n",
                  &ts,src,&sp,dst,&dp,&proto,&size,
                  &syn,&ack,&fin,&rst,&psh) == 12) {
        PacketRecord* p = &packets[count];
        p->packet_id   = count + 1;
        p->timestamp   = ts;
        p->protocol    = proto;
        p->packet_size = size;
        p->src_port    = (uint16_t)sp;
        p->dst_port    = (uint16_t)dp;
        p->flag_syn    = syn; p->flag_ack = ack;
        p->flag_fin    = fin; p->flag_rst = rst;
        p->flag_psh    = psh;
        strncpy(p->src_ip, src, 15);
        strncpy(p->dst_ip, dst, 15);
        count++;
    }

    fclose(f);
    return count;
}

/* ============================================================
 * SOCKET READER — receive packets from live bridge
 * ============================================================ */
int connect_to_bridge(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Cannot connect to packet bridge");
        close(sock);
        return -1;
    }
    return sock;
}

int recv_packet_from_socket(int sock, PacketRecord* p) {
    /* Read one JSON line */
    char buf[512]; int pos = 0; char c;
    while (pos < 511) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) return 0;
        if (c == '\n') break;
        buf[pos++] = c;
    }
    buf[pos] = '\0';

    /* Parse JSON into PacketRecord */
    long ts; char src[16],dst[16];
    int sp,dp,proto,size,syn,ack,fin,rst,psh;
    if (sscanf(buf,
        "{\"ts\":%ld,\"src\":\"%15[^\"]\",\"sp\":%d,"
        "\"dst\":\"%15[^\"]\",\"dp\":%d,\"proto\":%d,"
        "\"size\":%d,\"syn\":%d,\"ack\":%d,"
        "\"fin\":%d,\"rst\":%d,\"psh\":%d}",
        &ts,src,&sp,dst,&dp,&proto,&size,
        &syn,&ack,&fin,&rst,&psh) != 12) return 0;

    p->timestamp   = ts;
    p->protocol    = proto;
    p->packet_size = size;
    p->src_port    = (uint16_t)sp;
    p->dst_port    = (uint16_t)dp;
    p->flag_syn=syn; p->flag_ack=ack;
    p->flag_fin=fin; p->flag_rst=rst; p->flag_psh=psh;
    strncpy(p->src_ip, src, 15);
    strncpy(p->dst_ip, dst, 15);
    return 1;
}

/* ============================================================
 * DETECTION ENGINE (same as hybrid_coordinator.c)
 * ============================================================ */
int detect_signature(const PacketRecord* p, DetectionResult* r) {
    /* NULL scan */
    if (p->protocol==6 && !p->flag_syn && !p->flag_ack &&
        !p->flag_fin && !p->flag_rst && !p->flag_psh) {
        r->is_threat=1; r->threat_level=THREAT_MEDIUM; r->confidence=0.85;
        strcpy(r->attack_type,"NULL Scan");
        snprintf(r->description,256,"TCP NULL scan %s→%s:%d",
                 p->src_ip,p->dst_ip,p->dst_port);
        return 1;
    }
    /* Suspicious ports */
    uint16_t bad[]={4444,6667,6666,31337,12345,8888,9999,1080,0};
    for (int i=0;bad[i];i++) {
        if (p->dst_port==bad[i]||p->src_port==bad[i]) {
            r->is_threat=1; r->threat_level=THREAT_MEDIUM; r->confidence=0.75;
            strcpy(r->attack_type,"Suspicious Port");
            snprintf(r->description,256,"Malware port %d: %s→%s",
                     bad[i],p->src_ip,p->dst_ip);
            return 1;
        }
    }
    /* Port scan + brute force need lock */
    omp_set_lock(&state_lock);
    if (p->protocol==6 && p->flag_syn) {
        ScanState* s=get_scan(p->src_ip);
        if (s) {
            long now=time(NULL);
            if (now-s->first>60){s->cnt=0;s->first=now;}
            int found=0;
            for (int i=0;i<s->cnt;i++) if(s->ports[i]==p->dst_port){found=1;break;}
            if (!found&&s->cnt<MAX_PORTS) s->ports[s->cnt++]=p->dst_port;
            if (s->cnt>20) {
                int c=s->cnt; omp_unset_lock(&state_lock);
                r->is_threat=1; r->threat_level=THREAT_HIGH; r->confidence=0.88;
                strcpy(r->attack_type,"Port Scan");
                snprintf(r->description,256,"%s scanned %d ports on %s",
                         p->src_ip,c,p->dst_ip);
                return 1;
            }
        }
        if (p->dst_port==22||p->dst_port==3389||p->dst_port==21||p->dst_port==23) {
            RateState* rs=get_rate(p->src_ip);
            if (rs) {
                long now=time(NULL);
                if (now-rs->start>60){rs->cnt=0;rs->start=now;}
                rs->cnt++;
                if (rs->cnt>30) {
                    int c=rs->cnt; omp_unset_lock(&state_lock);
                    const char* svc=p->dst_port==22?"SSH":p->dst_port==3389?"RDP":"FTP";
                    r->is_threat=1; r->threat_level=THREAT_HIGH; r->confidence=0.90;
                    strcpy(r->attack_type,"Brute Force");
                    snprintf(r->description,256,"%s brute forcing %s on %s (%d attempts)",
                             p->src_ip,svc,p->dst_ip,c);
                    return 1;
                }
            }
        }
    }
    omp_unset_lock(&state_lock);
    return 0;
}

int detect_anomaly(const PacketRecord* p, DetectionResult* r) {
    double score=0.0; char reasons[200]="";
    double z=fabs((double)p->packet_size-base_mean)/(base_std+1.0);
    if (z>3.0){score+=40.0;strncat(reasons,"extreme size; ",190);}
    else if (z>2.0){score+=20.0;strncat(reasons,"unusual size; ",190);}
    if (p->protocol==6&&p->packet_size<40){score+=20.0;strncat(reasons,"tiny TCP; ",190);}

    omp_set_lock(&state_lock);
    base_n++;
    double old=base_mean;
    base_mean+=(p->packet_size-old)/base_n;
    base_m2+=(p->packet_size-old)*(p->packet_size-base_mean);
    if (base_n>1){double s=sqrt(base_m2/(base_n-1));base_std=s<10.0?10.0:s;}
    omp_unset_lock(&state_lock);

    if (score>=55.0){
        r->is_threat=1;r->threat_level=THREAT_HIGH;r->confidence=score/100.0;
        strcpy(r->attack_type,"Statistical Anomaly");
        snprintf(r->description,256,"Anomaly from %s: %s(%.0f)",p->src_ip,reasons,score);
        return 1;
    } else if (score>=30.0){
        r->is_threat=1;r->threat_level=THREAT_MEDIUM;r->confidence=score/100.0;
        strcpy(r->attack_type,"Mild Anomaly");
        snprintf(r->description,256,"Unusual from %s: %s(%.0f)",p->src_ip,reasons,score);
        return 1;
    }
    return 0;
}

DetectionResult analyze_packet(const PacketRecord* p, int rank, int tid) {
    DetectionResult r; memset(&r,0,sizeof(r));
    r.packet_id=p->packet_id; r.worker_rank=rank; r.thread_id=tid;
    strcpy(r.attack_type,"Normal"); strcpy(r.description,"No threat");
    double t0=MPI_Wtime();
    DetectionResult sig=r,ano=r;
    int sh=detect_signature(p,&sig),ah=detect_anomaly(p,&ano);
    if (sh&&sig.threat_level>=ano.threat_level) r=sig;
    else if (ah) r=ano;
    r.packet_id=p->packet_id; r.worker_rank=rank; r.thread_id=tid;
    r.analysis_time_ms=(MPI_Wtime()-t0)*1000.0;
    return r;
}

/* ============================================================
 * WORKER
 * ============================================================ */
void run_worker(int rank, int threads) {
    omp_init_lock(&state_lock);
    omp_set_num_threads(threads);
    PacketRecord batch[BATCH_SIZE];
    DetectionResult results[BATCH_SIZE];
    MPI_Status status;
    while (1) {
        MPI_Recv(batch,BATCH_SIZE*sizeof(PacketRecord),MPI_BYTE,
                 0,MPI_ANY_TAG,MPI_COMM_WORLD,&status);
        if (status.MPI_TAG==99) break;
        int bc; MPI_Get_count(&status,MPI_BYTE,&bc);
        bc/=sizeof(PacketRecord);
        #pragma omp parallel for schedule(dynamic,4)
        for (int i=0;i<bc;i++)
            results[i]=analyze_packet(&batch[i],rank,omp_get_thread_num());
        MPI_Send(results,bc*sizeof(DetectionResult),MPI_BYTE,0,2,MPI_COMM_WORLD);
    }
    omp_destroy_lock(&state_lock);
}

/* ============================================================
 * GENERATE TEST PACKETS (fallback)
 * ============================================================ */
void generate_packets(PacketRecord* pkts, int n) {
    srand(42);
    const char* atk[]={"10.0.0.5","172.16.0.10","45.33.32.156","192.168.5.1"};
    const char* vic[]={"192.168.1.100","192.168.1.101","192.168.1.1"};
    for (int i=0;i<n;i++) {
        PacketRecord* p=&pkts[i]; memset(p,0,sizeof(*p));
        p->packet_id=i+1; p->timestamp=time(NULL);
        int s=rand()%10;
        if (s<4){strcpy(p->src_ip,"192.168.1.50");strcpy(p->dst_ip,"8.8.8.8");
            p->protocol=(rand()%2)?6:17;
            p->dst_port=(uint16_t[]){80,443,53,25}[rand()%4];
            p->flag_ack=1;p->packet_size=200+rand()%800;}
        else if (s<6){strcpy(p->src_ip,atk[0]);strcpy(p->dst_ip,vic[rand()%3]);
            p->protocol=6;p->dst_port=(i*17+7)%1024;p->flag_syn=1;p->packet_size=40;}
        else if (s<7){strcpy(p->src_ip,atk[1]);strcpy(p->dst_ip,vic[0]);
            p->protocol=6;p->dst_port=22;p->flag_syn=1;p->packet_size=64;}
        else if (s<8){strcpy(p->src_ip,atk[2]);strcpy(p->dst_ip,vic[rand()%3]);
            p->protocol=6;p->dst_port=rand()%1024;p->packet_size=40;}
        else if (s<9){strcpy(p->src_ip,atk[rand()%4]);strcpy(p->dst_ip,vic[rand()%3]);
            p->protocol=6;
            p->dst_port=(uint16_t[]){4444,6667,31337,8888}[rand()%4];
            p->flag_syn=1;p->packet_size=64;}
        else{strcpy(p->src_ip,atk[rand()%4]);strcpy(p->dst_ip,vic[rand()%3]);
            p->protocol=6;p->packet_size=5000+rand()%60000;p->flag_syn=1;}
    }
}

/* ============================================================
 * COORDINATOR — sends batches, collects results, prints report
 * ============================================================ */
void run_coordinator(int workers, PacketRecord* packets, int total,
                     int threads) {
    DetectionResult* results = malloc(total * sizeof(DetectionResult));
    int results_n = 0, next = 0, pending = 0;
    MPI_Status status;

    double t0 = MPI_Wtime();

    /* Seed workers */
    for (int w=1;w<=workers&&next<total;w++) {
        int bs=(next+BATCH_SIZE<=total)?BATCH_SIZE:total-next;
        MPI_Send(&packets[next],bs*sizeof(PacketRecord),MPI_BYTE,w,1,MPI_COMM_WORLD);
        next+=bs; pending++;
    }

    /* Dynamic distribution */
    while (pending>0) {
        DetectionResult br[BATCH_SIZE];
        MPI_Recv(br,BATCH_SIZE*sizeof(DetectionResult),MPI_BYTE,
                 MPI_ANY_SOURCE,2,MPI_COMM_WORLD,&status);
        int got; MPI_Get_count(&status,MPI_BYTE,&got);
        got/=sizeof(DetectionResult);
        for (int i=0;i<got;i++) results[results_n++]=br[i];
        pending--;
        if (next<total) {
            int bs=(next+BATCH_SIZE<=total)?BATCH_SIZE:total-next;
            MPI_Send(&packets[next],bs*sizeof(PacketRecord),MPI_BYTE,
                     status.MPI_SOURCE,1,MPI_COMM_WORLD);
            next+=bs; pending++;
        }
    }

    /* Terminate workers */
    PacketRecord term={0};
    for (int w=1;w<=workers;w++)
        MPI_Send(&term,sizeof(PacketRecord),MPI_BYTE,w,99,MPI_COMM_WORLD);

    double elapsed = MPI_Wtime() - t0;

    /* Count threats */
    int threats=0,critical=0,high=0,medium=0,low=0;
    for (int i=0;i<results_n;i++) {
        if (!results[i].is_threat) continue;
        threats++;
        if      (results[i].threat_level==THREAT_CRITICAL) critical++;
        else if (results[i].threat_level==THREAT_HIGH)     high++;
        else if (results[i].threat_level==THREAT_MEDIUM)   medium++;
        else                                                low++;
    }

    /* Print results */
    printf("\n");
    if (threats > 0) {
        printf("  %-40s %-10s %s\n","ATTACK TYPE","LEVEL","SOURCE IP");
        printf("  %.60s\n","------------------------------------------------------------");
        for (int i=0;i<results_n;i++) {
            DetectionResult* r=&results[i];
            if (!r->is_threat) continue;
            const char* col =
                r->threat_level==THREAT_CRITICAL ? "\033[1;31m" :
                r->threat_level==THREAT_HIGH     ? "\033[0;31m" :
                r->threat_level==THREAT_MEDIUM   ? "\033[0;33m" :
                                                   "\033[0;34m";
            printf("  %s%-40s %-10s %s\033[0m\n",
                   col, r->attack_type,
                   threat_name(r->threat_level),
                   r->worker_rank>0?"(detected)":"");
        }
    } else {
        printf("  No threats detected in this packet set.\n");
    }

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf(  "║  ANALYSIS RESULTS                                ║\n");
    printf(  "╠══════════════════════════════════════════════════╣\n");
    printf(  "║  Packets analyzed:   %-27d║\n", total);
    printf(  "║  Threats detected:   %-27d║\n", threats);
    printf(  "║  ├── Critical:       %-27d║\n", critical);
    printf(  "║  ├── High:           %-27d║\n", high);
    printf(  "║  ├── Medium:         %-27d║\n", medium);
    printf(  "║  └── Low:            %-27d║\n", low);
    printf(  "╠══════════════════════════════════════════════════╣\n");
    printf(  "║  Workers:            %-27d║\n", workers);
    printf(  "║  Threads/worker:     %-27d║\n", threads);
    printf(  "║  Time:               %-24.4f sec║\n", elapsed);
    printf(  "║  Throughput:         %-23.0f pkt/s║\n", total/elapsed);
    printf(  "║  Detection rate:     %-23.1f%%  ║\n",
             (double)threats/total*100);
    printf(  "╚══════════════════════════════════════════════════╝\n\n");

    free(results);
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char* argv[]) {
    int provided;
    MPI_Init_thread(&argc,&argv,MPI_THREAD_FUNNELED,&provided);
    int rank,size;
    MPI_Comm_rank(MPI_COMM_WORLD,&rank);
    MPI_Comm_size(MPI_COMM_WORLD,&size);

    /* Parse args */
    int   input_mode  = INPUT_GENERATED;
    int   num_packets = 500;
    int   num_threads = omp_get_max_threads();
    char  csv_path[256] = "";
    char  sock_host[64] = "localhost";
    int   sock_port = 9999;

    for (int i=1;i<argc;i++) {
        if      (!strcmp(argv[i],"--file")   && i+1<argc) {
            input_mode=INPUT_FILE; strncpy(csv_path,argv[++i],255);
        } else if (!strcmp(argv[i],"--socket") && i+1<argc) {
            input_mode=INPUT_SOCKET;
            char* col=strchr(argv[++i],':');
            if (col) { *col='\0'; strncpy(sock_host,argv[i],63); sock_port=atoi(col+1); }
            else strncpy(sock_host,argv[i],63);
        } else if (!strcmp(argv[i],"-n") && i+1<argc) num_packets=atoi(argv[++i]);
        else if (!strcmp(argv[i],"-t") && i+1<argc) num_threads=atoi(argv[++i]);
    }

    int workers = size - 1;
    if (workers < 1) {
        if (rank==0) fprintf(stderr,"Need at least 2 processes: mpirun -np 4 ...\n");
        MPI_Finalize(); return 1;
    }

    if (rank == 0) {
        printf("\n╔══════════════════════════════════════════════════╗\n");
        printf(  "║   D-IDS COORDINATOR WITH REAL INPUT — Week 9    ║\n");
        printf(  "╠══════════════════════════════════════════════════╣\n");
        printf(  "║  Input:   %-38s║\n",
               input_mode==INPUT_FILE   ? csv_path :
               input_mode==INPUT_SOCKET ? "live socket stream" :
                                          "generated test packets");
        printf(  "║  Workers: %-38d║\n", workers);
        printf(  "║  Threads: %-38d║\n", num_threads);
        printf(  "╚══════════════════════════════════════════════════╝\n\n");

        /* Load packets based on mode */
        PacketRecord* packets = malloc(MAX_PACKETS * sizeof(PacketRecord));
        int total = 0;

        if (input_mode == INPUT_FILE) {
            printf("  Loading packets from %s...\n", csv_path);
            total = load_packets_from_csv(csv_path, packets, MAX_PACKETS);
            if (total == 0) {
                fprintf(stderr,"  No packets loaded. Check file path.\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            printf("  Loaded %d real packets.\n\n", total);

        } else if (input_mode == INPUT_SOCKET) {
            printf("  Connecting to packet bridge at %s:%d...\n",
                   sock_host, sock_port);
            int sock = connect_to_bridge(sock_host, sock_port);
            if (sock < 0) { MPI_Abort(MPI_COMM_WORLD, 1); }
            printf("  Connected! Receiving packets...\n\n");

            PacketRecord p;
            while (total < MAX_PACKETS && recv_packet_from_socket(sock, &p)) {
                p.packet_id = total + 1;
                packets[total++] = p;
                if (total % 100 == 0)
                    printf("  Received %d packets...\r", total);
            }
            close(sock);
            printf("\n  Received %d live packets.\n\n", total);

        } else {
            printf("  Generating %d test packets...\n\n", num_packets);
            generate_packets(packets, num_packets);
            total = num_packets;
        }

        run_coordinator(workers, packets, total, num_threads);
        free(packets);

    } else {
        run_worker(rank, num_threads);
    }

    MPI_Finalize();
    return 0;
}
