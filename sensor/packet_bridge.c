/*
 * =============================================================================
 * WEEK 9 — PACKET BRIDGE
 * File: sensor/packet_bridge.c
 * =============================================================================
 *
 * WHAT THIS DOES:
 *   Reads the CSV file written by packet_capture_csv.c and either:
 *   1. Displays it nicely on screen  (--read mode)
 *   2. Streams it to coordinator     (--serve mode)
 *
 * COMPILE:
 *   gcc -O2 -o build/packet_bridge sensor/packet_bridge.c
 *   (no -lpcap needed — we only read CSV, not raw packets)
 *
 * RUN:
 *   ./build/packet_bridge --read data/logs/packets.csv
 *   ./build/packet_bridge --serve data/logs/packets.csv
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
    long     timestamp;
    char     src_ip[16];
    char     dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint32_t packet_size;
    int      flag_syn, flag_ack, flag_fin, flag_rst, flag_psh;
} Packet;

/* ── Read one CSV row ── */
int read_csv_row(FILE* f, Packet* p) {
    char src[16], dst[16];
    int  sp, dp, proto, size, syn, ack, fin, rst, psh;
    long ts;
    if (fscanf(f,
        "%ld,%15[^,],%d,%15[^,],%d,%d,%d,%d,%d,%d,%d,%d\n",
        &ts, src, &sp, dst, &dp,
        &proto, &size, &syn, &ack, &fin, &rst, &psh) != 12) return 0;
    p->timestamp=ts; p->src_port=(uint16_t)sp; p->dst_port=(uint16_t)dp;
    p->protocol=(uint8_t)proto; p->packet_size=(uint32_t)size;
    p->flag_syn=syn; p->flag_ack=ack; p->flag_fin=fin;
    p->flag_rst=rst; p->flag_psh=psh;
    strncpy(p->src_ip,src,15); strncpy(p->dst_ip,dst,15);
    return 1;
}

/* ── Quick threat check ── */
const char* quick_detect(const Packet* p) {
    if (p->protocol==6 && !p->flag_syn && !p->flag_ack &&
        !p->flag_fin && !p->flag_rst && !p->flag_psh)
        return "\033[0;33m⚠  NULL SCAN\033[0m";
    uint16_t bad[]={4444,6667,31337,12345,8888,9999,1080,0};
    for (int i=0;bad[i];i++)
        if (p->dst_port==bad[i]||p->src_port==bad[i])
            return "\033[0;33m⚠  SUSPICIOUS PORT\033[0m";
    if (p->packet_size>5000) return "\033[0;33m⚠  HUGE PACKET\033[0m";
    if (p->dst_port==22&&p->flag_syn) return "\033[0;34mℹ  SSH attempt\033[0m";
    return NULL;
}

/* ============================================================
 * MODE 1: READ — show CSV on screen
 * ============================================================ */
void run_read_mode(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr,"\nERROR: Cannot open %s\n"
                       "  Did you run: sudo ./build/packet_capture_csv"
                       " -i lo -n 50 -o %s ?\n\n", path, path);
        return;
    }
    char header[256];
    if (!fgets(header, sizeof(header), f)) { fclose(f); return; }

    printf("\n╔══════════════════════════════════════════════╗\n");
    printf(  "║   PACKET BRIDGE — Showing CSV Contents       ║\n");
    printf(  "║   File: %-36s║\n", path);
    printf(  "╚══════════════════════════════════════════════╝\n\n");
    printf(" %-4s %-8s %-5s %-15s:%-5s %-15s:%-5s %-6s %s\n",
           "NUM","TIME","PROTO","SRC-IP","PORT","DST-IP","PORT","SIZE","ALERT");
    printf(" %.80s\n",
           "--------------------------------------------------------------------------------");

    Packet p; long n=0, threats=0;
    while (read_csv_row(f, &p)) {
        n++;
        time_t ts=(time_t)p.timestamp;
        char ts_str[10];
        struct tm* tm_i=localtime(&ts);
        strftime(ts_str, sizeof(ts_str), "%H:%M:%S", tm_i);

        const char* proto = p.protocol==6?"TCP":p.protocol==17?"UDP":
                            p.protocol==1?"ICMP":"OTHER";
        const char* alert = quick_detect(&p);
        if (alert) threats++;

        printf(" [%4ld] %s %-5s %-15s:%-5d %-15s:%-5d %5dB  %s\n",
               n, ts_str, proto,
               p.src_ip, p.src_port,
               p.dst_ip, p.dst_port,
               p.packet_size, alert ? alert : "");
    }
    fclose(f);

    printf("\n╔══════════════════════════════════════════════╗\n");
    printf(  "║  READ COMPLETE                               ║\n");
    printf(  "╠══════════════════════════════════════════════╣\n");
    printf(  "║  Packets read:  %-28ld║\n", n);
    printf(  "║  Threats found: %-28ld║\n", threats);
    printf(  "╠══════════════════════════════════════════════╣\n");
    printf(  "║  Now send to coordinator:                    ║\n");
    printf(  "║                                              ║\n");
    printf(  "║  OMP_NUM_THREADS=4 mpirun \\                 ║\n");
    printf(  "║    --oversubscribe -np 4 \\                  ║\n");
    printf(  "║    ./build/coordinator_real \\               ║\n");
    printf(  "║    --file data/logs/packets.csv             ║\n");
    printf(  "╚══════════════════════════════════════════════╝\n\n");
}

/* ============================================================
 * MODE 2: SERVE — stream CSV over TCP socket to coordinator
 * ============================================================ */
static int server_sock = -1;
static int client_sock = -1;

void serve_cleanup(int sig) {
    (void)sig;
    printf("\n  Server stopped.\n\n");
    if (client_sock>=0) close(client_sock);
    if (server_sock>=0) close(server_sock);
    exit(0);
}

void run_serve_mode(const char* path, int port) {
    signal(SIGINT, serve_cleanup);
    signal(SIGTERM, serve_cleanup);

    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", path); return;
    }
    char header[256];
    if (!fgets(header, sizeof(header), f)) { fclose(f); return; }

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt=1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port=htons(port);
    if (bind(server_sock,(struct sockaddr*)&addr,sizeof(addr))<0) {
        perror("bind"); fclose(f); return;
    }
    listen(server_sock, 1);

    printf("\n╔══════════════════════════════════════════════╗\n");
    printf(  "║   PACKET BRIDGE — Serve Mode                 ║\n");
    printf(  "╠══════════════════════════════════════════════╣\n");
    printf(  "║  Streaming: %-32s║\n", path);
    printf(  "║  Port:      %-32d║\n", port);
    printf(  "╠══════════════════════════════════════════════╣\n");
    printf(  "║  Waiting for coordinator to connect...       ║\n");
    printf(  "║                                              ║\n");
    printf(  "║  Run in terminal 2:                          ║\n");
    printf(  "║  OMP_NUM_THREADS=4 mpirun --oversubscribe   ║\n");
    printf(  "║    -np 4 ./build/coordinator_real           ║\n");
    printf(  "║    --socket localhost:%-23d║\n", port);
    printf(  "╚══════════════════════════════════════════════╝\n\n");

    struct sockaddr_in ca; socklen_t cal=sizeof(ca);
    client_sock = accept(server_sock,(struct sockaddr*)&ca,&cal);
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&ca.sin_addr,cip,INET_ADDRSTRLEN);
    printf("  Coordinator connected (%s) — streaming...\n\n", cip);

    Packet p; long sent=0;
    while (read_csv_row(f, &p)) {
        char json[512];
        snprintf(json, sizeof(json),
            "{\"ts\":%ld,\"src\":\"%s\",\"sp\":%d,"
            "\"dst\":\"%s\",\"dp\":%d,\"proto\":%d,"
            "\"size\":%d,\"syn\":%d,\"ack\":%d,"
            "\"fin\":%d,\"rst\":%d,\"psh\":%d}\n",
            p.timestamp, p.src_ip, p.src_port,
            p.dst_ip, p.dst_port, p.protocol, p.packet_size,
            p.flag_syn, p.flag_ack, p.flag_fin,
            p.flag_rst, p.flag_psh);
        if (send(client_sock,json,strlen(json),MSG_NOSIGNAL)<0) break;
        sent++;
        usleep(500);
    }
    fclose(f);
    printf("  Done. Sent %ld packets.\n\n", sent);
    close(client_sock); close(server_sock);
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("\nUsage:\n");
        printf("  %s --read  <file.csv>           show CSV contents\n", argv[0]);
        printf("  %s --serve <file.csv> [-p 9999] stream to coordinator\n\n", argv[0]);
        return 0;
    }
    char* mode=argv[1]; char* path=argv[2]; int port=9999;
    for (int i=3;i<argc;i++)
        if (!strcmp(argv[i],"-p")&&i+1<argc) port=atoi(argv[++i]);

    if (!strcmp(mode,"--read"))  run_read_mode(path);
    else if (!strcmp(mode,"--serve")) run_serve_mode(path,port);
    else { fprintf(stderr,"Unknown mode: %s\n",mode); return 1; }
    return 0;
}
