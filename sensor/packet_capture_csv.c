/*
 * =============================================================================
 * WEEK 9 — UPGRADED PACKET CAPTURE WITH CSV OUTPUT
 * File: sensor/packet_capture_csv.c
 * =============================================================================
 *
 * THIS IS YOUR WEEK 2 packet_capture.c WITH ONE NEW FEATURE:
 * It now saves every captured packet to a CSV file.
 *
 * That CSV file is what Week 9 is all about — it becomes the
 * bridge between your capture sensor and your MPI coordinator.
 *
 * WHAT CHANGED FROM WEEK 2:
 *   + Added --csv flag to save packets to a file
 *   + CSV format: timestamp,src_ip,src_port,dst_ip,dst_port,
 *                 protocol,size,syn,ack,fin,rst,psh
 *   Everything else is identical to your working Week 2 code.
 *
 * COMPILE:
 *   gcc -O2 -o build/packet_capture_csv sensor/packet_capture_csv.c -lpcap -lm
 *
 * RUN (capture 50 packets and save to CSV):
 *   sudo ./build/packet_capture_csv -i lo -n 50 -o data/logs/packets.csv
 *
 * THEN READ IT BACK (no sudo needed):
 *   ./build/packet_bridge --read data/logs/packets.csv
 *
 * THEN ANALYZE WITH MPI:
 *   mpirun --oversubscribe -np 4 ./build/coordinator_real \
 *          --file data/logs/packets.csv
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */
#define SNAP_LEN     65535
#define PROMISC      1
#define TIMEOUT_MS   1000
#define LOG_FILE     "data/logs/screen.log"

/* ============================================================
 * PACKET INFO STRUCT
 * ============================================================ */
typedef struct {
    long     timestamp;
    char     src_ip[16];
    char     dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;      /* 6=TCP 17=UDP 1=ICMP */
    uint32_t packet_size;
    int      flag_syn;
    int      flag_ack;
    int      flag_fin;
    int      flag_rst;
    int      flag_psh;
} PacketInfo;

/* ============================================================
 * STATS
 * ============================================================ */
typedef struct {
    uint64_t total;
    uint64_t tcp;
    uint64_t udp;
    uint64_t icmp;
    uint64_t other;
    uint64_t bytes;
    time_t   start;
} Stats;

/* ============================================================
 * GLOBALS
 * ============================================================ */
static pcap_t* handle     = NULL;
static FILE*   csv_file   = NULL;
static FILE*   log_file   = NULL;
static Stats   stats      = {0};
static int     max_count  = -1;

/* ============================================================
 * CSV HELPERS
 *
 * WHY CSV?
 *   CSV (Comma Separated Values) is the simplest way to store
 *   structured data. Every packet becomes one line.
 *   Your coordinator can read this file and analyze the packets
 *   without needing to recapture anything.
 *
 *   Format:
 *   timestamp,src_ip,src_port,dst_ip,dst_port,protocol,size,syn,ack,fin,rst,psh
 *   1715200000,192.168.1.1,54321,8.8.8.8,53,17,75,0,0,0,0,0
 * ============================================================ */
void write_csv_header(FILE* f) {
    fprintf(f, "timestamp,src_ip,src_port,dst_ip,dst_port,"
               "protocol,size,syn,ack,fin,rst,psh\n");
    fflush(f);
}

void write_csv_row(FILE* f, const PacketInfo* p) {
    fprintf(f, "%ld,%s,%d,%s,%d,%d,%d,%d,%d,%d,%d,%d\n",
            p->timestamp,
            p->src_ip,  p->src_port,
            p->dst_ip,  p->dst_port,
            p->protocol, p->packet_size,
            p->flag_syn, p->flag_ack,
            p->flag_fin, p->flag_rst, p->flag_psh);
    fflush(f);  /* write immediately — don't buffer */
}

/* ============================================================
 * PACKET HANDLER — called by libpcap for every captured packet
 * ============================================================ */
void packet_handler(u_char* user, const struct pcap_pkthdr* hdr,
                    const u_char* raw) {
    (void)user;

    /* Need at least Ethernet(14) + IP header(20) */
    if (hdr->caplen < 34) return;

    /* ── Parse Ethernet header ── */
    struct ether_header* eth = (struct ether_header*)raw;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        stats.other++; return;
    }

    /* ── Parse IP header ── */
    struct ip* iph = (struct ip*)(raw + 14);
    int ihl = iph->ip_hl * 4;   /* IP header length in bytes */

    PacketInfo p;
    memset(&p, 0, sizeof(p));
    p.timestamp   = (long)hdr->ts.tv_sec;
    p.packet_size = hdr->len;
    p.protocol    = iph->ip_p;

    /* inet_ntoa uses static buffer — copy immediately */
    strncpy(p.src_ip, inet_ntoa(iph->ip_src), 15);
    strncpy(p.dst_ip, inet_ntoa(iph->ip_dst), 15);

    /* ── Parse TCP / UDP ── */
    if (p.protocol == IPPROTO_TCP &&
        hdr->caplen >= (unsigned)(14 + ihl + 20)) {

        struct tcphdr* tcp = (struct tcphdr*)(raw + 14 + ihl);
        p.src_port = ntohs(tcp->th_sport);
        p.dst_port = ntohs(tcp->th_dport);
        p.flag_syn = (tcp->th_flags & TH_SYN)  ? 1 : 0;
        p.flag_ack = (tcp->th_flags & TH_ACK)  ? 1 : 0;
        p.flag_fin = (tcp->th_flags & TH_FIN)  ? 1 : 0;
        p.flag_rst = (tcp->th_flags & TH_RST)  ? 1 : 0;
        p.flag_psh = (tcp->th_flags & TH_PUSH) ? 1 : 0;
        stats.tcp++;

    } else if (p.protocol == IPPROTO_UDP &&
               hdr->caplen >= (unsigned)(14 + ihl + 8)) {

        struct udphdr* udp = (struct udphdr*)(raw + 14 + ihl);
        p.src_port = ntohs(udp->uh_sport);
        p.dst_port = ntohs(udp->uh_dport);
        stats.udp++;

    } else if (p.protocol == IPPROTO_ICMP) {
        stats.icmp++;
    } else {
        stats.other++;
    }

    stats.total++;
    stats.bytes += hdr->len;

    /* ── Print to screen ── */
    const char* proto_str =
        p.protocol == IPPROTO_TCP  ? "TCP"  :
        p.protocol == IPPROTO_UDP  ? "UDP"  :
        p.protocol == IPPROTO_ICMP ? "ICMP" : "OTHER";

    /* Format timestamp */
    time_t ts = (time_t)p.timestamp;
    struct tm* tm_info = localtime(&ts);
    char ts_str[20];
    strftime(ts_str, sizeof(ts_str), "%H:%M:%S", tm_info);

    printf("[%4lu] %s %-5s %-15s:%-5d → %-15s:%-5d",
           stats.total, ts_str, proto_str,
           p.src_ip, p.src_port,
           p.dst_ip, p.dst_port);

    if (p.protocol == IPPROTO_TCP) {
        printf(" [%s%s%s%s%s]",
               p.flag_syn ? "SYN " : "",
               p.flag_ack ? "ACK " : "",
               p.flag_fin ? "FIN " : "",
               p.flag_rst ? "RST " : "",
               p.flag_psh ? "PSH"  : "");
    }
    printf("  %d B\n", p.packet_size);

    /* ── Write to CSV ── */
    if (csv_file) {
        write_csv_row(csv_file, &p);
    }

    /* ── Write to screen log ── */
    if (log_file) {
        fprintf(log_file, "%lu,%s,%s,%d,%s,%d,%d,%d\n",
                stats.total, ts_str, p.src_ip,
                p.src_port, p.dst_ip, p.dst_port,
                p.protocol, p.packet_size);
        fflush(log_file);
    }
}

/* ============================================================
 * SIGNAL HANDLER — Ctrl+C prints summary before quitting
 * ============================================================ */
void on_signal(int sig) {
    (void)sig;
    printf("\n\n");
    printf("╔══════════════════════════════════════╗\n");
    printf("║  CAPTURE STOPPED                     ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║  Total:   %-26lu║\n", stats.total);
    printf("║  TCP:     %-26lu║\n", stats.tcp);
    printf("║  UDP:     %-26lu║\n", stats.udp);
    printf("║  ICMP:    %-26lu║\n", stats.icmp);
    printf("║  Bytes:   %-26lu║\n", stats.bytes);
    printf("╚══════════════════════════════════════╝\n");

    if (csv_file) {
        fclose(csv_file);
        printf("\n  CSV saved to: data/logs/packets.csv\n");
        printf("  Next step:\n");
        printf("  ./build/packet_bridge --read data/logs/packets.csv\n\n");
    }
    if (log_file) fclose(log_file);
    if (handle)   pcap_breakloop(handle);
    exit(0);
}

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char* argv[]) {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    /* ── Parse arguments ── */
    char* interface  = "lo";
    char* csv_path   = NULL;
    int   count      = -1;
    char* filter_str = "ip";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "-i") && i+1 < argc) interface  = argv[++i];
        else if (!strcmp(argv[i], "-n") && i+1 < argc) count      = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-o") && i+1 < argc) csv_path   = argv[++i];
        else if (!strcmp(argv[i], "-f") && i+1 < argc) filter_str = argv[++i];
        else if (!strcmp(argv[i], "-h")) {
            printf("\nUsage: %s -i <iface> -n <count> -o <file.csv>\n\n", argv[0]);
            printf("  -i <iface>    network interface (default: lo)\n");
            printf("  -n <count>    packets to capture (-1 = unlimited)\n");
            printf("  -o <file>     save to CSV file\n");
            printf("  -f <filter>   BPF filter (default: 'ip')\n\n");
            printf("Examples:\n");
            printf("  sudo %s -i lo -n 50 -o data/logs/packets.csv\n", argv[0]);
            printf("  sudo %s -i eth0 -n 200 -o data/logs/packets.csv\n\n", argv[0]);
            return 0;
        }
    }

    max_count = count;

    /* ── Create output directory ── */
    (void)system("mkdir -p data/logs");

    /* ── Open CSV file ── */
    if (csv_path) {
        csv_file = fopen(csv_path, "w");
        if (!csv_file) {
            fprintf(stderr, "ERROR: Cannot create CSV file: %s\n", csv_path);
            return 1;
        }
        write_csv_header(csv_file);
    }

    /* ── Open screen log ── */
    log_file = fopen(LOG_FILE, "a");

    /* ── Print header ── */
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   D-IDS PACKET CAPTURE — Week 9             ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Interface:  %-31s║\n", interface);
    printf("║  Filter:     %-31s║\n", filter_str);
    if (count < 0)
        printf("║  Count:      unlimited (Ctrl+C to stop)      ║\n");
    else
        printf("║  Count:      %-31d║\n", count);
    if (csv_path)
        printf("║  CSV output: %-31s║\n", csv_path);
    else
        printf("║  CSV output: none (add -o file.csv)          ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    /* ── Open network interface ── */
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);
    if (!handle) {
        fprintf(stderr, "ERROR: Cannot open interface '%s': %s\n",
                interface, errbuf);
        fprintf(stderr, "  → Run with sudo\n");
        fprintf(stderr, "  → Check interface name: ip link show\n");
        return 1;
    }

    /* ── Apply BPF filter ── */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "ERROR: Bad filter '%s'\n", filter_str);
        return 1;
    }
    pcap_freecode(&fp);

    /* ── Print column headers ── */
    printf(" %-4s %-8s %-5s %-15s:%-5s   %-15s:%-5s %s\n",
           "NUM", "TIME", "PROTO",
           "SRC-IP", "PORT", "DST-IP", "PORT", "SIZE");
    printf(" %.70s\n",
           "----------------------------------------------------------------------");

    /* ── START CAPTURING ── */
    stats.start = time(NULL);
    pcap_loop(handle, count, packet_handler, NULL);

    /* ── Normal exit (after capturing -n packets) ── */
    on_signal(0);
    return 0;
}
