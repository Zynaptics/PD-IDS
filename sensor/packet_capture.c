/*
 * =============================================================================
 * WEEK 2 - PACKET CAPTURE MODULE
 * File: sensor/packet_capture.c
 * =============================================================================
 *
 * WHAT THIS FILE DOES:
 *   This is your SENSOR. It sits on a computer and watches all network traffic
 *   going in and out. For every packet it sees, it extracts the important info
 *   (source IP, destination IP, ports, etc.) and saves it for analysis.
 *
 * ANALOGY:
 *   Think of a packet sniffer like a toll booth camera. Every car (packet)
 *   that passes gets photographed (captured). We record: license plate (IP),
 *   where it came from, where it's going.
 *
 * WHAT IS A NETWORK PACKET?
 *   Data on the internet travels in small chunks called "packets."
 *   Each packet has a HEADER (metadata: who sent it, who it goes to)
 *   and a PAYLOAD (the actual data: webpage content, file bytes, etc.)
 *
 *   Header structure:
 *   [Ethernet header 14 bytes][IP header 20+ bytes][TCP/UDP header][Data]
 *
 * COMPILE:
 *   gcc -O2 -o packet_capture packet_capture.c -lpcap -lm
 *   (the -lpcap flag links the libpcap library)
 *
 * RUN (you need root/sudo for raw packet capture):
 *   sudo ./packet_capture -i lo -n 20
 *   (capture 20 packets from the loopback interface)
 *
 *   To see available interfaces: ip link show
 *   Common interfaces: lo (loopback), eth0 (ethernet), wlan0 (wifi)
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

/* pcap.h = the packet capture library */
#include <pcap.h>

/* Network headers */
#include <netinet/in.h>         /* Internet address structures */
#include <netinet/if_ether.h>   /* Ethernet header */
#include <netinet/ip.h>         /* IP header structure */
#include <netinet/tcp.h>        /* TCP header structure */
#include <netinet/udp.h>        /* UDP header structure */
#include <arpa/inet.h>          /* inet_ntoa() - converts IP to string */

/* =============================================================================
 * CONSTANTS - values we define once and use throughout
 * ============================================================================= */

#define MAX_PACKET_SIZE   65535   /* Maximum possible IP packet size */
#define LOG_FILE          "data/logs/packets.log"
#define SNAP_LENGTH       65535   /* How many bytes of each packet to capture */
#define PROMISCUOUS_MODE  1       /* 1 = capture ALL packets, not just ours */
#define TIMEOUT_MS        1000    /* How long to wait for packets (milliseconds) */

/* =============================================================================
 * DATA STRUCTURES
 * ============================================================================= */

/*
 * PacketInfo - stores the key info we extract from each packet
 *
 * We don't store the entire packet (too much memory).
 * We just store the metadata we need for threat detection.
 */
typedef struct {
    /* When was this packet captured? */
    time_t  timestamp;
    char    timestamp_str[32];

    /* Who sent it? */
    char    src_ip[16];      /* e.g., "192.168.1.100" */
    uint16_t src_port;       /* e.g., 54321 */

    /* Who is it going to? */
    char    dst_ip[16];      /* e.g., "93.184.216.34" */
    uint16_t dst_port;       /* e.g., 80 (HTTP), 443 (HTTPS), 22 (SSH) */

    /* What type of packet? */
    uint8_t protocol;        /* 6=TCP, 17=UDP, 1=ICMP */
    char    protocol_str[8]; /* "TCP", "UDP", "ICMP", "OTHER" */

    /* Packet size */
    uint32_t packet_len;     /* Actual length on wire */
    uint32_t capture_len;    /* How much we captured */

    /* TCP specific flags (only valid if protocol==TCP) */
    /* Flags tell us what kind of TCP packet this is */
    uint8_t  tcp_flags;
    int      flag_syn;       /* SYN: starting a connection */
    int      flag_ack;       /* ACK: acknowledging data */
    int      flag_fin;       /* FIN: ending a connection */
    int      flag_rst;       /* RST: resetting/aborting connection */
    int      flag_psh;       /* PSH: push data immediately */

} PacketInfo;

/*
 * CaptureStats - track how many packets we've seen
 */
typedef struct {
    uint64_t total_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    uint64_t bytes_captured;
    time_t   start_time;
} CaptureStats;

/* =============================================================================
 * GLOBAL VARIABLES
 * ============================================================================= */

/* These are accessible from all functions */
static pcap_t*      pcap_handle = NULL;   /* Our connection to libpcap */
static FILE*        log_file    = NULL;    /* Log file handle */
static CaptureStats stats       = {0};    /* Initialize all to 0 */
static int          max_packets = -1;      /* -1 = capture forever */

/* =============================================================================
 * FUNCTION: get_protocol_name
 *
 * PURPOSE: Convert protocol number to human-readable name
 *
 * PARAMS:
 *   protocol - the IP protocol number (6, 17, 1, etc.)
 *
 * RETURNS:
 *   String like "TCP", "UDP", "ICMP"
 * ============================================================================= */
const char* get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "OTHER";
    }
}

/* =============================================================================
 * FUNCTION: get_service_name
 *
 * PURPOSE: Tell us what service a port number usually belongs to
 *          (for human-readable output)
 *
 * PARAMS:
 *   port - the port number (0-65535)
 *
 * RETURNS:
 *   String like "HTTP", "SSH", "HTTPS", or "unknown"
 * ============================================================================= */
const char* get_service_name(uint16_t port) {
    switch (port) {
        case 20:   return "FTP-DATA";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "TELNET";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-ALT";
        default:   return "unknown";
    }
}

/* =============================================================================
 * FUNCTION: print_packet_info
 *
 * PURPOSE: Print packet info to screen AND write to log file
 *
 * PARAMS:
 *   pkt  - pointer to the PacketInfo we want to print
 *   num  - packet number (for display)
 * ============================================================================= */
void print_packet_info(const PacketInfo* pkt, uint64_t num) {
    /* Build the output string */
    char output[512];

    if (pkt->protocol == IPPROTO_TCP) {
        /* For TCP: show flags */
        char flags[32] = "";
        if (pkt->flag_syn) strcat(flags, "SYN ");
        if (pkt->flag_ack) strcat(flags, "ACK ");
        if (pkt->flag_fin) strcat(flags, "FIN ");
        if (pkt->flag_rst) strcat(flags, "RST ");
        if (pkt->flag_psh) strcat(flags, "PSH ");
        if (strlen(flags) == 0) strcpy(flags, "---");

        snprintf(output, sizeof(output),
            "[%lu] %s | TCP | %s:%-5d --> %s:%-5d | %s | %d bytes | [%s]\n",
            num,
            pkt->timestamp_str,
            pkt->src_ip, pkt->src_port,
            pkt->dst_ip, pkt->dst_port,
            get_service_name(pkt->dst_port),
            pkt->packet_len,
            flags);

    } else if (pkt->protocol == IPPROTO_UDP) {
        snprintf(output, sizeof(output),
            "[%lu] %s | UDP | %s:%-5d --> %s:%-5d | %s | %d bytes\n",
            num,
            pkt->timestamp_str,
            pkt->src_ip, pkt->src_port,
            pkt->dst_ip, pkt->dst_port,
            get_service_name(pkt->dst_port),
            pkt->packet_len);

    } else if (pkt->protocol == IPPROTO_ICMP) {
        snprintf(output, sizeof(output),
            "[%lu] %s | ICMP | %s --> %s | %d bytes\n",
            num,
            pkt->timestamp_str,
            pkt->src_ip,
            pkt->dst_ip,
            pkt->packet_len);
    } else {
        snprintf(output, sizeof(output),
            "[%lu] %s | %s | %s --> %s | %d bytes\n",
            num,
            pkt->timestamp_str,
            pkt->protocol_str,
            pkt->src_ip,
            pkt->dst_ip,
            pkt->packet_len);
    }

    /* Print to screen */
    printf("%s", output);

    /* Write to log file */
    if (log_file != NULL) {
        fprintf(log_file, "%s", output);
        fflush(log_file);  /* Force write to disk immediately */
    }
}

/* =============================================================================
 * FUNCTION: packet_handler (CALLBACK)
 *
 * PURPOSE: This function is called by libpcap AUTOMATICALLY for every
 *          packet captured. It's a "callback" function.
 *
 *          libpcap does the hard work of reading from the network card.
 *          It calls this function and gives us the raw packet bytes.
 *          Our job: parse those bytes and extract the useful info.
 *
 * HOW PACKET PARSING WORKS:
 *   Raw packet bytes:
 *   [00 01 02 03 ... Ethernet 14 bytes ... ][IP header][TCP/UDP][Data]
 *                                            ^
 *                                            We skip to here by adding 14
 *
 * PARAMS:
 *   user    - our custom data (we pass &stats, the CaptureStats)
 *   header  - pcap metadata: when packet arrived, how big it is
 *   packet  - raw bytes of the packet
 * ============================================================================= */
void packet_handler(u_char* user, const struct pcap_pkthdr* header,
                    const u_char* packet) {

    /* Cast our user data back to CaptureStats */
    CaptureStats* s = (CaptureStats*)user;

    /* This will hold the parsed packet info */
    PacketInfo pkt;
    memset(&pkt, 0, sizeof(PacketInfo));  /* Zero out all fields */

    /* -----------------------------------------------------------------------
     * STEP 1: Record timestamp
     * ----------------------------------------------------------------------- */
    pkt.timestamp = header->ts.tv_sec;

    /* Convert timestamp to human-readable format */
    struct tm* tm_info = localtime(&pkt.timestamp);
    strftime(pkt.timestamp_str, sizeof(pkt.timestamp_str),
             "%Y-%m-%d %H:%M:%S", tm_info);

    /* -----------------------------------------------------------------------
     * STEP 2: Record packet sizes
     * ----------------------------------------------------------------------- */
    pkt.packet_len  = header->len;      /* Original packet length */
    pkt.capture_len = header->caplen;   /* How much we actually got */

    s->bytes_captured += pkt.packet_len;
    s->total_packets++;

    /* -----------------------------------------------------------------------
     * STEP 3: Parse Ethernet header (layer 2)
     *
     * Every Ethernet frame starts with:
     * [6 bytes: destination MAC][6 bytes: source MAC][2 bytes: type]
     * Total = 14 bytes
     *
     * We need to skip past this to get to the IP header.
     * ----------------------------------------------------------------------- */
    if (header->caplen < 14) {
        /* Packet too small to even have an Ethernet header - skip */
        s->other_packets++;
        return;
    }

    /*
     * Cast the raw bytes to an Ethernet header struct.
     * struct ether_header is defined in <netinet/if_ether.h>
     * It gives us fields: ether_dhost (dest MAC), ether_shost (src MAC),
     * ether_type (what's inside: IP, ARP, etc.)
     */
    struct ether_header* eth = (struct ether_header*)packet;

    /* Check if it's an IP packet */
    /* ETHERTYPE_IP = 0x0800 */
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        /* Not IP (could be ARP, IPv6, etc.) - skip for now */
        s->other_packets++;
        return;
    }

    /* -----------------------------------------------------------------------
     * STEP 4: Parse IP header (layer 3)
     *
     * After the 14-byte Ethernet header comes the IP header.
     * IP header structure (simplified):
     * - Version + IHL (1 byte)
     * - Type of Service (1 byte)
     * - Total Length (2 bytes)
     * - Identification (2 bytes)
     * - Flags + Fragment Offset (2 bytes)
     * - TTL (1 byte)
     * - Protocol (1 byte) <- we want this: 6=TCP, 17=UDP, 1=ICMP
     * - Checksum (2 bytes)
     * - Source IP (4 bytes) <- we want this
     * - Destination IP (4 bytes) <- we want this
     * Total minimum: 20 bytes (IHL field tells us actual size)
     * ----------------------------------------------------------------------- */
    if (header->caplen < 14 + 20) {
        s->other_packets++;
        return;
    }

    /* Move pointer past Ethernet header to IP header */
    struct ip* ip_hdr = (struct ip*)(packet + 14);

    /* Extract source and destination IP addresses */
    /* inet_ntoa converts binary IP to string "192.168.1.1" */
    /* IMPORTANT: inet_ntoa uses static buffer - copy immediately! */
    strncpy(pkt.src_ip, inet_ntoa(ip_hdr->ip_src), 15);
    strncpy(pkt.dst_ip, inet_ntoa(ip_hdr->ip_dst), 15);

    /* Get protocol number */
    pkt.protocol = ip_hdr->ip_p;
    strncpy(pkt.protocol_str, get_protocol_name(pkt.protocol), 7);

    /*
     * ip_hl = IP Header Length in 32-bit words
     * Multiply by 4 to get bytes
     * (minimum is 5 words = 20 bytes, max is 15 words = 60 bytes)
     */
    int ip_header_len = ip_hdr->ip_hl * 4;

    /* -----------------------------------------------------------------------
     * STEP 5: Parse TCP or UDP header (layer 4)
     *
     * After the IP header comes either TCP, UDP, or ICMP header.
     * We move our pointer past IP to get here.
     * ----------------------------------------------------------------------- */
    if (pkt.protocol == IPPROTO_TCP) {
        /* TCP Header:
         * - Source Port (2 bytes)  <- we want this
         * - Dest Port (2 bytes)    <- we want this
         * - Sequence Number (4 bytes)
         * - Acknowledgment Number (4 bytes)
         * - Data Offset + Flags (2 bytes) <- flags tell us SYN/ACK/FIN/RST
         * - Window Size (2 bytes)
         * - Checksum (2 bytes)
         * - Urgent Pointer (2 bytes)
         */
        struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + ip_header_len);

        /* ntohs() = "network to host short"
         * Network uses big-endian byte order, x86 uses little-endian.
         * ntohs() converts between them for 16-bit values.
         */
        pkt.src_port = ntohs(tcp_hdr->th_sport);
        pkt.dst_port = ntohs(tcp_hdr->th_dport);

        /* Extract TCP flags */
        pkt.tcp_flags = tcp_hdr->th_flags;
        pkt.flag_syn  = (pkt.tcp_flags & TH_SYN) ? 1 : 0;
        pkt.flag_ack  = (pkt.tcp_flags & TH_ACK) ? 1 : 0;
        pkt.flag_fin  = (pkt.tcp_flags & TH_FIN) ? 1 : 0;
        pkt.flag_rst  = (pkt.tcp_flags & TH_RST) ? 1 : 0;
        pkt.flag_psh  = (pkt.tcp_flags & TH_PUSH) ? 1 : 0;

        s->tcp_packets++;

    } else if (pkt.protocol == IPPROTO_UDP) {
        /* UDP Header:
         * - Source Port (2 bytes)
         * - Dest Port (2 bytes)
         * - Length (2 bytes)
         * - Checksum (2 bytes)
         * Much simpler than TCP!
         */
        struct udphdr* udp_hdr = (struct udphdr*)(packet + 14 + ip_header_len);
        pkt.src_port = ntohs(udp_hdr->uh_sport);
        pkt.dst_port = ntohs(udp_hdr->uh_dport);
        s->udp_packets++;

    } else if (pkt.protocol == IPPROTO_ICMP) {
        /* ICMP has no ports (ping, traceroute use ICMP) */
        pkt.src_port = 0;
        pkt.dst_port = 0;
        s->icmp_packets++;

    } else {
        s->other_packets++;
    }

    /* -----------------------------------------------------------------------
     * STEP 6: Output the packet info
     * ----------------------------------------------------------------------- */
    print_packet_info(&pkt, s->total_packets);
}

/* =============================================================================
 * FUNCTION: signal_handler
 *
 * PURPOSE: Handle Ctrl+C gracefully.
 *          When user presses Ctrl+C, we want to print statistics
 *          BEFORE exiting, not just crash.
 * ============================================================================= */
void signal_handler(int sig) {
    printf("\n\n");
    printf("================================================\n");
    printf("  CAPTURE STOPPED (Ctrl+C pressed)\n");
    printf("================================================\n");
    printf("  Total packets captured:  %lu\n", stats.total_packets);
    printf("  TCP packets:             %lu\n", stats.tcp_packets);
    printf("  UDP packets:             %lu\n", stats.udp_packets);
    printf("  ICMP packets:            %lu\n", stats.icmp_packets);
    printf("  Other packets:           %lu\n", stats.other_packets);
    printf("  Total bytes:             %lu\n", stats.bytes_captured);
    printf("================================================\n");
    printf("  Log saved to: %s\n", LOG_FILE);
    printf("================================================\n");

    if (pcap_handle != NULL) {
        pcap_breakloop(pcap_handle);  /* Tell libpcap to stop */
    }
    if (log_file != NULL) {
        fclose(log_file);
    }
    exit(0);
}

/* =============================================================================
 * FUNCTION: print_usage
 *
 * PURPOSE: Show help when user runs the program wrong
 * ============================================================================= */
void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>   Network interface to capture on (default: lo)\n");
    printf("  -n <count>       Number of packets to capture (default: unlimited)\n");
    printf("  -f <filter>      BPF filter expression (default: 'ip')\n");
    printf("  -h               Show this help\n");
    printf("\nExamples:\n");
    printf("  sudo %s -i lo -n 20\n", program_name);
    printf("  sudo %s -i eth0 -n 100 -f 'tcp port 80'\n", program_name);
    printf("  sudo %s -i wlan0\n", program_name);
    printf("\nAvailable interfaces: run 'ip link show'\n");
}

/* =============================================================================
 * MAIN FUNCTION
 * ============================================================================= */
int main(int argc, char* argv[]) {
    /* -----------------------------------------------------------------------
     * Variables
     * ----------------------------------------------------------------------- */
    char  errbuf[PCAP_ERRBUF_SIZE];  /* Buffer for error messages */
    char* interface = "lo";           /* Default: loopback (localhost traffic) */
    char* filter_expr = "ip";         /* Default: capture all IP packets */
    int   packet_count = -1;          /* -1 = unlimited */

    /* -----------------------------------------------------------------------
     * STEP 1: Parse command-line arguments
     * ----------------------------------------------------------------------- */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i+1 < argc) {
            packet_count = atoi(argv[++i]);
            max_packets = packet_count;
        } else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            filter_expr = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    /* -----------------------------------------------------------------------
     * STEP 2: Set up signal handler for Ctrl+C
     * ----------------------------------------------------------------------- */
    signal(SIGINT, signal_handler);

    /* -----------------------------------------------------------------------
     * STEP 3: Create log directory and open log file
     * ----------------------------------------------------------------------- */
    system("mkdir -p data/logs");  /* Create directory if it doesn't exist */
    log_file = fopen(LOG_FILE, "a");  /* "a" = append (don't overwrite) */
    if (log_file == NULL) {
        fprintf(stderr, "WARNING: Cannot open log file %s\n", LOG_FILE);
        fprintf(stderr, "Will print to screen only.\n");
    }

    /* -----------------------------------------------------------------------
     * STEP 4: Print startup info
     * ----------------------------------------------------------------------- */
    printf("================================================\n");
    printf("  D-IDS PACKET CAPTURE SENSOR - WEEK 2\n");
    printf("================================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Filter:     %s\n", filter_expr);
    if (packet_count == -1)
        printf("  Count:      unlimited (Ctrl+C to stop)\n");
    else
        printf("  Count:      %d packets\n", packet_count);
    printf("  Log file:   %s\n", LOG_FILE);
    printf("================================================\n");
    printf("\n");

    /* -----------------------------------------------------------------------
     * STEP 5: Open the network interface for capture
     *
     * pcap_open_live() - opens a network device for packet capture
     * Parameters:
     *   device      = interface name ("eth0", "lo", etc.)
     *   snaplen     = how many bytes to capture per packet (65535 = all)
     *   promisc     = 1 = promiscuous mode (capture ALL packets, not just ours)
     *   to_ms       = timeout in ms (how long to wait for packets)
     *   errbuf      = where to store error message if it fails
     *
     * Returns: pcap handle or NULL on error
     * ----------------------------------------------------------------------- */
    pcap_handle = pcap_open_live(interface, SNAP_LENGTH, PROMISCUOUS_MODE,
                                  TIMEOUT_MS, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "ERROR: Cannot open interface '%s': %s\n",
                interface, errbuf);
        fprintf(stderr, "Make sure to:\n");
        fprintf(stderr, "  1. Run as root: sudo ./packet_capture\n");
        fprintf(stderr, "  2. Check interface name: ip link show\n");
        return 1;
    }

    printf("Successfully opened interface: %s\n\n", interface);

    /* -----------------------------------------------------------------------
     * STEP 6: Apply BPF filter
     *
     * BPF = Berkeley Packet Filter
     * A mini-language for filtering packets.
     * Examples:
     *   "ip"              = only IP packets
     *   "tcp"             = only TCP
     *   "tcp port 80"     = only HTTP traffic
     *   "host 1.2.3.4"    = only traffic to/from that IP
     *
     * This saves CPU - we don't process packets we don't care about.
     * ----------------------------------------------------------------------- */
    struct bpf_program fp;  /* Compiled filter */

    /* pcap_compile - compile the filter expression into bytecode */
    if (pcap_compile(pcap_handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "ERROR: Bad filter expression '%s': %s\n",
                filter_expr, pcap_geterr(pcap_handle));
        return 1;
    }

    /* pcap_setfilter - apply the compiled filter */
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "ERROR: Cannot set filter: %s\n", pcap_geterr(pcap_handle));
        return 1;
    }
    pcap_freecode(&fp);  /* Free compiled filter (not needed anymore) */

    printf("Filter applied: '%s'\n", filter_expr);
    printf("Starting capture... (Ctrl+C to stop)\n");
    printf("================================================\n");
    printf("%-4s %-19s %-4s %-15s:%-5s --> %-15s:%-5s %-10s %s\n",
           "NUM", "TIMESTAMP", "PROT", "SRC-IP", "PORT", "DST-IP", "PORT",
           "SERVICE", "BYTES");
    printf("------------------------------------------------\n");

    /* -----------------------------------------------------------------------
     * STEP 7: Initialize statistics
     * ----------------------------------------------------------------------- */
    stats.start_time = time(NULL);

    /* -----------------------------------------------------------------------
     * STEP 8: START CAPTURING!
     *
     * pcap_loop() - the main capture loop
     * Parameters:
     *   handle    = our pcap handle
     *   cnt       = how many packets to capture (-1 = unlimited)
     *   callback  = function to call for each packet (our packet_handler)
     *   user      = extra data to pass to callback (our stats struct)
     *
     * This function BLOCKS (keeps running) until:
     *   - We've captured 'cnt' packets
     *   - pcap_breakloop() is called (by Ctrl+C handler)
     *   - Error occurs
     * ----------------------------------------------------------------------- */
    int result = pcap_loop(pcap_handle, packet_count, packet_handler,
                           (u_char*)&stats);

    /* -----------------------------------------------------------------------
     * STEP 9: Cleanup and print final stats
     * ----------------------------------------------------------------------- */
    printf("\n================================================\n");
    printf("  CAPTURE COMPLETE\n");
    printf("================================================\n");
    printf("  Total packets:  %lu\n", stats.total_packets);
    printf("  TCP:            %lu\n", stats.tcp_packets);
    printf("  UDP:            %lu\n", stats.udp_packets);
    printf("  ICMP:           %lu\n", stats.icmp_packets);
    printf("  Other:          %lu\n", stats.other_packets);
    printf("  Bytes:          %lu\n", stats.bytes_captured);
    time_t duration = time(NULL) - stats.start_time;
    printf("  Duration:       %ld seconds\n", duration);
    printf("================================================\n");

    if (log_file != NULL) fclose(log_file);
    pcap_close(pcap_handle);

    return 0;
}
