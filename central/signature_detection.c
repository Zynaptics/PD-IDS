/*
 * =============================================================================
 * WEEK 3 - SIGNATURE DETECTION ENGINE
 * File: central/signature_detection.c
 * =============================================================================
 *
 * WHAT THIS FILE DOES:
 *   This is your first detection engine. It detects known attacks by matching
 *   network packets against a database of "signatures" (patterns).
 *
 * ANALOGY:
 *   Think of it like antivirus software. Antivirus has a database of known
 *   virus patterns (signatures). When it sees a file, it checks: "does this
 *   file match any known virus pattern?" Same idea here, but for network packets.
 *
 * ATTACKS WE DETECT:
 *   1. Port Scan      - Someone scanning many ports looking for open services
 *   2. Brute Force    - Many login attempts (SSH, RDP)
 *   3. DDoS           - Flood of packets trying to overwhelm the server
 *   4. ICMP Flood     - Ping flood attack
 *   5. NULL Scan      - Stealth port scan using TCP packets with no flags
 *   6. SYN Flood      - TCP handshake attack
 *   7. Suspicious Ports - Traffic to known malware ports
 *
 * COMPILE (standalone for testing):
 *   gcc -O2 -o signature_detection signature_detection.c -lm
 *
 * RUN TEST:
 *   ./signature_detection
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
/* =============================================================================
 * DATA STRUCTURES
 * ============================================================================= */

/*
 * ThreatLevel - how dangerous is this?
 * Used to prioritize alerts (critical first)
 */
typedef enum {
    THREAT_NONE     = 0,   /* Normal, benign traffic */
    THREAT_INFO     = 1,   /* Informational, worth noting */
    THREAT_LOW      = 2,   /* Low risk, monitor */
    THREAT_MEDIUM   = 3,   /* Medium risk, investigate */
    THREAT_HIGH     = 4,   /* High risk, respond soon */
    THREAT_CRITICAL = 5    /* Critical, respond immediately */
} ThreatLevel;

/*
 * PacketInfo - simplified packet structure for detection
 * (In the real system, this comes from packet_capture.c)
 */
typedef struct {
    time_t   timestamp;
    char     src_ip[16];
    char     dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;       /* 6=TCP, 17=UDP, 1=ICMP */
    uint32_t packet_size;

    /* TCP flags */
    int flag_syn;
    int flag_ack;
    int flag_fin;
    int flag_rst;
    int flag_psh;
    int flag_urg;
} PacketInfo;

/*
 * DetectionResult - what did we find?
 */
typedef struct {
    int          is_threat;           /* 1 if threat detected */
    ThreatLevel  level;               /* How dangerous */
    char         attack_type[64];     /* "Port Scan", "DDoS", etc. */
    char         description[256];    /* Human-readable explanation */
    double       confidence;          /* 0.0 to 1.0 */
    char         src_ip[16];          /* Who is attacking */
    char         dst_ip[16];          /* Who is being attacked */
} DetectionResult;

/* =============================================================================
 * DETECTION STATE STRUCTURES
 * These track statistics ACROSS multiple packets (needed for detecting patterns)
 * =============================================================================*/

/*
 * For port scan detection, we need to track: 
 * "how many different ports has this IP tried to connect to?"
 */
#define MAX_TRACKED_IPS  500
#define MAX_TRACKED_PORTS 200

typedef struct {
    char     ip[16];
    uint16_t ports_tried[MAX_TRACKED_PORTS];
    int      port_count;
    time_t   first_seen;
    time_t   last_seen;
} IPTracker;

static IPTracker ip_tracker[MAX_TRACKED_IPS];
static int       ip_tracker_count = 0;

/*
 * For DDoS detection, track packets per second per source IP
 */
typedef struct {
    char   ip[16];
    int    packet_count;
    time_t window_start;  /* When did we start counting? */
} PacketRateTracker;

static PacketRateTracker rate_tracker[MAX_TRACKED_IPS];
static int               rate_tracker_count = 0;

/* Known malware/botnet command-and-control ports */
static uint16_t suspicious_ports[] = {
    1080,  /* SOCKS proxy (often used by malware) */
    4444,  /* Metasploit default */
    5555,  /* Android Debug Bridge */
    6667,  /* IRC (botnet control) */
    6666,  /* IRC (botnet control) */
    8888,  /* Common malware backdoor */
    9999,  /* Common malware backdoor */
    12345, /* NetBus RAT */
    31337, /* Back Orifice RAT (reads "ELITE" in leet speak) */
    0      /* Sentinel - marks end of list */
};

/* =============================================================================
 * HELPER FUNCTIONS
 * ============================================================================= */

/*
 * Convert ThreatLevel to string for display
 */
const char* threat_level_name(ThreatLevel level) {
    switch (level) {
        case THREAT_NONE:     return "NONE";
        case THREAT_INFO:     return "INFO";
        case THREAT_LOW:      return "LOW";
        case THREAT_MEDIUM:   return "MEDIUM";
        case THREAT_HIGH:     return "HIGH";
        case THREAT_CRITICAL: return "CRITICAL";
        default:              return "UNKNOWN";
    }
}

/*
 * find_or_create_ip_tracker
 *
 * Find this IP in our tracker array, or create a new entry.
 * Returns pointer to the tracker, or NULL if we're full.
 */
IPTracker* find_or_create_ip_tracker(const char* ip) {
    /* Search for existing entry */
    for (int i = 0; i < ip_tracker_count; i++) {
        if (strcmp(ip_tracker[i].ip, ip) == 0) {
            return &ip_tracker[i];
        }
    }

    /* Not found - create new entry if space available */
    if (ip_tracker_count < MAX_TRACKED_IPS) {
        IPTracker* t = &ip_tracker[ip_tracker_count++];
        strncpy(t->ip, ip, 15);
        t->port_count  = 0;
        t->first_seen  = time(NULL);
        t->last_seen   = time(NULL);
        return t;
    }

    return NULL;  /* Table full */
}

/*
 * find_or_create_rate_tracker
 *
 * Similar to above, but for packet rate tracking.
 */
PacketRateTracker* find_or_create_rate_tracker(const char* ip) {
    for (int i = 0; i < rate_tracker_count; i++) {
        if (strcmp(rate_tracker[i].ip, ip) == 0) {
            return &rate_tracker[i];
        }
    }
    if (rate_tracker_count < MAX_TRACKED_IPS) {
        PacketRateTracker* t = &rate_tracker[rate_tracker_count++];
        strncpy(t->ip, ip, 15);
        t->packet_count  = 0;
        t->window_start  = time(NULL);
        return t;
    }
    return NULL;
}

/*
 * port_already_tried
 *
 * Check if we've already recorded this IP trying this port.
 * Used to avoid counting the same port multiple times.
 */
int port_already_tried(IPTracker* t, uint16_t port) {
    for (int i = 0; i < t->port_count; i++) {
        if (t->ports_tried[i] == port) return 1;
    }
    return 0;
}

/* =============================================================================
 * DETECTION FUNCTIONS
 * Each function checks for one specific attack type.
 * Returns 1 if attack detected, 0 if not.
 * ============================================================================= */

/*
 * detect_port_scan
 *
 * WHAT IS A PORT SCAN?
 *   Attackers probe computers to find open ports (open doors).
 *   They try connecting to many different ports rapidly.
 *   Normal users connect to 1-3 ports. Port scanners try 100+.
 *
 * HOW WE DETECT IT:
 *   Track how many unique destination ports each source IP has tried.
 *   If it's > 20 ports in < 60 seconds, it's a port scan.
 *
 * THRESHOLD: 20 ports in 60 seconds
 */
int detect_port_scan(const PacketInfo* pkt, DetectionResult* result) {
    /* Only check TCP SYN packets (connection attempts) */
    if (pkt->protocol != 6 || !pkt->flag_syn) return 0;

    IPTracker* t = find_or_create_ip_tracker(pkt->src_ip);
    if (t == NULL) return 0;

    /* Check if too much time has passed - reset if so */
    time_t now = time(NULL);
    if (now - t->first_seen > 60) {
        /* Reset this IP's tracking after 60 seconds */
        t->port_count = 0;
        t->first_seen = now;
    }

    /* Record this port if new */
    if (!port_already_tried(t, pkt->dst_port)) {
        if (t->port_count < MAX_TRACKED_PORTS) {
            t->ports_tried[t->port_count++] = pkt->dst_port;
        }
    }
    t->last_seen = now;

    /* Check threshold */
    int port_threshold = 20;  /* If scanned more than this many ports... */
    if (t->port_count > port_threshold) {
        result->is_threat = 1;
        result->level = THREAT_HIGH;
        result->confidence = 0.85;

        snprintf(result->attack_type, sizeof(result->attack_type),
                 "Port Scan");
        snprintf(result->description, sizeof(result->description),
                 "Source %s scanned %d unique ports on %s in %ld seconds. "
                 "Likely reconnaissance activity.",
                 pkt->src_ip, t->port_count, pkt->dst_ip,
                 (long)(now - t->first_seen));
        return 1;
    }

    return 0;
}

/*
 * detect_brute_force
 *
 * WHAT IS BRUTE FORCE?
 *   Attackers try many username/password combinations trying to log in.
 *   Common targets: SSH (port 22), RDP (3389), FTP (21), Telnet (23)
 *
 * HOW WE DETECT IT:
 *   Normal users connect to SSH a few times.
 *   Attackers connect many times rapidly (automated password guessing).
 *
 * THRESHOLD: >30 SYN packets to SSH/RDP in 60 seconds
 */
int detect_brute_force(const PacketInfo* pkt, DetectionResult* result) {
    /* Only check TCP SYN to login ports */
    uint16_t login_ports[] = {22, 23, 21, 3389, 5900, 1433, 0};
    int is_login_port = 0;
    char service_name[16] = "service";

    for (int i = 0; login_ports[i] != 0; i++) {
        if (pkt->dst_port == login_ports[i]) {
            is_login_port = 1;
            if (login_ports[i] == 22)   strcpy(service_name, "SSH");
            if (login_ports[i] == 23)   strcpy(service_name, "Telnet");
            if (login_ports[i] == 21)   strcpy(service_name, "FTP");
            if (login_ports[i] == 3389) strcpy(service_name, "RDP");
            if (login_ports[i] == 5900) strcpy(service_name, "VNC");
            break;
        }
    }

    if (!is_login_port || pkt->protocol != 6 || !pkt->flag_syn) return 0;

    /* Use rate tracker to count connection attempts */
    PacketRateTracker* t = find_or_create_rate_tracker(pkt->src_ip);
    if (t == NULL) return 0;

    time_t now = time(NULL);

    /* Reset counter every 60 seconds */
    if (now - t->window_start > 60) {
        t->packet_count = 0;
        t->window_start = now;
    }

    t->packet_count++;

    int bf_threshold = 30;  /* 30 attempts in 60 seconds = brute force */
    if (t->packet_count > bf_threshold) {
        result->is_threat = 1;
        result->level = THREAT_HIGH;
        result->confidence = 0.90;

        snprintf(result->attack_type, sizeof(result->attack_type),
                 "Brute Force Attack");
        snprintf(result->description, sizeof(result->description),
                 "Source %s made %d %s login attempts to %s in 60 seconds. "
                 "Automated password guessing detected.",
                 pkt->src_ip, t->packet_count, service_name, pkt->dst_ip);
        return 1;
    }

    return 0;
}

/*
 * detect_ddos
 *
 * WHAT IS DDoS?
 *   Distributed Denial of Service. Flooding a server with so many
 *   packets that it can't serve legitimate users.
 *
 * HOW WE DETECT IT:
 *   Track packets per second from each source IP.
 *   Normal traffic: maybe 10-50 packets/sec.
 *   DDoS: hundreds or thousands per second.
 *
 * THRESHOLD: >500 packets in 1 second from same source
 */
int detect_ddos(const PacketInfo* pkt, DetectionResult* result) {
    PacketRateTracker* t = find_or_create_rate_tracker(pkt->src_ip);
    if (t == NULL) return 0;

    time_t now = time(NULL);

    /* We measure per SECOND (1 second window) */
    if (now > t->window_start) {
        /* New second - check if previous second was an attack */
        int ddos_threshold = 500;  /* packets per second */
        int was_attack = (t->packet_count > ddos_threshold);

        /* Reset for new second */
        t->packet_count = 0;
        t->window_start = now;

        if (was_attack) {
            result->is_threat = 1;
            result->level = THREAT_CRITICAL;
            result->confidence = 0.95;

            snprintf(result->attack_type, sizeof(result->attack_type),
                     "DDoS Attack");
            snprintf(result->description, sizeof(result->description),
                     "Flood attack from %s: over %d packets/second detected. "
                     "Target: %s. System may become unavailable.",
                     pkt->src_ip, ddos_threshold, pkt->dst_ip);
            return 1;
        }
    }

    t->packet_count++;
    return 0;
}

/*
 * detect_null_scan
 *
 * WHAT IS A NULL SCAN?
 *   A stealth scanning technique where TCP packets are sent with NO flags set.
 *   Normal TCP always has at least one flag (SYN to start connection, etc.)
 *   A packet with no flags is abnormal and used by tools like nmap.
 *
 * HOW WE DETECT IT:
 *   Check if it's TCP with zero flags. That's always suspicious.
 */
int detect_null_scan(const PacketInfo* pkt, DetectionResult* result) {
    /* TCP packet with NO flags at all = NULL scan */
    if (pkt->protocol == 6 &&
        !pkt->flag_syn && !pkt->flag_ack && !pkt->flag_fin &&
        !pkt->flag_rst && !pkt->flag_psh && !pkt->flag_urg) {

        result->is_threat = 1;
        result->level = THREAT_MEDIUM;
        result->confidence = 0.80;

        snprintf(result->attack_type, sizeof(result->attack_type),
                 "NULL Scan (Stealth Probe)");
        snprintf(result->description, sizeof(result->description),
                 "TCP NULL scan detected from %s to %s:%d. "
                 "No TCP flags set - likely nmap or stealth scanner.",
                 pkt->src_ip, pkt->dst_ip, pkt->dst_port);
        return 1;
    }
    return 0;
}

/*
 * detect_syn_flood
 *
 * WHAT IS A SYN FLOOD?
 *   TCP connections start with a SYN packet.
 *   The server responds with SYN-ACK and waits for ACK to complete.
 *   Attackers send many SYN packets but never complete the handshake.
 *   The server's connection table fills up, blocking real users.
 *
 * HOW WE DETECT IT:
 *   Many SYN packets to the same destination port with no ACKs.
 */
int detect_syn_flood(const PacketInfo* pkt, DetectionResult* result) {
    /* Only SYN packets (no ACK - pure SYN, not SYN-ACK) */
    if (pkt->protocol != 6 || !pkt->flag_syn || pkt->flag_ack) return 0;

    /* Use the rate tracker but only count SYN packets */
    static int syn_counts[MAX_TRACKED_IPS] = {0};
    static time_t syn_times[MAX_TRACKED_IPS];
    static char syn_ips[MAX_TRACKED_IPS][16];
    static int syn_count_total = 0;

    /* Find or create entry */
    int idx = -1;
    for (int i = 0; i < syn_count_total; i++) {
        if (strcmp(syn_ips[i], pkt->src_ip) == 0) {
            idx = i;
            break;
        }
    }

    if (idx == -1 && syn_count_total < MAX_TRACKED_IPS) {
        idx = syn_count_total++;
        strncpy(syn_ips[idx], pkt->src_ip, 15);
        syn_counts[idx] = 0;
        syn_times[idx] = time(NULL);
    }

    if (idx == -1) return 0;

    time_t now = time(NULL);
    if (now - syn_times[idx] > 10) {
        /* Reset every 10 seconds */
        syn_counts[idx] = 0;
        syn_times[idx] = now;
    }

    syn_counts[idx]++;

    int syn_threshold = 100;  /* 100 SYNs in 10 seconds = SYN flood */
    if (syn_counts[idx] > syn_threshold) {
        result->is_threat = 1;
        result->level = THREAT_CRITICAL;
        result->confidence = 0.90;

        snprintf(result->attack_type, sizeof(result->attack_type),
                 "SYN Flood");
        snprintf(result->description, sizeof(result->description),
                 "SYN flood from %s: %d SYN packets in 10 seconds to %s:%d. "
                 "TCP half-open connection exhaustion attack.",
                 pkt->src_ip, syn_counts[idx], pkt->dst_ip, pkt->dst_port);
        return 1;
    }
    return 0;
}

/*
 * detect_suspicious_port
 *
 * WHAT ARE SUSPICIOUS PORTS?
 *   Some port numbers are almost exclusively used by malware, RATs
 *   (Remote Access Trojans), and hacking tools.
 *   Traffic to/from these ports is inherently suspicious.
 *
 * HOW WE DETECT IT:
 *   Check the destination port against a list of known-bad ports.
 */
int detect_suspicious_port(const PacketInfo* pkt, DetectionResult* result) {
    for (int i = 0; suspicious_ports[i] != 0; i++) {
        if (pkt->dst_port == suspicious_ports[i] ||
            pkt->src_port == suspicious_ports[i]) {

            result->is_threat = 1;
            result->level = THREAT_MEDIUM;
            result->confidence = 0.70;

            snprintf(result->attack_type, sizeof(result->attack_type),
                     "Suspicious Port Activity");
            snprintf(result->description, sizeof(result->description),
                     "Traffic on known-malware port %d between %s and %s. "
                     "Associated with RATs, botnets, or backdoors.",
                     (pkt->dst_port == suspicious_ports[i]) ?
                         pkt->dst_port : pkt->src_port,
                     pkt->src_ip, pkt->dst_ip);
            return 1;
        }
    }
    return 0;
}

/*
 * detect_icmp_flood
 *
 * WHAT IS ICMP FLOOD?
 *   Sending massive amounts of ICMP (ping) packets to overwhelm a target.
 *   Also known as "ping flood" or "smurf attack".
 *
 * HOW WE DETECT IT:
 *   Track ICMP packet rate. Normal: occasional pings.
 *   Attack: hundreds of pings per second.
 */
int detect_icmp_flood(const PacketInfo* pkt, DetectionResult* result) {
    if (pkt->protocol != 1) return 0;  /* Not ICMP */

    static int icmp_count = 0;
    static time_t icmp_window = 0;
    static char icmp_src[16] = "";

    time_t now = time(NULL);

    /* Reset if new second or new source */
    if (now > icmp_window || strcmp(icmp_src, pkt->src_ip) != 0) {
        icmp_count = 0;
        icmp_window = now;
        strncpy(icmp_src, pkt->src_ip, 15);
    }

    icmp_count++;

    int icmp_threshold = 100;  /* 100 pings/second is abnormal */
    if (icmp_count > icmp_threshold) {
        result->is_threat = 1;
        result->level = THREAT_HIGH;
        result->confidence = 0.88;

        snprintf(result->attack_type, sizeof(result->attack_type),
                 "ICMP Flood (Ping Flood)");
        snprintf(result->description, sizeof(result->description),
                 "ICMP flood from %s: %d ICMP packets/second to %s. "
                 "Bandwidth exhaustion attack.",
                 pkt->src_ip, icmp_count, pkt->dst_ip);
        return 1;
    }
    return 0;
}

/* =============================================================================
 * MAIN DETECTION FUNCTION
 * This is called for EVERY packet. It runs ALL detectors and returns
 * the most severe result.
 * ============================================================================= */

/*
 * run_signature_detection
 *
 * Runs all detectors on a packet.
 * If multiple detectors fire, returns the most severe one.
 *
 * PARAMS:
 *   pkt - the packet to analyze
 *
 * RETURNS:
 *   DetectionResult with findings (is_threat=0 if no threat found)
 */
DetectionResult run_signature_detection(const PacketInfo* pkt) {
    /* Start with a clean result (no threat) */
    DetectionResult result;
    memset(&result, 0, sizeof(DetectionResult));
    result.is_threat = 0;
    result.level = THREAT_NONE;
    result.confidence = 0.0;
    strncpy(result.src_ip, pkt->src_ip, 15);
    strncpy(result.dst_ip, pkt->dst_ip, 15);
    strcpy(result.attack_type, "Normal Traffic");
    strcpy(result.description, "No threats detected");

    /*
     * Array of detection functions.
     * We'll call each one and keep the most severe result.
     *
     * WHY USE AN ARRAY OF FUNCTION POINTERS?
     * Makes it easy to add new detectors: just add to this array!
     * No need to change the logic below.
     */
    typedef int (*DetectorFunc)(const PacketInfo*, DetectionResult*);
    DetectorFunc detectors[] = {
        detect_port_scan,
        detect_brute_force,
        detect_ddos,
        detect_null_scan,
        detect_syn_flood,
        detect_suspicious_port,
        detect_icmp_flood,
        NULL  /* Sentinel - marks end of array */
    };

    DetectionResult temp;

    /* Run each detector */
    for (int i = 0; detectors[i] != NULL; i++) {
        memset(&temp, 0, sizeof(DetectionResult));
        temp.level = THREAT_NONE;

        if (detectors[i](pkt, &temp)) {
            /* This detector fired! Keep if more severe than current result */
            if (temp.level > result.level) {
                result = temp;
                strncpy(result.src_ip, pkt->src_ip, 15);
                strncpy(result.dst_ip, pkt->dst_ip, 15);
            }
        }
    }

    return result;
}

/* =============================================================================
 * PRINT / DISPLAY FUNCTIONS
 * ============================================================================= */

void print_result(const DetectionResult* r, uint64_t packet_num) {
    if (!r->is_threat) {
        /* For normal packets, just show a dot to indicate processing */
        printf(".");
        fflush(stdout);
        return;
    }

    /* Color codes for terminal */
    const char* color;
    switch (r->level) {
        case THREAT_CRITICAL: color = "\033[1;31m"; break;  /* Bold Red */
        case THREAT_HIGH:     color = "\033[0;31m"; break;  /* Red */
        case THREAT_MEDIUM:   color = "\033[0;33m"; break;  /* Yellow */
        case THREAT_LOW:      color = "\033[0;34m"; break;  /* Blue */
        default:              color = "\033[0m";    break;  /* Reset */
    }
    const char* reset = "\033[0m";

    printf("\n");
    printf("%s========================================%s\n", color, reset);
    printf("%s  🚨 THREAT DETECTED - %s%s\n", color, threat_level_name(r->level), reset);
    printf("%s========================================%s\n", color, reset);
    printf("  Packet #:    %lu\n", packet_num);
    printf("  Attack Type: %s\n", r->attack_type);
    printf("  Source IP:   %s\n", r->src_ip);
    printf("  Target IP:   %s\n", r->dst_ip);
    printf("  Confidence:  %.0f%%\n", r->confidence * 100);
    printf("  Description: %s\n", r->description);
    printf("%s========================================%s\n\n", color, reset);
}

/* =============================================================================
 * TEST FUNCTION
 * Creates fake packets to verify our detectors work correctly
 * ============================================================================= */

void run_tests() {
    printf("================================================\n");
    printf("  SIGNATURE DETECTION ENGINE - WEEK 3 TEST\n");
    printf("================================================\n\n");

    uint64_t pkt_num = 0;
    int tests_passed = 0;
    int tests_total = 0;

    /* ---- Test 1: Normal HTTP traffic (should NOT trigger) ---- */
    tests_total++;
    printf("[Test 1] Normal HTTP traffic...\n");
    {
        PacketInfo pkt = {0};
        strcpy(pkt.src_ip, "192.168.1.100");
        strcpy(pkt.dst_ip, "93.184.216.34");
        pkt.src_port = 54321;
        pkt.dst_port = 80;   /* HTTP */
        pkt.protocol = 6;    /* TCP */
        pkt.flag_syn = 1;
        pkt.packet_size = 64;

        DetectionResult r = run_signature_detection(&pkt);
        pkt_num++;

        if (!r.is_threat) {
            printf("  ✅ PASS: Normal HTTP not flagged as threat\n\n");
            tests_passed++;
        } else {
            printf("  ❌ FAIL: Normal HTTP incorrectly flagged as: %s\n\n",
                   r.attack_type);
        }
    }

    /* ---- Test 2: NULL Scan (should trigger MEDIUM threat) ---- */
    tests_total++;
    printf("[Test 2] NULL scan packet (no TCP flags)...\n");
    {
        PacketInfo pkt = {0};
        strcpy(pkt.src_ip, "10.0.0.5");
        strcpy(pkt.dst_ip, "192.168.1.1");
        pkt.src_port = 60000;
        pkt.dst_port = 22;   /* SSH */
        pkt.protocol = 6;    /* TCP */
        /* All flags = 0 = NULL scan */
        pkt.packet_size = 40;

        DetectionResult r = run_signature_detection(&pkt);
        pkt_num++;

        if (r.is_threat && r.level == THREAT_MEDIUM) {
            printf("  ✅ PASS: NULL scan detected correctly\n");
            print_result(&r, pkt_num);
            tests_passed++;
        } else {
            printf("  ❌ FAIL: NULL scan not detected (or wrong level)\n\n");
        }
    }

    /* ---- Test 3: Port Scan simulation ---- */
    tests_total++;
    printf("[Test 3] Port scan (connecting to 25 different ports)...\n");
    {
        int scan_detected = 0;
        /* Simulate connecting to 25 different ports rapidly */
        for (int port = 1; port <= 25; port++) {
            PacketInfo pkt = {0};
            strcpy(pkt.src_ip, "172.16.0.5");
            strcpy(pkt.dst_ip, "192.168.1.1");
            pkt.src_port = 60000 + port;
            pkt.dst_port = port * 100;
            pkt.protocol = 6;
            pkt.flag_syn = 1;
            pkt.packet_size = 40;

            DetectionResult r = run_signature_detection(&pkt);
            pkt_num++;

            if (r.is_threat && strstr(r.attack_type, "Port Scan")) {
                scan_detected = 1;
                if (port == 21 || port == 25) {
                    printf("  ✅ PASS: Port scan detected after %d ports\n", port);
                    print_result(&r, pkt_num);
                }
            }
        }
        if (scan_detected) {
            tests_passed++;
        } else {
            printf("  ❌ FAIL: Port scan not detected\n\n");
        }
    }

    /* ---- Test 4: Suspicious port ---- */
    tests_total++;
    printf("[Test 4] Traffic to suspicious port 4444 (Metasploit)...\n");
    {
        PacketInfo pkt = {0};
        strcpy(pkt.src_ip, "192.168.1.200");
        strcpy(pkt.dst_ip, "10.0.0.100");
        pkt.src_port = 55555;
        pkt.dst_port = 4444;  /* Metasploit default */
        pkt.protocol = 6;
        pkt.flag_syn = 1;
        pkt.packet_size = 64;

        DetectionResult r = run_signature_detection(&pkt);
        pkt_num++;

        if (r.is_threat) {
            printf("  ✅ PASS: Suspicious port detected\n");
            print_result(&r, pkt_num);
            tests_passed++;
        } else {
            printf("  ❌ FAIL: Suspicious port not detected\n\n");
        }
    }

    /* ---- Test 5: Brute force SSH ---- */
    tests_total++;
    printf("[Test 5] SSH brute force (35 rapid connection attempts)...\n");
    {
        int bf_detected = 0;
        for (int attempt = 0; attempt < 35; attempt++) {
            PacketInfo pkt = {0};
            strcpy(pkt.src_ip, "45.33.32.156");  /* Fake attacker IP */
            strcpy(pkt.dst_ip, "192.168.1.10");
            pkt.src_port = 60000 + attempt;
            pkt.dst_port = 22;  /* SSH */
            pkt.protocol = 6;
            pkt.flag_syn = 1;
            pkt.packet_size = 64;

            DetectionResult r = run_signature_detection(&pkt);
            pkt_num++;

            if (r.is_threat && strstr(r.attack_type, "Brute Force")) {
                bf_detected = 1;
                if (attempt == 30) {
                    printf("  ✅ PASS: Brute force detected after %d attempts\n", attempt);
                    print_result(&r, pkt_num);
                }
            }
        }
        if (bf_detected) {
            tests_passed++;
        } else {
            printf("  ❌ FAIL: Brute force not detected\n\n");
        }
    }

    /* ---- Summary ---- */
    printf("\n================================================\n");
    printf("  TEST RESULTS: %d/%d PASSED\n", tests_passed, tests_total);
    if (tests_passed == tests_total) {
        printf("  ✅ ALL TESTS PASSED!\n");
        printf("  Detection engine is working correctly.\n");
        printf("  Ready to integrate with MPI in Week 4!\n");
    } else {
        printf("  ⚠️  Some tests failed. Review detection logic.\n");
    }
    printf("================================================\n");
}

int main() {
    run_tests();
    return 0;
}
