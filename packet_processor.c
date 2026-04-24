/*
 * Packet processor (C): captures TCP/UDP packets via libpcap and outputs
 * note commands (frequency Hz, duration ms) to stdout for a player to sonify.
 * Build: make (or gcc -o packet_processor packet_processor.c -lpcap)
 * Run: sudo ./packet_processor [interface]   (omit interface to use default)
 */

#define _DARWIN_C_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>
#include <unistd.h>

/* A4 = 440 Hz; 12 semitones per octave */
#define A4_HZ      440.0
#define SEMITONE   1.059463094359  /* 2^(1/12) */

/* Note mapping: port mod 12 -> semitone offset from base; TCP vs UDP -> octave */
#define MIN_DURATION_MS  30
#define MAX_DURATION_MS  200
#define MIN_FREQ_HZ      110.0
#define MAX_FREQ_HZ      880.0

/* Ethernet header length (standard 802.3) — avoid redefining the system macro */
#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN  14
#endif

static double clamp(double v, double lo, double hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

/*
 * Map a TCP or UDP packet to a musical note.
 *
 * Frequency: derived from the destination port modulo 12 (chromatic semitone
 *            within an octave), offset from A4.
 * Octave:    TCP packets sound in the lower octave (octave offset 0),
 *            UDP packets sound in the upper octave (octave offset +12 semitones).
 * Duration:  proportional to the IP total length, clamped to [MIN, MAX] ms.
 */
static void port_to_note(int is_tcp, uint16_t port, uint16_t ip_len,
                          double *freq_out, int *dur_out)
{
    /* Semitone within octave: port mod 12, centred on A4 */
    int semitone_offset = (int)(port % 12) - 6;   /* -6 … +5  */

    /* UDP sounds an octave higher than TCP */
    int octave = is_tcp ? 0 : 12;

    double freq = A4_HZ * pow(SEMITONE, semitone_offset + octave);
    *freq_out = clamp(freq, MIN_FREQ_HZ, MAX_FREQ_HZ);

    /* Duration: scale IP payload length linearly into [MIN, MAX] ms */
    int dur = MIN_DURATION_MS +
              (int)((ip_len > 40 ? ip_len - 40 : 0) *
                    (MAX_DURATION_MS - MIN_DURATION_MS) / 1460.0);
    *dur_out = dur < MIN_DURATION_MS ? MIN_DURATION_MS :
               (dur > MAX_DURATION_MS ? MAX_DURATION_MS : dur);
}

/* pcap callback — called for every captured packet */
static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr,
                            const u_char *pkt)
{
    (void)user;

    /* Require a full Ethernet + IP header */
    if (hdr->caplen < (unsigned)(ETHER_HDR_LEN + (int)sizeof(struct ip)))
        return;

    const struct ip *ip_hdr = (const struct ip *)(pkt + ETHER_HDR_LEN);

    /* Only handle IPv4 */
    if (ip_hdr->ip_v != 4)
        return;

    int ip_hlen = ip_hdr->ip_hl * 4;
    uint16_t ip_len = ntohs(ip_hdr->ip_len);

    double freq = 0.0;
    int    dur  = 0;
    const char *proto_name = NULL;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        /* Need at least the TCP header */
        if (hdr->caplen < (unsigned)(ETHER_HDR_LEN + ip_hlen + (int)sizeof(struct tcphdr)))
            return;
        const struct tcphdr *tcp =
            (const struct tcphdr *)(pkt + ETHER_HDR_LEN + ip_hlen);
        port_to_note(1, ntohs(tcp->th_dport), ip_len, &freq, &dur);
        proto_name = "tcp";

    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        /* Need at least the UDP header */
        if (hdr->caplen < (unsigned)(ETHER_HDR_LEN + ip_hlen + (int)sizeof(struct udphdr)))
            return;
        const struct udphdr *udp =
            (const struct udphdr *)(pkt + ETHER_HDR_LEN + ip_hlen);
        port_to_note(0, ntohs(udp->uh_dport), ip_len, &freq, &dur);
        proto_name = "udp";

    } else {
        return;  /* skip non-TCP/UDP */
    }

    /* Emit NOTE line: "NOTE <proto> <freq> <duration_ms>" */
    printf("NOTE %s %.1f %d\n", proto_name, freq, dur);
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = NULL;

    if (argc >= 2) {
        iface = argv[1];
    } else {
        /* pcap_lookupdev is deprecated but still works; fall back to pcap_findalldevs */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        iface = pcap_lookupdev(errbuf);
#pragma clang diagnostic pop
        if (!iface) {
            /* Try pcap_findalldevs as a fallback */
            pcap_if_t *devs = NULL;
            if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
                /* Use the first non-loopback device */
                for (pcap_if_t *d = devs; d; d = d->next) {
                    if (!(d->flags & PCAP_IF_LOOPBACK)) {
                        iface = d->name;
                        break;
                    }
                }
                if (!iface && devs)
                    iface = devs->name;  /* last resort: use whatever is first */
                /* Note: devs is not freed here intentionally (short-lived process) */
            }
        }
        if (!iface) {
            fprintf(stderr, "packet_processor: no network interface found: %s\n", errbuf);
            return 1;
        }
    }

    fprintf(stderr, "packet_processor: opening interface '%s'\n", iface);

    /* Open the interface in promiscuous mode, 65535 byte snap, 100 ms timeout */
    pcap_t *handle = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "packet_processor: pcap_open_live(%s): %s\n", iface, errbuf);
        return 1;
    }

    /* Filter: capture only TCP and UDP */
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp or udp", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "packet_processor: pcap_compile: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "packet_processor: pcap_setfilter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&fp);

    fprintf(stderr, "packet_processor: capturing TCP/UDP on '%s' — press Ctrl-C to stop\n",
            iface);

    /* Capture loop — runs until error or SIGINT */
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
