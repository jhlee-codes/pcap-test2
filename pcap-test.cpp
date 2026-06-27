#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHERTYPE_IP 0x0800
#define MAX_PAYLOAD_PRINT 20

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }

    param->dev_ = argv[1];
    return true;
}

#pragma pack(push, 1)

struct ethernet_hdr {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct ip_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

#pragma pack(pop)

void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const uint8_t* payload, int payload_len) {
    int print_len = payload_len;

    if (print_len > MAX_PAYLOAD_PRINT)
        print_len = MAX_PAYLOAD_PRINT;

    printf("Payload(%d bytes): ", payload_len);

    for (int i = 0; i < print_len; i++) {
        printf("%02x ", payload[i]);
    }

    printf("\n");
}

void print_packet_info(const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < sizeof(struct ethernet_hdr))
        return;

    struct ethernet_hdr* eth = (struct ethernet_hdr*)packet;

    if (ntohs(eth->type) != ETHERTYPE_IP)
        return;

    if (header->caplen < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr))
        return;

    struct ip_hdr* ip = (struct ip_hdr*)(packet + sizeof(struct ethernet_hdr));

    int ip_version = ip->ver_ihl >> 4;
    if (ip_version != 4)
        return;

    if (ip->protocol != IPPROTO_TCP)
        return;

    int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

    if (ip_header_len < 20)
        return;

    if (header->caplen < sizeof(struct ethernet_hdr) + ip_header_len + sizeof(struct tcp_hdr))
        return;

    struct tcp_hdr* tcp = (struct tcp_hdr*)(packet + sizeof(struct ethernet_hdr) + ip_header_len);

    int tcp_header_len = ((tcp->offset_reserved >> 4) & 0x0F) * 4;

    if (tcp_header_len < 20)
        return;

    int payload_offset = sizeof(struct ethernet_hdr) + ip_header_len + tcp_header_len;

    if ((int)header->caplen < payload_offset)
        return;

    const uint8_t* payload = packet + payload_offset;

    int ip_total_len = ntohs(ip->total_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    if (payload_len < 0)
        return;

    if ((int)header->caplen < payload_offset + payload_len) {
        payload_len = (int)header->caplen - payload_offset;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->dst_ip, dst_ip, sizeof(dst_ip));

    printf("========================================\n");

    printf("Ethernet Header\n");
    printf("  Src MAC: ");
    print_mac(eth->src_mac);
    printf("\n");

    printf("  Dst MAC: ");
    print_mac(eth->dst_mac);
    printf("\n");

    printf("IP Header\n");
    printf("  Src IP : %s\n", src_ip);
    printf("  Dst IP : %s\n", dst_ip);

    printf("TCP Header\n");
    printf("  Src Port: %u\n", ntohs(tcp->src_port));
    printf("  Dst Port: %u\n", ntohs(tcp->dst_port));

    printf("Data\n");
    print_payload(payload, payload_len);

    printf("========================================\n\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0)
            continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        print_packet_info(header, packet);
    }

    pcap_close(pcap);
    return 0;
}
