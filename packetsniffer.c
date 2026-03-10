#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <net/ethernet.h>

int main() {
    int raw_sock;
    char buffer[65536];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    // Create a raw socket to capture all packets
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("Socket Error");
        return 1;
    }

    printf("Packet Sniffer started... Press Ctrl+C to stop.\n");

    while (1) {
        // Receive a packet
        int data_size = recvfrom(raw_sock, buffer, sizeof(buffer), 0,
                                 &saddr, &saddr_len);

        // Handle minor read errors without stopping
        if (data_size < 0) {
            perror("Recvfrom error (continuing)");
            continue;  // Skip this packet and keep sniffing
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Check if it's an IP packet
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            struct sockaddr_in src, dest;
            src.sin_addr.s_addr = ip->saddr;
            dest.sin_addr.s_addr = ip->daddr;

            printf("\nPacket Length: %d bytes\n", data_size);
            printf("SRC IP: %s -> DST IP: %s\n",
                   inet_ntoa(src.sin_addr),
                   inet_ntoa(dest.sin_addr));

            // Identify protocol
            if (ip->protocol == IPPROTO_TCP) {
                printf("Protocol: TCP\n");
            } else if (ip->protocol == IPPROTO_UDP) {
                printf("Protocol: UDP\n");
            } else if (ip->protocol == IPPROTO_ICMP) {
                printf("Protocol: ICMP\n");
            } else {
                printf("Protocol: OTHER\n");
            }
        }
    }

    close(raw_sock);
    return 0;
}