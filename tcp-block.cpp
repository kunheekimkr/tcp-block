#include "tcp-block.h"
#include <iostream>

void dump_packet(const u_char *packet, int length)
{
    for (int i = 0; i < length; i++)
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

uint16_t ip_checksum(IPv4Hdr ipHeader)
{
    // set checksum field to zero
    ipHeader.ip_sum = 0;

    // split ip header into 16bit chunks
    uint16_t *ipHeader16 = (uint16_t *)&ipHeader;
    uint32_t sum = 0;

    // add all 16bit chunks
    for (int i = 0; i < 10; i++)
    {
        sum += ntohs(ipHeader16[i]);
    }

    // add carry
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // return checksum
    return htons((uint16_t)~sum);
}

uint16_t tcp_checksum(TcpPacketHdr *packet, int size)
{
    // 0. set checksum field to zero
    packet->tcp.th_sum = 0;

    // 1. make pseudo header
    PseudoHdr pseudoHdr;
    pseudoHdr.src_ip = packet->ip.ip_src;
    pseudoHdr.dst_ip = packet->ip.ip_dst;
    pseudoHdr.reserved = 0;
    pseudoHdr.protocol = packet->ip.ip_p;
    pseudoHdr.tcp_len = ntohs(size);

    // 2. split pseudo header into 16bit chunks and add all 16bit chunks
    uint32_t sum = 0;
    uint16_t *pseudoHdr16 = (uint16_t *)&pseudoHdr;
    for (int i = 0; i < 6; i++)
    {
        sum += ntohs(pseudoHdr16[i]);
    }

    // 3. add carry
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 4. split tcp header + data into 16bit chunks and add all 16bit chunks
    uint16_t *tcp16 = (uint16_t *)&packet->tcp;
    for (int i = 0; i < size / 2; i++)
    {
        sum += ntohs(tcp16[i]);

        // 4-1. add carry
        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // 4-2. handle where last 16bit chunk is odd
    if (size % 2 == 1)
    {
        sum += ntohs(tcp16[size / 2]);
    }

    // 5. calculate checksum
    uint16_t checksum = (uint16_t)~sum;
    return ntohs(checksum);
}

void block_packet(pcap_t *handle, const u_char *packet, int size)
{
    // 1. forward packet (RST Flag)
    // It is okay to discard Payload Data!
    TcpPacketHdr *packet_forward = (TcpPacketHdr *)malloc(sizeof(TcpPacketHdr));
    memcpy(packet_forward, packet, sizeof(TcpPacketHdr));

    packet_forward->ip.ip_len = htons(sizeof(IPv4Hdr) + sizeof(TcpHdr));
    packet_forward->tcp.th_off = 5;
    packet_forward->tcp.th_flags = TH_RST | TH_ACK;

    // Update Checksums
    packet_forward->ip.ip_sum = ip_checksum(packet_forward->ip);
    packet_forward->tcp.th_sum = tcp_checksum(packet_forward, sizeof(TcpHdr));

    // Send Forward Packet
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet_forward), sizeof(TcpPacketHdr));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // 2. backward packet (FIN Flag + redirect data)
    TcpPacketHdr *packet_backward = (TcpPacketHdr *)malloc(sizeof(TcpPacketHdr) + redirect_data.length());
    memcpy(packet_backward, packet, sizeof(TcpPacketHdr));

    // Update Ethernet Header
    packet_backward->eth.dmac_ = packet_backward->eth.smac_;

    // Update IP Header
    packet_backward->ip.ip_len = htons(sizeof(IPv4Hdr) + sizeof(TcpHdr) + redirect_data.length());
    packet_backward->ip.ip_ttl = 128;
    Ip tmp_ip = packet_backward->ip.ip_src;
    packet_backward->ip.ip_src = packet_backward->ip.ip_dst;
    packet_backward->ip.ip_dst = tmp_ip;

    // Update TCP Header
    uint16_t tmp_port = packet_backward->tcp.th_sport;
    packet_backward->tcp.th_sport = packet_backward->tcp.th_dport;
    packet_backward->tcp.th_dport = tmp_port;
    // SYN, ACK
    uint32_t tmp_seq = packet_backward->tcp.th_seq;
    packet_backward->tcp.th_seq = packet_backward->tcp.th_ack;
    // Calculate data payload lenth of original packet (To update ACK)
    uint16_t data_len = ntohs(packet_backward->ip.ip_len) - sizeof(IPv4Hdr) - packet_backward->tcp.th_off * 4;
    packet_backward->tcp.th_ack = tmp_seq + htonl(data_len);
    packet_backward->tcp.th_off = 5;
    packet_backward->tcp.th_flags = TH_FIN | TH_ACK;

    // Add redirect data
    memcpy((char *)packet_backward + sizeof(TcpPacketHdr), redirect_data.c_str(), redirect_data.length());

    // Update Checksums
    packet_backward->ip.ip_sum = ip_checksum(packet_backward->ip);
    packet_backward->tcp.th_sum = tcp_checksum(packet_backward, sizeof(TcpHdr) + redirect_data.length());

    // Send Backward Packet With Raw Socket

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
    {
        std::cerr << "Failed to create socket." << std::endl;
        return;
    }

    // Set socket options to enable IP headers inclusion
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        std::cerr << "Failed to set socket options." << std::endl;
        return;
    }

    // Prepare destination address structure
    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = packet_backward->tcp.th_dport;
    destAddr.sin_addr.s_addr = packet_backward->ip.ip_dst;

    // Create TCP packet
    char rawpacket[4096];
    memset(rawpacket, 0, sizeof(rawpacket));

    // IP header
    struct IPv4Hdr *ipHeader = (struct IPv4Hdr *)rawpacket;
    memcpy(ipHeader, &(packet_backward->ip), sizeof(IPv4Hdr));

    // TCP header
    struct TcpHdr *tcpHeader = (struct TcpHdr *)(rawpacket + sizeof(struct IPv4Hdr));
    memcpy(tcpHeader, &(packet_backward->tcp), sizeof(TcpHdr));

    // TCP payload (HTTP response)
    char *payload = rawpacket + sizeof(struct IPv4Hdr) + sizeof(struct TcpHdr);
    strcpy(payload, redirect_data.c_str());

    // Send the packet
    if (sendto(sockfd, rawpacket, ntohs(ipHeader->ip_len), 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0)
    {
        std::cerr << "Failed to send packet." << std::endl;
        return;
    }

    printf("Redirected To http://warning.or.kr\n");

    // Close socket
    close(sockfd);
    free(packet_forward);
    free(packet_backward);
}