#include "ethhdr.h"
#include "ipv4hdr.h"
#include "tcphdr.h"
#include <pcap.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>

using namespace std;
const string redirect_data = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

#pragma pack(push, 1) // Structure Padding Disable
typedef struct TcpPacketHdr
{
    EthHdr eth;
    IPv4Hdr ip;
    TcpHdr tcp;
} TcpPacketHdr;
#pragma pack(pop)

typedef struct PseudoHdr
{
    Ip src_ip;
    Ip dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
} PseudoHdr;

// Debug
void dump_packet(const u_char *packet, int length);

// Checksum
uint16_t ip_checksum(IPv4Hdr ipHeader);
uint16_t tcp_checksum(TcpPacketHdr *packet, int size);

// Main Logic (Send Forward & Backward Packet)
void block_packet(pcap_t *handle, const u_char *packet, int size);