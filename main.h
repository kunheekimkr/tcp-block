#include "ethhdr.h"
#include "ipv4hdr.h"
#include "tcphdr.h"

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