#pragma once
#include <cstdint>

/*
 *  TCP header
 *  Ref : http://packetfactory.openwall.net/projects/libnet/
 */

struct TcpHdr
{
    uint16_t th_sport; /* source port */
    uint16_t th_dport; /* destination port */
    uint32_t th_seq;   /* sequence number */
    uint32_t th_ack;   /* acknowledgement number */
    uint8_t th_x2 : 4, /* (unused) */
        th_off : 4;    /* data offset */
    uint8_t th_flags;  /* control flags */
    uint16_t th_win;   /* window */
    uint16_t th_sum;   /* checksum */
    uint16_t th_urp;   /* urgent pointer */

#define TH_FIN 0x01  /* finished send data */
#define TH_SYN 0x02  /* synchronize sequence numbers */
#define TH_RST 0x04  /* reset the connection */
#define TH_PUSH 0x08 /* push data to the app layer */
#define TH_ACK 0x10  /* acknowledge */
#define TH_URG 0x20  /* urgent! */
#define TH_ECE 0x40
#define TH_CWR 0x80
};