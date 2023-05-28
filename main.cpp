#include <iostream>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "ipv4hdr.h"
#include "tcphdr.h"
#include "bm.h"

using namespace std;

const string redirect_data = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
string pattern;

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

void usage()
{
	cout << "syntax : tcp-block <interface> <pattern>\n";
	cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"";
}

bool search_pattern(const u_char *packet, BmCtx *ctx)
{
	// Search pattern in packet
	// 1. parse tcp payload
	const u_char *data = packet + sizeof(TcpPacketHdr);
	uint16_t data_len = strlen((char *)data);

	// 2. boyer-moore search in payload
	char *found = (char *)BoyerMoore((uint8_t *)pattern.c_str(), strlen(pattern.c_str()), data, data_len, ctx);

	// 3. return true if pattern is found
	if (found == NULL)
		return false;
	else
	{
		printf("found packet with pattern!\n");
		return true;
	}
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
		// Debug : print tcp16[i]
		printf("%04x\n", ntohs(tcp16[i]));

		sum += ntohs(tcp16[i]);

		// 4-1. add carry
		while (sum >> 16)
		{
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
	}

	// handle where last 16bit chunk is odd
	if (size % 2 == 1)
	{
		printf("%04x\n", ntohs(tcp16[size / 2] << 8));
		sum += ntohs(tcp16[size / 2]);
	}
	printf("\n\n\n\n");
	// 5. calculate checksum
	uint16_t checksum = (uint16_t)~sum;
	return ntohs(checksum);
}

void send_packet(pcap_t *handle, TcpPacketHdr *packet, int size)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet), size);
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void block_packet(pcap_t *handle, const u_char *packet, int size)
{
	// 1. forward packet (RST Flag)
	// It is okay to discard Payload Data!
	TcpPacketHdr *packet_forward = (TcpPacketHdr *)malloc(sizeof(TcpPacketHdr));
	memcpy(packet_forward, packet, sizeof(TcpPacketHdr));

	packet_forward->ip.ip_len = htons(sizeof(IPv4Hdr) + sizeof(TcpHdr));
	packet_forward->tcp.th_seq += htons(size - sizeof(TcpPacketHdr));
	packet_forward->tcp.th_flags = TH_RST | TH_ACK;

	// Update Checksums
	packet_forward->ip.ip_sum = ip_checksum(packet_forward->ip);
	packet_forward->tcp.th_sum = tcp_checksum(packet_forward, sizeof(TcpHdr));
	send_packet(handle, packet_forward, sizeof(TcpPacketHdr));

	// 2. backward packet (FIN Flag + redirect data)

	TcpPacketHdr *packet_backward = (TcpPacketHdr *)malloc(sizeof(TcpPacketHdr) + redirect_data.length());
	memcpy(packet_backward, packet, sizeof(TcpPacketHdr));

	packet_backward->eth.dmac_ = packet_backward->eth.smac_;

	packet_backward->ip.ip_len = htons(sizeof(IPv4Hdr) + sizeof(TcpHdr) + redirect_data.length());
	packet_backward->ip.ip_ttl = 128;
	Ip tmp_ip = packet_backward->ip.ip_src;
	packet_backward->ip.ip_src = packet_backward->ip.ip_dst;
	packet_backward->ip.ip_dst = tmp_ip;

	uint16_t tmp_port = packet_backward->tcp.th_sport;
	packet_backward->tcp.th_sport = packet_backward->tcp.th_dport;
	packet_backward->tcp.th_dport = tmp_port;
	packet_backward->tcp.th_seq = packet_forward->tcp.th_ack;
	packet_backward->tcp.th_ack = packet_forward->tcp.th_seq;
	packet_backward->tcp.th_flags = TH_FIN | TH_ACK;

	// Add redirect data
	memcpy((char *)packet_backward + sizeof(TcpPacketHdr), redirect_data.c_str(), redirect_data.length());
	// Update Checksums
	packet_backward->ip.ip_sum = ip_checksum(packet_backward->ip);
	packet_backward->tcp.th_sum = tcp_checksum(packet_backward, sizeof(TcpHdr) + redirect_data.length());

	send_packet(handle, packet_backward, sizeof(TcpPacketHdr) + redirect_data.length());

	free(packet_forward);
	free(packet_backward);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		usage();
		return -1;
	}
	char *dev = argv[1];
	pattern = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// Boyer-Moore Init
	uint16_t pat_len = strlen(pattern.c_str());
	BmCtx *ctx = BoyerMooreCtxInit((uint8_t *)pattern.c_str(), pat_len);

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}

		if (search_pattern(packet, ctx))
		{
			block_packet(handle, packet, header->caplen);
		}
	}
	pcap_close(handle);
	BoyerMooreCtxDeInit(ctx);
	return 0;
}