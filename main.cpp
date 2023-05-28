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

typedef struct TcpPacketHdr
{
	EthHdr eth;
	IPv4Hdr ip;
	TcpHdr tcp;
} TcpPacketHdr;

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

uint16_t ip_checksum(TcpPacketHdr *packet)
{
}

uint32_t tcp_checksum(TcpPacketHdr *packet)
{
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
	packet_forward->ip.ip_sum = ip_checksum(packet_forward);
	packet_forward->tcp.th_sum = tcp_checksum(packet_forward);
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
	packet_backward->ip.ip_sum = ip_checksum(packet_backward);
	packet_backward->tcp.th_sum = tcp_checksum(packet_backward);

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