#include <iostream>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "ipv4hdr.h"
#include "tcphdr.h"
#include "bm.h"

using namespace std;

const string redirect_data ="HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
string pattern;

void usage() {
	cout << "syntax : tcp-block <interface> <pattern>\n";
	cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"";
}

bool search_pattern(const u_char* packet, BmCtx* ctx, int packet_len) {
	// Search pattern in packet
	// 1. parse tcp payload
    const u_char* data = packet + sizeof(EthHdr) + sizeof(IPv4Hdr) + sizeof(TcpHdr);
	uint16_t data_len = strlen((char*)data);

	// 2. boyer-moore search in payload
	char* found = (char*)BoyerMoore((uint8_t*)pattern.c_str(), strlen(pattern.c_str()), data, data_len, ctx);

	// 3. return if pattern is found
	if (found == NULL)
		return false;
	else{
		printf("found \n");
		return true;
	}
}

void block_packet (pcap_t* handle, const u_char* packet) {
	// Block packet & Redirect
}

int main(int argc, char* argv[]){
	if (argc != 3) {
		usage();
		return -1;
	}
	char* dev = argv[1];
    pattern = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// Boyer-Moore Init
	uint16_t pat_len = strlen(pattern.c_str());
	BmCtx* ctx = BoyerMooreCtxInit((uint8_t*)pattern.c_str(), pat_len);


	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);	
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}

		if (search_pattern(packet, ctx, header->caplen)) {
			// Block packet
			block_packet(handle ,packet);
		}
	}
    pcap_close(handle);
	BoyerMooreCtxDeInit(ctx);
	return 0;
}