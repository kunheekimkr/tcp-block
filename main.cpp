#include <iostream>
#include <string>
#include <pcap.h>

using namespace std;

const string redirect_data ="HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

void usage() {
	cout << "syntax : tcp-block <interface> <pattern>\n";
	cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"";
}

bool search_pattern(const u_char* packet, string pattern) {
	// Search pattern in packet
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
    string pattern = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);	
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}

		if (search_pattern(packet, pattern)) {
			// Block packet
			block_packet(handle ,packet);
		}
	}
    pcap_close(handle);
	return 0;
}