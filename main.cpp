#include <iostream>
#include <string>
#include "mac.h"
#include <pcap.h>

using namespace std;

void usage() {
	cout << "syntax : tcp-block <interface> <pattern>\n";
	cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"";
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

		// Search if pattern is in packet
	}
    pcap_close(handle);
	return 0;
}