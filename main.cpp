#include <iostream>
#include <string>

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
	string interface = argv[1];
    string pattern = argv[2];
    
	return 0;
}