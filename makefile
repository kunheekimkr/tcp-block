LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o ip.o mac.o ethhdr.o ipv4hdr.o tcphdr.o bm.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o 