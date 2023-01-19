all: snifferNspoofer sniffer spoofer #docker gateway

sniffer: sniffer.o
	gcc sniffer.o -o sniffer -lpcap

sniffer.o: sniffer.c
	gcc -c sniffer.c -o sniffer.o -lpcap

spoofer: spoofer.o
	gcc spoofer.o -o spoofer -lpcap

spoofer.o: spoofer.c
	gcc -Wall -g -c spoofer.c -o spoofer.o -lpcap

snifferNspoofer.o: snifferNspoofer.c
	gcc -Wall -g -c snifferNspoofer.c -o snifferNspoofer.o -lpcap

snifferNspoofer: snifferNspoofer.o
	gcc snifferNspoofer.o -o snifferNspoofer -lpcap

.PHONEY: clean all

clean:
	rm -f *.o *.txt sniffer spoofer docker gateway