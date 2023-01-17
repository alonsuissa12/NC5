all: sniffer spoofer #docker gateway

sniffer: sniffer.o
	gcc sniffer.o -o sniffer -lpcap

sniffer.o: sniffer.c
	gcc -c sniffer.c -o sniffer.o -lpcap

spoofer: spoofer.o
	gcc spoofer.o -o spoofer -lpcap

spoofer.o: spoofer.c
	gcc -Wall -g -c spoofer.c -o spoofer.o -lpcap

.PHONEY: clean all

clean:
	rm -f *.o *.txt sniffer spoofer docker gateway