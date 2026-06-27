all: pcap-test

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.cpp
	g++ -c -o pcap-test.o pcap-test.cpp

clean:
	rm -f pcap-test
	rm -f *.o
