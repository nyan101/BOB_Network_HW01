pcapture: pcap_capture.c
	gcc -o pcapture pcap_capture.c -lpcap

clean:
	rm pcapture

