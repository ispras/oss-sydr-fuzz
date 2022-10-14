#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <pcap/pcap.h>


int main(int argc, char** argv)
{
        pcap_t * pkts;
        char errbuf[PCAP_ERRBUF_SIZE];
        const u_char *pkt;
        struct pcap_pkthdr *header;
        struct pcap_stat stats;
        int r;

        //initialize structure
        pkts = pcap_open_offline(argv[1], errbuf);
        if (pkts == NULL) {
                printf("Couldn't open pcap file %s\n", errbuf);
                return 0;
        }

        //loop over packets
        r = pcap_next_ex(pkts, &header, &pkt);
        while (r > 0) {
                printf("packet length=%d/%d\n",header->caplen, header->len);
                r = pcap_next_ex(pkts, &header, &pkt);
        }
        if (pcap_stats(pkts, &stats) == 0) {
                printf("number of packets=%d\n", stats.ps_recv);
        }
        pcap_close(pkts);

    return 0;
}