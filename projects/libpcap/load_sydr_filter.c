#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

int main(int argc, char** argv)
{
        pcap_t * pkts;
        struct bpf_program bpf;
        char * filter;

        FILE *fd = fopen(argv[1], "rb");

        if (fd == NULL) return 1;
        fseek(fd, 0, SEEK_END);
        int fsize = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        char* buffer = (char*) malloc(sizeof(char) * fsize);
        fread(buffer, 1, fsize, fd);
        fclose(fd);

        pkts = pcap_open_dead(buffer[fsize-1], 0xFFFF);
        if (pkts == NULL) {
                printf("pcap_open_dead failed\n");
                return 0;
        }
        filter = malloc(fsize);
        memcpy(filter, buffer, fsize);
        //null terminate string
        filter[fsize - 1] = 0;

        if (pcap_compile(pkts, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(pkts, &bpf);
                pcap_close(pkts);
                pcap_freecode(&bpf);
        }
        else {
                pcap_close(pkts);
        }
        free(filter);

        return 0;
}