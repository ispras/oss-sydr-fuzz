#define NDPI_LIB_COMPILATION

#include "fuzz_common_code.h"
#include "ndpi_api.h"

#include <stdint.h>
#include <stdio.h>

extern void
processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct,
                           struct ndpi_flow_struct *flow, u_int16_t p_offset,
                           u_int16_t certificate_len);
struct ndpi_tcphdr tcph;
struct ndpi_iphdr iph;
struct ndpi_ipv6hdr iphv6;

struct ndpi_detection_module_struct *ndpi_struct = NULL;
struct ndpi_flow_struct *ndpi_flow = NULL;

int main(int argc, char **argv) {
        struct ndpi_packet_struct *packet;
        int is_ipv6;

        fuzz_init_detection_module(&ndpi_struct);
        ndpi_flow = ndpi_calloc(1, sizeof(struct ndpi_flow_struct));

        FILE *fd = fopen(argv[1], "rb");
        if (fd == NULL) return 1;
        fseek(fd, 0, SEEK_END);
        size_t size = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        unsigned char *data = (unsigned char *)malloc(sizeof(unsigned char) * size);
        fread(data, 1, size, fd);
        fclose(fd);

        if (size == 0) return -1;

        packet = &ndpi_struct->packet;
        packet->payload = data;
        packet->payload_packet_len = size;
        is_ipv6 = data[size - 1] % 5 ? 1 : 0; /* "Random" ipv4 vs ipv6 */
        packet->iphv6 = is_ipv6 ? &iphv6 : NULL;
        packet->iph = is_ipv6 ? NULL : &iph;
        packet->tcp = &tcph;

        memset(ndpi_flow, 0, sizeof(struct ndpi_flow_struct));
        strcpy(ndpi_flow->host_server_name, "doh.opendns.com");
        ndpi_flow->detected_protocol_stack[0] = NDPI_PROTOCOL_TLS;

        processCertificateElements(ndpi_struct, ndpi_flow, 0, size);
        ndpi_free_flow_data(ndpi_flow);

        return 0;
}