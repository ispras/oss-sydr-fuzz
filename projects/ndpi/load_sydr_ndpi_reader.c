#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>
#include <ndpi_api.h>
#include <reader_util.h>

struct ndpi_workflow_prefs *prefs = NULL;
struct ndpi_workflow *workflow = NULL;

int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t enable_flow_stats = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
ndpi_init_prefs init_prefs = ndpi_track_flow_payload | ndpi_enable_ja3_plus;
int enable_malloc_bins = 0;
int malloc_size_stats = 0;
int max_malloc_bins = 0;
struct ndpi_bin malloc_bins; /* unused */

int main(int argc, char** argv)
{
        pcap_t * pkts;
        const u_char *pkt;
        struct pcap_pkthdr *header;
        int r;
        char errbuf[PCAP_ERRBUF_SIZE];
        NDPI_PROTOCOL_BITMASK all;
        u_int i;
        if (prefs == NULL) {
                prefs = calloc(sizeof(struct ndpi_workflow_prefs), 1);
                if (prefs == NULL) {
                //should not happen
                return 1;
                }
                prefs->decode_tunnels = 1;
                prefs->num_roots = 16;
                prefs->max_ndpi_flows = 16 * 1024 * 1024;
                prefs->quiet_mode = 0;

                workflow = ndpi_workflow_init(prefs, NULL /* pcap handler will be set later */, 0, ndpi_serialization_format_json);
                // enable all protocols
                NDPI_BITMASK_SET_ALL(all);
                ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &all);
                memset(workflow->stats.protocol_counter, 0,
                        sizeof(workflow->stats.protocol_counter));
                memset(workflow->stats.protocol_counter_bytes, 0,
                        sizeof(workflow->stats.protocol_counter_bytes));
                memset(workflow->stats.protocol_flows, 0,
                        sizeof(workflow->stats.protocol_flows));
                ndpi_finalize_initialization(workflow->ndpi_struct);
        }

        pkts = pcap_open_offline(argv[1], errbuf);
        if (pkts == NULL) {
                return 0;
        }
        if (ndpi_is_datalink_supported(pcap_datalink(pkts)) == 0)
        {
                /* Do not fail if the datalink type is not supported (may happen often during fuzzing). */
                pcap_close(pkts);
                return 0;
        }

        workflow->pcap_handle = pkts;
        /* Init flow tree */
        workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

        header = NULL;
        r = pcap_next_ex(pkts, &header, &pkt);
        while (r > 0) {
                /* allocate an exact size buffer to check overflows */
                uint8_t *packet_checked = malloc(header->caplen);

                if(packet_checked) {
                        ndpi_risk flow_risk;

                        memcpy(packet_checked, pkt, header->caplen);
                        ndpi_workflow_process_packet(workflow, header, packet_checked, &flow_risk);
                        free(packet_checked);
                }

                r = pcap_next_ex(pkts, &header, &pkt);
        }
        pcap_close(pkts);

        /* Free flow trees */
        for(i = 0; i < workflow->prefs.num_roots; i++)
                ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
        ndpi_free(workflow->ndpi_flows_root);
        return 0;
}