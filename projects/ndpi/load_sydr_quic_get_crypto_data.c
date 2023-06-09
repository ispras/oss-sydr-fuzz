#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
struct ndpi_flow_struct *flow = NULL;

extern const uint8_t *get_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow,
				      uint32_t version,
				      u_int8_t *clear_payload, uint32_t clear_payload_len,
				      uint64_t *crypto_data_len);
extern void process_tls(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow,
			const u_int8_t *crypto_data, uint32_t crypto_data_len,
			uint32_t version);
extern void process_chlo(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow,
			 const u_int8_t *crypto_data, uint32_t crypto_data_len);
extern int is_version_with_tls(uint32_t version);


int main(int argc, char **argv)
{
        const u_int8_t *crypto_data;
        uint64_t crypto_data_len;
        u_int32_t first_int, version = 0;

        fuzz_init_detection_module(&ndpi_info_mod);
        flow = ndpi_calloc(1, SIZEOF_FLOW_STRUCT);

        FILE *fd = fopen(argv[1], "rb");
        if (fd == NULL) return 1;
        fseek(fd, 0, SEEK_END);
        size_t Size = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        unsigned char* Data = (unsigned char*) malloc(sizeof(unsigned char) * Size);
        fread(Data, 1, Size, fd);
        fclose(fd);


        if(Size < 4) {
                free(Data);
                return 0;
        }
        
        first_int = ntohl(*(u_int32_t *)Data);
        if((first_int % 4) == 0)
                version = 0x00000001; /* v1 */
        else if((first_int % 4) == 1)
                version = 0x51303530; /* Q050 */
        else if((first_int % 4) == 2)
                version = 0x51303436; /* Q046 */
        else if((first_int % 4) == 3)
                version = 0x709A50C4; /* v2 */

        memset(flow, '\0', sizeof(*flow));
        flow->detected_protocol_stack[0] = NDPI_PROTOCOL_QUIC;
        flow->l4_proto = IPPROTO_UDP;

        crypto_data = get_crypto_data(ndpi_info_mod, flow, version, (u_int8_t *)Data + 4, Size - 4, &crypto_data_len);

        if(crypto_data) {
                if(!is_version_with_tls(version)) {
                        process_chlo(ndpi_info_mod, flow, crypto_data, crypto_data_len);
                } else {
                        process_tls(ndpi_info_mod, flow, crypto_data, crypto_data_len, version);
                }
        }

        ndpi_free_flow_data(flow);
        free(Data);
        return 0;
}
