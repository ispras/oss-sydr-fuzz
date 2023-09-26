/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include "suricata-common.h"
#include "suricata.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer-parser.h"
#include "util-unittest-helper.h"
#include "conf-yaml-loader.h"

#define HEADER_LEN 6

//rule of thumb constant, so as not to timeout target
#define PROTO_DETECT_MAX_LEN 1024

#include "confyaml.c"

AppLayerProtoDetectThreadCtx *alpd_tctx = NULL;
SC_ATOMIC_EXTERN(unsigned int, engine_stage);

int main(int argc, char **argv)
{
    Flow *f;
    TcpSession ssn;
    bool reverse;
    AppProto alproto;
    AppProto alproto2;

    if (alpd_tctx == NULL) {
        //global init
        InitGlobal();
        run_mode = RUNMODE_UNITTEST;
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        MpmTableSetup();
        SpmTableSetup();
        EngineModeSetIDS();
        AppLayerProtoDetectSetup();
        AppLayerParserSetup();
        AppLayerParserRegisterProtocolParsers();
        alpd_tctx = AppLayerProtoDetectGetCtxThread();
        SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
    }

    FILE *fd = fopen(argv[1], "rb");

    if (fd == NULL) return 1;
    fseek(fd, 0, SEEK_END);
    size_t size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    unsigned char* data = (unsigned char*) malloc(sizeof(unsigned char) * size);
    fread(data, 1, size, fd);
    fclose(fd);

    if (size < HEADER_LEN) {
	free(data);
        return 0;
    }

    f = TestHelperBuildFlow(AF_INET, "1.2.3.4", "5.6.7.8", (uint16_t)((data[2] << 8) | data[3]),
            (uint16_t)((data[4] << 8) | data[5]));
    if (f == NULL) {
	free(data);
        return 0;
    }
    f->proto = data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);

    uint8_t flags = STREAM_TOCLIENT;
    if (data[0] & STREAM_TOSERVER) {
        flags = STREAM_TOSERVER;
    }
    alproto = AppLayerProtoDetectGetProto(
            alpd_tctx, f, data + HEADER_LEN, size - HEADER_LEN, f->proto, flags, &reverse);
    if (alproto != ALPROTO_UNKNOWN && alproto != ALPROTO_FAILED && f->proto == IPPROTO_TCP) {
        /* If we find a valid protocol at the start of a stream :
         * check that with smaller input
         * we find the same protocol or ALPROTO_UNKNOWN.
         * Otherwise, we have evasion with TCP splitting
         */
        for (size_t i = 0; i < size-HEADER_LEN && i < PROTO_DETECT_MAX_LEN; i++) {
            // reset detection at each try cf probing_parser_toserver_alproto_masks
            AppLayerProtoDetectReset(f);
            alproto2 = AppLayerProtoDetectGetProto(
                    alpd_tctx, f, data + HEADER_LEN, i, f->proto, flags, &reverse);
            if (alproto2 != ALPROTO_UNKNOWN && alproto2 != alproto) {
                printf("Failed with input length %" PRIuMAX " versus %" PRIuMAX
                       ", found %s instead of %s\n",
                        (uintmax_t)i, (uintmax_t)size - HEADER_LEN, AppProtoToString(alproto2),
                        AppProtoToString(alproto));
                printf("Assertion failure: %s-%s\n", AppProtoToString(alproto2),
                        AppProtoToString(alproto));
                fflush(stdout);
		free(data);
                abort();
            }
        }
    }
    FlowFree(f);
    free(data);
    return 0;
}

