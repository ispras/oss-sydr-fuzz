/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerParserParse
 */

#include "suricata-common.h"
#include "suricata.h"
#include "app-layer-detect-proto.h"
#include "flow-util.h"
#include "app-layer-parser.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "conf-yaml-loader.h"
#include "util-conf.h"

#define HEADER_LEN 6

int LLVMFuzzerInitialize(int argc, char **argv);

AppLayerParserThreadCtx *alp_tctx = NULL;

#include "confyaml.c"

/* input buffer is structured this way :
 * 6 bytes header,
 * then sequence of buffers separated by magic bytes 01 D5 CA 7A */

/* The 6 bytes header is
 * alproto
 * proto
 * source port (uint16_t)
 * destination port (uint16_t) */

const uint8_t separator[] = {0x01, 0xD5, 0xCA, 0x7A};
SCInstance surifuzz;
AppProto forceLayer = 0;
SC_ATOMIC_EXTERN(unsigned int, engine_stage);

int LLVMFuzzerInitialize(int argc, char **argv)
{
    char *target_suffix = strrchr(argv[0], '_');
    if (target_suffix != NULL) {
        AppProto applayer = StringToAppProto(target_suffix + 1);
        if (applayer != ALPROTO_UNKNOWN) {
            forceLayer = applayer;
            printf("Forcing %s=%" PRIu16 "\n", AppProtoToString(forceLayer), forceLayer);
            return 0;
        }
    }
    // else
    const char *forceLayerStr = getenv("FUZZ_APPLAYER");
    if (forceLayerStr) {
        if (ByteExtractStringUint16(&forceLayer, 10, 0, forceLayerStr) < 0) {
            forceLayer = 0;
            printf("Invalid numeric value for FUZZ_APPLAYER environment variable");
        } else {
            printf("Forcing %s\n", AppProtoToString(forceLayer));
        }
    }
    // http is the output name, but we want to fuzz HTTP1
    if (forceLayer == ALPROTO_HTTP) {
        forceLayer = ALPROTO_HTTP1;
    }
    return 0;
}

// arbitrary value
#define ALPROTO_MAXTX 4096

int main(int argc, char **argv)
{
    LLVMFuzzerInitialize(argc, argv);
    Flow * f;
    TcpSession ssn;
    const uint8_t * albuffer;
    uint8_t * alnext;
    size_t alsize;
    // used to find under and overflows
    // otherwise overflows do not fail as they read the next packet
    uint8_t * isolatedBuffer;

    if (alp_tctx == NULL) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();
        run_mode = RUNMODE_PCAP_FILE;
        GlobalsInitPreConfig();

        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        // disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }

        PostConfLoadedSetup(&surifuzz);
        alp_tctx = AppLayerParserThreadCtxAlloc();
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

    if (data[0] >= ALPROTO_MAX) {
	free(data);
        return 0;
    }
    //no UTHBuildFlow to have storage
    f = FlowAlloc();
    if (f == NULL) {
	free(data);
        return 0;
    }
    f->flags |= FLOW_IPV4;
    f->src.addr_data32[0] = 0x01020304;
    f->dst.addr_data32[0] = 0x05060708;
    f->sp = (uint16_t)((data[2] << 8) | data[3]);
    f->dp = (uint16_t)((data[4] << 8) | data[5]);
    f->proto = data[1];
    memset(&ssn, 0, sizeof(TcpSession));
    f->protoctx = &ssn;
    f->protomap = FlowGetProtoMapping(f->proto);
    if (forceLayer > 0) {
        f->alproto = forceLayer;
    } else {
        f->alproto = data[0];
    }

    FLOWLOCK_WRLOCK(f);
    /*
     * We want to fuzz multiple calls to AppLayerParserParse
     * because some parts of the code are only reached after
     * multiple packets (in SMTP for example).
     * So we treat our input as a list of buffers with magic separator.
     */
    albuffer = data + HEADER_LEN;
    alsize = size - HEADER_LEN;
    uint8_t flags = STREAM_START;
    int flip = 0;
    alnext = memmem(albuffer, alsize, separator, 4);
    while (alnext) {
        if (flip) {
            flags |= STREAM_TOCLIENT;
            flags &= ~(STREAM_TOSERVER);
            flip = 0;
        } else {
            flags |= STREAM_TOSERVER;
            flags &= ~(STREAM_TOCLIENT);
            flip = 1;
        }

        if (alnext != albuffer) {
            // only if we have some data
            isolatedBuffer = malloc(alnext - albuffer);
            if (isolatedBuffer == NULL) {
                goto bail;
            }
            memcpy(isolatedBuffer, albuffer, alnext - albuffer);
            (void) AppLayerParserParse(NULL, alp_tctx, f, f->alproto, flags, isolatedBuffer, alnext - albuffer);
            free(isolatedBuffer);
            if (FlowChangeProto(f)) {
                // exits if a protocol change is requested
                alsize = 0;
                break;
            }
            flags &= ~(STREAM_START);
            if (f->alparser &&
                   (((flags & STREAM_TOSERVER) != 0 &&
                     AppLayerParserStateIssetFlag(f->alparser, APP_LAYER_PARSER_EOF_TS)) ||
                    ((flags & STREAM_TOCLIENT) != 0 &&
                     AppLayerParserStateIssetFlag(f->alparser, APP_LAYER_PARSER_EOF_TC)))) {
                //no final chunk
                alsize = 0;
                break;
            }

            AppLayerParserTransactionsCleanup(f, flags & (STREAM_TOSERVER | STREAM_TOCLIENT));
        }
        alsize -= alnext - albuffer + 4;
        albuffer = alnext + 4;
        if (alsize == 0) {
            break;
        }
        alnext = memmem(albuffer, alsize, separator, 4);
    }
    if (alsize > 0 ) {
        if (flip) {
            flags |= STREAM_TOCLIENT;
            flags &= ~(STREAM_TOSERVER);
            flip = 0;
        } else {
            flags |= STREAM_TOSERVER;
            flags &= ~(STREAM_TOCLIENT);
            flip = 1;
        }
        flags |= STREAM_EOF;
        isolatedBuffer = malloc(alsize);
        if (isolatedBuffer == NULL) {
            goto bail;
        }
        memcpy(isolatedBuffer, albuffer, alsize);
        (void) AppLayerParserParse(NULL, alp_tctx, f, f->alproto, flags, isolatedBuffer, alsize);
        free(isolatedBuffer);
    }

bail:
    FLOWLOCK_UNLOCK(f);
    FlowFree(f);
    free(data);
    return 0;
}

