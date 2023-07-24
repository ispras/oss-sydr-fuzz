// Copyright 2023 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//			http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <pcap/pcap.h>
#include <netdissect-stdinc.h>
#include <netdissect.h>
#include <print.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t packets_captured = 0;

void print_packet(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *sp) {
	++packets_captured;
	pretty_print_packet((netdissect_options *)user, h, sp, packets_captured);
}

FILE *bufferToFile(const uint8_t *Data, size_t Size) {
	FILE *fd;
	fd = tmpfile();
	if (fd == NULL) {
		perror("Error tmpfile");
		return NULL;
	}
	if (fwrite (Data, 1, Size, fd) != Size) {
		perror("Error fwrite");
		fclose(fd);
		return NULL;
	}
	rewind(fd);
	return fd;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	pcap_t * pkts;
	const u_char *pkt;
	struct pcap_pkthdr *header;
	int r = 0;
	int packets_captured = 0;
	char eBuf[PCAP_ERRBUF_SIZE];
	FILE *fd;
	int dlt;
	pcap_handler callback = print_packet;

	netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;

	if (nd_init(eBuf, sizeof(eBuf)) == -1)
		return 0;	
	memset(ndo, 0, sizeof(*ndo));
	ndo_set_function_pointers(ndo);
	
	ndo->ndo_bflag++;
	ndo->ndo_eflag++;
	ndo->ndo_fflag++;
	ndo->ndo_Kflag++;
	ndo->ndo_nflag++;
	ndo->ndo_Nflag++;
	ndo->ndo_qflag++;
	ndo->ndo_Sflag++;
	ndo->ndo_tflag++;
	ndo->ndo_uflag++;
	ndo->ndo_vflag++;
	ndo->ndo_xflag++;
	ndo->ndo_Xflag++;
	ndo->ndo_Aflag++;
	ndo->ndo_Hflag++;

#ifdef SYDR
	fd = fopen(Data, "r");
#else
	fd = bufferToFile(Data, Size);
#endif
 	if (fd == NULL)
		return 0;

	pkts = pcap_fopen_offline(fd, eBuf);
	if (pkts == NULL) {
			fclose(fd);
			return 0;
	}
	
	dlt = pcap_datalink(pkts);
	ndo->ndo_if_printer = get_if_printer(dlt);
	
	ndo->ndo_snaplen = MAXIMUM_SNAPLEN;

	pcap_loop(pkts, 1, callback, (u_char *)ndo);

	pcap_close(pkts);
 	nd_cleanup();	
	return 0;
}
