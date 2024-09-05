/* $OpenBSD: sshd-session.c,v 1.5 2024/07/08 03:04:34 djm Exp $ */
/*
 * SSH2 implementation:
 * Privilege Separation:
 *
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "FuzzedDataProvider.h"

#include <stddef.h>
#include <stdint.h>
#include <cstdlib>
#include <unistd.h>
 
#include "entropy.h"
//#include "sshbuf.h"
//#include "log.h"
//#include "msg.h"

extern "C" void
recv_rexec_state(int fd, struct sshbuf *conf, uint64_t *timing_secretp);
extern "C" struct sshbuf *sshbuf_new(void);
extern "C" int sshbuf_put_cstring(struct sshbuf *buf, const char *v);
extern "C" int	sshbuf_put_stringb(struct sshbuf *buf, const struct sshbuf *v);
extern "C" int	sshbuf_put_u64(struct sshbuf *buf, u_int64_t val);
extern "C" void	sshbuf_free(struct sshbuf *buf);
extern "C" int	 ssh_msg_send(int, u_char, struct sshbuf *);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider data_provider(data, size);
    const std::string sconfig = data_provider.ConsumeRandomLengthString().c_str(),
               spriv_key = data_provider.ConsumeRandomLengthString(8192).c_str(),
               spub_key = data_provider.ConsumeRandomLengthString(8192).c_str(),
               scert = data_provider.ConsumeRandomLengthString(8192).c_str();
    const char *config   =   sconfig.c_str(), 
               *priv_key = spriv_key.c_str(),
               *pub_key  =  spub_key.c_str(),
               *cert     =     scert.c_str();

    struct sshbuf *cfg, *inc, *hostkeys, *msg;
    if ((cfg = sshbuf_new()) == NULL || (inc = sshbuf_new()) == NULL ||
            (hostkeys = sshbuf_new()) == NULL || (msg = sshbuf_new()) == NULL)
        exit(1);
    
    sshbuf_put_cstring(cfg, config);

    sshbuf_put_cstring(hostkeys, priv_key);
    sshbuf_put_cstring(hostkeys, pub_key);
    sshbuf_put_cstring(hostkeys, cert);
    
    int r;
    if ((r = sshbuf_put_stringb(msg, cfg)) != 0 ||
	    (r = sshbuf_put_u64(msg, data_provider.ConsumeIntegral<uint64_t>())) != 0 ||
	    (r = sshbuf_put_stringb(msg, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(msg, inc)) != 0) {
        fprintf(stderr, "Cannot write to message buffer");
        return 1;
    }
    int fd[2];
    if (pipe(fd) == -1) {
        fprintf(stderr, "Cannot create pipe");
        return 1;
    }
    if (ssh_msg_send(fd[1], 0, msg) == -1) {
        fprintf(stderr, "Cannot send a message");
        return 1;
    }
    close(fd[1]);
    uint64_t timing_secret = 0;
    recv_rexec_state(fd[0], cfg, &timing_secret);
    close(fd[0]);
    sshbuf_free(cfg);
    sshbuf_free(inc);
    sshbuf_free(hostkeys);
    sshbuf_free(msg);
    return 0;
}
