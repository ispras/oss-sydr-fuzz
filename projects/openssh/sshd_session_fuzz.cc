/* Copyright (C) 2024 ISP RAS
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "FuzzedDataProvider.h"

#include <stddef.h>
#include <stdint.h>
#include <cstdlib>
#include <unistd.h>
 
#include "entropy.h"

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
    const std::string sconfig = data_provider.ConsumeRandomLengthString(),
               spriv_key = data_provider.ConsumeRandomLengthString(8192),
               spub_key = data_provider.ConsumeRandomLengthString(8192),
               scert = data_provider.ConsumeRandomLengthString(8192);
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
