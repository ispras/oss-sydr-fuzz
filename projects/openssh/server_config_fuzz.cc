#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "fuzzer_temp_file.h"

extern "C" {

#include "includes.h"
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include "openbsd-compat/sys-tree.h"
#include "openbsd-compat/sys-queue.h"

#include "ssherr.h"
#include "xmalloc.h"
#include "groupaccess.h"
#include "ssh.h"
#include "ssh2.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "servconf.h"
#include "pathnames.h"
#include "hostfile.h"
#include "auth.h"

ServerOptions options;
struct sshbuf *cfg;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	const FuzzerTemporaryFile temp_file(data, size);

	struct include_list includes = TAILQ_HEAD_INITIALIZER(includes);

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	const char *config_file_name = temp_file.filename();
	if ((cfg = sshbuf_new()) == NULL)
		exit(1);
	if (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);
	parse_server_config(&options, config_file_name, cfg,
	    &includes, NULL, 0);

	return 0;
}

} // extern
