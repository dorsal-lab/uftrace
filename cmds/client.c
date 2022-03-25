#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/un.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"


void send_option(int fd, enum uftrace_dopt opt)
{
	if (write(fd, &opt, sizeof(enum uftrace_dopt)) == -1)
			pr_err("error sending option type");
}

bool is_valid_socket_file(char* filename)
{
	char *ext;
	char *file;
	struct stat st;
	bool ret = true;

	ext = strstr(filename, ".socket\0");
	if (ext == NULL) {
		ret = false;
		goto ret;
	}

	xasprintf(&file, "%s/%s", MCOUNT_DAEMON_SOCKET_DIR, filename);
	stat(file, &st);
	free(file);
	if (!S_ISSOCK(st.st_mode)) {
		ret = false;
	}
	else {
		for (size_t i = 0; i < strlen(filename) - strlen(ext); i++) {
			if (!isdigit(filename[i])) {
				ret = false;
				break;
			}
		}
	}
ret:
	return ret;
}

pid_t guess_uftrace_pid(struct opts *opts)
{
	pid_t pid = -1;
	DIR *d;
	struct dirent *dir;
	bool found = false;

	d = opendir(MCOUNT_DAEMON_SOCKET_DIR);

	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (is_valid_socket_file(dir->d_name)) {
				if (found) {
					pid = -1;
					break;
				}
				else {
					found = true;
					/* atol stops at the first non digit character */
					pid = (pid_t) atol(dir->d_name);
				}
			}
		}
		closedir(d);
	}

	return pid;
}

int command_client(int argc, char *argv[], struct opts *opts)
{
	int sfd;        /* Socket file descriptor, to communicate with the daemon */
	pid_t uftrace_pid;
	char *channel = NULL;
	struct sockaddr_un addr;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1)
		pr_err("error opening socket");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;

	if (opts->pid) {
		uftrace_pid = opts->pid;
	}
	else {
		uftrace_pid = guess_uftrace_pid(opts);
		if (uftrace_pid == -1)
			pr_err("cannot identify a running daemon");
		else
			pr_dbg2("located uftrace daemon with PID %d\n", uftrace_pid);
	}
	xasprintf(&channel, "%s/%d.socket", MCOUNT_DAEMON_SOCKET_DIR, uftrace_pid);
	strncpy(addr.sun_path, channel,
			sizeof(addr.sun_path) - 1);

	if (connect(sfd, (struct sockaddr *) &addr,
				sizeof(struct sockaddr_un)) == -1)
		pr_err("error connecting to socket");

	if (opts->daemon_kill)
		send_option(sfd, UFTRACE_DOPT_KILL);
	else
		send_option(sfd, UFTRACE_DOPT_CLOSE);

	close(sfd);

	free(channel);

	return 0;
}
