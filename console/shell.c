/*
 * shell.c
 *
 * PTY and shell session handling
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <termios.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pty.h>
#include <errno.h>
#include <sched.h>

#include "shell.h"
#include "container.h"
#include "buffer.h"
#include "tracing.h"

static struct console_slave *	processes;

static bool			tty_check_ttyname(const char *tty_name, int tty_fd);

static const struct console_slave *
process_exited(pid_t pid, int status, const struct rusage *rusage)
{
	struct console_slave *p;

	for (p = processes; p; p = p->next) {
		if (p->child_pid == pid) {
			p->exit_status = status;
			p->rusage = *rusage;
			p->child_pid = 0;

			return p;
		}
	}

	/* Oops, spurious child exit */
	return NULL;
}

static void
reaper(int sig)
{
	struct rusage rusage;
	int status;
	pid_t pid;

	while ((pid = wait3(&status, WNOHANG, &rusage)) > 0)
		process_exited(pid, status, &rusage);
}

static void
install_sigchild_handler(void)
{
	static bool handler_installed = false;
	struct sigaction act;

	if (handler_installed)
		return;

	memset(&act, 0, sizeof(act));
	act.sa_handler = reaper;
	act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigaction(SIGCHLD, &act, NULL);

	handler_installed = true;
}

struct console_slave *
start_shell(const struct shell_settings *settings, bool raw_mode)
{
	struct console_slave *ret;
	char slave_name[PATH_MAX];
	int mfd;
	pid_t pid;

	install_sigchild_handler();

	pid = forkpty(&mfd,
			slave_name, /* an API from the stone age */
			NULL, NULL);

	if (pid == 0) {
#ifndef TIOCTTY
		if (raw_mode) {
			struct termios tc;

			tcgetattr(0, &tc);
			cfmakeraw(&tc);
			tcsetattr(0, TCSANOW, &tc);
		}
#endif

		/* attach to container's namespaces */
		if (settings->container) {
			if (container_attach(settings->container) < 0)
				log_fatal("unable to attach to container namespaces\n");

			/* After changing namespaces, tty(1) will fail (and consequently,
			 * bash will not consider itself a login shell).
			 *
			 * The reason for this is that tty does this:
			 *
			 * readlink("/proc/self/fd/0"), which returns sth like "/dev/pts/15",
			 *	ie the name of the pts device in the _original_ namespace.
			 * stat("/dev/pts/15"), which returns ENOENT, because in our new
			 *	namespace, the pty will be /dev/pts/0.
			 */

			if (!tty_check_ttyname(slave_name, 1))
				log_warning("namespace issue: ttyname(3) cannot identify slave pty\n");
		}

		/* FIXME: close everything above fd 2 */

		execv(settings->command, settings->argv);
		log_fatal("unable to execute %s: %m\r\n", settings->command);
	}

#ifdef TIOCTTY
	if (raw_mode)
		ioctl(mfd, TIOCTTY, 1);
#endif

	fcntl(mfd, F_SETFD, FD_CLOEXEC);

	ret = calloc(1, sizeof(*ret));
	ret->master_fd = mfd;
	ret->tty_name = strdup(slave_name);
	ret->child_pid = pid;
	ret->child_pgrp = pid;	 /* child_pid gets cleared when the child exits; child_pgrp does not */

	ret->next = processes;
	processes = ret;

	return ret;
}

int
tty_get_window_size(int fd, unsigned int *rows, unsigned int *cols)
{
	struct winsize win;

	if (ioctl(fd, TIOCGWINSZ, &win) < 0) {
		log_error("ioctl(TIOCGWINSZ): %m");
		return -1;
	}

	*rows = win.ws_row;
	*cols = win.ws_col;
	return 0;
}

int
tty_set_window_size(int fd, unsigned int rows, unsigned int cols)
{
	struct winsize win;

	memset(&win, 0, sizeof(win));
	win.ws_row = rows;
	win.ws_col = cols;

	if (ioctl(fd, TIOCSWINSZ, &win) < 0) {
		log_error("ioctl(TIOCSWINSZ): %m");
		return -1;
	}

	return 0;
}

int
tty_redirect_null(int tty_fd)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		log_error("/dev/null: %m");
		return -1;
	}

	dup2(fd, tty_fd);
	close(fd);
	return 0;
}

bool
tty_check_ttyname(const char *tty_name, int tty_fd)
{
	const char *name;

#if 0
	/* These are really different device minor numbers... */
	{
		struct stat stb1, stb2;

		if (fstat(tty_fd, &stb1) >= 0)
			printf("%s: dev %lx\n", tty_name, stb1.st_rdev);
		if (stat("/dev/pts/0", &stb2) >= 0)
			printf("%s: dev %lx\n", "/dev/pts/0", stb2.st_rdev);
	}
#endif

	if ((name = ttyname(tty_fd)) == NULL) {
		trace("ttyname() returns NULL for slave pty\n");
		return false;
	}

	if (access(name, R_OK) < 0) {
		trace("slave pty not accessible at %s\n", name);
		return false;
	}

	return true;
}

void
process_hangup(struct console_slave *process)
{
	trace("%s(pgrp=%d, fd=%d)\n", __func__, process->child_pgrp, process->master_fd);
	/* FIXME: send a signal to the process group */
	if (process->child_pgrp) {
		if (kill(-process->child_pgrp, SIGTERM) < 0 && errno != ESRCH)
			log_error("%s: cannot send SIGTERM to pgrp %d: %m\n", __func__, process->child_pgrp);
	}

	if (process->master_fd >= 0
	 && tty_redirect_null(process->master_fd))
		log_fatal("%s: cannot redirect PTY master fd\n", __func__);
}

static int
__process_wait(struct console_slave *proc)
{
	struct rusage rusage;
	int status, rv;

	if (proc->child_pid == 0)
		return 0;

	rv = wait4(proc->child_pid, &status, 0, &rusage);
	if (rv < 0) {
		fprintf(stderr, "%s(%u): %m\n", __func__, proc->child_pid);
		return -1;
	}

	process_exited(rv, status, &rusage);

	return 0;
}

static void
__block_sigchild(sigset_t *old_set)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, old_set);
}

static void
__unblock_sigchild(sigset_t *old_set)
{
	sigprocmask(SIG_SETMASK, old_set, NULL);
}

int
process_wait(struct console_slave *proc)
{
	sigset_t oset;
	int rv;

	__block_sigchild(&oset);

	rv = __process_wait(proc);

	__unblock_sigchild(&oset);
	return rv;
}

int
process_killsignal(const struct console_slave *proc)
{
	if (proc->child_pid > 0)
		return -1;
	if (!WIFSIGNALED(proc->exit_status))
		return -1;
	return WTERMSIG(proc->exit_status);
}

int
process_exitstatus(const struct console_slave *proc)
{
	if (proc->child_pid > 0)
		return -1;
	if (!WIFEXITED(proc->exit_status))
		return -1;
	return WEXITSTATUS(proc->exit_status);
}

static int
__process_kill(struct console_slave *proc)
{
	if (proc->child_pid > 0)
		return kill(proc->child_pid, SIGKILL);

	return 0;
}

int
process_kill(struct console_slave *proc)
{
	sigset_t oset;
	int rv;

	__block_sigchild(&oset);

	rv = __process_kill(proc);

	__unblock_sigchild(&oset);
	return rv;
}

void
process_free(struct console_slave *proc)
{
	struct console_slave **pos, *rovr;
	sigset_t oset;

	assert(proc->child_pid == 0);

	__block_sigchild(&oset);
	for (pos = &processes; (rovr = *pos) != NULL; pos = &rovr->next) {
		if (rovr == proc) {
			*pos = rovr->next;
			break;
		}
	}
	__unblock_sigchild(&oset);

	free(proc);
}
