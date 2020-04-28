/*
 * container.c
 *
 * Encapsulate container namespace
 */

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>

#include "container.h"
#include "tracing.h"


static int	try_parse_pid(const char *);
static int	container_by_hostname(const char *);
static int	__container_uts_name(const char *proc_ns_uts_path, char **result);

struct container *
container_open(const char *id)
{
	char procpath[PATH_MAX];
	struct container *con;
	pid_t pid;
	int fd;

	if ((pid = try_parse_pid(id)) < 0) {
		pid = container_by_hostname(id);
	}
	if (pid < 0) {
		log_error("container_open: unknown container id \"%s\"\n", id);
		return NULL;
	}

	snprintf(procpath, sizeof(procpath), "/proc/%d/ns", pid);
	fd = open(procpath, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		log_error("%s: %m\n", procpath);
		return NULL;
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);

	trace("successfully opened %s.\n", procpath);

	con = calloc(1, sizeof(*con));
	con->pid = pid;
	con->procfd = fd;

	return con;
}


bool
container_has_command(const struct container *con, const char *command)
{
	char cmdpath[PATH_MAX];

	if (command == NULL)
		return true;

	snprintf(cmdpath, sizeof(cmdpath), "../root/%s", command);
	if (faccessat(con->procfd, cmdpath, X_OK, AT_SYMLINK_NOFOLLOW) < 0) {
		log_error("unable to access %s in container %d: %m\n",
				command, con->pid);
		return false;
	}

	trace("okay: container seems to have %s in its filesystem namespace.\n", command);
	return true;
}

static bool
shell_is_namespace_member(int procfd, const char *name)
{
	char pathbuf[PATH_MAX];
	struct stat stb1, stb2;

	if (fstatat(procfd, name, &stb1, 0) < 0) {
		log_error("Cannot stat namespace file %s: %m\n", name);
		return false;
	}

	snprintf(pathbuf, sizeof(pathbuf), "/proc/self/ns/%s", name);
	if (stat(pathbuf, &stb2) < 0) {
		log_error("Cannot stat namespace file %s: %m\n", pathbuf);
		return false;
	}

	return stb1.st_dev == stb2.st_dev && stb1.st_ino == stb2.st_ino;
}

int
container_attach(const struct container *con)
{
	struct nsname {
		const char *	name;
		int		id;
		bool		join;
	} nsnames[] = {
		{ "cgroup", CLONE_NEWCGROUP },
		{ "ipc",  CLONE_NEWIPC },
		{ "mnt", CLONE_NEWNS },
		{ "net", CLONE_NEWNET },
		{ "pid", CLONE_NEWPID },
		{ "user", CLONE_NEWUSER },
		{ "uts", CLONE_NEWUTS },
		{ NULL }
	};
	struct nsname *ns;

	trace("child process joining namespaces of container\n");
#if 0
	unshare(CLONE_NEWNS);
#endif

	for (ns = nsnames; ns->name; ++ns)
		ns->join = !shell_is_namespace_member(con->procfd, ns->name);

	for (ns = nsnames; ns->name; ++ns) {
		int fd;

		if (!ns->join) {
			trace("  %s: already a member\n", ns->name);
			continue;
		}

		if ((fd = openat(con->procfd, ns->name, O_RDONLY)) < 0) {
			log_error("Unable to open namespace %s: %m.\n", ns->name);
			return -1;
		}

		if (setns(fd, ns->id) < 0) {
			log_error("Unable to attach to namespace %s: %m.\n", ns->name);
			close(fd);
			return -1;
		}

		trace("  %s: OK\n", ns->name);
		close(fd);
	}

	chdir("/");
	return 0;
}

/*
 * Destroy container info
 */
void
container_info_destroy(struct container_info *info, unsigned int count)
{
	for (; count--; ++info) {
		if (info->hostname)
			free(info->hostname);
	}
}

/*
 * Return list of all containers visible from our namespace(s)
 */
int
container_list(struct container_info *result, unsigned int max)
{
	unsigned int num_containers = 0, i;
	int saved_uts_namespace = -1;
	struct stat my_uts_stb;
	struct container_info *info;
	DIR *dir;
	struct dirent *d;

	if (!(dir = opendir("/proc"))) {
		log_error("Unable to open /proc: %m\n");
		return -1;
	}

	if ((saved_uts_namespace = open("/proc/self/ns/uts", O_RDONLY)) < 0) {
		log_error("Unable to open /proc/self/ns/uts: %m\n");
		closedir(dir);
		return -1;
	}
	if (fstat(saved_uts_namespace, &my_uts_stb) < 0) {
		log_error("Unable to stat /proc/self/ns/uts: %m\n");
		close(saved_uts_namespace);
		closedir(dir);
		return -1;
	}

	memset(result, 0, max * sizeof(result[0]));
	while ((d = readdir(dir)) != NULL) {
		char procpath[PATH_MAX];
		struct stat stb;
		pid_t pid;

		if ((pid = try_parse_pid(d->d_name)) < 0)
			continue;

		snprintf(procpath, sizeof(procpath), "/proc/%s/ns/uts", d->d_name);
		if (stat(procpath, &stb) < 0) {
			if (errno != ENOENT)
				log_warning("%s: %m\n", procpath);
			continue;
		}

		/* Ignore other processes running in our own uts namespace */
		if (my_uts_stb.st_dev == stb.st_dev
		 && my_uts_stb.st_ino == stb.st_ino)
			continue;

		for (i = 0; i < num_containers; ++i) {
			info = &result[i];

			if (info->__private.dev == stb.st_dev
			 && info->__private.ino == stb.st_ino)
				goto next;
		}

		/* Detected new namespace */
		info = &result[num_containers++];
		info->pid = pid;
		info->__private.dev = stb.st_dev;
		info->__private.ino = stb.st_ino;

		__container_uts_name(procpath, &info->hostname);

		if (num_containers >= max)
			break;

next:		;
	}

	if (setns(saved_uts_namespace, CLONE_NEWUTS) < 0)
		log_warning("Unable to revert back to original uts namespace: %m\n");
	close(saved_uts_namespace);

	closedir(dir);
	return num_containers;
}

/*
 * Find pid of container identified by hostname
 */
int
container_by_hostname(const char *name)
{
	struct container_info list[128], *info;
	int i, count;
	pid_t pid = -1;

	count = container_list(list, 128);
	if (count < 0)
		return -1;

	for (i = 0, info = list; i < count; ++i, ++info) {
		if (info->hostname && !strcasecmp(info->hostname, name)) {
			pid = info->pid;
			break;
		}
	}

	container_info_destroy(list, count);
	return pid;
}

static int
__container_uts_name(const char *proc_ns_uts_path, char **result)
{
	struct utsname uts;
	int fd;

	if ((fd = open(proc_ns_uts_path, O_RDONLY)) < 0) {
		log_error("%s: %m\n", proc_ns_uts_path);
		return -1;
	}

	if (setns(fd, CLONE_NEWUTS) < 0) {
		log_warning("Unable to attach to container uts namespace: %m\n");
		return -1;
	}

	if (uname(&uts) < 0) {
		log_error("Cannot get uname for container: %m\n");
		return -1;
	}

	*result = strdup(uts.nodename);

	return 0;
}

static int
try_parse_pid(const char *name)
{
	pid_t pid;
	char *end;

	pid = strtoul(name, &end, 0);
	if (*end)
		return -1;

	return pid;
}
