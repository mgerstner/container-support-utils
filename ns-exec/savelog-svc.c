/*
 * savelog-svc.c
 *
 * Server side of the savelog facility.
 *
 *   Copyright (C) 2020 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "savelog.h"
#include "tracing.h"


int
savelog_dir_init(const char *pathname)
{
	struct stat stb;
	char description[128];
	int fd;

	fd = open(pathname, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		log_error("Unable to open directory \"%s\": %m\n", pathname);
		return -1;
	}

	if (fstat(fd, &stb) < 0) {
		close(fd);
		return -1;
	}

	// Remark 11: why is this file descriptor dup()'ed to 128?
	//
	// Couldn't this open file descriptor become dangerous when it's
	// inherited into arbitrary container sub-processes? Is there a
	// defined spot when this file descriptor is used in the container
	// context and then closed off?
	if (fd < 128) {
		dup2(fd, 128);
		close(fd);
		fd = 128;
	}

	snprintf(description, sizeof(description), "%d,%Lu/%lu", fd,
			(unsigned long long) stb.st_dev, /* on some architectures, dev_t is a long long */
			stb.st_ino);
	setenv("SAVELOG_DIRFD", description, 1);
	trace("Exporting SAVELOG_DIRFD=\"%s\"\n", description);

	return 0;
}

int
savelog_init(const char *destination)
{
	return savelog_dir_init(destination);
}
