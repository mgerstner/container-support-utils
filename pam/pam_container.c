/*
 * pam_container.c
 *
 * PAM module that provides a session function to enter an existing
 * container. See README.pam in the top-level source directory.
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

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <syslog.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <sys/file.h>

#include "container.h"

enum {
	STRATEGY_AUTO,
	STRATEGY_USER,
};

#define MAX_USERS	16
enum {
	POLICY_IGNORE,
	POLICY_APPLY
};

struct pam_container_state {
	char *			username;
	char *			container_name;
	struct container *	container;

	int			strategy;

	struct user {
		const char *	name;
		int		policy;
	}			user[MAX_USERS];
	unsigned int		user_count;
};

static int
_pam_container_state_init(pam_handle_t *pamh, struct pam_container_state *state)
{
	const char *username;
	int r;

	r = pam_get_user(pamh, &username, NULL);
	if (r != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "Unable to get user name");
		return r;
	}

	if (username == NULL || *username == '\0') {
		pam_syslog(pamh, LOG_ERR, "Invalid user name.");
		return PAM_SESSION_ERR;
	}

	state->username = strdup(username);

	return PAM_SUCCESS;
}

static void
_pam_container_state_free(struct pam_container_state *state)
{
	if (state->username)
		free(state->username);
	if (state->container_name)
		free(state->container_name);
	if (state->container)
		container_close(state->container);

	memset(state, 0xA5, sizeof(*state));
	free(state);
}

static void
_pam_container_cleanup_state(pam_handle_t *pamh, void *data, int error_status)
{
	struct pam_container_state *state = data;

	if (state != NULL)
		_pam_container_state_free(state);
}

static int
_pam_container_get_state(pam_handle_t *pamh, struct pam_container_state **ret_p)
{
	int r;

	r = pam_get_data(pamh, "pam_container", (const void **) ret_p);
	if (r == PAM_NO_MODULE_DATA) {
		struct pam_container_state *state;

		// Remark 1: calloc NULL return is not checked for
		state = calloc(1, sizeof(struct pam_container_state));

		r = _pam_container_state_init(pamh, state);
		if (r == PAM_SUCCESS)
			r = pam_set_data(pamh, "pam_container", state, _pam_container_cleanup_state);

		if (r == PAM_SUCCESS)
			*ret_p = state;
		else
			_pam_container_state_free(state);
	}

	return r;
}

static int
_pam_container_add_user(pam_handle_t *pamh, struct pam_container_state *state, const char *name, int policy)
{
	struct user *u;

	if (state->user_count >= MAX_USERS) {
		pam_syslog(pamh, LOG_ERR, "Too many user arguments.");
		return PAM_SESSION_ERR;
	}

	u = &state->user[state->user_count++];
	u->name = name;
	u->policy = policy;

	return PAM_SUCCESS;
}

static int
_pam_container_check_user(pam_handle_t *pamh, struct pam_container_state *state, int *policy_p)
{
	const char *username;
	unsigned int i;
	int r;

	// Remark 2: the username was already fetched in
	// _pam_container_state_init() and should be found in state->username.
	r = pam_get_user(pamh, &username, NULL);
	if (r != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "Unable to get user name");
		return r;
	}

	if (username == NULL || *username == '\0') {
		pam_syslog(pamh, LOG_ERR, "Invalid user name.");
		return PAM_SESSION_ERR;
	}

	*policy_p = POLICY_APPLY;

	for (i = 0; i < state->user_count; ++i) {
		struct user *u = &state->user[i];

		// Remark 3: you might want to document that the first match
		// wins i.e. if "all" appears first then it would override
		// later appearances of usernames that might also match.
		//
		// or you could somehow rearrange "all" to appear always last
		// in the user list to avoid this effect.
		if (strcmp(u->name, username) && strcmp(u->name, "all"))
			continue;

		if (u->policy != POLICY_APPLY)
			pam_syslog(pamh, LOG_INFO, "Not attaching to a container for user %s.", username);
		*policy_p = u->policy;
		break;
	}

	return PAM_SUCCESS;
}

static int
_pam_container_parse_args(pam_handle_t *pamh, struct pam_container_state *state, int argc, const char **argv)
{
	int i, r;

	for (i = 0; i < argc; ++i) {
		const char *a = argv[i];

		if (!strcmp(a, "auto")) {
			state->strategy = STRATEGY_AUTO;
		} else if (!strcmp(a, "user")) {
			state->strategy = STRATEGY_USER;
		} else if (!strncmp(a, "user_apply=", 11)) {
			r = _pam_container_add_user(pamh, state, a + 11, POLICY_APPLY);
			if (r != PAM_SUCCESS)
				return r;
		} else if (!strncmp(a, "user_ignore=", 12)) {
			r = _pam_container_add_user(pamh, state, a + 12, POLICY_IGNORE);
			if (r != PAM_SUCCESS)
				return r;
		} else {
			pam_syslog(pamh, LOG_ERR, "Unknown argument \"%s\".", a);
			return PAM_SESSION_ERR;
		}
	}
	return PAM_SUCCESS;
}

static int
_pam_container_choose_auto(pam_handle_t *pamh, struct pam_container_state *state)
{
	static const unsigned int MAX_CONTAINERS = 128;
	struct container_info containers[MAX_CONTAINERS];
	int i, count;

	if ((count = container_list(containers, MAX_CONTAINERS)) < 0) {
		pam_syslog(pamh, LOG_ERR, "Failed to get list of containers");
		return PAM_SESSION_ERR;
	}

	/* For auto strategy, it's okay if no container exists; we will user
	 * the host context instead.
	 * We don't want root to lock themselves out.
	 */
	if (count == 0) {
		pam_syslog(pamh, LOG_INFO, "No containers found.");
		return PAM_SUCCESS;
	}

	if (count > 1) {
		/* We could try to choose a container interactively, by displaying
		 * a list of container IDs and prompting the user to choose one.
		 * But this is probably a waste of effort, because not every application
		 * provides conversation functions for session management (ssh does not,
		 * for instance). In addition to that, most containers will have some sort
		 * of crypto hash as their hostname, which will not be helpful for the
		 * user.
		 */
		pam_syslog(pamh, LOG_INFO, "Found %u containers, picking random container", count);
	}

	for (i = 0; i < count; ++i) {
		const char *name = containers[i].hostname;

		// Remark 8: it would be better to have a function like
		// `container_open(struct container_info*)`, because we
		// already have the info that `container_open(const char*)` is
		// looking up again by iterating through /proc. Furthermore
		// the `container_open(const char*)` may end up opening a
		// different namespace than originally intended.
		state->container = container_open(name);
		if (state->container) {
			state->container_name = strdup(name);
			break;
		}

		pam_syslog(pamh, LOG_INFO, "Tried to open container %s, but failed.%s", name,
				(i < count)? " Keep trying." : "");
	}

	container_info_destroy(containers, count);
	if (state->container == NULL) {
		pam_syslog(pamh, LOG_ERR, "Unable to open any container.");
		return PAM_SESSION_ERR;
	}

	pam_syslog(pamh, LOG_INFO, "auto selected container %s.", state->container_name);
	return PAM_SUCCESS;
}

static int
_pam_container_choose_user(pam_handle_t *pamh, struct pam_container_state *state)
{
	char container_name[256];

	// Remark 10: any user in the system can fork a UTS namespace and
	// set the hostname to "user:whatever". In the context of the root
	// user this could cause it to enter arbitrary unexpected containers
	// controlled by unprivileged users.
	// Also I noticed that the regular `hostname` utility doesn't allow
	// ':' in hostnames, but the underlying `sethostname()` system call
	// does.
	snprintf(container_name, sizeof(container_name), "user:%s", state->username);

	state->container = container_open(container_name);
	if (state->container == NULL) {
		pam_syslog(pamh, LOG_ERR, "Unable to open container %s.", container_name);
		return PAM_SESSION_ERR;
	}

	state->container_name = strdup(container_name);
	return PAM_SUCCESS;
}

static int
_pam_container_choose_container(pam_handle_t *pamh, struct pam_container_state *state)
{
	int r;

	switch (state->strategy) {
	case STRATEGY_AUTO:
		r = _pam_container_choose_auto(pamh, state);
		break;

	case STRATEGY_USER:
		r = _pam_container_choose_user(pamh, state);
		break;

	default:
		pam_syslog(pamh, LOG_ERR, "strategy %d not implemented.", state->strategy);
		r = PAM_SESSION_ERR;
		break;
	}

	return r;
}

static int
_pam_container_enter_container(pam_handle_t *pamh, struct pam_container_state *state)
{
	if (state->container == NULL) {
		pam_syslog(pamh, LOG_ERR, "%s: no container set", __func__);
		return PAM_SESSION_ERR;
	}

	if (container_attach(state->container) < 0) {
		pam_syslog(pamh, LOG_ERR, "Failed to attach to container \"%s\".", state->container_name);
		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct pam_container_state *state;
	int r, policy;

	r = _pam_container_get_state(pamh, &state);
	if (r != PAM_SUCCESS)
		return r;

	if (_pam_container_parse_args(pamh, state, argc, argv) < 0)
		return PAM_SESSION_ERR;

	r = _pam_container_check_user(pamh, state, &policy);
	if (r != PAM_SUCCESS)
		return r;

	if (policy != POLICY_APPLY)
		return PAM_SUCCESS;

	r = _pam_container_choose_container(pamh, state);
	if (r != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "Unable to set up session; but the caller may ignore our error code. Duh.");
		return r;
	}

	/* If there were no containers, just behave like normal session */
	if (state->container == NULL) {
		pam_syslog(pamh, LOG_INFO, "No container selected; creating session in host context.");
		return PAM_SUCCESS;
	}

	r = _pam_container_enter_container(pamh, state);
	if (r != PAM_SUCCESS)
		return PAM_SESSION_ERR;

	pam_syslog(pamh, LOG_INFO, "Successfully attached to container %s.", state->container_name);

	pam_info(pamh, "Session running in container %s.", state->container_name);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
