/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
 * Copyright (c) 2006-2012. QLogic Corporation. All rights reserved.
 * Copyright (c) 2003-2006, PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// This file contains ipath service routine interface used by the low
// level infinipath protocol code.

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "ipath_service.h"

#include <scif.h>
#define PSMD_HOST_PORT		SCIF_OFED_PORT_7	/* reserved, match psm library */
#define BACKLOG			10
scif_epd_t			psm_epd = -1;

static void
psmd_syslog(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsyslog(LOG_ERR|LOG_USER, format, ap);
    va_end(ap);
}

static int
psmd_scif_send(void *buf, size_t len)
{
    int ret;
    while (len) {
	ret = scif_send(psm_epd, buf, (uint32_t)len, SCIF_SEND_BLOCK);
	if (ret < 0) {
	    if (errno == EINTR) continue;
	    return ret;
	}
	buf += ret;
	len -= ret;
    }
    return 0;
}

static int
psmd_scif_recv(void *buf, size_t len)
{
    int ret;
    while (len) {
	ret = scif_recv(psm_epd, buf, (uint32_t)len, SCIF_RECV_BLOCK);
	if (ret < 0) {
	    if (errno == EINTR) continue;
	    return ret;
	}
	buf += ret;
	len -= ret;
    }
    return 0;
}

static void child_handler(int signo)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static int
psmd_service(void)
{
    int ret;
    struct ipath_cmd cmd;

    while (1) {
	ret = psmd_scif_recv(&cmd, sizeof(cmd));
	if (ret) {
		//psmd_syslog("get request error\n");
		scif_close(psm_epd);
		psm_epd = -1;
		return 0;
	}

	switch(cmd.type) {
	case IPATH_CMD_CONTEXT_OPEN:
	{
		int fd;

		fd = ipath_context_open(cmd.cmd.mic_info.unit,
			cmd.cmd.mic_info.port, cmd.cmd.mic_info.data3);

		cmd.cmd.mic_info.data1 = fd;
		if (fd < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			close(fd);
			goto err;
		}
		break;
	}

	case IPATH_CMD_CONTEXT_CLOSE:
	{
		ipath_context_close(cmd.cmd.mic_info.data1);
		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_ASSIGN_CONTEXT:
	{
		int fd;
		struct ipath_base_info binfo;

		ret = psmd_scif_recv(&fd, sizeof(fd));
		if (ret) goto err;

		memset(&binfo, 0, sizeof(binfo));
		cmd.cmd.user_info.spu_base_info = (__u64)&binfo;
		cmd.cmd.user_info.spu_base_info_size = sizeof(binfo);
		ret = ipath_cmd_assign_context(fd, &cmd, sizeof(cmd));

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;

		if (cmd.cmd.mic_info.data1 >= 0) {
			ret = psmd_scif_send(&binfo, sizeof(binfo));
			if (ret) goto err;
		}
		break;
	}

	case IPATH_CMD_USER_INIT:
	{
		int fd;
		struct ipath_base_info binfo;

		ret = psmd_scif_recv(&binfo, sizeof(binfo));
		if (ret) goto err;
		ret = psmd_scif_recv(&fd, sizeof(fd));
		if (ret) goto err;

		cmd.cmd.user_info.spu_base_info = (__u64)&binfo;
		cmd.cmd.user_info.spu_base_info_size = sizeof(binfo);
		ret = ipath_cmd_user_init(fd, &cmd, sizeof(cmd));

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;

		if (cmd.cmd.mic_info.data1 >= 0) {
			ret = psmd_scif_send(&binfo, sizeof(binfo));
			if (ret) goto err;
		}
		break;
	}

	case IPATH_CMD_SET_PART_KEY:
	case IPATH_CMD_PIOAVAILUPD:
	case IPATH_CMD_ACK_EVENT:
	case IPATH_CMD_POLL_TYPE:

	case IPATH_CMD_RECV_CTRL:
	case IPATH_CMD_ARMLAUNCH_CTRL:
	case IPATH_CMD_DISARM_BUFS:
	{
		int fd;

		ret = psmd_scif_recv(&fd, sizeof(fd));
		if (ret) goto err;

		ret = ipath_cmd_write(fd, &cmd, sizeof(cmd));

		cmd.cmd.mic_info.data1 = ret;
		if (ret) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_NUM_UNITS:
	{
		ret = ipath_get_num_units();

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_NUM_CTXTS:
	{
		ret = ipath_get_num_contexts(cmd.cmd.mic_info.unit);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_PORT_LID:
	{
		ret = ipath_get_port_lid(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_PORT_GID:
	{
		ret = ipath_get_port_gid(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port,
				(uint64_t*)&cmd.cmd.mic_info.data3,
				(uint64_t*)&cmd.cmd.mic_info.data4);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_PORT_LMC:
	{
		ret = ipath_get_port_lmc(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_PORT_RATE:
	{
		ret = ipath_get_port_rate(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_PORT_S2V:
	{
		ret = ipath_get_port_sl2vl(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port,
				cmd.cmd.mic_info.data1);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_STATS_NAMES:
	{
		char *name = NULL;

		ret = infinipath_get_stats_names(&name);

		cmd.cmd.mic_info.data1 = ret;
		if (ret <= 0) {
			if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		} else cmd.cmd.mic_info.data2 = strlen(name);

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (name) free(name);
			goto err;
		}

		/* with name and count is greater than zero */
		if (name && cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(name, strlen(name)+1);
		}
		if (name) free(name);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_STATS:
	{
		uint64_t *s;

		s = malloc(cmd.cmd.mic_info.data1*sizeof(*s));
		if (!s) {
			cmd.cmd.mic_info.data1 = -1;
			cmd.cmd.mic_info.data2 = ENOMEM;

			ret = psmd_scif_send(&cmd, sizeof(cmd));
			if (ret) goto err;
		}

		ret = infinipath_get_stats(s, cmd.cmd.mic_info.data1);

		cmd.cmd.mic_info.data1 = ret;
		if (ret <= 0) {
			if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		}

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (s) free(s);
			goto err;
		}

		if (cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(s, cmd.cmd.mic_info.data1*sizeof(*s));
		}
		if (s) free(s);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_CTRS_UNAMES:
	{
		char *name = NULL;

		ret = infinipath_get_ctrs_unit_names(cmd.cmd.mic_info.unit, &name);

		cmd.cmd.mic_info.data1 = ret;
		if (ret <= 0) {
			if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		} else cmd.cmd.mic_info.data2 = strlen(name);

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (name) free(name);
			goto err;
		}

		/* with name and count is greater than zero */
		if (name && cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(name, strlen(name)+1);
		}
		if (name) free(name);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_CTRS_UNIT:
	{
		uint64_t *c;

		c = malloc(cmd.cmd.mic_info.data1*sizeof(*c));
		if (!c) {
			cmd.cmd.mic_info.data1 = -1;
			cmd.cmd.mic_info.data2 = ENOMEM;

			ret = psmd_scif_send(&cmd, sizeof(cmd));
			if (ret) goto err;
		}

		ret = infinipath_get_ctrs_unit(cmd.cmd.mic_info.unit,
				c, cmd.cmd.mic_info.data1);

		cmd.cmd.mic_info.data1 = ret;
		if (ret <= 0) {
			if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		}

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (c) free(c);
			goto err;
		}

		if (cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(c, cmd.cmd.mic_info.data1*sizeof(*c));
		}
		if (c) free(c);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_CTRS_PNAMES:
	{
		char *name = NULL;

		ret = infinipath_get_ctrs_port_names(cmd.cmd.mic_info.unit, &name);

		cmd.cmd.mic_info.data1 = ret;
		if (ret <= 0) {
			if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		} else cmd.cmd.mic_info.data2 = strlen(name);

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (name) free(name);
			goto err;
		}

		/* with name and count is greater than zero */
		if (name && cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(name, strlen(name)+1);
		}
		if (name) free(name);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_CTRS_PORT:
	{
		uint64_t *c;

		c = malloc(cmd.cmd.mic_info.data1*sizeof(*c));
		if (!c) {
			cmd.cmd.mic_info.data1 = -1;
			cmd.cmd.mic_info.data2 = ENOMEM;

			ret = psmd_scif_send(&cmd, sizeof(cmd));
			if (ret) goto err;
		}

		ret = infinipath_get_ctrs_port(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port,
				c, cmd.cmd.mic_info.data1);

		cmd.cmd.mic_info.data1 = ret;
		if (ret <= 0) {
			if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		}

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (c) free(c);
			goto err;
		}

		if (cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(c, cmd.cmd.mic_info.data1*sizeof(*c));
		}
		if (c) free(c);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_CC_SETTINGS:
	{
		char ccabuf[256];

		ret = ipath_get_cc_settings_bin(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port, ccabuf);

		cmd.cmd.mic_info.data1 = ret;
		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;

		if (cmd.cmd.mic_info.data1 == 1) {
			ret = psmd_scif_send(ccabuf, 84);
			if (ret) goto err;
		}
		break;
	}

	case IPATH_CMD_GET_CC_TABLE:
	{
		uint16_t *cct = NULL;

		ret = ipath_get_cc_table_bin(cmd.cmd.mic_info.unit,
				cmd.cmd.mic_info.port, &cct);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (cct) free(cct);
			goto err;
		}

		if (cmd.cmd.mic_info.data1 > 0) {
			ret = psmd_scif_send(cct,
				(cmd.cmd.mic_info.data1+1)*sizeof(uint16_t));
		}
		if (cct) free(cct);
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_WAIT_FOR_PACKET:
	{
		ret = ipath_cmd_wait_for_packet(cmd.cmd.mic_info.data1);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	case IPATH_CMD_GET_UNIT_FLASH:
	{
		char *data = NULL;

		ret = infinipath_get_unit_flash(cmd.cmd.mic_info.unit, &data);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;
		else cmd.cmd.mic_info.data2 = strlen(data);

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) {
			if (data) free(data);
			goto err;
		}

		if (data) {
			ret = psmd_scif_send(data, strlen(data)+1);
			free(data);
			if (ret) goto err;
		}
		break;
	}

	case IPATH_CMD_PUT_UNIT_FLASH:
	{
		char *data;
		int len;

		len = cmd.cmd.mic_info.data1;
		data = malloc(len + 1);
		if (!data) goto err;

		ret = psmd_scif_recv(data, len); 
		if (ret) {
			free(data);
			goto err;
		}

		ret = infinipath_put_unit_flash(cmd.cmd.mic_info.unit, data, len);
		free(data);

		cmd.cmd.mic_info.data1 = ret;
		if (ret < 0) cmd.cmd.mic_info.data2 = errno;

		ret = psmd_scif_send(&cmd, sizeof(cmd));
		if (ret) goto err;
		break;
	}

	default:
		goto err;
	} /* switch */
    } /* while (1) */

err:
    psmd_syslog("error, request type = %d", cmd.type);
    scif_close(psm_epd);
    psm_epd = -1;
    return 1;
}

int
main(int argc, char *argv[])
{
	uid_t uid;
	gid_t gid;
	pid_t pid;
	scif_epd_t epd;
	struct scif_portID portID;
	struct sigaction act;
	int count;

	/* Only root can run this code */
	if (getuid()) {
		fprintf(stderr, "Only root can run psmd\n");
		psmd_syslog("Only root can run psmd");
		exit(1);
	}

	/* start to daemonize psmd */
	pid = fork();
	if (pid < 0) {
		psmd_syslog("fork() failed with err %d", errno);
		exit(1);
	}
	if (pid > 0) {
		exit(0);
	}

	/* At this point we are executing as the child process */

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	if (setsid() < 0) {
		psmd_syslog("setsid() failed with err %d", errno);
		exit(1);
	}

	/* Change the current working directory.*/
	if ((chdir("/tmp")) < 0) {
		psmd_syslog("chdir() failed with err %d", errno);
		exit(1);
	}

	/* Redirect standard files to /dev/null */
	if (freopen( "/dev/null", "r", stdin) == NULL ||
	    freopen( "/dev/null", "w", stdout) == NULL ||
	    freopen( "/dev/null", "w", stderr) == NULL) {
		psmd_syslog("freopen() failed with err %d", errno);
		exit(1);
	}

	/* Install sigchild handler */
	memset(&act, 0, sizeof act);
	act.sa_handler = child_handler;
	sigaction(SIGCHLD, &act, NULL);

	/* open end pt */
	if ((epd = scif_open()) < 0) {
		psmd_syslog("scif_open() failed with err %d", errno);
		exit(1);
	}

	/* bind end pt to specified port */
	if (scif_bind(epd, PSMD_HOST_PORT) < 0) {
		scif_close(epd);
		psmd_syslog("scif_bind() failed with err %d", errno);
		exit(1);
	}

	/* marks an end pt as listening end pt and queues up a maximum of BACKLOG
	 * no: of incoming connection requests
	 */
	if (scif_listen(epd, BACKLOG) != 0) {
		scif_close(epd);
		psmd_syslog("scif_listen() failed with err %d", errno);
		exit(1);
	}

	count = 0;
	while (1) {
		/* accepts a conn request by creating a new end pt that connects to peer */
		if (scif_accept(epd, &portID, &psm_epd, SCIF_ACCEPT_SYNC) < 0) {
			if (errno == EINTR) continue;
			psmd_syslog("scif_accept() failed with err %d", errno);
			count++;
			if (count < 20) continue;
			scif_close(epd);
			exit(1);
		}
		count = 0; /* not error in row */

		/* if connection is from host, reject it. */
		if (portID.node == 0) {
			psmd_syslog("reject connection from host");
			scif_close(psm_epd);
			psm_epd = -1;
			continue;
		}

		if (scif_recv(psm_epd, &uid, sizeof(uid), SCIF_RECV_BLOCK) != sizeof(uid)) {
			psmd_syslog("cannot get peer uid");
			scif_close(psm_epd);
			psm_epd = -1;
			continue;
		}
		if (scif_recv(psm_epd, &gid, sizeof(gid), SCIF_RECV_BLOCK) != sizeof(gid)) {
			psmd_syslog("cannot get peer gid");
			scif_close(psm_epd);
			psm_epd = -1;
			continue;
		}

		pid = fork();
		if (pid == 0) {
			/* need to change gid first */
			if (setgid(gid)) {
				psmd_syslog("cannot set peer gid");
				scif_close(psm_epd);
				psm_epd = -1;
				exit(1);
			}
			if (setgroups(0, 0)) {
				psmd_syslog("cannot setgroups(0,0)");
				scif_close(psm_epd);
				psm_epd = -1;
				exit(1);
			}
			if (setuid(uid)) {
				psmd_syslog("cannot set peer uid");
				scif_close(psm_epd);
				psm_epd = -1;
				exit(1);
			}

			exit(psmd_service());
		} else {
			scif_close(psm_epd);
			psm_epd = -1;
		}
	}

	exit(0);
}
