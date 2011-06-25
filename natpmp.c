/*
 * Copyright (c) 2011 Matt Dainty <matt@bodgit-n-scarper.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/route.h>

#include <fcntl.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <errno.h>

#include "natpmp.h"

#define NATPMP_MAX_VERSION	0
#define NATPMP_MAX_RETRIES	10
#define NATPMP_MAX_DELETES	3
#define NATPMP_CLIENT_PORT	5350
#define NATPMP_SERVER_PORT	5351
#define NATPMP_MAX_PACKET_SIZE	16

#define NATPMP_COMMAND_PROBE	0

void	 natpmp_recvmsg(int, short, void *);
void	 route_recvmsg(int, short, void *);
void	 natpmp_probe(int, short, void *);
int	 default_gateway(in_addr_t *);

int		 mcast_fd;
int		 route_fd;
int		 ctrl_fd;
in_addr_t	 gateway;
int		 probe_count;
struct event	 probe_ev;

struct timeval timeouts[NATPMP_MAX_RETRIES] = {
	{  0,      0 },
	{  0, 250000 },
	{  0, 500000 },
	{  1,      0 },
	{  2,      0 },
	{  4,      0 },
	{  8,      0 },
	{ 16,      0 },
	{ 32,      0 },
	{ 64,      0 },
};

typedef enum {
	NATPMP_UNKNOWN = 0,
	NATPMP_DISABLED,
	NATPMP_ENABLED,
} natpmp_status_t;

natpmp_status_t status = NATPMP_UNKNOWN;

int
natpmp_init(struct event_base *base)
{
	struct ip_mreq		 mreq;
	struct sockaddr_in	 sock;
	static struct event	 mcast_ev;
	static struct event	 route_ev;
	static struct event	 ctrl_ev;
	unsigned char		 loop = 0;
	int			 reuse = 1;

	/* Listening on 224.0.0.1:5350 */
	memset(&sock, 0, sizeof(sock));
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	sock.sin_port = htons(NATPMP_CLIENT_PORT);

	if ((mcast_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		// fatal("socket");
		return (-1);

	if (fcntl(mcast_fd, F_SETFL, O_NONBLOCK) == -1)
		// fatal("fcntl");
		return (-1);

	/* SO_REUSEADDR and/or SO_REUSEPORT? */
	if (setsockopt(mcast_fd, SOL_SOCKET, SO_REUSEADDR,
	    &reuse, sizeof(reuse)) == -1)
		// fatal("setsockopt: SO_REUSEADDR");
		return (-1);

	if (bind(mcast_fd, (struct sockaddr *)&sock, sizeof(sock)) == -1)
		// fatalx("");
		return (-1);

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr = sock.sin_addr;
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	if (setsockopt(mcast_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	    &mreq, sizeof(mreq)) == -1)
		// fatal("");
		return (-1);

	if (setsockopt(mcast_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
	    &loop, sizeof(loop)) == -1)
		// fatal("");
		return (-1);

	event_set(&mcast_ev, mcast_fd, EV_READ|EV_PERSIST, natpmp_recvmsg,
	    NULL);
	if (base)
		event_base_set(base, &mcast_ev);
	event_add(&mcast_ev, NULL);

	/* Routing socket listening for default gateway changes */
	if ((route_fd = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
		// fatal("socket");
		return (-1);

	if (fcntl(route_fd, F_SETFL, O_NONBLOCK) == -1)
		// fatal("fcntl");
		return (-1);

	event_set(&route_ev, route_fd, EV_READ|EV_PERSIST, route_recvmsg,
	    NULL);
	if (base)
		event_base_set(base, &route_ev);
	event_add(&route_ev, NULL);

	if (default_gateway(&gateway) == 0) {
		memset(&sock, 0, sizeof(sock));
		sock.sin_family = AF_INET;
		sock.sin_port = htons(NATPMP_SERVER_PORT);
		sock.sin_addr.s_addr = gateway;

		if ((ctrl_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
			// fatal("socket");
			return (-1);

		if (fcntl(ctrl_fd, F_SETFL, O_NONBLOCK) == -1)
			// fatal("fcntl");
			return (-1);

		if (connect(ctrl_fd, (struct sockaddr *)&sock,
		    sizeof(sock)) == -1)
			// fatal("connect");
			return (-1);

		event_set(&ctrl_ev, ctrl_fd, EV_READ|EV_PERSIST,
		    natpmp_recvmsg, NULL);
		if (base)
			event_base_set(base, &ctrl_ev);
		event_add(&ctrl_ev, NULL);

		probe_count = 0;
		evtimer_set(&probe_ev, natpmp_probe, NULL);
		if (base)
			event_base_set(base, &probe_ev);
		evtimer_add(&probe_ev, &timeouts[probe_count]);
	}

	return (0);
}

void
natpmp_recvmsg(int fd, short event, void *arg)
{
	socklen_t		 slen;
	struct sockaddr_in	 ss;
	u_int8_t		 storage[NATPMP_MAX_PACKET_SIZE];
	ssize_t			 len;

	struct natpmp_response {
		u_int8_t	 version;
		u_int8_t	 opcode;
		u_int16_t	 result;
		u_int32_t	 sssoe;
		union {
			struct {
				u_int32_t	 address;
			} announce;
			struct {
				u_int16_t	 port[2];
				u_int32_t	 lifetime;
			} mapping;
		} data;
	};
	struct natpmp_response	*r;
	r = (struct natpmp_response *)storage;

	slen = sizeof(ss);
	if ((len = recvfrom(fd, storage, NATPMP_MAX_PACKET_SIZE, 0,
	    (struct sockaddr *)&ss, &slen)) == -1) {
		switch (errno) {
		case ECONNREFUSED:
			return;
		default:
			return;
		}
	}

	if (ss.sin_addr.s_addr != gateway)
		return;

	/* Need at least 4 bytes to do anything useful */
	if (len < 4)
		return;

	if (r->version != NATPMP_MAX_VERSION)
		return;

	if (r->opcode < 0x80)
		return;

	if (r->result != 0)
		return;

	switch (r->opcode) {
	case 0x80:
		status = NATPMP_ENABLED;
		if (evtimer_pending(&probe_ev, NULL))
			evtimer_del(&probe_ev);
		break;
	case 0x81:
		/* FALLTHROUGH */
	case 0x82:
		break;
	default:
		break;
	}
}

void
route_recvmsg(int fd, short event, void *arg)
{
	char			 msg[2048];
	struct rt_msghdr	*rtm = (struct rt_msghdr *)&msg;
	ssize_t			 len;
	in_addr_t		 new_gateway;

	len = read(fd, msg, sizeof(msg));

	if (rtm->rtm_version != RTM_VERSION)
		return;

	switch (rtm->rtm_type) {
	case RTM_DELETE:
		/* Gateway gone? */
		if (default_gateway(&gateway) == -1)
			status = NATPMP_UNKNOWN;
		/* FIXME Need to kill off any pending timers? */
		break;
	case RTM_ADD:
		/* Gateway added and NAT-PMP wasn't previously available */
		if ((default_gateway(&gateway) == 0)
		    && (status == NATPMP_UNKNOWN)) {
			probe_count = 0;
			evtimer_add(&probe_ev, &timeouts[probe_count]);
		}
		break;
	case RTM_CHANGE:
		/* Gateway changed */
		/* FIXME Need to think of all corner cases here */
		if ((default_gateway(&new_gateway) == 0)
		    && (new_gateway != gateway)) {
			gateway = new_gateway;
			probe_count = 0;
			evtimer_add(&probe_ev, &timeouts[probe_count]);
		}
		break;
	}
}

/* libevent timer to send periodic NAT-PMP probes to the gateway for the
 * external NAT IPv4 address. This should be performed at startup and in
 * response to events such as a change of gateway.
 */
void
natpmp_probe(int fd, short event, void *arg)
{
	u_int8_t	 packet[2] = { NATPMP_MAX_VERSION, NATPMP_COMMAND_PROBE };

	/* We only send 9 probes, the 10th time through we just note that
	 * NAT-PMP isn't available.
	 */
	if (probe_count < (NATPMP_MAX_RETRIES - 1)) {
		if (send(ctrl_fd, packet, 2, 0) == -1)
			/* Connection Refused errors are caught elsewhere by
			 * natpmp_recvmsg().
			 */
			switch (errno) {
			case EHOSTDOWN:
				/* FALLTHROUGH */
			case EHOSTUNREACH:
				/* Gateway dead, bigger problems are afoot */
				status = NATPMP_DISABLED;
				break;
			default:
				break;
			}
	} else
		status = NATPMP_DISABLED;

	/* If we haven't run this 10 times or decided already that NAT-PMP
	 * isn't avauilable, queue up another to fire after the appropriate
	 * delay.
	 */
	if ((status == NATPMP_UNKNOWN)
	    && (++probe_count < NATPMP_MAX_RETRIES))
		evtimer_add(&probe_ev, &timeouts[probe_count]);
}

struct {
	struct rt_msghdr	 m_rtm;
	char			 m_space[512];
} m_rtmsg;

int
default_gateway(in_addr_t *gateway)
{
	struct sockaddr		 so_dst;
	struct sockaddr		 so_mask;
	struct sockaddr		*sock = NULL;
	struct rt_msghdr	*msg_hdr;
	char			*cp = m_rtmsg.m_space;
	int			 seq;
	int			 l;
	int			 s;
	int			 i;
	int			 rtm_addrs;
	pid_t			 pid = getpid();

	if ((s = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
		return (-1);

#define NEXTADDR(w, u)				\
	if (rtm_addrs & (w)) {			\
		l = sizeof(struct sockaddr);	\
		memcpy(cp, &(u), l);		\
		cp += l;			\
	}

	errno = 0;
	memset(&m_rtmsg, 0, sizeof(m_rtmsg));
#define rtm m_rtmsg.m_rtm
	rtm.rtm_type = RTM_GET;
	rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_seq = ++seq;
	rtm_addrs = RTA_DST | RTA_NETMASK;
	rtm.rtm_addrs = rtm_addrs;

	memset(&so_dst, 0, sizeof(so_dst));
	so_dst.sa_family = AF_INET;
	memset(&so_mask, 0, sizeof(so_mask));
	so_mask.sa_family = AF_INET;

	NEXTADDR(RTA_DST, so_dst);
	NEXTADDR(RTA_NETMASK, so_mask);
	rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
	if (write(s, &m_rtmsg, l) != l) {
		// warn("writing to routing socket");
		return (-1);
	}
	do {
		l = read(s, &m_rtmsg, sizeof(m_rtmsg));
	} while(l > 0 && (rtm.rtm_version != RTM_VERSION ||
	    rtm.rtm_seq != seq || rtm.rtm_pid != pid));
	if (l == -1)
		// warn("read from routing socket");
		return (-1);
	else {
		msg_hdr = &rtm;

		cp = ((char *)(msg_hdr + 1));
		for(i = 1; msg_hdr->rtm_addrs && i <= RTA_GATEWAY; i <<= 1)
			if (i & msg_hdr->rtm_addrs) {
				if (i == RTA_GATEWAY)
					sock = (struct sockaddr *)cp;
				cp += sizeof(struct sockaddr);
			}
	}
#undef rtm
	if (sock) {
		*gateway = ((struct sockaddr_in *)sock)->sin_addr.s_addr;
		return (0);
	}
	return (-1);
}
