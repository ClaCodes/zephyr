/*
 * Copyright (c) 2025 The Zephyr Contributors.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_pkt_filter.h>
#include <zephyr/net/socket.h>
#include <zephyr/posix/fcntl.h>

#include <posix_board_if.h>

LOG_MODULE_REGISTER(qos_udp_send);

#define SINGLE_RUN_DEADLINE K_MSEC(2000)

#define MTU 1500
#define NUM_SOCK 8

struct net_if_fake_data {
	uint8_t mac[sizeof(struct net_eth_addr)];
	struct net_linkaddr ll_addr;
};

struct udp_sockets {
    int socks[NUM_SOCK];
    uint8_t prios[NUM_SOCK];
};

struct statistics {
	unsigned int port_0_count;
	unsigned int port_1_count;
	unsigned int port_2_count;
	unsigned int port_3_count;
	unsigned int port_4_count;
	unsigned int port_5_count;
	unsigned int port_6_count;
	unsigned int port_7_count;
};

static K_SEM_DEFINE(port_0_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_1_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_2_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_3_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_4_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_5_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_6_send, 0, UINT_MAX);
static K_SEM_DEFINE(port_7_send, 0, UINT_MAX);

int net_fake_dev_init(const struct device *dev)
{
	return 0;
}

static void copy_mac_to(char destination[static 6])
{
	/* 00-00-5E-00-53-xx Documentation RFC 7042 */
	/* taken from arp test */
	destination[0] = 0x00;
	destination[1] = 0x00;
	destination[2] = 0x5E;
	destination[3] = 0x00;
	destination[4] = 0x53;
	destination[5] = 0x3B;
}

static void net_iface_init(struct net_if *iface)
{
	const struct device *device = net_if_get_device(iface);
	struct net_if_fake_data *context = device->data;

	if (context->mac[2] == 0x00) {
		copy_mac_to(context->mac);
	}

	net_if_set_link_addr(iface, context->mac, sizeof(context->mac), NET_LINK_ETHERNET);
}

static int net_if_fake_send(const struct device *dev, struct net_pkt *pkt)
{
	int ok;
	char buf[2000] = {0};

	net_pkt_cursor_init(pkt);
	net_pkt_set_overwrite(pkt, true);
	net_pkt_skip(pkt, sizeof(struct net_eth_hdr));
	net_pkt_skip(pkt, net_pkt_ip_hdr_len(pkt));

	uint16_t src_port, dst_port, length, check;
	uint32_t simulated_work_time;
	net_pkt_read_be16(pkt, &src_port);
	net_pkt_read_be16(pkt, &dst_port);
	net_pkt_read_be16(pkt, &length);
	net_pkt_read_be16(pkt, &check);
	net_pkt_read_be32(pkt, &simulated_work_time);
	simulated_work_time = ntohl(simulated_work_time);
	dst_port = ntohs(dst_port);

	LOG_INF("sending UDP pkt %p on port %u, simulated_work_time %u", pkt, dst_port, simulated_work_time);

	posix_cpu_hold(simulated_work_time);

	switch (dst_port) {
	case 0:
		k_sem_give(&port_0_send);
		break;
	case 1:
		k_sem_give(&port_1_send);
		break;
	case 2:
		k_sem_give(&port_2_send);
		break;
	case 3:
		k_sem_give(&port_3_send);
		break;
	case 4:
		k_sem_give(&port_4_send);
		break;
	case 5:
		k_sem_give(&port_5_send);
		break;
	case 6:
		k_sem_give(&port_6_send);
		break;
	case 7:
		k_sem_give(&port_7_send);
		break;
	default: /* nothing to do */
		break;
	}

	return 0;
}

static const struct ethernet_api net_if_api = {
	.iface_api.init = net_iface_init,
	.send = net_if_fake_send,
};

static struct net_if_fake_data context;

#define _ETH_L2_LAYER    ETHERNET_L2
#define _ETH_L2_CTX_TYPE NET_L2_GET_CTX_TYPE(ETHERNET_L2)

NET_DEVICE_INIT(net_if_fake, "fake", net_fake_dev_init, NULL, &context, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, &net_if_api, _ETH_L2_LAYER, _ETH_L2_CTX_TYPE,
		MTU);

static int init_sockets(struct udp_sockets *u)
{
	int flags;

	for (int i = 0; i < ARRAY_SIZE(u->socks); i++) {
		u->socks[i] = zsock_socket(AF_INET, SOCK_DGRAM, 0);
		if (u->socks[i] < 0) {
			LOG_ERR("Failed to create socket: %s", strerror(errno));
			return -1;
		}
		struct ifreq ifreq = {
			.ifr_name = "eth1",
		};

		if (zsock_setsockopt(u->socks[i], SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq)) < 0) {
			LOG_ERR("Failed to bind socket to device: %s", strerror(errno));
			return -1;
		}

		flags = zsock_fcntl(u->socks[i], F_GETFL, 0);
		if (flags < 0) {
			LOG_ERR("Failed get flag: %s", strerror(errno));
			return -1;
		}

		if (zsock_fcntl(u->socks[i], F_SETFL, flags | O_NONBLOCK) < 0) {
			LOG_ERR("Failed set flag: %s", strerror(errno));
			return -1;
		}

	}
	return 0;
}

static int configure_priorities(struct udp_sockets *u)
{
	BUILD_ASSERT(ARRAY_SIZE(u->socks) == ARRAY_SIZE(u->prios));
	for (int i = 0; i < ARRAY_SIZE(u->socks); i++) {
		if (zsock_setsockopt(u->socks[i], SOL_SOCKET, SO_PRIORITY,
					&u->prios[i], sizeof(u->prios[i])) < 0) {
			LOG_ERR("failed to set prio %d for socket %d: %s", u->prios[i], u->socks[i], strerror(errno));
			return -1;
		}
	}
	return 0;
}

static struct statistics single_run_with_simulated_work(struct udp_sockets *udp, uint32_t w)
{
	k_timepoint_t deadline = sys_timepoint_calc(SINGLE_RUN_DEADLINE);

	k_sem_reset(&port_0_send);
	k_sem_reset(&port_1_send);
	k_sem_reset(&port_2_send);
	k_sem_reset(&port_3_send);
	k_sem_reset(&port_4_send);
	k_sem_reset(&port_5_send);
	k_sem_reset(&port_6_send);
	k_sem_reset(&port_7_send);

	while (!sys_timepoint_expired(deadline)) {
		/*every tick try to send out a udp packet */
		for (int i = 0; i < ARRAY_SIZE(udp->socks); i++)
		{
			struct sockaddr_in dest = {
				.sin_family = AF_INET,
				.sin_port = i,
				.sin_addr = 123,
			};
			LOG_INF("queuing UDP on port %u, simulated_work_time %u", i, w);
			zsock_sendto(udp->socks[i], &w, sizeof(w), 0, (struct sockaddr *)&dest, sizeof(dest));
		}
		k_sleep(K_TICKS(1));
	}

	return (struct statistics){
		.port_0_count = k_sem_count_get(&port_0_send),
		.port_1_count = k_sem_count_get(&port_1_send),
		.port_2_count = k_sem_count_get(&port_2_send),
		.port_3_count = k_sem_count_get(&port_3_send),
		.port_4_count = k_sem_count_get(&port_4_send),
		.port_5_count = k_sem_count_get(&port_5_send),
		.port_6_count = k_sem_count_get(&port_6_send),
		.port_7_count = k_sem_count_get(&port_7_send),
	};
}

static void print_result(const char *msg, size_t cnt, uint32_t simulated_work_times[static cnt],
		  struct statistics stats[static cnt])
{
	LOG_INF("--- Statistics (%s) ---", msg);
	LOG_INF("s (x) := udp sending on port x (high means higher priority)");
	LOG_INF("+---------+------+------+------+------+------+------+------+------+");
	LOG_INF("| work us | c(7) | c(6) | c(5) | c(4) | c(3) | c(2) | c(1) | c(0) |");
	LOG_INF("+=========+======+======+======+======+======+======+======+======+");
	for (size_t i = 0; i < cnt; ++i) {
		LOG_INF("| %7u | %4d | %4d | %4d | %4d | %4d | %4d | %4d | %4d |",
			simulated_work_times[i],
			stats[i].port_7_count,
			stats[i].port_6_count,
			stats[i].port_5_count,
			stats[i].port_4_count,
			stats[i].port_3_count,
			stats[i].port_2_count,
			stats[i].port_1_count,
			stats[i].port_0_count);
		LOG_INF("+---------+------+------+------+------+------+------+------+------+");
	}
}

int main(int argc, char **argv)
{
	struct net_if *iface = NULL;
	struct in_addr addr = { { { 192, 168, 0, 43 } } };
	struct in_addr gw = { { { 192, 168, 0, 42 } } };
	uint32_t simulated_work_times[] = {
		2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 15000,
	};
	struct statistics stats_no_filter[ARRAY_SIZE(simulated_work_times)] = {0};
	struct statistics stats_with_filter[ARRAY_SIZE(simulated_work_times)] = {0};
	struct udp_sockets udp = {
		.prios = {
			NET_PRIORITY_BK, NET_PRIORITY_BE, NET_PRIORITY_EE, NET_PRIORITY_CA,
			NET_PRIORITY_VI, NET_PRIORITY_VO, NET_PRIORITY_IC, NET_PRIORITY_NC
		}
	};

	iface = net_if_lookup_by_dev(DEVICE_GET(net_if_fake));
	if (iface == NULL) {
		LOG_ERR("No device");
		return 1;
	}

	net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);
	net_if_ipv4_set_gw(iface, &gw);

	if (init_sockets(&udp) < 0) {
		LOG_ERR("Failed to create sockets");
		return 1;
	}

	for (size_t i = 0; i < ARRAY_SIZE(simulated_work_times); ++i) {
		stats_no_filter[i] = single_run_with_simulated_work(&udp, simulated_work_times[i]);
		k_msleep(200);
		print_result("In Progress", i + 1, simulated_work_times, stats_no_filter);
		/* let simulation settle down */
		k_msleep(800);
	}

	if (configure_priorities(&udp) < 0) {
		LOG_ERR("Failed to create sockets");
		return 1;
	}

	for (size_t i = 0; i < ARRAY_SIZE(simulated_work_times); ++i) {
		stats_with_filter[i] = single_run_with_simulated_work(&udp, simulated_work_times[i]);
		k_msleep(200);
		print_result("In Progress", i + 1, simulated_work_times, stats_with_filter);
		/* let simulation settle down */
		k_msleep(800);
	}

	k_msleep(4000);
	print_result("Prior to configuring priorities", ARRAY_SIZE(simulated_work_times),
		     simulated_work_times, stats_no_filter);
	print_result("After configuring priorities", ARRAY_SIZE(simulated_work_times),
		     simulated_work_times, stats_with_filter);

	for (int i = 0; i < ARRAY_SIZE(udp.socks); i++) {
		zsock_close(udp.socks[i]);
	}

	return 0;
}
