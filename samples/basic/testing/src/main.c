/*
 * Copyright (c) 2025 Cla Mattia Galliard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/ethernet.h>

struct datas {
	const char *data;
	size_t size;
	uint8_t priority;
};

#define DATA(x) \
static int data_cnt_##x;\
static const char data_##x[] = {\
	0,0,0,0,0,0,\
	0,0,0,0,0,0,\
	0,x,\
	123,145,245,5,35,36,4,56,156,45,63,156,145,63,4};\
static enum net_verdict recv_##x(struct net_if *iface, uint16_t ptype, struct net_pkt *pkt)\
{\
	data_cnt_##x++;\
	printf("GOT %d %s\n", ptype, k_thread_name_get(k_current_get()));\
	net_pkt_unref(pkt);\
	return NET_OK;\
}\
ETH_NET_L3_REGISTER(TEST##x, x, recv_##x)

#define DATA_LINE(x) \
	{.data = data_##x, .size = sizeof(data_##x), .priority = x}

DATA(NET_PRIORITY_BK);
DATA(NET_PRIORITY_BE);
DATA(NET_PRIORITY_EE);
DATA(NET_PRIORITY_CA);
DATA(NET_PRIORITY_VI);
DATA(NET_PRIORITY_VO);
DATA(NET_PRIORITY_IC);
DATA(NET_PRIORITY_NC);

static const struct datas ds[] = {
	DATA_LINE(NET_PRIORITY_BK),
	DATA_LINE(NET_PRIORITY_BE),
	DATA_LINE(NET_PRIORITY_EE),
	DATA_LINE(NET_PRIORITY_CA),
	DATA_LINE(NET_PRIORITY_VI),
	DATA_LINE(NET_PRIORITY_VO),
	DATA_LINE(NET_PRIORITY_IC),
	DATA_LINE(NET_PRIORITY_NC),
};

int main(void)
{
	printf("Starting\n");
	struct net_if *iface = net_if_get_default();

	for (size_t repeat = 0; repeat < 1000; ++repeat) {
		/* k_busy_wait(30000); */
		for (size_t i = 0; i < ARRAY_SIZE(ds); ++i) {
			struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(iface, 50, AF_UNSPEC, 0, K_NO_WAIT);
			if (!pkt) {
				printf("Failed to obtain RX buffer\n");
				continue;
			}
			net_pkt_set_priority(pkt, ds[i].priority);

			if (net_pkt_write(pkt, ds[i].data, ds[i].size)) {
				printf("Failed to append RX buffer to context buffer\n");
				net_pkt_unref(pkt);
				return 1;
			}

			int res = net_recv_data(iface, pkt);
			if (res < 0) {
				printf("Failed to enqueue frame into RX queue: %d\n", res);
				net_pkt_unref(pkt);
				return 1;
			}
		}
	}
	printf("data_cnt_NET_PRIORITY_BK=%d\n", data_cnt_NET_PRIORITY_BK);
	printf("data_cnt_NET_PRIORITY_BE=%d\n", data_cnt_NET_PRIORITY_BE);
	printf("data_cnt_NET_PRIORITY_EE=%d\n", data_cnt_NET_PRIORITY_EE);
	printf("data_cnt_NET_PRIORITY_CA=%d\n", data_cnt_NET_PRIORITY_CA);
	printf("data_cnt_NET_PRIORITY_VI=%d\n", data_cnt_NET_PRIORITY_VI);
	printf("data_cnt_NET_PRIORITY_VO=%d\n", data_cnt_NET_PRIORITY_VO);
	printf("data_cnt_NET_PRIORITY_IC=%d\n", data_cnt_NET_PRIORITY_IC);
	printf("data_cnt_NET_PRIORITY_NC=%d\n", data_cnt_NET_PRIORITY_NC);
	return 0;
}
