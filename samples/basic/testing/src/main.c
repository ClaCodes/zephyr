/*
 * Copyright (c) 2025 Cla Mattia Galliard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/ethernet.h>

static const char data0[] = {
	0,0,0,0,0,0,
	0,0,0,0,0,0,
	0,0,
	123,145,245,5,35,36,4,56,156,45,63,156,145,63,4};

static const char data1[] = {
	0,0,0,0,0,0,
	0,0,0,0,0,0,
	0,1,
	123,145,245,5,35,36,4,56,156,45,63,156,145,63,4};

static const char data2[] = {
	0,0,0,0,0,0,
	0,0,0,0,0,0,
	0,2,
	123,145,245,5,35,36,4,56,156,45,63,156,145,63,4};

struct datas {
	const char *data;
	size_t size;
};

static const struct datas ds[] = {
	{.data = data0, .size = sizeof(data0)},
	{.data = data1, .size = sizeof(data1)},
	{.data = data2, .size = sizeof(data2)},
};

static int data0_cnt;
static int data1_cnt;
static int data2_cnt;

int main(void)
{
	printf("Starting\n");
	struct net_if *iface = net_if_get_default();

	for (size_t repeat = 0; repeat < 10000; ++repeat) {
		for (size_t i = 0; i < ARRAY_SIZE(ds); ++i) {
			struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(iface, 1500, AF_UNSPEC, 0, K_NO_WAIT);
			if (!pkt) {
				printf("Failed to obtain RX buffer\n");
				continue;
			}

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
	printf("data0_cnt=%d\n", data0_cnt);
	printf("data1_cnt=%d\n", data1_cnt);
	printf("data2_cnt=%d\n", data2_cnt);
	printf("Done\n");

	return 0;
}

static enum net_verdict recv_0(struct net_if *iface, uint16_t ptype, struct net_pkt *pkt)
{
	data0_cnt++;
	printf("GOT recv_0\n");
	net_pkt_unref(pkt);
	return NET_OK;
}
static enum net_verdict recv_1(struct net_if *iface, uint16_t ptype, struct net_pkt *pkt)
{
	data1_cnt++;
	printf("GOT recv_1\n");
	net_pkt_unref(pkt);
	return NET_OK;
}
static enum net_verdict recv_2(struct net_if *iface, uint16_t ptype, struct net_pkt *pkt)
{
	data2_cnt++;
	printf("GOT recv_2\n");
	net_pkt_unref(pkt);
	return NET_OK;
}

ETH_NET_L3_REGISTER(TEST0, 0, recv_0);
ETH_NET_L3_REGISTER(TEST1, 1, recv_1);
ETH_NET_L3_REGISTER(TEST2, 2, recv_2);
