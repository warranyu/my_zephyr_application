/* echo-server.c - Networking echo server */

/*
 * Copyright (c) 2016 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_echo_server_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <shell/shell.h>

#include <net/net_core.h>
#include <net/tls_credentials.h>

#include <net/net_mgmt.h>
#include <net/net_event.h>
#include <net/net_conn_mgr.h>

#include <net/net_if.h>

#include "common.h"
#include "certificate.h"

#define APP_BANNER "Run echo server"

static struct k_sem quit_lock;
static struct net_mgmt_event_callback mgmt_cb;
static bool connected;
K_SEM_DEFINE(run_app, 0, 1);
static bool want_to_quit;

#if defined(CONFIG_USERSPACE)
K_APPMEM_PARTITION_DEFINE(app_partition);
struct k_mem_domain app_domain;
#endif

#define EVENT_MASK (NET_EVENT_L4_CONNECTED | \
		    NET_EVENT_L4_DISCONNECTED)

APP_DMEM struct configs conf = {
	.ipv4 = {
		.proto = "IPv4",
	},
	.ipv6 = {
		.proto = "IPv6",
	},
};

void quit(void)
{
	k_sem_give(&quit_lock);
}

static void start_udp_and_tcp(void)
{
	LOG_INF("Starting...");

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		start_tcp();
	}

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		start_udp();
	}
}

static void stop_udp_and_tcp(void)
{
	LOG_INF("Stopping...");

	if (IS_ENABLED(CONFIG_NET_UDP)) {
		stop_udp();
	}

	if (IS_ENABLED(CONFIG_NET_TCP)) {
		stop_tcp();
	}
}

static void event_handler(struct net_mgmt_event_callback *cb,
			  uint32_t mgmt_event, struct net_if *iface)
{
	if ((mgmt_event & EVENT_MASK) != mgmt_event) {
		return;
	}

	if (want_to_quit) {
		k_sem_give(&run_app);
		want_to_quit = false;
	}

	if (is_tunnel(iface)) {
		/* Tunneling is handled separately, so ignore it here */
		return;
	}

	if (mgmt_event == NET_EVENT_L4_CONNECTED) {
		LOG_INF("Network connected");

		connected = true;
		k_sem_give(&run_app);

		return;
	}

	if (mgmt_event == NET_EVENT_L4_DISCONNECTED) {
		if (connected == false) {
			LOG_INF("Waiting network to be connected");
		} else {
			LOG_INF("Network disconnected");
			connected = false;
		}

		k_sem_reset(&run_app);

		return;
	}
}

static void init_app(void)
{
#if defined(CONFIG_USERSPACE)
	struct k_mem_partition *parts[] = {
#if Z_LIBC_PARTITION_EXISTS
		&z_libc_partition,
#endif
		&app_partition
	};

	k_mem_domain_init(&app_domain, ARRAY_SIZE(parts), parts);
#endif

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS) || \
	defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	int err;
#endif

	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

	LOG_INF(APP_BANNER);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#if defined(CONFIG_NET_SAMPLE_CERTS_WITH_SC)
	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_certificate,
				 sizeof(ca_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register CA certificate: %d", err);
	}
#endif

	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 server_certificate,
				 sizeof(server_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register public certificate: %d", err);
	}


	err = tls_credential_add(SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, sizeof(private_key));
	if (err < 0) {
		LOG_ERR("Failed to register private key: %d", err);
	}
#endif

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK,
				psk,
				sizeof(psk));
	if (err < 0) {
		LOG_ERR("Failed to register PSK: %d", err);
	}
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK_ID,
				psk_id,
				sizeof(psk_id) - 1);
	if (err < 0) {
		LOG_ERR("Failed to register PSK ID: %d", err);
	}
#endif

	if (IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		net_mgmt_init_event_callback(&mgmt_cb,
					     event_handler, EVENT_MASK);
		net_mgmt_add_event_callback(&mgmt_cb);

		net_conn_mgr_resend_status();
	}

	init_vlan();
	init_tunnel();
}

static int cmd_sample_quit(const struct shell *shell,
			  size_t argc, char *argv[])
{
	want_to_quit = true;

	net_conn_mgr_resend_status();

	quit();

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sample_commands,
	SHELL_CMD(quit, NULL,
		  "Quit the sample application\n",
		  cmd_sample_quit),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sample, &sample_commands,
		   "Sample application commands", NULL);



#if defined(CONFIG_NET_DHCPV4)
static struct net_mgmt_event_callback mgmt_cb;

static void ipv4_addr_add_handler(struct net_mgmt_event_callback *cb,
				  uint32_t mgmt_event,
				  struct net_if *iface)
{
	char hr_addr[NET_IPV4_ADDR_LEN];
	int i = 0;

	if (mgmt_event != NET_EVENT_IPV4_ADDR_ADD) {
		/* Spurious callback. */
		return;
	}

	for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
		struct net_if_addr *if_addr =
			&iface->config.ip.ipv4->unicast[i];

		if (if_addr->addr_type != NET_ADDR_DHCP || !if_addr->is_used) {
			continue;
		}

		LOG_INF("IPv4 address: %s",
			log_strdup(net_addr_ntop(AF_INET,
					       &if_addr->address.in_addr,
					       hr_addr, NET_IPV4_ADDR_LEN)));
		LOG_INF("Lease time: %u seconds",
			 iface->config.dhcpv4.lease_time);
		LOG_INF("Subnet: %s",
			log_strdup(net_addr_ntop(AF_INET,
					       &iface->config.ip.ipv4->netmask,
					       hr_addr, NET_IPV4_ADDR_LEN)));
		LOG_INF("Router: %s",
			log_strdup(net_addr_ntop(AF_INET,
						 &iface->config.ip.ipv4->gw,
						 hr_addr, NET_IPV4_ADDR_LEN)));
		break;
	}
}

static void setup_dhcpv4(struct net_if *iface)
{
	LOG_INF("Running dhcpv4 client...");

	net_mgmt_init_event_callback(&mgmt_cb, ipv4_addr_add_handler,
				     NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt_cb);

	net_dhcpv4_start(iface);
}

#else
#define setup_dhcpv4(...)
#endif /* CONFIG_NET_DHCPV4 */

#if defined(CONFIG_NET_IPV4) && !defined(CONFIG_NET_DHCPV4)

#if !defined(CONFIG_NET_CONFIG_MY_IPV4_ADDR)
#error "You need to define an IPv4 Address or enable DHCPv4!"
#endif

static void setup_ipv4(struct net_if *iface)
{
	char hr_addr[NET_IPV4_ADDR_LEN];
	struct in_addr addr;

	if (net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &addr)) {
		LOG_ERR("Invalid address: %s", CONFIG_NET_CONFIG_MY_IPV4_ADDR);
		return;
	}

	net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);

	LOG_INF("IPv4 address: %s",
		log_strdup(net_addr_ntop(AF_INET, &addr, hr_addr,
					 NET_IPV4_ADDR_LEN)));
}

#else
#define setup_ipv4(...)
#endif /* CONFIG_NET_IPV4 && !CONFIG_NET_DHCPV4 */

#if defined(CONFIG_NET_IPV6)

#define MCAST_IP6ADDR "ff84::2"

#ifndef CONFIG_NET_CONFIG_MY_IPV6_ADDR
#error "You need to define an IPv6 Address!"
#endif

static void setup_ipv6(struct net_if *iface)
{
	char hr_addr[NET_IPV6_ADDR_LEN];
	struct in6_addr addr;

	if (net_addr_pton(AF_INET6, CONFIG_NET_CONFIG_MY_IPV6_ADDR, &addr)) {
		LOG_ERR("Invalid address: %s", CONFIG_NET_CONFIG_MY_IPV6_ADDR);
		return;
	}

	net_if_ipv6_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);

	LOG_INF("IPv6 address: %s",
		log_strdup(net_addr_ntop(AF_INET6, &addr, hr_addr,
					 NET_IPV6_ADDR_LEN)));

	if (net_addr_pton(AF_INET6, MCAST_IP6ADDR, &addr)) {
		LOG_ERR("Invalid address: %s", MCAST_IP6ADDR);
		return;
	}

	net_if_ipv6_maddr_add(iface, &addr);
}

#else
#define setup_ipv6(...)
#endif /* CONFIG_NET_IPV6 */


void main(void)
{
	init_app();

	struct net_if *iface = net_if_get_default();

	LOG_INF("Starting Telnet sample");

	setup_ipv4(iface);

	setup_dhcpv4(iface);

	setup_ipv6(iface);

	if (!IS_ENABLED(CONFIG_NET_CONNECTION_MANAGER)) {
		/* If the config library has not been configured to start the
		 * app only after we have a connection, then we can start
		 * it right away.
		 */
		k_sem_give(&run_app);
	}

	/* Wait for the connection. */
	k_sem_take(&run_app, K_FOREVER);

	start_udp_and_tcp();

	k_sem_take(&quit_lock, K_FOREVER);

	if (connected) {
		stop_udp_and_tcp();
	}
}
