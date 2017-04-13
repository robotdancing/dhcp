/*
 * Copyright (c) 2017 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   https://www.isc.org/
 *
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "keama.h"

TAILQ_HEAD(options, option) options;
struct option *dynamics = NULL;

/* From common/tables.c */

/// DHCPv4
struct option_def options4[] = {
	{ "subnet-mask", "I",			"dhcp",   1, 2},
	{ "time-offset", "l",			"dhcp4",   2, 2},
	{ "routers", "IA",			"dhcp4",   3, 2},
	{ "time-servers", "IA",			"dhcp4",   4, 2},
	{ "ien116-name-servers", "IA",		"dhcp4",   5, 2},
	/// ien116-name-servers -> name-servers
	{ "domain-name-servers", "IA",		"dhcp4",   6, 2},
	{ "log-servers", "IA",			"dhcp4",   7, 2},
	{ "cookie-servers", "IA",		"dhcp4",   8, 2},
	{ "lpr-servers", "IA",			"dhcp4",   9, 2},
	{ "impress-servers", "IA",		"dhcp4",  10, 2},
	{ "resource-location-servers", "IA",	"dhcp4",  11, 2},
	{ "host-name", "t",			"dhcp4",  12, 2},
	{ "boot-size", "S",			"dhcp4",  13, 2},
	{ "merit-dump", "t",			"dhcp4",  14, 2},
	{ "domain-name", "t",			"dhcp4",  15, 2},
	{ "swap-server", "I",			"dhcp4",  16, 2},
	{ "root-path", "t",			"dhcp4",  17, 2},
	{ "extensions-path", "t",		"dhcp4",  18, 2},
	{ "ip-forwarding", "f",			"dhcp4",  19, 2},
	{ "non-local-source-routing", "f",	"dhcp4",  20, 2},
	{ "policy-filter", "IIA",		"dhcp4",  21, 2},
	{ "max-dgram-reassembly", "S",		"dhcp4",  22, 2},
	{ "default-ip-ttl", "B",		"dhcp4",  23, 2},
	{ "path-mtu-aging-timeout", "L",	"dhcp4",  24, 2},
	{ "path-mtu-plateau-table", "SA",	"dhcp4",  25, 2},
	{ "interface-mtu", "S",			"dhcp4",  26, 2},
	{ "all-subnets-local", "f",		"dhcp4",  27, 2},
	{ "broadcast-address", "I",		"dhcp4",  28, 2},
	{ "perform-mask-discovery", "f",	"dhcp4",  29, 2},
	{ "mask-supplier", "f",			"dhcp4",  30, 2},
	{ "router-discovery", "f",		"dhcp4",  31, 2},
	{ "router-solicitation-address", "I",	"dhcp4",  32, 2},
	{ "static-routes", "IIA",		"dhcp4",  33, 2},
	{ "trailer-encapsulation", "f",		"dhcp4",  34, 2},
	{ "arp-cache-timeout", "L",		"dhcp4",  35, 2},
	{ "ieee802-3-encapsulation", "f",	"dhcp4",  36, 2},
	{ "default-tcp-ttl", "B",		"dhcp4",  37, 2},
	{ "tcp-keepalive-interval", "L",	"dhcp4",  38, 2},
	{ "tcp-keepalive-garbage", "f",		"dhcp4",  39, 2},
	{ "nis-domain", "t",			"dhcp4",  40, 2},
	{ "nis-servers", "IA",			"dhcp4",  41, 2},
	{ "ntp-servers", "IA",			"dhcp4",  42, 2},
	{ "vendor-encapsulated-options", "E.",	"dhcp4",  43, 2},
	{ "netbios-name-servers", "IA",		"dhcp4",  44, 2},
	{ "netbios-dd-server", "IA",		"dhcp4",  45, 2},
	{ "netbios-node-type", "B",		"dhcp4",  46, 2},
	{ "netbios-scope", "t",			"dhcp4",  47, 2},
	{ "font-servers", "IA",			"dhcp4",  48, 2},
	{ "x-display-manager", "IA",		"dhcp4",  49, 2},
	{ "dhcp-requested-address", "I",	"dhcp4",  50, 2},
	{ "dhcp-lease-time", "L",		"dhcp4",  51, 2},
	{ "dhcp-option-overload", "B",		"dhcp4",  52, 2},
	{ "dhcp-message-type", "B",		"dhcp4",  53, 2},
	{ "dhcp-server-identifier", "I",	"dhcp4",  54, 2},
	{ "dhcp-parameter-request-list", "BA",	"dhcp4",  55, 2},
	{ "dhcp-message", "t",			"dhcp4",  56, 2},
	{ "dhcp-max-message-size", "S",		"dhcp4",  57, 2},
	{ "dhcp-renewal-time", "L",		"dhcp4",  58, 2},
	{ "dhcp-rebinding-time", "L",		"dhcp4",  59, 2},
	{ "vendor-class-identifier", "X",	"dhcp4",  60, 2},
	{ "dhcp-client-identifier", "X",	"dhcp4",  61, 2},
	{ "nwip-domain", "t",			"dhcp4",  62, 2},
	/// nwip-domain nwip-domain-name
	{ "nwip-suboptions", "Enwip.",		"dhcp4",  63, 2},
	{ "nisplus-domain", "t",		"dhcp4",  64, 2},
	/// nisplus-domain nisplus-domain-name
	{ "nisplus-servers", "IA",		"dhcp4",  65, 2},
	{ "tftp-server-name", "t",		"dhcp4",  66, 2},
	{ "bootfile-name", "t",			"dhcp4",  67, 2},
	/// bootfile-name boot-file-name
	{ "mobile-ip-home-agent", "IA",		"dhcp4",  68, 2},
	{ "smtp-server", "IA",			"dhcp4",  69, 2},
	{ "pop-server", "IA",			"dhcp4",  70, 2},
	{ "nntp-server", "IA",			"dhcp4",  71, 2},
	{ "www-server", "IA",			"dhcp4",  72, 2},
	{ "finger-server", "IA",		"dhcp4",  73, 2},
	{ "irc-server", "IA",			"dhcp4",  74, 2},
	{ "streettalk-server", "IA",		"dhcp4",  75, 2},
	{ "streettalk-directory-assistance-server", "IA",
						"dhcp4",  76, 2},
	{ "user-class", "t",			"dhcp4",  77, 2},
	{ "slp-directory-agent", "fIa",		"dhcp4",  78, 0},
	/// not supported by Kea
	{ "slp-service-scope", "fto",		"dhcp4",  79, 0},
	/// not supported by Kea
	/* 80 is the zero-length rapid-commit (RFC 4039) */
	{ "fqdn", "Efqdn.",			"dhcp4",  81, 2},
	{ "relay-agent-information", "Eagent.",	"dhcp4",  82, 2},
	/// relay-agent-information dhcp-agent-options
	/* 83 is iSNS (RFC 4174) */
	/* 84 is unassigned */
	{ "nds-servers", "IA",			"dhcp4",  85, 0},
	/// not supported by Kea
	{ "nds-tree-name", "t",			"dhcp4",  86, 0},
	/// not supported by Kea
	{ "nds-context", "t",			"dhcp4",  87, 0},
	/// not supported by Kea
	{ "bcms-controller-names", "D",		"dhcp4",  88, 0},
	/// not supported by Kea
	{ "bcms-controller-address", "Ia",	"dhcp4",  89, 0},
	/// not supported by Kea
	{ "authentication", "X",		"dhcp4",  90, 1},
	/// not supported by ISC DHCP
	{ "client-last-transaction-time", "L",  "dhcp4",  91, 2},
	{ "associated-ip", "Ia",                "dhcp4",  92, 2},
	{ "client-system", "S",			"dhcp4",  93, 1},
	/// not supported by ISC DHCP
	{ "client-ndi", "BBB",			"dhcp4",  94, 1},
	/// not supported by ISC DHCP
	{ "uuid-guid", "BX",			"dhcp4",  97, 1},
	/// not supported by ISC DHCP
	{ "uap-servers", "t",			"dhcp4",  98, 0},
	/// not supported by Kea
        { "geoconf-civic", "X",                 "dhcp4",  99, 0},
	/// not supported by Kea
	{ "pcode", "t",				"dhcp4", 100, 0},
	/// not supported by Kea
	{ "tcode", "t",				"dhcp4", 101, 0},
	/// not supported by Kea
	{ "netinfo-server-address", "Ia",	"dhcp4", 112, 0},
	/// not supported by Kea
	{ "netinfo-server-tag", "t",		"dhcp4", 113, 0},
	/// not supported by Kea
	{ "default-url", "t",			"dhcp4", 114, 0},
	/// not supported by Kea
	{ "auto-config", "B",			"dhcp4", 116, 0},
	/// not supported by Kea
	{ "name-service-search", "Sa",		"dhcp4", 117, 0},
	/// not supported by Kea
	{ "subnet-selection", "I",		"dhcp4", 118, 2},
	{ "domain-search", "Dc",		"dhcp4", 119, 2},
	/// Kea uses different format
	{ "vivco", "Evendor-class.",		"dhcp4", 124, 2},
	/// vivco vivco-suboptions
	{ "vivso", "Evendor.",			"dhcp4", 125, 2},
	/// vivso vivso-suboptions
	{"pana-agent", "Ia",			"dhcp4", 136, 0},
	/// not supported by Kea
	{"v4-lost", "d",			"dhcp4", 137, 0},
	/// not supported by Kea
	{"capwap-ac-v4", "Ia",			"dhcp4", 138, 0},
	/// not supported by Kea
	{ "sip-ua-cs-domains", "Dc",		"dhcp4", 141, 0},
	/// not supported by Kea
	{ "ipv4-address-andsf", "IA",		"dhcp4", 142, 0},
	/// not supported by Kea
        { "rdnss-selection", "BIID",		"dhcp4", 146, 0},
	/// not supported by Kea
	{ "v4-portparams", "BBS",		"dhcp4", 159, 0},
	/// not supported by Kea
	{ "v4-captive-portal", "t",		"dhcp4", 160, 0},
	/// not supported by Kea
        { "option-6rd", "BB6Ia",		"dhcp4", 212, 0},
	/// not supported by Kea
	{"v4-access-domain", "d",		"dhcp4", 213, 0},
	/// not supported by Kea
	{ NULL, NULL, NULL, 0, 0 }
};

/// DHCPv6
struct option_def options6[] = {
	{ "client-id", "X",			"dhcp6",  1, 2},
	/// client-id clientid
	{ "server-id", "X",			"dhcp6",  2, 2},
	/// server-id serverid
	{ "ia-na", "X",				"dhcp6",  3, 2},
	{ "ia-ta", "X",				"dhcp6",  4, 2},
	{ "ia-addr", "X",			"dhcp6",  5, 2},
	/// ia-addr iaaddr
	{ "oro", "SA",				"dhcp6",  6, 2},
	{ "preference", "B",			"dhcp6",  7, 2},
	{ "elapsed-time", "S",			"dhcp6",  8, 2},
	{ "relay-msg", "X",			"dhcp6",  9, 2},
	{ "auth", "X",				"dhcp6", 10, 1},
	/// not supported by ISC DHCP
	{ "unicast", "6",			"dhcp6", 12, 2},
	{ "status-code", "Nstatus-codes.to",	"dhcp6", 13, 2},
	{ "rapid-commit", "Z",			"dhcp6", 14, 2},
	{ "user-class", "X",			"dhcp6", 15, 1},
	/// not supported by ISC DHCP
	{ "vendor-class", "LX",			"dhcp6", 16, 1},
	/// not supported by ISC DHCP
	{ "vendor-opts", "Evsio.",		"dhcp6", 17, 2},
	{ "interface-id", "X",			"dhcp6", 18, 2},
	{ "reconf-msg", "Ndhcpv6-messages.",	"dhcp6", 19, 2},
	{ "reconf-accept", "Z",			"dhcp6", 20, 2},
	{ "sip-servers-names", "D",		"dhcp6", 21, 2},
	/// sip-servers-names sip-server-dns
	{ "sip-servers-addresses", "6A",	"dhcp6", 22, 2},
	/// sip-servers-addresses sip-server-addr
	{ "name-servers", "6A",			"dhcp6", 23, 2},
	/// name-servers dns-servers
	{ "domain-search", "D",			"dhcp6", 24, 2},
	{ "ia-pd", "X",				"dhcp6", 25, 2},
	{ "ia-prefix", "X",			"dhcp6", 26, 2},
	/// ia-prefix iaprefix
	{ "nis-servers", "6A", 			"dhcp6", 27, 2},
	{ "nisp-servers", "6A",			"dhcp6", 28, 2},
	{ "nis-domain-name", "D",		"dhcp6", 29, 2},
	{ "nisp-domain-name", "D",		"dhcp6", 30, 2},
	{ "sntp-servers", "6A",			"dhcp6", 31, 2},
	{ "info-refresh-time", "T",		"dhcp6", 32, 2},
	/// info-refresh-time information-refresh-time
	{ "bcms-server-d", "D",			"dhcp6", 33, 2},
	/// bcms-server-d bcms-server-dns
	{ "bcms-server-a", "6A",		"dhcp6", 34, 2},
	/// bcms-server-a bcms-server-addr
	/* Note that 35 is not assigned. */
	{ "geoconf-civic", "X",			"dhcp6", 36, 2},
	{ "remote-id", "X",			"dhcp6", 37, 2},
	{ "subscriber-id", "X",			"dhcp6", 38, 2},
	{ "fqdn", "Efqdn6-if-you-see-me-its-a-bug-bug-bug.",
						"dhcp6", 39, 2},
	/// fqdn client-fqdn
	{ "pana-agent", "6A",			"dhcp6", 40, 2},
	{ "new-posix-timezone", "t",		"dhcp6", 41, 2},
	{ "new-tzdb-timezone", "t",		"dhcp6", 42, 2},
	{ "ero", "SA",				"dhcp6", 43, 2},
	{ "lq-query", "X",			"dhcp6", 44, 2},
	{ "client-data", "X",			"dhcp6", 45, 2},
	{ "clt-time", "L",			"dhcp6", 46, 2},
	{ "lq-relay-data", "6X",		"dhcp6", 47, 2},
	{ "lq-client-link", "6A",		"dhcp6", 48, 2},
	{ "v6-lost", "d",			"dhcp6", 51, 0},
	/// not supported by Kea
	{ "capwap-ac-v6", "6a",			"dhcp6", 52, 0},
	/// not supported by Kea
	{ "relay-id", "X",			"dhcp6", 53, 0},
	/// not supported by Kea
	{ "v6-access-domain", "d",		"dhcp6", 57, 0},
	/// not supported by Kea
	{ "sip-ua-cs-list", "D",		"dhcp6", 58, 0},
	/// not supported by Kea
	{ "bootfile-url", "t",			"dhcp6", 59, 2},
	{ "bootfile-param", "X",		"dhcp6", 60, 2},
	{ "client-arch-type", "SA",		"dhcp6", 61, 2},
	{ "nii", "BBB",				"dhcp6", 62, 2},
	{ "aftr-name", "d",			"dhcp6", 64, 2},
	{ "erp-local-domain-name", "d",		"dhcp6", 65, 2},
	{ "rsoo", "Ersoo,",			"dhcp6", 66, 1},
	/// not supported by ISC DHCP
	{ "pd-exclude", "X",			"dhcp6", 67, 1},
	/// not supported by ISC DHCP (prefix6 format)
	{ "rdnss-selection", "6BD",		"dhcp6", 74, 0},
	/// not supported by Kea
	{ "client-linklayer-addr", "X",		"dhcp6", 79, 2},
	{ "link-address", "6",			"dhcp6", 80, 0},
	/// not supported by Kea
	{ "solmax-rt", "L",			"dhcp6", 82, 0},
	/// not supported by Kea
	{ "inf-max-rt", "L",			"dhcp6", 83, 0},
	/// not supported by Kea
	{ "dhcpv4-msg", "X",			"dhcp6", 87, 2},
	/// dhcpv4-msg dhcpv4-message
	{ "dhcp4-o-dhcp6-server", "6A",		"dhcp6", 88, 2},
	/// dhcp4-o-dhcp6-server dhcp4o6-server-addr
	{ "v6-captive-portal", "t",		"dhcp6", 103, 0},
	/// not supported by Kea
	{ "ipv6-address-andsf", "6A",		"dhcp6", 143, 0},
	/// not supported by Kea
	{ NULL, NULL, NULL, 0, 0 }
};

/// SERVER
struct option_def configs[] = {
	{ "default-lease-time", "T",		"_server_",   1, 3},
	{ "max-lease-time", "T",		"_server_",   2, 0},
	{ "min-lease-time", "T",		"_server_",   3, 0},
	{ "dynamic-bootp-lease-cutoff", "T",	"_server_",   4, 0},
	{ "dynamic-bootp-lease-length", "L",	"_server_",   5, 0},
	{ "boot-unknown-clients", "f",		"_server_",   6, 0},
	{ "dynamic-bootp", "f",			"_server_",   7, 0},
	{ "allow-bootp", "f",			"_server_",   8, 0},
	{ "allow-booting", "f",			"_server_",   9, 0},
	{ "one-lease-per-client", "f",		"_server_",  10, 0},
	{ "get-lease-hostnames", "f",		"_server_",  11, 0},
	{ "use-host-decl-names", "f",		"_server_",  12, 0},
	{ "use-lease-addr-for-default-route", "f",
						"_server_",  13, 0},
	{ "min-secs", "B",			"_server_",  14, 0},
	{ "filename", "t",			"_server_",  15, 3},
	{ "server-name", "t",			"_server_",  16, 3},
	{ "next-server", "I",			"_server_",  17, 3},
	{ "authoritative", "f",			"_server_",  18, 3},
	{ "vendor-option-space", "U",		"_server_",  19, 3},
	{ "always-reply-rfc1048", "f",		"_server_",  20, 0},
	{ "site-option-space", "X",		"_server_",  21, 3},
	{ "always-broadcast", "f",		"_server_",  22, 0},
	{ "ddns-domainname", "t",		"_server_",  23, 3},
	{ "ddns-hostname", "t",			"_server_",  24, 0},
	{ "ddns-rev-domainname", "t",		"_server_",  25, 0},
	{ "lease-file-name", "t",		"_server_",  26, 0},
	{ "pid-file-name", "t",			"_server_",  27, 0},
	{ "duplicates", "f",			"_server_",  28, 0},
	{ "declines", "f",			"_server_",  29, 0},
	{ "ddns-updates", "f",			"_server_",  30, 3},
	{ "omapi-port", "S",			"_server_",  31, 0},
	{ "local-port", "S",			"_server_",  32, 0},
	{ "limited-broadcast-address", "I",	"_server_",  33, 0},
	{ "remote-port", "S",			"_server_",  34, 0},
	{ "local-address", "I",			"_server_",  35, 3},
	{ "omapi-key", "d",			"_server_",  36, 0},
	{ "stash-agent-options", "f",		"_server_",  37, 0},
	{ "ddns-ttl", "T",			"_server_",  38, 0},
	{ "ddns-update-style", "Nddns-styles.",	"_server_",  39, 3},
	{ "client-updates", "f",		"_server_",  40, 0},
	{ "update-optimization", "f",		"_server_",  41, 0},
	{ "ping-check", "f",			"_server_",  42, 0},
	{ "update-static-leases", "f",		"_server_",  43, 0},
	{ "log-facility", "Nsyslog-facilities.",
						"_server_",  44, 0},
	{ "do-forward-updates", "f",		"_server_",  45, 0},
	{ "ping-timeout", "T",			"_server_",  46, 0},
	{ "infinite-is-reserved", "f",		"_server_",  47, 0},
	{ "update-conflict-detection", "f",	"_server_",  48, 0},
	{ "leasequery", "f",			"_server_",  49, 0},
	{ "adaptive-lease-time-threshold", "B",	"_server_",  50, 0},
	{ "do-reverse-updates", "f",		"_server_",  51, 0},
	{ "fqdn-reply", "f",			"_server_",  52, 0},
	{ "preferred-lifetime", "T",		"_server_",  53, 3},
	{ "dhcpv6-lease-file-name", "t",	"_server_",  54, 0},
	{ "dhcpv6-pid-file-name", "t",		"_server_",  55, 0},
	{ "limit-addrs-per-ia", "L",		"_server_",  56, 0},
	{ "limit-prefs-per-ia", "L",		"_server_",  57, 0},
	{ "dhcp-cache-threshold", "B",		"_server_",  78, 0},
	{ "dont-use-fsync", "f",		"_server_",  79, 0},
	{ "ddns-local-address4", "I",		"_server_",  80, 0},
	{ "ddns-local-address6", "6",		"_server_",  81, 0},
	{ "ignore-client-uids", "f",		"_server_",  82, 3},
	{ "log-threshold-low", "B",		"_server_",  83, 0},
	{ "log-threshold-high", "B",		"_server_",  84, 0},
	{ "echo-client-id", "f",		"_server_",  85, 5},
	{ "server-id-check", "f",		"_server_",  86, 0},
	{ "prefix-length-mode", "Nprefix_length_modes.",
						"_server_",  87, 0},
	{ "dhcpv6-set-tee-times", "f",		"_server_",  88, 3},
	{ "abandon-lease-time", "T",		"_server_",  89, 3},
	{ NULL, NULL, NULL, 0, 0 }
};

void
options_init(void)
{
	struct option_def *def;
	struct option *option;

	TAILQ_INIT(&options);

	/* Fill DHCPv4 options */
	for (def = options4; def->name != NULL; def++) {
		option = (struct option *)malloc(sizeof(*option));
		assert(option != NULL);
		memset(option, 0, sizeof(*option));
		option->old = def->name;
		switch (def->code) {
		case 5:
			option->name = "name-servers";
			break;
		case 62:
			option->name = "nwip-domain-name";
			break;
		case 64:
			option->name = "nisplus-domain-name";
			break;
		case 67:
			option->name = "boot-file-name";
			break;
		case 82:
			option->name = "dhcp-agent-options";
			break;
		case 124:
			option->name = "vivco-suboptions";
			break;
		case 125:
			option->name = "vivso-suboptions";
			break;
		default:
			option->name = def->name;
		}
		option->name = def->name;
		option->format = def->format;
		option->space = def->space;
		option->code = def->code;
		option->status = def->status;
		TAILQ_INSERT_TAIL(&options, option, next);
	}

	/* Fill DHCPv6 options */
	for (def = options6; def->name != NULL; def++) {
		option = (struct option *)malloc(sizeof(*option));
		assert(option != NULL);
		memset(option, 0, sizeof(*option));
		option->old = def->name;
		switch (def->code) {
		case 1:
			option->name = "clientid";
			break;
		case 2:
			option->name = "serverid";
			break;
		case 5:
			option->name = "iaaddr";
			break;
		case 21:
			option->name = "sip-server-dns";
			break;
		case 22:
			option->name = "sip-server-addr";
			break;
		case 23:
			option->name = "dns-servers";
			break;
		case 26:
			option->name = "iaprefix";
			break;
		case 32:
			option->name = "information-refresh-time";
			break;
		case 33:
			option->name = "bcms-server-dns";
			break;
		case 34:
			option->name = "bcms-server-addr ";
			break;
		case 39:
			option->name = "client-fqdn";
			break;
		case 87:
			option->name = "dhcpv4-message";
			break;
		case 88:
			option->name = "dhcp4o6-server-addr";
			break;
		default:
			option->name = def->name;
			break;
		}
		option->format = def->format;
		option->space = def->space;
		option->code = def->code;
		option->status = def->status;
		TAILQ_INSERT_TAIL(&options, option, next);
	}

	/* Fill server config options */
	for (def = configs; def->name != NULL; def++) {
		option = (struct option *)malloc(sizeof(*option));
		assert(option != NULL);
		memset(option, 0, sizeof(*option));
		option->old = def->name;
		option->name = def->name;
		option->format = def->format;
		option->space = def->space;
		option->code = def->code;
		option->status = def->status;
		TAILQ_INSERT_TAIL(&options, option, next);
	}
}

const char *
option_map_space(const char *space)
{
	if (strcmp(space, "dhcp") == 0)
		return "dhcp4";
	else if (strcmp(space, "dhcp6") == 0)
		return space;
	else if (strcmp(space, "vendor") == 0)
		return "vendor-encapsulated-options-space";
	else if(strcmp(space, "agent") == 0)
		return "dhcp-agent-options-space";
	else if(strcmp(space, "vsio") == 0)
		return "vendor-opts-space";
	else
		return NULL;
}

struct option *
option_lookup_name(const char *space, const char *name)
{
	struct option *option;

	TAILQ_FOREACH(option, &options, next) {
		if (strcmp(space, option->space) != 0)
			continue;
		if (strcmp(name, option->old) == 0)
			return option;
	}
	return NULL;
}

struct option *
option_lookup_code(const char *space, unsigned code)
{
	struct option *option;

	TAILQ_FOREACH(option, &options, next) {
		if (strcmp(space, option->space) != 0)
			continue;
		if (code == option->code)
			return option;
	}
	return NULL;
}

void
push_option(struct option *option)
{
	option->old = option->name;
	option->status = kea_unknown;
	TAILQ_INSERT_TAIL(&options, option, next);
	if (dynamics == NULL)
		dynamics = option;
}

struct comments *
get_config_comments(unsigned code)
{
	static struct comments comments;
	struct comment *comment = NULL;

	TAILQ_INIT(&comments);
	switch (code) {
	case 2: /* max-lease-time */
		comment = createComment("/// max-lease-time is not supported");
	lease_time:
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// use default-lease-time insted");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5219");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 3: /* min-lease-time */
		comment = createComment("/// min-lease-time is not supported");
		goto lease_time;

	case 4: /* dynamic-bootp-lease-cutoff */
	case 5: /* dynamic-bootp-lease-length */
	case 6: /* boot-unknown-clients */
	case 7: /* dynamic-bootp */
	case 8: /* allow-bootp */
	no_bootp:
		comment = createComment("/// bootp protocol is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 9: /* allow-booting */
		comment = createComment("/// allow-booting is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// no concrete usage known?");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5229");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 10: /* one-lease-per-client */
		comment = createComment("/// one-lease-per-client is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5228");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 11: /* get-lease-hostnames */
		comment = createComment("/// get-lease-hostnames is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5230");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 12: /* use-host-decl-names */
		comment = createComment("/// use-host-decl-names defaults "
				       "to always on");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 13: /* use-lease-addr-for-default-route */
		comment = createComment("/// use-lease-addr-for-default-route "
				       "is obsolete");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 14: /* min-secs */
		comment = createComment("/// min-secs is not (yet?) "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5231");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 20: /* always-reply-rfc1048 */
		goto no_bootp;

	case 21: /* site-option-space */
		comment = createComment("/// site-option-space is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// site-option-space can be used "
				       "only once (defeating its purpose)");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 22: /* always-broadcast */
		comment = createComment("/// always-broadcast is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5232");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 24: /* ddns-hostname */
		comment = createComment("/// ddns-hostname is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Please use hostname in a "
				       "host reservation instead");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 25: /* ddns-rev-domainname */
		comment = createComment("/// ddns-rev-domainname is an "
				       "obsolete (so not supported) feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 26: /* lease-file-name */
		comment = createComment("/// lease-file-name is an internal "
				       "ISC DHCP feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 27: /* pid-file-name */
		comment = createComment("/// pid-file-nam is an internal "
				       "ISC DHCP feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 28: /* duplicates */
		comment = createComment("/// duplicates is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Kea model is different (and "
				       "stricter)");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 29: /* declines */
		comment = createComment("/// declines is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                comment = createComment("/// Kea honors decline messages "
				       " and holds address for "
				       "decline-probation-period");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 31: /* omapi-port */
		comment = createComment("/// omapi-port is an internal "
				       "ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 32: /* local-port */
		comment = createComment("/// local-port is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// command line -p parameter "
				       "should be used instead");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 33: /* limited-broadcast-address */
		comment = createComment("/// limited-broadcast-address "
				       "is not (yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                comment = createComment("/// Reference Kea #5233");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 34: /* remote-port */
		comment = createComment("/// remote-port is a not portable "
				       "(so not supported) feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 36: /* omapi-key */
		comment = createComment("/// omapi-key is an internal "
					"ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 37: /* stash-agent-options */
		comment = createComment("/// stash-agent-options is not "
					"(yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5234");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 38: /* ddns-ttl */
		comment = createComment("/// ddns-ttl is a D2 not (yet?) "
					"supported feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                comment = createComment("/// Reference Kea #5235");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 40: /* client-updates */
		comment = createComment("/// ddns-ttl client-updates is "
					"not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Kea model is very different");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 41: /* update-optimization */
		comment = createComment("/// update-optimization is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                comment = createComment("/// Kea follows RFC 4702");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 42: /* ping-check */
		comment = createComment("/// ping-check is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
	no_ping:
		comment = createComment("/// Kea has no ping probing");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 43: /* update-static-leases */
		comment = createComment("/// update-static-leases is an "
					"obsolete feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 44: /* log-facility */
		comment = createComment("/// log-facility is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Please use the "
					"KEA_LOGGER_DESTINATION environment "
					"variable instead");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 45: /* do-forward-updates */
		comment = createComment("/// do-forward-updates is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
	ddns_updates:
		comment = createComment("/// Kea model is equivalent but "
					"different");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 46: /* ping-timeout */
		comment = createComment("/// ping-timeout is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		goto no_ping;

	case 47: /* infinite-is-reserved */
		comment = createComment("/// infinite-is-reserved is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Kea does not support reserved "
					"leases");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 48: /* update-conflict-detection */
		comment = createComment("/// update-conflict-detection is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// DDNS is handled by the D2 "
					"server using a dedicated config");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 49: /* leasequery */
		comment = createComment("/// leasequery is not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Kea does not (yet) support "
					"the leasequery protocol");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 50: /* adaptive-lease-time-threshold */
		comment = createComment("/// adaptive-lease-time-threshold is "
					"not supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5236");
		TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 51: /* do-reverse-updates */
		comment = createComment("/// do-reverse-updates is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		goto ddns_updates;

	case 52: /* fqdn-reply */
		comment = createComment("/// fqdn-reply is an obsolete "
					"feature");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 54: /* dhcpv6-lease-file-name */
		comment = createComment("/// dhcpv6-lease-file-name "
					"is an internal ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 55: /* dhcpv6-pid-file-name */
		comment = createComment("/// dhcpv6-pid-file-name "
                                        "is an internal ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 56: /* limit-addrs-per-ia */
		comment = createComment("/// limit-addrs-per-ia "
					"is not (yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
	limit_resources:
		comment = createComment("/// Reference Kea #5237");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 57: /* limit-prefs-per-ia */
		comment = createComment("/// limit-prefs-per-ia"
                                        "is not (yet?) supported");
                TAILQ_INSERT_TAIL(&comments, comment, next);
		goto limit_resources;

	case 78: /* dhcp-cache-threshold */
		comment = createComment("/// dhcp-cache-threshold "
					"is not (yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5238");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 79: /* dont-use-fsync */
		comment = createComment("/// dont-use-fsync is an internal "
					"ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;

	case 80: /* ddns-local-address4 */
		comment = createComment("/// ddns-local-address4 is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
	d2_ip_address:
		comment = createComment("/// Kea D2 equivalent config is "
					"ip-address");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 81: /* ddns-local-address6 */
		comment = createComment("/// ddns-local-address6 is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		goto d2_ip_address;

	case 83: /* log-threshold-low */
		comment = createComment("/// log-threshold-low is not (yet?) "
					"supported");
                TAILQ_INSERT_TAIL(&comments, comment, next);
	log_threshold:
		comment = createComment("/// Reference Kea #5220");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;		

	case 84: /* log-threshold-high */
		comment = createComment("/// log-threshold-high is not (yet?) "
                                        "supported");
                TAILQ_INSERT_TAIL(&comments, comment, next);
		goto log_threshold;

	case 86: /* server-id-check */
		comment = createComment("/// server-id-check is not (yet?) "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Reference Kea #5239");
                TAILQ_INSERT_TAIL(&comments, comment, next);
		break;

	case 87: /* prefix-length-mode */
		comment = createComment("/// prefix-length-mode is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment, next);
		comment = createComment("/// Kea model is different (and "
					"simpler?)");
                TAILQ_INSERT_TAIL(&comments, comment, next);
                break;
	}
	return &comments;
}
