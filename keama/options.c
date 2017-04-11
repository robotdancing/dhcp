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
#include <string.h>

#include "keama.h"

/* From common/tables.c */

struct option options[] = {
/// DHCPv4

	{ "subnet-mask", "I",			"dhcp",   1, 1},
	{ "time-offset", "l",			"dhcp",   2, 1},
	{ "routers", "IA",			"dhcp",   3, 1},
	{ "time-servers", "IA",			"dhcp",   4, 1},
	{ "ien116-name-servers", "IA",		"dhcp",   5, 2},
	/// ien116-name-servers -> name-servers
	{ "domain-name-servers", "IA",		"dhcp",   6, 1},
	{ "log-servers", "IA",			"dhcp",   7, 1},
	{ "cookie-servers", "IA",		"dhcp",   8, 1},
	{ "lpr-servers", "IA",			"dhcp",   9, 1},
	{ "impress-servers", "IA",		"dhcp",  10, 1},
	{ "resource-location-servers", "IA",	"dhcp",  11, 1},
	{ "host-name", "t",			"dhcp",  12, 1},
	{ "boot-size", "S",			"dhcp",  13, 1},
	{ "merit-dump", "t",			"dhcp",  14, 1},
	{ "domain-name", "t",			"dhcp",  15, 1},
	{ "swap-server", "I",			"dhcp",  16, 1},
	{ "root-path", "t",			"dhcp",  17, 1},
	{ "extensions-path", "t",		"dhcp",  18, 1},
	{ "ip-forwarding", "f",			"dhcp",  19, 1},
	{ "non-local-source-routing", "f",	"dhcp",  20, 1},
	{ "policy-filter", "IIA",		"dhcp",  21, 1},
	{ "max-dgram-reassembly", "S",		"dhcp",  22, 1},
	{ "default-ip-ttl", "B",		"dhcp",  23, 1},
	{ "path-mtu-aging-timeout", "L",	"dhcp",  24, 1},
	{ "path-mtu-plateau-table", "SA",	"dhcp",  25, 1},
	{ "interface-mtu", "S",			"dhcp",  26, 1},
	{ "all-subnets-local", "f",		"dhcp",  27, 1},
	{ "broadcast-address", "I",		"dhcp",  28, 1},
	{ "perform-mask-discovery", "f",	"dhcp",  29, 1},
	{ "mask-supplier", "f",			"dhcp",  30, 1},
	{ "router-discovery", "f",		"dhcp",  31, 1},
	{ "router-solicitation-address", "I",	"dhcp",  32, 1},
	{ "static-routes", "IIA",		"dhcp",  33, 1},
	{ "trailer-encapsulation", "f",		"dhcp",  34, 1},
	{ "arp-cache-timeout", "L",		"dhcp",  35, 1},
	{ "ieee802-3-encapsulation", "f",	"dhcp",  36, 1},
	{ "default-tcp-ttl", "B",		"dhcp",  37, 1},
	{ "tcp-keepalive-interval", "L",	"dhcp",  38, 1},
	{ "tcp-keepalive-garbage", "f",		"dhcp",  39, 1},
	{ "nis-domain", "t",			"dhcp",  40, 1},
	{ "nis-servers", "IA",			"dhcp",  41, 1},
	{ "ntp-servers", "IA",			"dhcp",  42, 1},
	{ "vendor-encapsulated-options", "E.",	"dhcp",  43, 1},
	{ "netbios-name-servers", "IA",		"dhcp",  44, 1},
	{ "netbios-dd-server", "IA",		"dhcp",  45, 1},
	{ "netbios-node-type", "B",		"dhcp",  46, 1},
	{ "netbios-scope", "t",			"dhcp",  47, 1},
	{ "font-servers", "IA",			"dhcp",  48, 1},
	{ "x-display-manager", "IA",		"dhcp",  49, 1},
	{ "dhcp-requested-address", "I",	"dhcp",  50, 1},
	{ "dhcp-lease-time", "L",		"dhcp",  51, 1},
	{ "dhcp-option-overload", "B",		"dhcp",  52, 1},
	{ "dhcp-message-type", "B",		"dhcp",  53, 1},
	{ "dhcp-server-identifier", "I",	"dhcp",  54, 1},
	{ "dhcp-parameter-request-list", "BA",	"dhcp",  55, 1},
	{ "dhcp-message", "t",			"dhcp",  56, 1},
	{ "dhcp-max-message-size", "S",		"dhcp",  57, 1},
	{ "dhcp-renewal-time", "L",		"dhcp",  58, 1},
	{ "dhcp-rebinding-time", "L",		"dhcp",  59, 1},
	{ "vendor-class-identifier", "X",	"dhcp",  60, 1},
	{ "dhcp-client-identifier", "X",	"dhcp",  61, 1},
	{ "nwip-domain", "t",			"dhcp",  62, 2},
	/// nwip-domain nwip-domain-name
	{ "nwip-suboptions", "Enwip.",		"dhcp",  63, 1},
	{ "nisplus-domain", "t",		"dhcp",  64, 2},
	/// nisplus-domain nisplus-domain-name
	{ "nisplus-servers", "IA",		"dhcp",  65, 1},
	{ "tftp-server-name", "t",		"dhcp",  66, 1},
	{ "bootfile-name", "t",			"dhcp",  67, 2},
	/// bootfile-name boot-file-name
	{ "mobile-ip-home-agent", "IA",		"dhcp",  68, 1},
	{ "smtp-server", "IA",			"dhcp",  69, 1},
	{ "pop-server", "IA",			"dhcp",  70, 1},
	{ "nntp-server", "IA",			"dhcp",  71, 1},
	{ "www-server", "IA",			"dhcp",  72, 1},
	{ "finger-server", "IA",		"dhcp",  73, 1},
	{ "irc-server", "IA",			"dhcp",  74, 1},
	{ "streettalk-server", "IA",		"dhcp",  75, 1},
	{ "streettalk-directory-assistance-server", "IA",
						"dhcp",  76, 1},
	{ "user-class", "t",			"dhcp",  77, 1},
	{ "slp-directory-agent", "fIa",		"dhcp",  78, 0},
	/// not supported by Kea
	{ "slp-service-scope", "fto",		"dhcp",  79, 9},
	/// not supported by Kea
	/* 80 is the zero-length rapid-commit (RFC 4039) */
	{ "fqdn", "Efqdn.",			"dhcp",  81, 1},
	{ "relay-agent-information", "Eagent.",	"dhcp",  82, 2},
	/// relay-agent-information dhcp-agent-options
	/* 83 is iSNS (RFC 4174) */
	/* 84 is unassigned */
	{ "nds-servers", "IA",			"dhcp",  85, 0},
	/// not supported by Kea
	{ "nds-tree-name", "t",			"dhcp",  86, 0},
	/// not supported by Kea
	{ "nds-context", "t",			"dhcp",  87, 0},
	/// not supported by Kea
	{ "bcms-controller-names", "D",		"dhcp",  88, 0},
	/// not supported by Kea
	{ "bcms-controller-address", "Ia",	"dhcp",  89, 0},
	/// not supported by Kea
	/* 90 is the authentication option (RFC 3118) */
	/// supported by Kea
	{ "client-last-transaction-time", "L",  "dhcp",  91, 1},
	{ "associated-ip", "Ia",                "dhcp",  92, 1},
	/// 93 supported by Kea
	/// 94 supported by Kea
	/// 97 supported by Kea
	{ "uap-servers", "t",			"dhcp",  98, 0},
	/// not supported by Kea
        { "geoconf-civic", "X",                 "dhcp",  99, 0},
	/// not supported by Kea
	{ "pcode", "t",				"dhcp", 100, 0},
	/// not supported by Kea
	{ "tcode", "t",				"dhcp", 101, 0},
	/// not supported by Kea
	{ "netinfo-server-address", "Ia",	"dhcp", 112, 0},
	/// not supported by Kea
	{ "netinfo-server-tag", "t",		"dhcp", 113, 0},
	/// not supported by Kea
	{ "default-url", "t",			"dhcp", 114, 0},
	/// not supported by Kea
	{ "auto-config", "B",			"dhcp", 116, 0},
	/// not supported by Kea
	{ "name-service-search", "Sa",		"dhcp", 117, 0},
	/// not supported by Kea
	{ "subnet-selection", "I",		"dhcp", 118, 1},
	{ "domain-search", "Dc",		"dhcp", 119, 1},
	/// Kea uses different format
	{ "vivco", "Evendor-class.",		"dhcp", 124, 2},
	/// vivco vivco-suboptions
	{ "vivso", "Evendor.",			"dhcp", 125, 2},
	/// vivso vivso-suboptions
	{"pana-agent", "Ia",			"dhcp", 136, 0},
	/// not supported by Kea
	{"v4-lost", "d",			"dhcp", 137, 0},
	/// not supported by Kea
	{"capwap-ac-v4", "Ia",			"dhcp", 138, 0},
	/// not supported by Kea
	{ "sip-ua-cs-domains", "Dc",		"dhcp", 141, 0},
	/// not supported by Kea
	{ "ipv4-address-andsf", "IA",		"dhcp", 142, 0},
	/// not supported by Kea
        { "rdnss-selection", "BIID",		"dhcp", 146, 0},
	/// not supported by Kea
	{ "v4-portparams", "BBS",		"dhcp", 159, 0},
	/// not supported by Kea
	{ "v4-captive-portal", "t",		"dhcp", 160, 0},
	/// not supported by Kea
        { "option-6rd", "BB6Ia",		"dhcp", 212, 0},
	/// not supported by Kea
	{"v4-access-domain", "d",		"dhcp", 213, 0},
	/// not supported by Kea

/// DHCPv6

	{ "client-id", "X",			"dhcp6",  1, 2},
	/// client-id clientid
	{ "server-id", "X",			"dhcp6",  2, 2},
	/// server-id serverid
	{ "ia-na", "X",				"dhcp6",  3, 1},
	{ "ia-ta", "X",				"dhcp6",  4, 1},
	{ "ia-addr", "X",			"dhcp6",  5, 2},
	/// ia-addr iaaddr
	{ "oro", "SA",				"dhcp6",  6, 1},
	{ "preference", "B",			"dhcp6",  7, 1},
	{ "elapsed-time", "S",			"dhcp6",  8, 1},
	{ "relay-msg", "X",			"dhcp6",  9, 1},
	/* 10 is auth */
	/// 10 supported by Kea
	{ "unicast", "6",			"dhcp6", 12, 1},
	{ "status-code", "Nstatus-codes.to",	"dhcp6", 13, 1},
	{ "rapid-commit", "Z",			"dhcp6", 14, 1},
	/* 15 is user-class */
	/// 15 supported by Kea
	/* 16 is vendor-class */
	/// 16 supported by Kea
	{ "vendor-opts", "Evsio.",		"dhcp6", 17, 1},
	{ "interface-id", "X",			"dhcp6", 18, 1},
	{ "reconf-msg", "Ndhcpv6-messages.",	"dhcp6", 19, 1},
	{ "reconf-accept", "Z",			"dhcp6", 20, 1},
	{ "sip-servers-names", "D",		"dhcp6", 21, 2},
	/// sip-servers-names sip-server-dns
	{ "sip-servers-addresses", "6A",	"dhcp6", 22, 2},
	/// sip-servers-addresses sip-server-addr
	{ "name-servers", "6A",			"dhcp6", 23, 2},
	/// name-servers dns-servers
	{ "domain-search", "D",			"dhcp6", 24, 1},
	{ "ia-pd", "X",				"dhcp6", 25, 1},
	{ "ia-prefix", "X",			"dhcp6", 26, 2},
	/// ia-prefix iaprefix
	{ "nis-servers", "6A", 			"dhcp6", 27, 1},
	{ "nisp-servers", "6A",			"dhcp6", 28, 1},
	{ "nis-domain-name", "D",		"dhcp6", 29, 1},
	{ "nisp-domain-name", "D",		"dhcp6", 30, 1},
	{ "sntp-servers", "6A",			"dhcp6", 31, 1},
	{ "info-refresh-time", "T",		"dhcp6", 32, 2},
	/// info-refresh-time information-refresh-time
	{ "bcms-server-d", "D",			"dhcp6", 33, 2},
	/// bcms-server-d bcms-server-dns
	{ "bcms-server-a", "6A",		"dhcp6", 34, 2},
	/// bcms-server-a bcms-server-addr
	/* Note that 35 is not assigned. */
	{ "geoconf-civic", "X",			"dhcp6", 36, 1},
	{ "remote-id", "X",			"dhcp6", 37, 1},
	{ "subscriber-id", "X",			"dhcp6", 38, 1},
	{ "fqdn", "Efqdn6-if-you-see-me-its-a-bug-bug-bug.",
						"dhcp6", 39, 2},
	/// fqdn client-fqdn
	{ "pana-agent", "6A",			"dhcp6", 40, 1},
	{ "new-posix-timezone", "t",		"dhcp6", 41, 1},
	{ "new-tzdb-timezone", "t",		"dhcp6", 42, 1},
	{ "ero", "SA",				"dhcp6", 43, 1},
	{ "lq-query", "X",			"dhcp6", 44, 1},
	{ "client-data", "X",			"dhcp6", 45, 1},
	{ "clt-time", "L",			"dhcp6", 46, 1},
	{ "lq-relay-data", "6X",		"dhcp6", 47, 1},
	{ "lq-client-link", "6A",		"dhcp6", 48, 1},
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
	{ "bootfile-url", "t",			"dhcp6", 59, 1},
	{ "bootfile-param", "X",		"dhcp6", 60, 1},
	{ "client-arch-type", "SA",		"dhcp6", 61, 1},
	{ "nii", "BBB",				"dhcp6", 62, 1},
	{ "aftr-name", "d",			"dhcp6", 64, 1},
	{ "erp-local-domain-name", "d",		"dhcp6", 65, 1},
	/// 66 supported by Kea
	/// 67 supported by Kea
	{ "rdnss-selection", "6BD",		"dhcp6", 74, 0},
	/// not supported by Kea
	{ "client-linklayer-addr", "X",		"dhcp6", 79, 1},
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

/// SERVER

	{ "default-lease-time", "T",		"_server_",   1, 0},
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
	{ "filename", "t",			"_server_",  15, 0},
	{ "server-name", "t",			"_server_",  16, 0},
	{ "next-server", "I",			"_server_",  17, 0},
	{ "authoritative", "f",			"_server_",  18, 0},
	{ "vendor-option-space", "U",		"_server_",  19, 0},
	{ "always-reply-rfc1048", "f",		"_server_",  20, 0},
	{ "site-option-space", "X",		"_server_",  21, 0},
	{ "always-broadcast", "f",		"_server_",  22, 0},
	{ "ddns-domainname", "t",		"_server_",  23, 0},
	{ "ddns-hostname", "t",			"_server_",  24, 0},
	{ "ddns-rev-domainname", "t",		"_server_",  25, 0},
	{ "lease-file-name", "t",		"_server_",  26, 0},
	{ "pid-file-name", "t",			"_server_",  27, 0},
	{ "duplicates", "f",			"_server_",  28, 0},
	{ "declines", "f",			"_server_",  29, 0},
	{ "ddns-updates", "f",			"_server_",  30, 0},
	{ "omapi-port", "S",			"_server_",  31, 0},
	{ "local-port", "S",			"_server_",  32, 0},
	{ "limited-broadcast-address", "I",	"_server_",  33, 0},
	{ "remote-port", "S",			"_server_",  34, 0},
	{ "local-address", "I",			"_server_",  35, 0},
	{ "omapi-key", "d",			"_server_",  36, 0},
	{ "stash-agent-options", "f",		"_server_",  37, 0},
	{ "ddns-ttl", "T",			"_server_",  38, 0},
	{ "ddns-update-style", "Nddns-styles.",	"_server_",  39, 0},
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
	{ "preferred-lifetime", "T",		"_server_",  53, 0},
	{ "dhcpv6-lease-file-name", "t",	"_server_",  54, 0},
	{ "dhcpv6-pid-file-name", "t",		"_server_",  55, 0},
	{ "limit-addrs-per-ia", "L",		"_server_",  56, 0},
	{ "limit-prefs-per-ia", "L",		"_server_",  57, 0},
	{ "dhcp-cache-threshold", "B",		"_server_",  78, 0},
	{ "dont-use-fsync", "f",		"_server_",  79, 0},
	{ "ddns-local-address4", "I",		"_server_",  80, 0},
	{ "ddns-local-address6", "6",		"_server_",  81, 0},
	{ "ignore-client-uids", "f",		"_server_",  82, 0},
	{ "log-threshold-low", "B",		"_server_",  83, 0},
	{ "log-threshold-high", "B",		"_server_",  84, 0},
	{ "echo-client-id", "f",		"_server_",  85, 0},
	{ "server-id-check", "f",		"_server_",  86, 0},
	{ "prefix-length-mode", "Nprefix_length_modes.",
						"_server_",  87, 0},
	{ "dhcpv6-set-tee-times", "f",		"_server_",  88, 0},
	{ "abandon-lease-time", "T",		"_server_",  89, 0},

/// END maker

	{ NULL, NULL, NULL, 0, 0 }
};

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

	for (option = options; option->name != NULL; option++) {
		if (strcmp(space, option->space) != 0)
			continue;
		if (strcmp(name, option->name) == 0)
			return option;
	}
	return NULL;
}

struct option *
option_lookup_code(const char *space, unsigned code)
{
	struct option *option;

	for (option = options; option->name != NULL; option++) {
		if (strcmp(space, option->space) != 0)
			continue;
		if (code == option->code)
			return option;
	}
	return NULL;
}

void
option_map_name(struct option *option)
{
	assert(option != NULL);
	assert(option->status == must_renamed);

	if (strcmp("dhcp4", option->space) == 0)
		switch (option->code) {
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
			break;
		}
	if (strcmp("dhcp6", option->space) == 0)
		switch (option->code) {
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
			break;
		}
	assert(0);
}
