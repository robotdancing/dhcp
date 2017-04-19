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

TAILQ_HEAD(spaces, space) spaces;
TAILQ_HEAD(options, option) options;

/* From common/tables.c */

/// SPACES
struct space_def space_defs[] = {
	{ "dhcp", "dhcp4", 2},
	{ "nwip", "nwip", 0},
	{ "agent", "dhcp-agent-options-space", 2},
	{ "vendor-class", "_vivco_", 0},
	{ "vendor", "_vivso_", 0},
	{ "isc", "_isc_", 0},
	{ "", "vendor-encapsulated-options-space", 1},
	{ "_docsis3_", "vendor-4491", 1},
	{ "dhcp6", "dhcp6", 2},
	{ "vsio", "vendor-opts-space", 2},
	{ "isc6", "_isc6_", 0},
	{ "_rsoo_", "rsoo-opts", 1},
	{ "_isc6_", "vendor-2495", 1},
	{ "server", "_server_", 0},
	{ NULL, NULL, 0}
};

/// DHCPv4
struct option_def options4[] = {
	{ "subnet-mask", "I",			"dhcp",   1, 2},
	{ "time-offset", "l",			"dhcp",   2, 2},
	{ "routers", "IA",			"dhcp",   3, 2},
	{ "time-servers", "IA",			"dhcp",   4, 2},
	{ "ien116-name-servers", "IA",		"dhcp",   5, 2},
	/// ien116-name-servers -> name-servers
	{ "domain-name-servers", "IA",		"dhcp",   6, 2},
	{ "log-servers", "IA",			"dhcp",   7, 2},
	{ "cookie-servers", "IA",		"dhcp",   8, 2},
	{ "lpr-servers", "IA",			"dhcp",   9, 2},
	{ "impress-servers", "IA",		"dhcp",  10, 2},
	{ "resource-location-servers", "IA",	"dhcp",  11, 2},
	{ "host-name", "t",			"dhcp",  12, 2},
	{ "boot-size", "S",			"dhcp",  13, 2},
	{ "merit-dump", "t",			"dhcp",  14, 2},
	{ "domain-name", "t",			"dhcp",  15, 2},
	{ "swap-server", "I",			"dhcp",  16, 2},
	{ "root-path", "t",			"dhcp",  17, 2},
	{ "extensions-path", "t",		"dhcp",  18, 2},
	{ "ip-forwarding", "f",			"dhcp",  19, 2},
	{ "non-local-source-routing", "f",	"dhcp",  20, 2},
	{ "policy-filter", "IIA",		"dhcp",  21, 2},
	{ "max-dgram-reassembly", "S",		"dhcp",  22, 2},
	{ "default-ip-ttl", "B",		"dhcp",  23, 2},
	{ "path-mtu-aging-timeout", "L",	"dhcp",  24, 2},
	{ "path-mtu-plateau-table", "SA",	"dhcp",  25, 2},
	{ "interface-mtu", "S",			"dhcp",  26, 2},
	{ "all-subnets-local", "f",		"dhcp",  27, 2},
	{ "broadcast-address", "I",		"dhcp",  28, 2},
	{ "perform-mask-discovery", "f",	"dhcp",  29, 2},
	{ "mask-supplier", "f",			"dhcp",  30, 2},
	{ "router-discovery", "f",		"dhcp",  31, 2},
	{ "router-solicitation-address", "I",	"dhcp",  32, 2},
	{ "static-routes", "IIA",		"dhcp",  33, 2},
	{ "trailer-encapsulation", "f",		"dhcp",  34, 2},
	{ "arp-cache-timeout", "L",		"dhcp",  35, 2},
	{ "ieee802-3-encapsulation", "f",	"dhcp",  36, 2},
	{ "default-tcp-ttl", "B",		"dhcp",  37, 2},
	{ "tcp-keepalive-interval", "L",	"dhcp",  38, 2},
	{ "tcp-keepalive-garbage", "f",		"dhcp",  39, 2},
	{ "nis-domain", "t",			"dhcp",  40, 2},
	{ "nis-servers", "IA",			"dhcp",  41, 2},
	{ "ntp-servers", "IA",			"dhcp",  42, 2},
	{ "vendor-encapsulated-options", "E.",	"dhcp",  43, 2},
	{ "netbios-name-servers", "IA",		"dhcp",  44, 2},
	{ "netbios-dd-server", "IA",		"dhcp",  45, 2},
	{ "netbios-node-type", "B",		"dhcp",  46, 2},
	{ "netbios-scope", "t",			"dhcp",  47, 2},
	{ "font-servers", "IA",			"dhcp",  48, 2},
	{ "x-display-manager", "IA",		"dhcp",  49, 2},
	{ "dhcp-requested-address", "I",	"dhcp",  50, 2},
	{ "dhcp-lease-time", "L",		"dhcp",  51, 2},
	{ "dhcp-option-overload", "B",		"dhcp",  52, 2},
	{ "dhcp-message-type", "B",		"dhcp",  53, 2},
	{ "dhcp-server-identifier", "I",	"dhcp",  54, 2},
	{ "dhcp-parameter-request-list", "BA",	"dhcp",  55, 2},
	{ "dhcp-message", "t",			"dhcp",  56, 2},
	{ "dhcp-max-message-size", "S",		"dhcp",  57, 2},
	{ "dhcp-renewal-time", "L",		"dhcp",  58, 2},
	{ "dhcp-rebinding-time", "L",		"dhcp",  59, 2},
	{ "vendor-class-identifier", "X",	"dhcp",  60, 2},
	{ "dhcp-client-identifier", "X",	"dhcp",  61, 2},
	{ "nwip-domain", "t",			"dhcp",  62, 2},
	/// nwip-domain nwip-domain-name
	{ "nwip-suboptions", "Enwip.",		"dhcp",  63, 2},
	{ "nisplus-domain", "t",		"dhcp",  64, 2},
	/// nisplus-domain nisplus-domain-name
	{ "nisplus-servers", "IA",		"dhcp",  65, 2},
	{ "tftp-server-name", "t",		"dhcp",  66, 2},
	{ "bootfile-name", "t",			"dhcp",  67, 2},
	/// bootfile-name boot-file-name
	{ "mobile-ip-home-agent", "IA",		"dhcp",  68, 2},
	{ "smtp-server", "IA",			"dhcp",  69, 2},
	{ "pop-server", "IA",			"dhcp",  70, 2},
	{ "nntp-server", "IA",			"dhcp",  71, 2},
	{ "www-server", "IA",			"dhcp",  72, 2},
	{ "finger-server", "IA",		"dhcp",  73, 2},
	{ "irc-server", "IA",			"dhcp",  74, 2},
	{ "streettalk-server", "IA",		"dhcp",  75, 2},
	{ "streettalk-directory-assistance-server", "IA",
						"dhcp",  76, 2},
	{ "user-class", "t",			"dhcp",  77, 2},
	{ "slp-directory-agent", "fIa",		"dhcp",  78, 0},
	/// not supported by Kea
	{ "slp-service-scope", "fto",		"dhcp",  79, 0},
	/// not supported by Kea
	/* 80 is the zero-length rapid-commit (RFC 4039) */
	{ "fqdn", "Efqdn.",			"dhcp",  81, 2},
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
	{ "authentication", "X",		"dhcp",  90, 1},
	/// not supported by ISC DHCP
	{ "client-last-transaction-time", "L",  "dhcp",  91, 2},
	{ "associated-ip", "Ia",                "dhcp",  92, 2},
	{ "client-system", "S",			"dhcp",  93, 1},
	/// not supported by ISC DHCP
	{ "client-ndi", "BBB",			"dhcp",  94, 1},
	/// not supported by ISC DHCP
	{ "uuid-guid", "BX",			"dhcp",  97, 1},
	/// not supported by ISC DHCP
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
	{ "subnet-selection", "I",		"dhcp", 118, 2},
	{ "domain-search", "Dc",		"dhcp", 119, 2},
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
	{ "default-lease-time", "T",		"server",   1, 3},
	{ "max-lease-time", "T",		"server",   2, 0},
	{ "min-lease-time", "T",		"server",   3, 0},
	{ "dynamic-bootp-lease-cutoff", "T",	"server",   4, 0},
	{ "dynamic-bootp-lease-length", "L",	"server",   5, 0},
	{ "boot-unknown-clients", "f",		"server",   6, 0},
	{ "dynamic-bootp", "f",			"server",   7, 0},
	{ "allow-bootp", "f",			"server",   8, 0},
	{ "allow-booting", "f",			"server",   9, 0},
	{ "one-lease-per-client", "f",		"server",  10, 0},
	{ "get-lease-hostnames", "f",		"server",  11, 0},
	{ "use-host-decl-names", "f",		"server",  12, 0},
	{ "use-lease-addr-for-default-route", "f",
						"server",  13, 0},
	{ "min-secs", "B",			"server",  14, 0},
	{ "filename", "t",			"server",  15, 3},
	{ "server-name", "t",			"server",  16, 3},
	{ "next-server", "I",			"server",  17, 3},
	{ "authoritative", "f",			"server",  18, 3},
	{ "vendor-option-space", "U",		"server",  19, 0},
	{ "always-reply-rfc1048", "f",		"server",  20, 0},
	{ "site-option-space", "X",		"server",  21, 0},
	{ "always-broadcast", "f",		"server",  22, 0},
	{ "ddns-domainname", "t",		"server",  23, 3},
	{ "ddns-hostname", "t",			"server",  24, 0},
	{ "ddns-rev-domainname", "t",		"server",  25, 0},
	{ "lease-file-name", "t",		"server",  26, 0},
	{ "pid-file-name", "t",			"server",  27, 0},
	{ "duplicates", "f",			"server",  28, 0},
	{ "declines", "f",			"server",  29, 0},
	{ "ddns-updates", "f",			"server",  30, 3},
	{ "omapi-port", "S",			"server",  31, 0},
	{ "local-port", "S",			"server",  32, 0},
	{ "limited-broadcast-address", "I",	"server",  33, 0},
	{ "remote-port", "S",			"server",  34, 0},
	{ "local-address", "I",			"server",  35, 0},
	{ "omapi-key", "d",			"server",  36, 0},
	{ "stash-agent-options", "f",		"server",  37, 0},
	{ "ddns-ttl", "T",			"server",  38, 0},
	{ "ddns-update-style", "Nddns-styles.",	"server",  39, 3},
	{ "client-updates", "f",		"server",  40, 0},
	{ "update-optimization", "f",		"server",  41, 0},
	{ "ping-check", "f",			"server",  42, 0},
	{ "update-static-leases", "f",		"server",  43, 0},
	{ "log-facility", "Nsyslog-facilities.",
						"server",  44, 0},
	{ "do-forward-updates", "f",		"server",  45, 0},
	{ "ping-timeout", "T",			"server",  46, 0},
	{ "infinite-is-reserved", "f",		"server",  47, 0},
	{ "update-conflict-detection", "f",	"server",  48, 0},
	{ "leasequery", "f",			"server",  49, 0},
	{ "adaptive-lease-time-threshold", "B",	"server",  50, 0},
	{ "do-reverse-updates", "f",		"server",  51, 0},
	{ "fqdn-reply", "f",			"server",  52, 0},
	{ "preferred-lifetime", "T",		"server",  53, 3},
	{ "dhcpv6-lease-file-name", "t",	"server",  54, 0},
	{ "dhcpv6-pid-file-name", "t",		"server",  55, 0},
	{ "limit-addrs-per-ia", "L",		"server",  56, 0},
	{ "limit-prefs-per-ia", "L",		"server",  57, 0},
	{ "dhcp-cache-threshold", "B",		"server",  78, 0},
	{ "dont-use-fsync", "f",		"server",  79, 0},
	{ "ddns-local-address4", "I",		"server",  80, 0},
	{ "ddns-local-address6", "6",		"server",  81, 0},
	{ "ignore-client-uids", "f",		"server",  82, 3},
	{ "log-threshold-low", "B",		"server",  83, 0},
	{ "log-threshold-high", "B",		"server",  84, 0},
	{ "echo-client-id", "f",		"server",  85, 3},
	{ "server-id-check", "f",		"server",  86, 0},
	{ "prefix-length-mode", "Nprefix_length_modes.",
						"server",  87, 0},
	{ "dhcpv6-set-tee-times", "f",		"server",  88, 3},
	{ "abandon-lease-time", "T",		"server",  89, 3},
	{ NULL, NULL, NULL, 0, 0 }
};

void
spaces_init(void)
{
	struct space_def *def;
	struct space *space;

	TAILQ_INIT(&spaces);

	/* Fill spaces */
	for (def = space_defs; def->name != NULL; def++) {
		space = (struct space *)malloc(sizeof(*space));
		assert(space != NULL);
		memset(space, 0, sizeof(*space));
		space->old = def->old;
		space->name = def->name;
		space->status = def->status;
		TAILQ_INSERT_TAIL(&spaces, space);
	}
}

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
		option->space = space_lookup(def->space);
		assert(option->space != NULL);
		option->code = def->code;
		option->status = def->status;
		TAILQ_INSERT_TAIL(&options, option);
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
		option->space = space_lookup(def->space);
		assert(option->space != NULL);
		option->code = def->code;
		option->status = def->status;
		TAILQ_INSERT_TAIL(&options, option);
	}

	/* Fill server config options */
	for (def = configs; def->name != NULL; def++) {
		option = (struct option *)malloc(sizeof(*option));
		assert(option != NULL);
		memset(option, 0, sizeof(*option));
		option->old = def->name;
		option->name = def->name;
		option->format = def->format;
		option->space = space_lookup(def->space);
		assert(option->space != NULL);
		option->code = def->code;
		option->status = def->status;
		TAILQ_INSERT_TAIL(&options, option);
	}
}

struct space *
space_lookup(const char *name)
{
	struct space *space;

	TAILQ_FOREACH(space, &spaces) {
		if (space->status == isc_dhcp_unknown)
			continue;
		if (strcmp(name, space->old) == 0)
			return space;
	}
	return NULL;
}

struct option *
option_lookup_name(const char *space, const char *name)
{
	struct space *universe;
	struct option *option;

	universe = space_lookup(space);
	if (universe == NULL)
		return NULL;
	TAILQ_FOREACH(option, &options) {
		if (option->status == isc_dhcp_unknown)
			continue;
		if (universe != option->space)
			continue;
		if (strcmp(name, option->old) == 0)
			return option;
	}
	return NULL;
}

struct option *
option_lookup_code(const char *space, unsigned code)
{
	struct space *universe;
	struct option *option;

	universe = space_lookup(space);
	if (universe == NULL)
		return NULL;
	TAILQ_FOREACH(option, &options) {
		if (universe != option->space)
			continue;
		if (code == option->code)
			return option;
	}
	return NULL;
}

void
push_space(struct space *space)
{
	space->status = dynamic;
	TAILQ_INSERT_TAIL(&spaces, space);
}

void
push_option(struct option *option)
{
	assert(option->space != NULL);
	option->old = option->name;
	option->status = dynamic;
	TAILQ_INSERT_TAIL(&options, option);
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
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// use default-lease-time instead");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5219");
		TAILQ_INSERT_TAIL(&comments, comment);
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
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 9: /* allow-booting */
		comment = createComment("/// allow-booting is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// no concrete usage known?");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5229");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 10: /* one-lease-per-client */
		comment = createComment("/// one-lease-per-client is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5228");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 11: /* get-lease-hostnames */
		comment = createComment("/// get-lease-hostnames is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5230");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 12: /* use-host-decl-names */
		comment = createComment("/// use-host-decl-names defaults "
				       "to always on");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 13: /* use-lease-addr-for-default-route */
		comment = createComment("/// use-lease-addr-for-default-route "
				       "is obsolete");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 14: /* min-secs */
		comment = createComment("/// min-secs is not (yet?) "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5231");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 19: /* vendor-option-space */
		comment = createComment("/// vendor-option-space is not "
					"(yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5073");
		TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 20: /* always-reply-rfc1048 */
		goto no_bootp;

	case 21: /* site-option-space */
		comment = createComment("/// site-option-space is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5240");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 22: /* always-broadcast */
		comment = createComment("/// always-broadcast is not "
				       "supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5232");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 24: /* ddns-hostname */
		comment = createComment("/// ddns-hostname is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Please use hostname in a "
				       "host reservation instead");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 25: /* ddns-rev-domainname */
		comment = createComment("/// ddns-rev-domainname is an "
				       "obsolete (so not supported) feature");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 26: /* lease-file-name */
		comment = createComment("/// lease-file-name is an internal "
				       "ISC DHCP feature");
		TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 27: /* pid-file-name */
		comment = createComment("/// pid-file-nam is an internal "
				       "ISC DHCP feature");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 28: /* duplicates */
		comment = createComment("/// duplicates is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Kea model is different (and "
				       "stricter)");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 29: /* declines */
		comment = createComment("/// declines is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
                comment = createComment("/// Kea honors decline messages "
				       " and holds address for "
				       "decline-probation-period");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 31: /* omapi-port */
		comment = createComment("/// omapi-port is an internal "
				       "ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 32: /* local-port */
		comment = createComment("/// local-port is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// command line -p parameter "
				       "should be used instead");
		TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 33: /* limited-broadcast-address */
		comment = createComment("/// limited-broadcast-address "
				       "is not (yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment);
                comment = createComment("/// Reference Kea #5233");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 34: /* remote-port */
		comment = createComment("/// remote-port is a not portable "
				       "(so not supported) feature");
		TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 35: /* local-address */
		comment = createComment("/// local-address is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Kea equivalent feature is "
					"to specify an interface address");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 36: /* omapi-key */
		comment = createComment("/// omapi-key is an internal "
					"ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 37: /* stash-agent-options */
		comment = createComment("/// stash-agent-options is not "
					"(yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5234");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 38: /* ddns-ttl */
		comment = createComment("/// ddns-ttl is a D2 not (yet?) "
					"supported feature");
		TAILQ_INSERT_TAIL(&comments, comment);
                comment = createComment("/// Reference Kea #5235");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 40: /* client-updates */
		comment = createComment("/// ddns-ttl client-updates is "
					"not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Kea model is very different");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 41: /* update-optimization */
		comment = createComment("/// update-optimization is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
                comment = createComment("/// Kea follows RFC 4702");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 42: /* ping-check */
		comment = createComment("/// ping-check is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
	no_ping:
		comment = createComment("/// Kea has no ping probing");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 43: /* update-static-leases */
		comment = createComment("/// update-static-leases is an "
					"obsolete feature");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 44: /* log-facility */
		comment = createComment("/// log-facility is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Please use the "
					"KEA_LOGGER_DESTINATION environment "
					"variable instead");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 45: /* do-forward-updates */
		comment = createComment("/// do-forward-updates is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
	ddns_updates:
		comment = createComment("/// Kea model is equivalent but "
					"different");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 46: /* ping-timeout */
		comment = createComment("/// ping-timeout is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		goto no_ping;

	case 47: /* infinite-is-reserved */
		comment = createComment("/// infinite-is-reserved is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Kea does not support reserved "
					"leases");
		TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 48: /* update-conflict-detection */
		comment = createComment("/// update-conflict-detection is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// DDNS is handled by the D2 "
					"server using a dedicated config");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 49: /* leasequery */
		comment = createComment("/// leasequery is not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Kea does not (yet) support "
					"the leasequery protocol");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 50: /* adaptive-lease-time-threshold */
		comment = createComment("/// adaptive-lease-time-threshold is "
					"not supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5236");
		TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 51: /* do-reverse-updates */
		comment = createComment("/// do-reverse-updates is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		goto ddns_updates;

	case 52: /* fqdn-reply */
		comment = createComment("/// fqdn-reply is an obsolete "
					"feature");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 54: /* dhcpv6-lease-file-name */
		comment = createComment("/// dhcpv6-lease-file-name "
					"is an internal ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 55: /* dhcpv6-pid-file-name */
		comment = createComment("/// dhcpv6-pid-file-name "
                                        "is an internal ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 56: /* limit-addrs-per-ia */
		comment = createComment("/// limit-addrs-per-ia "
					"is not (yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment);
	limit_resources:
		comment = createComment("/// Reference Kea #5237");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 57: /* limit-prefs-per-ia */
		comment = createComment("/// limit-prefs-per-ia"
                                        "is not (yet?) supported");
                TAILQ_INSERT_TAIL(&comments, comment);
		goto limit_resources;

	case 78: /* dhcp-cache-threshold */
		comment = createComment("/// dhcp-cache-threshold "
					"is not (yet?) supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5238");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 79: /* dont-use-fsync */
		comment = createComment("/// dont-use-fsync is an internal "
					"ISC DHCP feature");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;

	case 80: /* ddns-local-address4 */
		comment = createComment("/// ddns-local-address4 is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
	d2_ip_address:
		comment = createComment("/// Kea D2 equivalent config is "
					"ip-address");
		TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 81: /* ddns-local-address6 */
		comment = createComment("/// ddns-local-address6 is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		goto d2_ip_address;

	case 83: /* log-threshold-low */
		comment = createComment("/// log-threshold-low is not (yet?) "
					"supported");
                TAILQ_INSERT_TAIL(&comments, comment);
	log_threshold:
		comment = createComment("/// Reference Kea #5220");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;		

	case 84: /* log-threshold-high */
		comment = createComment("/// log-threshold-high is not (yet?) "
                                        "supported");
                TAILQ_INSERT_TAIL(&comments, comment);
		goto log_threshold;

	case 86: /* server-id-check */
		comment = createComment("/// server-id-check is not (yet?) "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Reference Kea #5239");
                TAILQ_INSERT_TAIL(&comments, comment);
		break;

	case 87: /* prefix-length-mode */
		comment = createComment("/// prefix-length-mode is not "
					"supported");
		TAILQ_INSERT_TAIL(&comments, comment);
		comment = createComment("/// Kea model is different (and "
					"simpler?)");
                TAILQ_INSERT_TAIL(&comments, comment);
                break;
	}
	return &comments;
}
