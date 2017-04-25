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

/* From server/confpars.c */

#include "keama.h"

#include <sys/errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

isc_boolean_t got_authoritative = ISC_FALSE;
isc_boolean_t use_client_id = ISC_FALSE;
isc_boolean_t use_flex_id = ISC_FALSE;
isc_boolean_t use_hw_address = ISC_FALSE;

unsigned subclass_counter = 0;

/* To map reservations to declared subnets */
struct subnet {
	struct element *subnet;
	struct string *addr;
	struct string *mask;
	TAILQ_ENTRY(subnet) next;
};

TAILQ_HEAD(subnets, subnet) known_subnets;

static void add_host_reservation_identifiers(struct parse *, const char *);
static void subclass_inherit(struct parse *, struct element *,
			     struct element *);
static void add_match_class(struct parse *, struct element *,
			    struct element *);
static void option_data_derive(struct parse *, struct handle *,
			       struct handle *, isc_boolean_t);
static void new_network_interface(struct parse *, struct element *);
static struct string *addrmask(const struct string *, const struct string *);
static struct element *find_match(struct parse *, struct element *);
static int get_prefix_length(const char *, const char *);

/* Add head config file comments to the DHCP server map */

size_t
conf_file_parse(struct parse *cfile)
{
	struct element *top;
	struct element *dhcp;
	struct element *hosts;
	size_t issues;

	TAILQ_INIT(&known_subnets);

	top = createMap();
	top->kind = TOPLEVEL;
	dhcp = createMap();
	dhcp->kind = ROOT_GROUP;
	TAILQ_CONCAT(&dhcp->comments, &cfile->comments);
	stackPush(cfile, dhcp);
	assert(cfile->stack_top == 1);
	cfile->stack[0] = top;

	if (local_family == AF_INET)
		mapSet(top, dhcp, "Dhcp4");
	else if (local_family == AF_INET6)
		mapSet(top, dhcp, "Dhcp6");
	else
		parse_error(cfile, "address family is not set");

	issues = conf_file_subparse(cfile, ROOT_GROUP);

	if (!got_authoritative)
		parse_error(cfile,
			    "missing top level authoritative statement");

	hosts = mapGet(cfile->stack[1], "reservations");
	if (hosts != NULL) {
		struct element *orphans;
		struct element *host;
		struct element *where;
		struct element *dest;

		mapRemove(cfile->stack[1], "reservations");
		orphans = createList();
		orphans->kind = HOST_DECL;
		while (listSize(hosts) > 0) {
			host = listGet(hosts, 0);
			listRemove(hosts, 0);
			where = find_match(cfile, host);
			if (where == cfile->stack[1])
				dest = orphans;
			else
				dest = mapGet(where, "reservations");
			if (dest == NULL) {
				dest = createList();
				dest->kind = HOST_DECL;
				mapSet(where, dest, "reservations");
			}
			listPush(dest, host);
		}
		if (listSize(orphans) > 0) {
			struct comment *comment;

			comment = createComment("/// Orphan reservations");
			TAILQ_INSERT_TAIL(&orphans->comments, comment);
			comment = createComment("/// Kea reservations are "
						"per subnet");
			TAILQ_INSERT_TAIL(&orphans->comments, comment);
			comment = createComment("/// Reference Kea #5246");
			TAILQ_INSERT_TAIL(&orphans->comments, comment);
			orphans->skip = ISC_TRUE;
			issues++;
			mapSet(cfile->stack[1], orphans, "reservations");
		}
	}

	/* Kea todo: cleanup classes */

	return issues;
}

void
read_conf_file(struct parse *parent, const char *filename, int group_type)
{
	int file;
	struct parse *cfile;
	size_t amount = parent->stack_size * sizeof(struct element *);
	size_t cnt;

	if ((file = open (filename, O_RDONLY)) < 0)
		parse_error(parent, "Can't open %s: %s",
			    filename, strerror(errno));

	cfile = new_parse(file, NULL, 0, filename, 0);
	if (cfile == NULL)
		parse_error(parent, "Can't create new parse structure");

	cfile->stack = (struct element **)malloc(amount);
	if (cfile->stack == NULL)
		parse_error(parent, "Can't create new element stack");
	memcpy(cfile->stack, parent->stack, amount);
	cfile->stack_size = parent->stack_size;
	cfile->stack_top = parent->stack_top;
	cfile->issue_counter = parent->issue_counter;

	cnt = conf_file_subparse(cfile, group_type);

	amount = cfile->stack_size * sizeof(struct element *);
	if (cfile->stack_size > parent->stack_size) {
		parent->stack =
			(struct element **)realloc(parent->stack, amount);
		if (parent->stack == NULL)
			parse_error(cfile, "can't resize element stack");
	}
	memcpy(parent->stack, cfile->stack, amount);
	parent->stack_size = cfile->stack_size;
	parent->stack_top = cfile->stack_top;
	parent->issue_counter = cfile->issue_counter;
	end_parse(cfile);
}

/* conf-file :== parameters declarations END_OF_FILE
   parameters :== <nil> | parameter | parameters parameter
   declarations :== <nil> | declaration | declarations declaration */

size_t
conf_file_subparse(struct parse *cfile, int type)
{
	const char *val;
	enum dhcp_token token;
	isc_boolean_t declaration = ISC_FALSE;

	for (;;) {
		token = peek_token(&val, NULL, cfile);
		if (token == END_OF_FILE)
			break;
		declaration = parse_statement(cfile, type, declaration);
	}
	skip_token(&val, NULL, cfile);

	return cfile->issue_counter;
}

/* statement :== parameter | declaration

   parameter :== DEFAULT_LEASE_TIME lease_time
	       | MAX_LEASE_TIME lease_time
	       | DYNAMIC_BOOTP_LEASE_CUTOFF date
	       | DYNAMIC_BOOTP_LEASE_LENGTH lease_time
	       | BOOT_UNKNOWN_CLIENTS boolean
	       | ONE_LEASE_PER_CLIENT boolean
	       | GET_LEASE_HOSTNAMES boolean
	       | USE_HOST_DECL_NAME boolean
	       | NEXT_SERVER ip-addr-or-hostname SEMI
	       | option_parameter
	       | SERVER-IDENTIFIER ip-addr-or-hostname SEMI
	       | FILENAME string-parameter
	       | SERVER_NAME string-parameter
	       | hardware-parameter
	       | fixed-address-parameter
	       | ALLOW allow-deny-keyword
	       | DENY allow-deny-keyword
	       | USE_LEASE_ADDR_FOR_DEFAULT_ROUTE boolean
	       | AUTHORITATIVE
	       | NOT AUTHORITATIVE

   declaration :== host-declaration
		 | group-declaration
		 | shared-network-declaration
		 | subnet-declaration
		 | VENDOR_CLASS class-declaration
		 | USER_CLASS class-declaration
		 | RANGE address-range-declaration */

isc_boolean_t
parse_statement(struct parse *cfile, int type, isc_boolean_t declaration)
{
	enum dhcp_token token;
	const char *val;
	struct element *hardware;
	struct element *cache;
	struct element *et;
	isc_boolean_t lose;
	isc_boolean_t known;
	isc_boolean_t authoritative;
	struct option *option;
	size_t host_decl = 0;
	size_t subnet = 0;
	size_t i;

	token = peek_token(&val, NULL, cfile);

	switch (token) {
	case INCLUDE:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != STRING)
			parse_error(cfile, "filename string expected.");
		read_conf_file(cfile, val, type);
		parse_semi(cfile);
		return 1;
		
	case HOST:
		skip_token(&val, NULL, cfile);
		if (type != HOST_DECL && type != CLASS_DECL)
			parse_host_declaration(cfile);
		else
			parse_error(cfile,
				    "host declarations not allowed here.");
		return 1;

	case GROUP:
		skip_token(&val, NULL, cfile);
		if (type != HOST_DECL && type != CLASS_DECL)
			parse_group_declaration(cfile);
		else
			parse_error(cfile,
				    "group declarations not allowed here.");
		return 1;

	case SHARED_NETWORK:
		skip_token(&val, NULL, cfile);
		if (type == SHARED_NET_DECL ||
		    type == HOST_DECL ||
		    type == SUBNET_DECL ||
		    type == CLASS_DECL)
			parse_error(cfile, "shared-network parameters not %s.",
				    "allowed here");
		parse_shared_net_declaration(cfile);
		return 1;

	case SUBNET:
	case SUBNET6:
		skip_token(&val, NULL, cfile);
		if (type == HOST_DECL || type == SUBNET_DECL ||
		    type == CLASS_DECL)
			parse_error(cfile,
				    "subnet declarations not allowed here.");

		if (token == SUBNET)
			parse_subnet_declaration(cfile);
		else
			parse_subnet6_declaration(cfile);
		return 1;

	case VENDOR_CLASS:
	case USER_CLASS:
	case CLASS:
	case SUBCLASS:
		skip_token(&val, NULL, cfile);
		if (token == VENDOR_CLASS)
			parse_error(cfile, "obsolete 'vendor-class' "
				    "declaration");
		if (token == USER_CLASS)
			parse_error(cfile, "obsolete 'user-class' "
				    "declaration");
		if (type == CLASS_DECL)
			parse_error(cfile,
				    "class declarations not allowed here.");
		parse_class_declaration(cfile, token == CLASS
					       ? CLASS_TYPE_CLASS
					       : CLASS_TYPE_SUBCLASS);
		return 1;

	case HARDWARE:
		if (!use_hw_address) {
			add_host_reservation_identifiers(cfile,
							 "hw-address");
			use_hw_address = ISC_TRUE;
		}

		skip_token(&val, NULL, cfile);
		if (!host_decl) {
			for (i = cfile->stack_top; i > 0; --i) {
				if (cfile->stack[i]->kind == HOST_DECL) {
					host_decl = i;
					break;
				}
			}
		}
		if (!host_decl)
			parse_error(cfile, "hardware address parameter %s",
				    "not allowed here.");
		if (mapContains(cfile->stack[host_decl], "hw-address"))
			parse_error(cfile, "Host hardware address already "
				    "configured.");
		hardware = parse_hardware_param(cfile);
		mapSet(cfile->stack[host_decl], hardware, "hw-address");
		break;

	case FIXED_ADDR:
	case FIXED_ADDR6:
		skip_token(&val, NULL, cfile);
		if (!host_decl) {
			for (i = cfile->stack_top; i > 0; --i) {
				if (cfile->stack[i]->kind == HOST_DECL) {
					host_decl = i;
					break;
				}
			}
		}
		if (!host_decl)
			parse_error(cfile,
				   "fixed-address parameter not "
				   "allowed here.");
		cache = parse_fixed_addr_param(cfile, token);
		if (token == FIXED_ADDR) {
			struct element *addr;

			if (mapContains(cfile->stack[host_decl], "ip-address"))
				parse_error(cfile, "Only one fixed address "
					    "declaration per host.");
			addr = listGet(cache, 0);
			listRemove(cache, 0);
			mapSet(cfile->stack[host_decl], addr, "ip-address");
			if (listSize(cache) > 0) {
				cache->skip = ISC_TRUE;
				cfile->issue_counter++;
				mapSet(cfile->stack[host_decl],
				       cache, "extra-ip-addresses");
			}
		} else {
			if (mapContains(cfile->stack[host_decl],
					"ip-addresses"))
				parse_error(cfile, "Only one fixed address "
					    "declaration per host.");
			mapSet(cfile->stack[host_decl], cache, "ip-addresses");
		}
		break;

	case POOL:
		skip_token(&val, NULL, cfile);
		if (type == POOL_DECL)
			parse_error(cfile, "pool declared within pool.");
		if (type != SUBNET_DECL && type != SHARED_NET_DECL)
			parse_error(cfile, "pool declared outside of network");
		parse_pool_statement(cfile, type);

		return declaration;

	case RANGE:
		skip_token(&val, NULL, cfile);
		if (!subnet) {
			for (i = cfile->stack_top; i > 0; --i) {
				if (cfile->stack[i]->kind == SUBNET_DECL) {
					subnet = i;
					break;
				}
			}
		}
		if (type != SUBNET_DECL || !subnet)
			parse_error(cfile,
				    "range declaration not allowed here.");
		parse_address_range(cfile, type, subnet);
		return declaration;

	case RANGE6:
		if (local_family != AF_INET6)
			goto unknown;
		skip_token(NULL, NULL, cfile);
		if (!subnet) {
			for (i = cfile->stack_top; i > 0; --i) {
				if (cfile->stack[i]->kind == SUBNET_DECL) {
					subnet = i;
					break;
				}
			}
		}
	        if ((type != SUBNET_DECL) || !subnet)
			parse_error(cfile,
				    "range6 declaration not allowed here.");
	      	parse_address_range6(cfile, type, subnet);
		return declaration;

	case PREFIX6:
		if (local_family != AF_INET6)
			goto unknown;
		skip_token(NULL, NULL, cfile);
		if (!subnet) {
			for (i = cfile->stack_top; i > 0; --i) {
				if (cfile->stack[i]->kind == SUBNET_DECL) {
					subnet = i;
					break;
				}
			}
		}
		if ((type != SUBNET_DECL) || !subnet)
			parse_error(cfile,
				    "prefix6 declaration not allowed here.");
	      	parse_prefix6(cfile, type, subnet);
		return declaration;

	case FIXED_PREFIX6:
		if (local_family != AF_INET6)
			goto unknown;
		skip_token(&val, NULL, cfile);
		if (!host_decl) {
			for (i = cfile->stack_top; i > 0; --i) {
				if (cfile->stack[i]->kind == HOST_DECL) {
					host_decl = i;
					break;
				}
			}
		}
		if (!host_decl)
			parse_error(cfile,
				    "fixed-prefix6 declaration not "
				    "allowed here.");
		parse_fixed_prefix6(cfile, host_decl);
		break;

	case POOL6:
		if (local_family != AF_INET6)
			goto unknown;
		skip_token(&val, NULL, cfile);
		if (type == POOL_DECL)
			parse_error(cfile, "pool6 declared within pool.");
		if (type != SUBNET_DECL)
			parse_error(cfile,
				    "pool6 declared outside of network");
		parse_pool6_statement(cfile, type);

		return declaration;

	case TOKEN_NOT:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		switch (token) {
		case AUTHORITATIVE:
			authoritative = ISC_FALSE;
			goto authoritative;
		default:
			parse_error(cfile, "expecting assertion");
		}
		break;
	case AUTHORITATIVE:
		skip_token(&val, NULL, cfile);
		authoritative = ISC_TRUE;
	authoritative:
		if (type == HOST_DECL)
			parse_error(cfile, "authority makes no sense here.");
		if (type == ROOT_GROUP) {
			got_authoritative = authoritative;
			parse_semi(cfile);
			break;
		}
		cache = createBool(authoritative);
		cache->skip = ISC_TRUE;
		TAILQ_CONCAT(&cache->comments, &cfile->comments);
		mapSet(cfile->stack[cfile->stack_top], cache, "authoritative");
		cfile->issue_counter++;
		parse_semi(cfile);
		break;

		/* "server-identifier" is a special hack, equivalent to
		   "option dhcp-server-identifier". */
	case SERVER_IDENTIFIER:
		option = option_lookup_code("dhcp",
					    DHO_DHCP_SERVER_IDENTIFIER);
		assert(option);
		skip_token(&val, NULL, cfile);
		goto finish_option;

	case OPTION:
		skip_token(&val, NULL, cfile);
		token = peek_token(&val, NULL, cfile);
		if (token == SPACE) {
			if (type != ROOT_GROUP)
				parse_error(cfile,
					    "option space definitions %s",
					    "may not be scoped.");
			parse_option_space_decl(cfile);
			return declaration;
		}

		known = ISC_FALSE;
		option = parse_option_name(cfile, ISC_TRUE, &known);
		token = peek_token(&val, NULL, cfile);
		if (token == CODE) {
			if (type != ROOT_GROUP)
				parse_error(cfile,
					    "option definitions%s",
					    " may not be scoped.");
			skip_token(&val, NULL, cfile);

			/* next function must deal with redefinitions */
			parse_option_code_definition(cfile, option);
			return declaration;
		}
		/* If this wasn't an option code definition, don't
		   allow an unknown option. */
		if (!known)
			parse_error(cfile, "unknown option %s.%s",
				    option->space->old, option->old);
	finish_option:
		parse_option_statement(NULL, cfile, option,
				       supersede_option_statement);
		return declaration;
		break;

	case FAILOVER:
		skip_token(&val, NULL, cfile);
		parse_error(cfile, "No failover support.");
			
	case SERVER_DUID:
		if (local_family != AF_INET6)
			goto unknown;
		parse_server_duid_conf(cfile);
		break;

	case LEASE_ID_FORMAT:
		token = next_token(&val, NULL, cfile);
		/* ignore: ISC DHCP specific */
		break;

	unknown:
		skip_token(&val, NULL, cfile);

	default:
		et = createMap();
		TAILQ_CONCAT(&et->comments, &cfile->comments);
		lose = ISC_FALSE;
		if (!parse_executable_statement(et, cfile, &lose,
						context_any, ISC_TRUE)) {
			if (!lose) {
				if (declaration)
					parse_error(cfile,
						    "expecting a declaration");
				else
					parse_error(cfile,
						    "expecting a parameter %s",
						    "or declaration");
			}
			return declaration;
		}
		if (mapSize(et) == 0)
			return declaration;
		
		et->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(cfile->stack[cfile->stack_top], et, "statement");
	}

	return 0;
}

/*!
 * 
 * \brief Parse allow and deny statements
 *
 * This function handles the common processing code for permit and deny
 * statements in the parse_pool_statement and parse_pool6_statement functions.
 * 
 * The allow or deny token should already be consumed, this function expects
 * one of the following:
 *   known-clients;
 *   unknown-clients;
 *   known clients;
 *   unknown clients;
 *   authenticated clients;
 *   unauthenticated clients;
 *   all clients;
 *   dynamic bootp clients;
 *   members of <class name>;
 *   after <date>;
 *
 * \param[in] cfile       = the configuration file being parsed
 * \param[in] permit_head = the head of the permit list (permit or prohibit)
 *			    to which to attach the newly created  permit structure
 */

void
get_permit(struct parse *cfile, struct element *permit_head)
{
	enum dhcp_token token;
	struct string *permit;
	const char *val;
	isc_boolean_t need_clients = ISC_TRUE;

	token = next_token(&val, NULL, cfile);
	switch (token) {
	case UNKNOWN:
		permit = makeString(-1, "unknown clients");
		break;
				
	case KNOWN_CLIENTS:
		need_clients = ISC_FALSE;
		permit = makeString(-1, "known-clients");
		break;

	case UNKNOWN_CLIENTS:
		need_clients = ISC_FALSE;
		permit = makeString(-1, "unknown-clients");
		break;

	case KNOWN:
		permit = makeString(-1, "known clients");
		break;
				
	case AUTHENTICATED:
		permit = makeString(-1, "authenticated clients");
		break;
				
	case UNAUTHENTICATED:
		permit = makeString(-1, "unauthenticated clients");
		break;

	case ALL:
		permit = makeString(-1, "all clients");
		break;
				
	case DYNAMIC:
		if (next_token(&val, NULL, cfile) != TOKEN_BOOTP)
			parse_error(cfile, "expecting \"bootp\"");
		permit = makeString(-1, "dynamic bootp clients");
		break;

	case MEMBERS:
		/* we don't check the class... */
		need_clients = ISC_FALSE;
		if (next_token(&val, NULL, cfile) != OF)
			parse_error(cfile, "expecting \"of\"");
		if (next_token(&val, NULL, cfile) != STRING)
			parse_error(cfile, "expecting class name.");
		permit = makeString(-1, "member of ");
		appendString(permit, val);
		break;

	case AFTER:
		/* don't use parse_date_code() */
		need_clients = ISC_FALSE;
		permit = makeString(-1, "after");
		while (peek_raw_token(NULL, NULL, cfile) != SEMI) {
			next_raw_token(&val, NULL, cfile);
			appendString(permit, val);
		}
		break;

	default:
		parse_error(cfile, "expecting permit type.");
	}

	/*
	 * The need_clients flag is set if we are expecting the
	 * CLIENTS token
	 */
	if (need_clients && (next_token(&val, NULL, cfile) != CLIENTS))
		parse_error(cfile, "expecting \"clients\"");
	listPush(permit_head, createString(permit));
	parse_semi(cfile);

	return;
}

/*!
 *
 * \brief Parse a pool statement
 *
 * Pool statements are used to group declarations and permit & deny information
 * with a specific address range.  They must be declared within a shared network
 * or subnet and there may be multiple pools withing a shared network or subnet.
 * Each pool may have a different set of permit or deny options.
 *
 * \param[in] cfile = the configuration file being parsed
 * \param[in] type  = the type of the enclosing statement.  This must be
 *		      SHARED_NET_DECL or SUBNET_DECL for this function.
 *
 * \return
 * void - This function either parses the statement and updates the structures
 *        or it generates an error message and possible halts the program if
 *        it encounters a problem.
 */
void
parse_pool_statement(struct parse *cfile, int type)
{
	enum dhcp_token token;
	const char *val;
	isc_boolean_t done = ISC_FALSE;
	struct element *pool;
	struct element *pools;
	struct element *permit;
	struct element *prohibit;
	int declaration = 0;

	pool = createMap();
	pool->kind = POOL_DECL;
	TAILQ_CONCAT(&pool->comments, &cfile->comments);

	if (type != SUBNET_DECL && type != SHARED_NET_DECL)
		parse_error(cfile, "Dynamic pools are only valid inside "
			    "subnet or shared-network statements.");
	parse_lbrace(cfile);

	pools = mapGet(cfile->stack[cfile->stack_top], "pools");
	if (pools == NULL) {
		pools = createList();
		pools->kind = POOL_DECL;
		mapSet(cfile->stack[cfile->stack_top], pools, "pools");
	} else if ((type == SHARED_NET_DECL) && (listSize(pools) > 0)) {
		cfile->stack[cfile->stack_top]->skip = ISC_TRUE;
		cfile->issue_counter++;
	}
	listPush(pools, pool);
	stackPush(cfile, pool);
	type = POOL_DECL;

	permit = createList();
	permit->skip = ISC_TRUE;
	prohibit = createList();
	prohibit->skip = ISC_TRUE;

	do {
		token = peek_token(&val, NULL, cfile);
		switch (token) {
		case TOKEN_NO:
		case FAILOVER:
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "No failover support.");

		case RANGE:
			skip_token(&val, NULL, cfile);
			parse_address_range(cfile, type, cfile->stack_top);
			break;

		case ALLOW:
			skip_token(&val, NULL, cfile);
			get_permit(cfile, permit);
			mapSet(pool, permit, "allow");
			cfile->issue_counter++;
			break;

		case DENY:
			skip_token(&val, NULL, cfile);
			get_permit(cfile, prohibit);
			mapSet(pool, prohibit, "deny");
			cfile->issue_counter++;
			break;
			
		case RBRACE:
			skip_token(&val, NULL, cfile);
			done = ISC_TRUE;
			break;

		case END_OF_FILE:
			/*
			 * We can get to END_OF_FILE if, for instance,
			 * the parse_statement() reads all available tokens
			 * and leaves us at the end.
			 */
			parse_error(cfile, "unexpected end of file");

		default:
			declaration = parse_statement(cfile, type,
						      declaration);
			break;
		}
	} while (!done);

	if (local_family == AF_INET) {
		struct element *opt_list;

		opt_list = mapGet(pool, "option-data");
		if (opt_list != NULL) {
			struct comment *comment;

			comment = createComment("/// Kea doesn't support "
						"option-data in DHCPv4 pools");
			TAILQ_INSERT_TAIL(&opt_list->comments, comment);
			if (!opt_list->skip) {
				opt_list->skip = ISC_TRUE;
				cfile->issue_counter++;
			}
		}
	}

	cfile->stack_top--;
}

/* Expect a left brace */

void
parse_lbrace(struct parse *cfile)
{
	enum dhcp_token token;
	const char *val;

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "expecting left brace.");
}

/* host-declaration :== hostname RBRACE parameters declarations LBRACE */

void
parse_host_declaration(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	struct element *host;
	struct string *name;
	struct element *where;
	struct element *hosts = NULL;
	int declaration = 0;

	host = createMap();
	host->kind = HOST_DECL;
	TAILQ_CONCAT(&host->comments, &cfile->comments);

	name = parse_host_name(cfile);
	if (!name)
		parse_error(cfile, "expecting a name for host declaration.");

	mapSet(host, createString(name), "hostname");

	parse_lbrace(cfile);

	stackPush(cfile, host);

	for (;;) {
		token = peek_token(&val, NULL, cfile);
		if (token == RBRACE) {
			skip_token(&val, NULL, cfile);
			break;
		}
		if (token == END_OF_FILE)
			parse_error(cfile, "unexpected end of file");
		/* If the host declaration was created by the server,
		   remember to save it. */
		if (token == DYNAMIC) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "dynamic hosts don't exist "
				    "in the config file");
		}
		/* If the host declaration was created by the server,
		   remember to save it. */
		if (token == TOKEN_DELETED) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "deleted hosts don't exist "
				    "in the config file");
		}

		if (token == GROUP) {
			struct element *group;
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (token != STRING && !is_identifier(token))
				parse_error(cfile,
					    "expecting string or identifier.");
			/* Kea Todo */
			group = createString(makeString(-1, val));
			group->skip = ISC_TRUE;
			cfile->issue_counter++;
			mapSet(host, group, "group");
			parse_semi(cfile);
			continue;
		}

		if (token == UID) {
			struct string *client_id;

			if (!use_client_id) {
				add_host_reservation_identifiers(cfile,
								 "client-id");
				use_client_id = ISC_TRUE;
			}

			skip_token(&val, NULL, cfile);

			if (mapContains(host, "client-id"))
				parse_error(cfile, "Host %s already has a "
						   "client identifier.",
					    name->content);

			/* See if it's a string or a cshl. */
			token = peek_token(&val, NULL, cfile);
			if (token == STRING) {
				skip_token(&val, NULL, cfile);
				client_id = makeString(-1, val);
			} else {
				struct string *bin;
				unsigned len = 0;
				unsigned i;
				char buf[4];

				bin = parse_numeric_aggregate
					(cfile, NULL, &len, ':', 16, 8);
				if (!bin)
					parse_error(cfile,
						    "expecting hex list.");
				client_id = makeString(0, NULL);
				for (i = 0; i < bin->length; i++) {
					if (i != 0)
						appendString(client_id, ":");
					snprintf(buf, sizeof(buf),
						 "%02hhx", bin->content[i]);
					appendString(client_id, buf);
				}
			}
			/* Kea todo: get text */
			mapSet(host, createString(client_id), "client-id");

			parse_semi(cfile);
			continue;
		}

		if (token == HOST_IDENTIFIER) {
			struct string *host_id;
			isc_boolean_t known;
			struct option *option;
			struct element *expr;
			struct element *data;
			int relays;

			if (!use_flex_id) {
				add_host_reservation_identifiers(cfile,
								 "flex-id");
				use_flex_id = ISC_TRUE;
			}

			if (mapContains(host, "host-identifier"))
				parse_error(cfile,
					    "only one host-identifier allowed "
					    "per host");
	      		skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			host_id = makeString(-1, val);
			appendString(host_id, " ");
			if (token == V6RELOPT) {
				token = next_token(&val, NULL, cfile); 

				if (token != NUMBER)
					parse_error(cfile,
						    "host-identifier v6relopt "
						    "must have a number");
				appendString(host_id, val);
				appendString(host_id, " ");
				relays = atoi(val);
				if (relays < 0)
					parse_error(cfile,
						    "host-identifier v6relopt "
						    "must have a number >= 0");
			} else if (token != OPTION)
				parse_error(cfile, 
					    "host-identifier must be an option"
					    " or v6relopt");
			known = ISC_FALSE;
			option = parse_option_name(cfile, ISC_TRUE, &known);
			if (!known)
				parse_error(cfile, "unknown option %s.%s",
					    option->space->old, option->old);
			appendString(host_id, option->space->name);
			appendString(host_id, ".");
			appendString(host_id, option->name);
			appendString(host_id, " ");

			expr = createMap();
			if (!parse_option_data(expr, cfile, option))
				parse_error(cfile, "can't parse option data");

			parse_semi(cfile);

			data = mapGet(expr, "data");
			if (data == NULL)
				parse_error(cfile, "can't get option data");
			if (data->type != ELEMENT_STRING)
				parse_error(cfile, "option data must be a "
					    "string or binary option");
			
			concatString(host_id, stringValue(data));
			expr = createString(host_id);
			expr->skip = ISC_TRUE;
			cfile->issue_counter++;
			mapSet(host, expr, "host-identifier");

			mapSet(host, data, "flex-id");
			/* Kea todo: push the flex-id glue */
			continue;
		}

		declaration = parse_statement(cfile, HOST_DECL, declaration);
	}

	cfile->stack_top--;

	where = find_match(cfile, host);
	hosts = mapGet(where, "reservations");
	if (hosts == NULL) {
		hosts = createList();
		hosts->kind = HOST_DECL;
		mapSet(where, hosts, "reservations");
	}
	listPush(hosts, host);
}

static void
add_host_reservation_identifiers(struct parse *cfile, const char *id)
{
	struct element *ids;

	ids = mapGet(cfile->stack[1], "host-reservation-identifiers");
	if (ids == NULL) {
		ids = createList();
		mapSet(cfile->stack[1], ids, "host-reservation-identifiers");
	}
	listPush(ids, createString(makeString(-1, id)));
}

/* class-declaration :== STRING LBRACE parameters declarations RBRACE
 *
 * in fact:
 * (CLASS) NAME(STRING) LBRACE ... RBRACE
 * (SUBCLASS) SUPER(STRING) DATA/HASH(STRING | <hexa>) [BRACE ... RBRACE]
 * 
 * class "name" { MATCH IF <boolean-expr> }: direct: belong when true
 * class "name" { MATCH <data-expr> }: indirect: use subclasses
 * class "name" { MATCH <data-expr> SPAWN WITH <data-expr> }: indirect:
 *  create dynamically a subclass
 * subclass "super" <data-expr = string or binary aka hash>: belongs when
 *  super <data-expr> == <hash>
 */

void
parse_class_declaration(struct parse *cfile, int type)
{
	const char *val;
	enum dhcp_token token;
	size_t group;
	size_t i;
	struct element *group_classes = NULL;
	struct element *classes;
	struct element *class = NULL;
	struct element *pc = NULL; /* p(arent)c(lass) */
	struct element *tmp;
	struct element *expr;
	int declaration = 0;
	struct string *data;
	isc_boolean_t binary = ISC_FALSE;
	struct string *name;
	isc_boolean_t lose = ISC_FALSE;
	
	token = next_token(&val, NULL, cfile);
	if (token != STRING)
		parse_error(cfile, "Expecting class name");

	/* Find group and root classes */
	classes = mapGet(cfile->stack[1], "client-classes");
	if (classes == NULL) {
		classes = createList();
		classes->kind = CLASS_DECL;
		mapSet(cfile->stack[1], classes, "client-classes");
	}
	for (group = cfile->stack_top; group > 0; --group) {
		int kind;

		kind = cfile->stack[group]->kind;
		if (kind == CLASS_DECL)
			parse_error(cfile, "class in class");
		if ((kind == GROUP_DECL) || (kind == ROOT_GROUP))
			break;
	}
	if (cfile->stack[group]->kind == GROUP_DECL) {
		group_classes = mapGet(cfile->stack[group], "client-classes");
		if (group_classes == NULL) {
			group_classes = createList();
			group_classes->kind = CLASS_DECL;
			mapSet(cfile->stack[group], group_classes,
			       "client-classes");
		}
	} else
		group_classes = classes;

	/* See if there's already a class with the specified name. */
	for (i = 0; i < listSize(classes); ++i) {
		struct element *name;

		tmp = listGet(classes, i);
		name = mapGet(tmp, "name");
		if (name == NULL)
			continue;
		if (strcmp(stringValue(name)->content, val) == 0) {
			pc = tmp;
			break;
		}
	}

	/* If it is a class, we're updating it.  If it's any of the other
	 * types (subclass, vendor or user class), the named class is a
	 * reference to the parent class so its mandatory.
	 */
	if ((pc != NULL) && (type == CLASS_TYPE_CLASS)) {
		class = pc;
		pc = NULL;
	} else if (type != CLASS_TYPE_CLASS) {
		if (pc == NULL)
			parse_error(cfile, "no class named %s", val);
		if (!mapContains(pc, "spawning") ||
		    !mapContains(pc, "submatch"))
			parse_error(cfile, "found class name %s but it is "
				    "not a suitable superclass", val);
	}

	name = makeString(-1, val);
	/* If this is a straight subclass, parse the hash string. */
	if (type == CLASS_TYPE_SUBCLASS) {
		token = peek_token(&val, NULL, cfile);
		if (token == STRING) {
			unsigned data_len;

			skip_token(&val, &data_len, cfile);
			data = makeString(data_len, val);
		} else if (token == NUMBER_OR_NAME || token == NUMBER) {
			data = makeString(-1, "0x");
			concatString(data, parse_hexa(cfile));
			binary = ISC_TRUE;
		} else {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "Expecting string or hex list.");
		}
	}

	/* See if there's already a class in the hash table matching the
	   hash data. */
	if (type != CLASS_TYPE_CLASS) {
		for (i = 0; i < listSize(classes); i++) {
			struct element *super;
			struct element *selector;

			tmp = listGet(classes, i);
			super = mapGet(tmp, "super");
			if (super == NULL)
				continue;
			if (!eqString(stringValue(super), name))
				continue;
			if (binary)
				selector = mapGet(tmp, "binary");
			else
				selector = mapGet(tmp, "string");
			if (selector == NULL)
				continue;
			if (eqString(stringValue(selector), data)) {
				class = tmp;
				break;
			}
		}
	}
			
	/* Note the class declaration in the enclosing group */
	if (group_classes != classes) {
		struct element *gc;

		gc = createMap();
		gc->kind = CLASS_DECL;
		tmp = createString(name);
		if (type == CLASS_TYPE_CLASS)
			mapSet(gc, tmp, "name");
		else {
			tmp->skip = ISC_TRUE;
			mapSet(gc, tmp, "super");
			tmp = createString(data);
			tmp->skip = ISC_TRUE;
			if (binary)
				mapSet(gc, tmp, "binary");
			else
				mapSet(gc, tmp, "string");
		}
		listPush(group_classes, gc);
	}

	/* If we didn't find an existing class, allocate a new one. */
	if (!class) {
		/* Allocate the class structure... */
		class = createMap();
		class->kind = CLASS_DECL;
		TAILQ_CONCAT(&class->comments, &cfile->comments);
		if (type == CLASS_TYPE_SUBCLASS) {
			struct string *subname;
			char buf[40];

			cfile->issue_counter++;
			tmp = createString(name);
			tmp->skip = ISC_TRUE;
			mapSet(class, tmp, "super");
			tmp = createString(data);
			tmp->skip = ISC_TRUE;
			if (binary)
				mapSet(class, tmp, "binary");
			else
				mapSet(class, tmp, "string");
			subname = makeString(-1, "sub#");
			concatString(subname, name);
			snprintf(buf, sizeof(buf),
				 "#%u", subclass_counter++);
			appendString(subname, buf);
			mapSet(class, createString(subname), "name");
		} else
			/* Save the name, if there is one. */
			mapSet(class, createString(name), "name");
		listPush(classes, class);
	}

	/* Spawned classes don't have to have their own settings. */
	if (type == CLASS_TYPE_SUBCLASS) {
		token = peek_token(&val, NULL, cfile);
		if (token == SEMI) {
			skip_token(&val, NULL, cfile);
			subclass_inherit(cfile, class, copy(pc));
			return;
		}
	}

	parse_lbrace(cfile);

	stackPush(cfile, class);

	for (;;) {
		token = peek_token(&val, NULL, cfile);
		if (token == RBRACE) {
			skip_token(&val, NULL, cfile);
			break;
		} else if (token == END_OF_FILE) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "unexpected end of file");
		} else if (token == DYNAMIC) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "dynamic classes don't exist "
				    "in the config file");
		} else if (token == TOKEN_DELETED) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "deleted hosts don't exist "
				    "in the config file");
		} else if (token == MATCH) {
			skip_token(&val, NULL, cfile);
			if (pc)
				parse_error(cfile,
					    "invalid match in subclass.");
			if (mapContains(class, "spawning") ||
			    mapContains(class, "match-if") ||
			    mapContains(class, "submatch") ||
			    mapContains(class, "test"))
				parse_error(cfile,
					    "A class may only have "
					    "one 'match' or 'spawn' clause.");
			token = peek_token(&val, NULL, cfile);
			if (token != IF) {
				expr = createBool(ISC_FALSE);
				expr->skip = 1;
				mapSet(class, expr, "spawning");
				goto submatch;
			}
			skip_token(&val, NULL, cfile);
			expr = createMap();
			if (!parse_boolean_expression(expr, cfile, &lose)) {
				if (!lose)
					parse_error(cfile,
						    "expecting boolean expr.");
			} else {
				add_match_class(cfile, class, expr);
				parse_semi(cfile);
			}
		} else if (token == SPAWN) {
			skip_token(&val, NULL, cfile);
			if (pc)
				parse_error(cfile,
					    "invalid spawn in subclass.");
			if (mapContains(class, "spawning") ||
			    mapContains(class, "match-if") ||
			    mapContains(class, "submatch") ||
			    mapContains(class, "test"))
				parse_error(cfile,
					    "A class may only have "
					    "one 'match' or 'spawn' clause.");
			class->skip = ISC_TRUE;
			cfile->issue_counter++;
			expr = createBool(ISC_TRUE);
			expr->skip = ISC_TRUE;
			mapSet(class, expr, "spawning");
			token = next_token(&val, NULL, cfile);
			if (token != WITH)
				parse_error(cfile,
					    "expecting with after spawn");
		submatch:
			expr = createMap();
			if (!parse_data_expression(expr, cfile, &lose)) {
				if (!lose)
					parse_error(cfile,
						    "expecting data expr.");
			} else {
				expr->skip = ISC_TRUE;
				cfile->issue_counter++;
				mapSet(class, expr, "submatch");
				parse_semi(cfile);
			}
		} else if (token == LEASE) {
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (token != LIMIT)
				parse_error(cfile, "expecting \"limit\"");
			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile, "expecting a number");
			tmp = createInt(atoll(val));
			tmp->skip = ISC_TRUE;
			cfile->issue_counter++;
			mapSet(class, tmp, "lease-limit");
			parse_semi(cfile);
		} else
			declaration = parse_statement(cfile, CLASS_DECL,
						      declaration);
	}

	cfile->stack_top--;

	if (type == CLASS_TYPE_SUBCLASS)
		subclass_inherit(cfile, class, copy(pc));
}

static void
subclass_inherit(struct parse *cfile,
		 struct element *class,
		 struct element *superclass)
{
	struct string *name;
	struct element *submatch;
	struct handle *handle;
	struct string *mmsg;
	struct string *dmsg;
	struct element *expr;
	struct element *data;
	struct element *match;
	struct element *reduced;
	unsigned order = 0;
	struct comment *comment;
	isc_boolean_t marked = ISC_FALSE;
	isc_boolean_t lose = ISC_FALSE;

	expr = mapGet(superclass, "name");
	if (expr == NULL)
		parse_error(cfile, "can't get superclass name");
	name = stringValue(expr);
	submatch = mapGet(superclass, "submatch");
	if (submatch == NULL)
		parse_error(cfile, "can't get superclass submatch");

	/* Iterates on (copy of) superclass entrie */
	while (mapSize(superclass) > 0) {
		handle = mapPop(superclass);
		if ((handle == NULL) || (handle->key == NULL) ||
		    (handle->value == NULL))
			parse_error(cfile, "can't get superclass %s item at "
				    "%u", name->content, order);
		handle->order = order++;
		/* Superclass specific entries */
		if ((strcmp(handle->key, "name") == 0) ||
		    (strcmp(handle->key, "spawning") == 0) ||
		    (strcmp(handle->key, "submatch") == 0))
			continue;
		/* Subclass specific so impossible entries */
		if ((strcmp(handle->key, "super") == 0) ||
		    (strcmp(handle->key, "binary") == 0) ||
		    (strcmp(handle->key, "string") == 0))
			parse_error(cfile, "superclass %s has unexpected %s "
				    "at %u",
				    name->content, handle->key, order);
		/* Special entries */
		if (strcmp(handle->key, "option-data") == 0) {
			struct element *opt_list;

			opt_list = mapGet(class, handle->key);
			if (opt_list != NULL)
				merge_option_data(handle->value, opt_list);
			else
				mapSet(class, handle->value, handle->key);
			continue;
		}
		/* Just copy */
		if ((strcmp(handle->key, "lease-limit") == 0) ||
		    (strcmp(handle->key, "boot-file-name") == 0) ||
		    (strcmp(handle->key, "serverhostname") == 0) ||
		    (strcmp(handle->key, "next-server") == 0)) {
			mapSet(class, handle->value, handle->key);
			continue;
		}
		/* Unknown */
		if (!marked) {
			marked = ISC_TRUE;
			comment = createComment("/// copied from superclass");
			TAILQ_INSERT_TAIL(&handle->value->comments, comment);
		}
		comment = createComment("/// unhandled entry");
		TAILQ_INSERT_TAIL(&handle->value->comments, comment);
		if (!handle->value->skip) {
			handle->value->skip = ISC_TRUE;
			cfile->issue_counter++;
		}
		mapSet(class, handle->value, handle->key);
	}

	/* build submatch = data */
	expr = mapGet(class, "binary");
	if (expr != NULL) {
		data = createMap();
		mapSet(data, copy(expr), "const-data");
	} else
		data = mapGet(class, "string");
	if (data == NULL)
		parse_error(cfile, "can't get subclass %s data",
			    name->content);
	match = createMap();
	mapSet(match, submatch, "left");
	mapSet(match, copy(data), "right");
	expr = createMap();
	mapSet(expr, match, "equal");
	
	mmsg = makeString(-1, "/// from: match ");
	appendString(mmsg, print_data_expression(submatch, &lose));
	dmsg = makeString(-1, "/// data: ");
	appendString(dmsg, print_data_expression(data, &lose));

	reduced = reduce_boolean_expression(expr);
	if ((reduced != NULL) && (reduced->type == ELEMENT_BOOLEAN))
		parse_error(cfile, "class matching rule reduced to a "
			    "constant boolean expression: %s = %s",
			    print_data_expression(submatch, &lose),
			    print_data_expression(data, &lose));
	if ((reduced == NULL) || (reduced->type != ELEMENT_STRING))
		return;
	if (!lose) {
		comment = createComment(mmsg->content);
		TAILQ_INSERT_TAIL(&reduced->comments, comment);
		comment = createComment(dmsg->content);
		TAILQ_INSERT_TAIL(&reduced->comments, comment);
	}
	mapSet(class, reduced, "test");
}

static void
add_match_class(struct parse *cfile,
		struct element *class,
		struct element *expr)
{
	struct element *reduced;
	struct comment *comment;
	struct string *msg;
	isc_boolean_t lose = ISC_FALSE;

	msg = makeString(-1, "/// from: match if ");
	appendString(msg, print_boolean_expression(expr, &lose));
	if (!lose)
		comment = createComment(msg->content);

	reduced = reduce_boolean_expression(expr);
	if ((reduced != NULL) && (reduced->type == ELEMENT_BOOLEAN))
		parse_error(cfile, "'match if' with a constant boolean "
			    "expression %s",
			    print_boolean_expression(expr, &lose));
	if ((reduced == NULL) || (reduced->type != ELEMENT_STRING)) {
		expr->skip = ISC_TRUE;
		cfile->issue_counter++;
		TAILQ_INSERT_TAIL(&expr->comments, comment);
		mapSet(class, expr, "match-if");
	} else {
		TAILQ_INSERT_TAIL(&reduced->comments, comment);
		mapSet(class, reduced, "test");
	}
}

/* shared-network-declaration :==
			hostname LBRACE declarations parameters RBRACE */

void
parse_shared_net_declaration(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	struct element *share;
	struct element *subnets;
	struct element *interface;
	struct element *subnet;
	struct string *name;
	int declaration = 0;

	share = createMap();
	share->kind = SHARED_NET_DECL;
	TAILQ_CONCAT(&share->comments, &cfile->comments);

	/* Get the name of the shared network... */
	token = peek_token(&val, NULL, cfile);
	if (token == STRING) {
		skip_token(&val, NULL, cfile);

		if (val[0] == 0)
			parse_error(cfile, "zero-length shared network name");
		name = makeString(-1, val);
	} else {
		name = parse_host_name(cfile);
		if (!name)
			parse_error(cfile,
				    "expecting a name for shared-network");
	}
	mapSet(share, createString(name), "name");

	subnets = createList();
	mapSet(share, subnets, "subnets");

	parse_lbrace(cfile);

	stackPush(cfile, share);

	for (;;) {
		token = peek_token(&val, NULL, cfile);
		if (token == RBRACE) {
			skip_token(&val, NULL, cfile);
			break;
		} else if (token == END_OF_FILE) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "unexpected end of file");
		} else if (token == INTERFACE) {
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (mapContains(share, "interface"))
				parse_error(cfile,
					    "A shared network can't be "
					    "connected to two interfaces.");
			interface = createString(makeString(-1, val));
			mapSet(share, interface, "interface");
			new_network_interface(cfile, interface);
			parse_semi(cfile);
			continue;
		}

		declaration = parse_statement(cfile, SHARED_NET_DECL,
					      declaration);
	}

	cfile->stack_top--;

	if (listSize(subnets) == 0)
		parse_error(cfile, "empty shared-network decl");
	if (listSize(subnets) > 1) {
		struct element *shares;

		share->skip = ISC_TRUE;
		cfile->issue_counter++;
		shares = mapGet(cfile->stack[cfile->stack_top],
				"shared-networks");
		if (shares == NULL) {
			shares = createList();
			shares->skip = ISC_TRUE;
			shares->kind = SHARED_NET_DECL;
			mapSet(cfile->stack[cfile->stack_top],
			       shares, "shared-networks");
		}
		listPush(shares, share);
		return;
	}

	/* There is one subnet so the shared network is useless */
	subnet = listGet(subnets, 0);
	listRemove(subnets, 0);
	mapRemove(share, "name");
	mapRemove(share, "subnets");
	/* specific case before calling generic merge */
	if (mapContains(share, "pools") &&
	    mapContains(subnet, "pools")) {
		struct element *pools;
		struct element *sub;

		pools = mapGet(share, "pools");
		mapRemove(share, "pools");
		sub = mapGet(subnet, "pools");
		concat(sub, pools);
	}
	if (mapContains(share, "pd-pools") &&
	    mapContains(subnet, "pd-pools")) {
		struct element *pools;
		struct element *sub;

		pools = mapGet(share, "pd-pools");
		mapRemove(share, "pd-pools");
		sub = mapGet(subnet, "pd-pools");
		concat(sub, pools);
	}
	if (mapContains(share, "option-data") &&
	    mapContains(subnet, "option-data")) {
		struct element *opt_list;
		struct element *sub;

		opt_list = mapGet(share, "option-data");
		mapRemove(share, "option-data");
		sub = mapGet(subnet, "option-data");
		merge_option_data(opt_list, sub);
	}
	merge(subnet, share);

	if (local_family == AF_INET) {
		subnets = mapGet(cfile->stack[1], "subnet4");
		if (subnets == NULL) {
			subnets = createList();
			subnets->kind = SUBNET_DECL;
			mapSet(cfile->stack[1], subnets, "subnet4");
		}
	} else {
		subnets = mapGet(cfile->stack[1], "subnet6");
		if (subnets == NULL) {
			subnets = createList();
			subnets->kind = SUBNET_DECL;
			mapSet(cfile->stack[1], subnets, "subnet6");
		}
	}
	listPush(subnets, subnet);
}

static void
common_subnet_parsing(struct parse *cfile,
		      struct element *subnets,
		      struct element *subnet)
{
	enum dhcp_token token;
	struct element *interface;
	const char *val;
	int declaration = 0;

	parse_lbrace(cfile);

	stackPush(cfile, subnet);

	for (;;) {
		token = peek_token(&val, NULL, cfile);
		if (token == RBRACE) {
			skip_token(&val, NULL, cfile);
			break;
		} else if (token == END_OF_FILE) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "unexpected end of file");
			break;
		} else if (token == INTERFACE) {
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (mapContains(subnet, "interface"))
				parse_error(cfile,
					    "A subnet can't be connected "
					    "to two interfaces.");
			interface = createString(makeString(-1, val));
			mapSet(subnet, interface, "interface");
			new_network_interface(cfile, interface);
			parse_semi(cfile);
			continue;
		}
		declaration = parse_statement(cfile, SUBNET_DECL, declaration);
	}

	cfile->stack_top--;

	/* Add the subnet to the list of subnets in this shared net. */
	listPush(subnets, subnet);

	return;
}

/* subnet-declaration :==
	net NETMASK netmask RBRACE parameters declarations LBRACE */

void
parse_subnet_declaration(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	struct element *subnet;
	struct subnet *chain;
	struct element *subnets;
	struct string *address;
	struct string *netmask;
	struct string *prefix;
	unsigned char addr[4];
	unsigned len = sizeof(addr);
	size_t parent;
	size_t i;
	int kind = 0;

	subnet = createMap();
	subnet->kind = SUBNET_DECL;
	TAILQ_CONCAT(&subnet->comments, &cfile->comments);

	chain = (struct subnet *)malloc(sizeof(*chain));
	if (chain == NULL)
		parse_error(cfile, "can't allocate subnet");
	memset(chain, 0, sizeof(*chain));
	chain->subnet = subnet;
	TAILQ_INSERT_TAIL(&known_subnets, chain);

	/* Find parent */
	for (i = cfile->stack_top; i > 0; --i) {
		kind = cfile->stack[i]->kind;
		if ((kind == SHARED_NET_DECL) || (kind == ROOT_GROUP)) {
			parent = i;
			break;
		}
	}
	if (kind == 0)
		parse_error(cfile, "can't find a place to put subnet");
	if (kind == SHARED_NET_DECL) {
		subnets = mapGet(cfile->stack[parent], "subnets");
		if (subnets == NULL)
			parse_error(cfile, "shared network without subnets");
	} else {
		subnets = mapGet(cfile->stack[1], "subnet4");
		if (subnets == NULL) {
			subnets = createList();
			subnets->kind = SUBNET_DECL;
			mapSet(cfile->stack[1], subnets, "subnet4");
		}
	}

	/* Get the network number... */
	address = parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
	if (address == NULL)
		parse_error(cfile, "can't decode network number");
	if (address->length != 4)
		parse_error(cfile, "bad IPv4 address length");
	chain->addr = address;

	token = next_token(&val, NULL, cfile);
	if (token != NETMASK)
		parse_error(cfile, "Expecting netmask");

	/* Get the netmask... */
	netmask = parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
	if (netmask == NULL)
		parse_error(cfile, "can't decode network mask");
	if (netmask->length != address->length)
		parse_error(cfile, "bad IPv4 mask length");
	chain->mask = netmask;

	prefix = addrmask(address, netmask);
	if (prefix == NULL)
		parse_error(cfile, "can't get a prefix from %s mask %s",
			    address->content, netmask->content);
	mapSet(subnet, createString(prefix), "subnet");

	common_subnet_parsing(cfile, subnets, subnet);
}

/* subnet6-declaration :==
	net / bits RBRACE parameters declarations LBRACE */

void
parse_subnet6_declaration(struct parse *cfile)
{
	enum dhcp_token token;
	const char *val;
	struct element *subnet;
	struct subnet *chain;
	struct element *subnets;
	struct string *address;
	struct string *prefix;
	struct string *netmask;
	size_t parent;
        size_t i;
        int kind = 0;
	char paddr[80];
	char *p;

        if (local_family != AF_INET6)
                parse_error(cfile, "subnet6 statement is only supported "
				   "in DHCPv6 mode.");

	subnet = createMap();
	subnet->kind = SUBNET_DECL;
	TAILQ_CONCAT(&subnet->comments, &cfile->comments);

	chain = (struct subnet *)malloc(sizeof(*chain));
	if (chain == NULL)
		parse_error(cfile, "can't allocate subnet");
	memset(chain, 0, sizeof(*chain));
	chain->subnet = subnet;
	TAILQ_INSERT_TAIL(&known_subnets, chain);

	/* Find parent */
	for (i = cfile->stack_top; i > 0; --i) {
		kind = cfile->stack[i]->kind;
		if ((kind == SHARED_NET_DECL) || (kind == ROOT_GROUP)) {
			parent = i;
			break;
		}
	}
	if (kind == 0)
		parse_error(cfile, "can't find a place to put subnet");
	if (kind == SHARED_NET_DECL) {
		subnets = mapGet(cfile->stack[parent], "subnets");
		if (subnets == NULL)
			parse_error(cfile, "shared network without subnets");
	} else {
		subnets = mapGet(cfile->stack[1], "subnet6");
		if (subnets == NULL) {
			subnets = createList();
			subnets->kind = SUBNET_DECL;
			mapSet(cfile->stack[1], subnets, "subnet6");
		}
	}

	address = parse_ip6_addr(cfile);
	if (address == NULL)
		parse_error(cfile, "can't decode network number");
	if (address->length != 16)
		parse_error(cfile, "bad IPv6 address length");
	chain->addr = address;

	memset(paddr, 0, sizeof(paddr));
	if (!inet_ntop(AF_INET6, address->content, paddr, sizeof(paddr)))
		parse_error(cfile, "can't print network number");
	prefix = makeString(-1, paddr);

	token = next_token(&val, NULL, cfile);
	if (token != SLASH)
		parse_error(cfile, "Expecting a '/'.");
	appendString(prefix, val);

	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "Expecting a number.");
	appendString(prefix, val);

	netmask = makeString(16, "0123456789abcdef");
	memset(netmask->content, 0, 16);
	p = netmask->content;
	for (i = atoi(val); i >= 8; i -= 8)
		*p++ = 0xff;
	*p = 0xff << (8 - i);
	chain->mask = netmask;

	mapSet(subnet, createString(prefix), "subnet");

	common_subnet_parsing(cfile, subnets, subnet);
}

/* group-declaration :== RBRACE parameters declarations LBRACE */

void
parse_group_declaration(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	struct element *group;
	int declaration = 0;
	struct string *name = NULL;

	if (mapContains(cfile->stack[cfile->stack_top], "group"))
		parse_error(cfile, "another group is already open");
	group = createMap();
	group->skip = ISC_TRUE;
	group->kind = GROUP_DECL;
	TAILQ_CONCAT(&group->comments, &cfile->comments);
	mapSet(cfile->stack[cfile->stack_top], group, "group");

	token = peek_token(&val, NULL, cfile);
	if (is_identifier(token) || token == STRING) {
		skip_token(&val, NULL, cfile);
		
		name = makeString(-1, val);
		if (!name)
			parse_error(cfile, "no memory for group decl name %s",
				    val);
	}		

	parse_lbrace(cfile);

	stackPush(cfile, group);

	for (;;) {
		token = peek_token(&val, NULL, cfile);
		if (token == RBRACE) {
			skip_token(&val, NULL, cfile);
			break;
		} else if (token == END_OF_FILE) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "unexpected end of file");
			break;
		} else if (token == TOKEN_DELETED) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "deleted groups don't exist "
				    "in the config file");
		} else if (token == DYNAMIC) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "dynamic groups don't exist "
				    "in the config file");
		} else if (token == STATIC) {
			skip_token(&val, NULL, cfile);
			parse_error(cfile, "static groups don't exist "
				    "in the config file");
		}
		declaration = parse_statement(cfile, GROUP_DECL, declaration);
	}

	cfile->stack_top--;

	if (name != NULL)
		mapSet(group, createString(name), "name");
	dissolve_group(cfile, group);
}

void
dissolve_group(struct parse *cfile, struct element *group)
{
	struct handle *handle;
	struct handle *nh;
	struct element *parent;
	struct element *item;
	struct element *param;
	struct handle *hosts = NULL;
	struct handle *shares = NULL;
	struct handle *subnets = NULL;
	struct handle *classes = NULL;
	struct handle *pdpools = NULL;
	struct handle *pools = NULL;
	struct handles downs;
	struct comment *comment;
	const char *key;
	const char *name = NULL;
	unsigned order = 0;
	isc_boolean_t marked = ISC_FALSE;

	TAILQ_INIT(&downs);

	/* check that group is in its parent */
	parent = cfile->stack[cfile->stack_top];
	if (parent->kind == PARAMETER)
		parse_error(cfile, "unexpected kind for group parent %d",
			    parent->kind);
	item = mapGet(parent, "group");
	if (item == NULL)
		parse_error(cfile, "no group in parent");
	if (item != group)
		parse_error(cfile, "got a different group from parent");
	mapRemove(parent, "group");

	/* classify content */
	while (mapSize(group) > 0) {
		handle = mapPop(group);
		if ((handle == NULL) || (handle->key == NULL) ||
		    (handle->value == NULL))
		    parse_error(cfile, "can't get group item at %u",
				order);
		handle->order = order++;
		switch (handle->value->kind) {
		case TOPLEVEL:
		case ROOT_GROUP:
		case GROUP_DECL:
		badkind:
			parse_error(cfile, "impossible group item (kind %d) "
				    "for %s at order %u",
				    handle->value->kind, handle->key, order);

		case HOST_DECL:
			if (strcmp(handle->key, "reservations") != 0)
				parse_error(cfile, "expected reservations "
					    "got %s at %u",
					    handle->key, order);
			if (hosts != NULL)
				parse_error(cfile, "got reservations twice "
					    "at %u and %u",
					    hosts->order, order);
			if ((parent->kind == HOST_DECL) ||
			    (parent->kind == CLASS_DECL))
				parse_error(cfile, "host declarations not "
					    "allowed here.");
			hosts = handle;
			handle = NULL;
			break;

		case SHARED_NET_DECL:
			if (strcmp(handle->key, "shared-networks") != 0)
				parse_error(cfile, "expected shared-networks "
					    "got %s at %u",
					    handle->key, order);
			if ((parent->kind == SHARED_NET_DECL) ||
			    (parent->kind == HOST_DECL) ||
			    (parent->kind == SUBNET_DECL) ||
			    (parent->kind == CLASS_DECL))
				parse_error(cfile, "shared-network parameters "
					    "not allowed here.");
			shares = handle;
			handle = NULL;
			break;

		case SUBNET_DECL:
			key = local_family == AF_INET ? "subnet4" : "subnet6";
			if (strcmp(handle->key, key) != 0)
				parse_error(cfile, "expected %s got %s at %u",
					    key, handle->key, order);
			if (subnets != NULL)
				parse_error(cfile, "got %s twice at %u and %u",
					    key, subnets->order, order);
			if ((parent->kind == HOST_DECL) ||
			    (parent->kind == SUBNET_DECL) ||
			    (parent->kind == CLASS_DECL))
				parse_error(cfile, "subnet declarations not "
					    "allowed here.");
			subnets = handle;
			handle = NULL;
			break;

		case CLASS_DECL:
			if (strcmp(handle->key, "client-classes") != 0)
				parse_error(cfile, "expected client-classes "
					    "got %s at %u",
					    handle->key, order);
			if (classes != NULL)
				parse_error(cfile, "got %s twice at %u and %u",
					    key, classes->order, order);
			if (parent->kind == CLASS_DECL)
				parse_error(cfile, "class declarations not "
					    "allowed here.");
			classes = handle;
			/* Kea todo: resolve names or super/select */
			handle = NULL;
                        break;

		case POOL_DECL:
			if (strcmp(handle->key, "pd-pools") == 0) {
                                if (pdpools != NULL)
                                        parse_error(cfile, "got pd-pools "
						    "twice at %u and %u",
                                                    pdpools->order, order);
                                pdpools = handle;
			} else if (strcmp(handle->key, "pools") == 0) {
				if (pools != NULL)
					parse_error(cfile, "got pools twice "
						    "at %u and %u",
						    pools->order, order);
				pools = handle;
			} else
				parse_error(cfile, "expecyed [pd-]pools got "
					    "%s at %u",
					    handle->key, order);
			if (parent->kind == POOL_DECL)
				parse_error(cfile, "pool declared within "
					    "pool.");
			if ((parent->kind == HOST_DECL) ||
			    (parent->kind == CLASS_DECL))
				parse_error(cfile, "pool declared outside "
					    "of network");
			handle = NULL;
			break;
		default:
			if (handle->value->kind != PARAMETER)
				goto badkind;
		}
		if (handle == NULL)
			continue;

		/* we have a parameter */
		param = handle->value;
		/* group name */
		if (strcmp(handle->key, "name") == 0) {
			name = stringValue(param)->content;
			continue;
		}
		/* unexpected values */
		if ((strcmp(handle->key, "reservations") == 0) ||
		    (strcmp(handle->key, "group") == 0) ||
		    (strcmp(handle->key, "shared-networks") == 0) ||
		    (strcmp(handle->key, "subnets") == 0) ||
		    (strcmp(handle->key, "subnet4") == 0) ||
		    (strcmp(handle->key, "subnet6") == 0) ||
		    (strcmp(handle->key, "subnet") == 0) ||
		    (strcmp(handle->key, "client-classes") == 0) ||
		    (strcmp(handle->key, "hw-address") == 0) ||
		    (strcmp(handle->key, "ip-address") == 0) ||
		    (strcmp(handle->key, "extra-ip-addresses") == 0) ||
		    (strcmp(handle->key, "ip-addresses") == 0) ||
		    (strcmp(handle->key, "prefixes") == 0) ||
		    (strcmp(handle->key, "pool") == 0) ||
		    (strcmp(handle->key, "prefix") == 0) ||
		    (strcmp(handle->key, "delegated-len") == 0) ||
		    (strcmp(handle->key, "prefix-len") == 0) ||
		    (strcmp(handle->key, "prefix-highest") == 0) ||
		    (strcmp(handle->key, "option-def") == 0) ||
		    (strcmp(handle->key, "hostname") == 0) ||
		    (strcmp(handle->key, "client-id") == 0) ||
		    (strcmp(handle->key, "host-identifier") == 0) ||
		    (strcmp(handle->key, "flex-id") == 0) ||
		    (strcmp(handle->key, "test") == 0) ||
		    (strcmp(handle->key, "dhcp-ddns") == 0) ||
		    (strcmp(handle->key, "host-reservation-identifiers") == 0))
			parse_error(cfile, "unexpected parameter %s "
				    "in group at %u",
				    handle->key, order);
		/* to parent at group position */
		if ((strcmp(handle->key, "authoritative") == 0) ||
		    (strcmp(handle->key, "option-space") == 0) ||
		    (strcmp(handle->key, "server-duid") == 0) ||
		    (strcmp(handle->key, "statement") == 0) ||
		    (strcmp(handle->key, "config") == 0) ||
		    (strcmp(handle->key, "ddns-update-style") == 0) ||
		    (strcmp(handle->key, "echo-client-id") == 0)) {
			if (!marked) {
				struct string *msg;

				marked = ISC_TRUE;
				msg = makeString(-1, "/// moved from group");
				if (name != NULL)
					appendString(msg, " ");
				appendString(msg, name);
				comment = createComment(msg->content);
				TAILQ_INSERT_TAIL(&param->comments, comment);
			}
			mapSet(parent, param, handle->key);
			free(handle);
			continue;
		}
		/* To reconsider: qualifying-suffix, enable-updates */
		if ((strcmp(handle->key, "option-data") == 0) ||
		    (strcmp(handle->key, "allow") == 0) ||
		    (strcmp(handle->key, "deny") == 0) ||
		    (strcmp(handle->key, "interface") == 0) ||
		    (strcmp(handle->key, "valid-lifetime") == 0) ||
		    (strcmp(handle->key, "preferred-lifetime") == 0) ||
		    (strcmp(handle->key, "renew-timer") == 0) ||
		    (strcmp(handle->key, "rebind-timer") == 0) ||
		    (strcmp(handle->key, "boot-file-name") == 0) ||
		    (strcmp(handle->key, "server-hostname") == 0) ||
		    (strcmp(handle->key, "next-server") == 0) ||
		    (strcmp(handle->key, "match-client-id") == 0)) {
			TAILQ_INSERT_TAIL(&downs, handle);
			continue;
		}
		/* unknown */
		if (!marked) {
			struct string *msg;

			marked = ISC_TRUE;
			msg = makeString(-1, "/// moved from group");
			if (name != NULL)
				appendString(msg, " ");
			appendString(msg, name);
			comment = createComment(msg->content);
			TAILQ_INSERT_TAIL(&param->comments, comment);
		}
		comment = createComment("/// unhandled parameter");
		TAILQ_INSERT_TAIL(&param->comments, comment);
		param->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(parent, param, handle->key);
		free(handle);
	}
	TAILQ_FOREACH_SAFE(handle, &downs, nh) {
		if (strcmp(handle->key, "option-data") == 0) {
			option_data_derive(cfile, handle, hosts, ISC_FALSE);
			option_data_derive(cfile, handle, shares, ISC_FALSE);
			option_data_derive(cfile, handle, subnets, ISC_FALSE);
			option_data_derive(cfile, handle, classes, ISC_FALSE);
			option_data_derive(cfile, handle, pdpools, ISC_FALSE);
			option_data_derive(cfile, handle, pools, ISC_TRUE);
		} else if ((strcmp(handle->key, "allow") == 0) ||
			   (strcmp(handle->key, "deny") == 0)) {
			derive(handle, pdpools);
			derive(handle, pools);
		} else if ((strcmp(handle->key, "interface") == 0) ||
			   (strcmp(handle->key, "valid-lifetime") == 0) ||
			   (strcmp(handle->key, "preferred-lifetime") == 0) ||
			   (strcmp(handle->key, "renew-timer") == 0) ||
			   (strcmp(handle->key, "rebind-timer") == 0) ||
			   (strcmp(handle->key, "match-client-id") == 0)) {
			derive(handle, shares);
			derive(handle, subnets);
		} else if ((strcmp(handle->key, "boot-file-name") == 0) ||
			   (strcmp(handle->key, "server-hostname") == 0)) {
			derive(handle, hosts);
			derive(handle, classes);
		} else if (strcmp(handle->key, "next-server") == 0) {
			derive(handle, hosts);
			derive(handle, subnets);
			derive(handle, classes);
		} else
			parse_error(cfile, "unexpected parameter %s to derive",
				    handle->key);
	}
	if (hosts != NULL) {
		struct element *root;

		root = mapGet(cfile->stack[1], "reservations");
		if (root == NULL)
			mapSet(cfile->stack[1], hosts->value, "reservations");
		else
			concat(root, hosts->value);
	}
	if (shares != NULL) {
		struct element *upper;

		upper = mapGet(parent, "shared-networks");
		if (upper == NULL)
			mapSet(parent, shares->value, "shared-networks");
		else
			concat(upper, shares->value);
	}
	key = local_family == AF_INET ? "subnet4" : "subnet6";
	if (subnets != NULL) {
		struct element *upper;

		upper = mapGet(parent, key);
		if (upper == NULL)
			mapSet(parent, subnets->value, key);
		else
			concat(upper, subnets->value);
	}
	if (classes != NULL) {
		/*
		 * Kea todo: move class refs to upper group
                struct element *root;


		root = mapGet(cfile->stack[1], "client-classes");
		if (root == NULL)
			mapSet(cfile->stack[1], classes->value,
			       "client-classes");
		else
			concat(root, classes->value);
		*/
	}
	if (pdpools != NULL) {
		struct element *upper;

		upper = mapGet(parent, "pd-pools");
		if (upper == NULL)
                        mapSet(parent, pdpools->value, "pools");
                else
                        concat(upper, pdpools->value);
	}
	if (pools != NULL) {
		struct element *upper;

		upper = mapGet(parent, "pools");
		if (upper == NULL)
                        mapSet(parent, pools->value, "pools");
                else
                        concat(upper, pools->value);
	}
}

static void
option_data_derive(struct parse *cfile, struct handle *src,
		   struct handle *dst, isc_boolean_t is_pools)
{
	struct element *list;
	struct element *item;
	struct element *opt_list;
	size_t i;

	if (dst == NULL)
		return;
	list = dst->value;
	assert(list != NULL);
	assert(list->type == ELEMENT_LIST);
	for (i = 0; i < listSize(list); i++) {
		item = listGet(list, i);
		assert(item != NULL);
		assert(item->type == ELEMENT_MAP);
		opt_list = mapGet(item, src->key);
		if (opt_list != NULL) {
			merge_option_data(src->value, opt_list);
			continue;
		}
		opt_list = copy(src->value);
		if (is_pools && (local_family == AF_INET)) {
			struct comment *comment;

			comment = createComment("/// Kea doesn't support "
						"option-data in DHCPv4 pools");
			TAILQ_INSERT_TAIL(&opt_list->comments, comment);
			if (!opt_list->skip) {
				opt_list->skip = ISC_TRUE;
				cfile->issue_counter++;
			}
			mapSet(item, opt_list, src->key);
		}
	}
}

/* fixed-addr-parameter :== ip-addrs-or-hostnames SEMI
   ip-addrs-or-hostnames :== ip-addr-or-hostname
			   | ip-addrs-or-hostnames ip-addr-or-hostname */

struct element *
parse_fixed_addr_param(struct parse *cfile, enum dhcp_token type) {
	const char *val;
	enum dhcp_token token;
	struct element *addr;
	struct element *addresses;
	struct string *address;

	addresses = createList();
	TAILQ_CONCAT(&addresses->comments, &cfile->comments);

	do {
		address = NULL;
		if (type == FIXED_ADDR)
			address = parse_ip_addr_or_hostname(cfile, ISC_TRUE);
		else if (type == FIXED_ADDR6)
			address = parse_ip6_addr_txt(cfile);
		else
			parse_error(cfile, "requires FIXED_ADDR[6]");
		if (address == NULL)
			parse_error(cfile, "can't parse fixed address");
		addr = createString(address);
		/* Take the comment for resolution into multiple addresses */
		TAILQ_CONCAT(&addr->comments, &cfile->comments);
		listPush(addresses, addr);
		token = peek_token(&val, NULL, cfile);
		if (token == COMMA)
			token = next_token(&val, NULL, cfile);
	} while (token == COMMA);

	parse_semi(cfile);

	/* Sanity */
	if (listSize(addresses) == 0)
		parse_error(cfile, "can't get fixed address");

	return addresses;

}

/* address-range-declaration :== ip-address ip-address SEMI
			       | DYNAMIC_BOOTP ip-address ip-address SEMI */

void
parse_address_range(struct parse *cfile, int type, size_t where)
{
	struct string *low, *high, *range;
	unsigned char addr[4];
	unsigned len = sizeof(addr);
	enum dhcp_token token;
	const char *val;
	isc_boolean_t dynamic = ISC_FALSE;
	struct element *pool;
	char taddr[40];
	struct element *r;

	if ((token = peek_token(&val, NULL, cfile)) == DYNAMIC_BOOTP) {
		skip_token(&val, NULL, cfile);
		dynamic = ISC_TRUE;
	}

	/* Get the bottom address in the range... */
	low = parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
	if (low == NULL)
		parse_error(cfile, "can't parse range (low)");

	/* Only one address? */
	token = peek_token(&val, NULL, cfile);
	if (token == SEMI)
		high = low;
	else {
		/* Get the top address in the range... */
		high = parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
		if (high ==  NULL)
			parse_error(cfile, "can't parse range (high)");
	}

	token = next_token(&val, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "semicolon expected.");

	if (type != POOL_DECL) {
		struct element *group;
		struct element *pools;
#ifdef want_bootp
		struct element *permit;
#endif

		group = cfile->stack[where];
		pool = createMap();
#ifdef want_bootp
		permit = createList();
		permit->skip = ISC_TRUE;

		/* Dynamic pools permit all clients.   Otherwise
		   we prohibit BOOTP clients. */
		if (dynamic) {
			struct string *all;

			all = makeString(-1, "all clients");
			listPush(permit, createString(all));
			mapSet(pool, permit, "allow");
		} else {
			struct string *dyn_bootp;

			dyn_bootp = makeString(-1, "dynamic bootp clients");
			listPush(permit, createString(dyn_bootp));
			mapSet(pool, permit, "deny");
		}
#endif

		pools = mapGet(group, "pools");
		if (pools == NULL) {
			pools = createList();
			pools->kind = POOL_DECL;
			mapSet(group, pools, "pools");
		}
		listPush(pools, pool);
	} else
		pool = cfile->stack[where];

	/* Create the new address range... */
	if (memcmp(high->content, low->content, high->length) < 0) {
		struct string *swap;

		swap = low;
		low = high;
		high = swap;
	}
	memset(taddr, 0, sizeof(taddr));
	if (!inet_ntop(AF_INET, low->content, taddr, sizeof(taddr)))
		parse_error(cfile, "can't print range address (low)");
	range = makeString(-1, taddr);
	appendString(range, " - ");

	memset(taddr, 0, sizeof(taddr));
	if (!inet_ntop(AF_INET, high->content, taddr, sizeof(taddr)))
		parse_error(cfile, "can't print range address (high)");
	appendString(range, taddr);

	r = createString(range);
	TAILQ_CONCAT(&r->comments, &cfile->comments);

	mapSet(pool, r, "pool");
}

/* address-range6-declaration :== ip-address6 ip-address6 SEMI
			       | ip-address6 SLASH number SEMI
			       | ip-address6 [SLASH number] TEMPORARY SEMI */

void 
parse_address_range6(struct parse *cfile, int type, size_t where)
{
	struct string *lo, *hi;
	enum dhcp_token token;
	const char *val;
	isc_boolean_t is_temporary = ISC_FALSE;
	struct element *pool;
	struct element *range;

        if (local_family != AF_INET6)
                parse_error(cfile, "range6 statement is only supported "
			    "in DHCPv6 mode.");

	/*
	 * Read starting address as text.
	 */
	lo = parse_ip6_addr_txt(cfile);
	if (lo == NULL)
		parse_error(cfile, "can't parse range6 address (low)");

	/* 
	 * See if we we're using range or CIDR notation or TEMPORARY
	 */
	token = peek_token(&val, NULL, cfile);
	if (token == SLASH) {
		appendString(lo, val);
		/*
		 * '/' means CIDR notation, so read the bits we want.
		 */
		skip_token(NULL, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != NUMBER)
			parse_error(cfile, "expecting number");
		/*
		 * no sanity checks
		 */
		appendString(lo, val);
		/*
		 * can be temporary (RFC 4941 like)
		 */
		token = peek_token(&val, NULL, cfile);
		if (token == TEMPORARY) {
			is_temporary = ISC_TRUE;
			appendString(lo, " ");
			appendString(lo, val);
		}			
	} else if (token == TEMPORARY) {
		/*
		 * temporary (RFC 4941)
		 */
		is_temporary = ISC_TRUE;
		appendString(lo, "/64 ");
		appendString(lo, val);
		skip_token(NULL, NULL, cfile);
	} else {
		/*
		 * No '/', so we are looking for the end address of 
		 * the IPv6 pool.
		 */
		hi = parse_ip6_addr_txt(cfile);
		if (hi == NULL)
			parse_error(cfile,
				    "can't parse range6 address (high)");
		/* No sanity checks */
		appendString(lo, " - ");
		appendString(lo, hi->content);
	}

	token = next_token(NULL, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "semicolon expected.");

	if (type != POOL_DECL) {
		struct element *group;
		struct element *pools;

		group = cfile->stack[where];
		pool = createMap();
		pools = mapGet(group, "pools");
		if (pools == NULL) {
			pools = createList();
			pools->kind = POOL_DECL;
			mapSet(group, pools, "pools");
		}
		listPush(pools, pool);
	} else
		pool = cfile->stack[where];

	range = createString(lo);
	TAILQ_CONCAT(&range->comments, &cfile->comments);
	if (is_temporary) {
		range->skip = ISC_TRUE;
		cfile->issue_counter++;
	}
	mapSet(pool, range, "pool");
}

/* prefix6-declaration :== ip-address6 ip-address6 SLASH number SEMI */

void 
parse_prefix6(struct parse *cfile, int type, size_t where)
{
	struct string *lo, *hi;
	int plen;
	int bits;
	enum dhcp_token token;
	const char *val;
	struct element *pool;
	struct element *prefix;

	if (local_family != AF_INET6)
		parse_error(cfile, "prefix6 statement is only supported "
			    "in DHCPv6 mode.");

	/*
	 * Read starting and ending address as text.
	 */
	lo = parse_ip6_addr_txt(cfile);
	if (lo == NULL)
		parse_error(cfile, "can't parse prefix6 address (low)");

	hi = parse_ip6_addr_txt(cfile);
	if (hi == NULL)
		parse_error(cfile, "can't parse prefix6 address (high)");

	/*
	 * Next is '/' number ';'.
	 */
	token = next_token(NULL, NULL, cfile);
	if (token != SLASH)
		parse_error(cfile, "expecting '/'");
	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "expecting number");
	bits = atoi(val);
	if ((bits <= 0) || (bits >= 128))
		parse_error(cfile, "networks have 0 to 128 bits (exclusive)");

	token = next_token(NULL, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "semicolon expected.");

	if (type != POOL_DECL) {
		struct element *group;
		struct element *pools;

		group = cfile->stack[where];
		pool = createMap();
		pools = mapGet(group, "pd-pools");
		if (pools == NULL) {
			pools = createList();
			pools->kind = POOL_DECL;
			mapSet(group, pools, "pd-pools");
		}
		listPush(pools, pool);
	} else
		pool = cfile->stack[where];

	prefix = createString(lo);
	TAILQ_CONCAT(&prefix->comments, &cfile->comments);
	mapSet(pool, prefix, "prefix");
	mapSet(pool, createInt(bits), "delegated-len");
	plen = get_prefix_length(lo->content, hi->content);
	if (plen >= 0)
		mapSet(pool, createInt(plen), "prefix-len");
	else {
		if (!pool->skip)
			cfile->issue_counter++;
		pool->skip = ISC_TRUE;
		mapSet(pool, createString(hi), "prefix-highest");
	}
}

/* fixed-prefix6 :== ip6-address SLASH number SEMI */

void
parse_fixed_prefix6(struct parse *cfile, size_t host_decl)
{
	struct string *ia;
	enum dhcp_token token;
	const char *val;
	struct element *host;
	struct element *prefixes;
	struct element *prefix;

	if (local_family != AF_INET6)
		parse_error(cfile, "fixed-prefix6 statement is only "
			    "supported in DHCPv6 mode.");

	/*
	 * Get the fixed-prefix list.
	 */
	host = cfile->stack[host_decl];
	prefixes = mapGet(host, "prefixes");
	if (prefixes == NULL) {
		prefixes = createList();
		mapSet(host, prefixes, "prefixes");
	}

	ia = parse_ip6_addr_txt(cfile);
	if (ia == NULL)
		parse_error(cfile, "can't parse fixed-prefix6 address");
	token = next_token(NULL, NULL, cfile);
	if (token != SLASH)
		parse_error(cfile, "expecting '/'");
	appendString(ia, val);
	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "expecting number");
	appendString(ia, val);
	token = next_token(NULL, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "semicolon expected.");

	prefix = createString(ia);
	TAILQ_CONCAT(&prefix->comments, &cfile->comments);
	listPush(prefixes, prefix);
}

/*!
 *
 * \brief Parse a pool6 statement
 *
 * Pool statements are used to group declarations and permit & deny information
 * with a specific address range.  They must be declared within a shared network
 * or subnet and there may be multiple pools withing a shared network or subnet.
 * Each pool may have a different set of permit or deny options.
 *
 * \param[in] cfile = the configuration file being parsed
 * \param[in] type  = the type of the enclosing statement.  This must be
 *		      SUBNET_DECL for this function.
 *
 * \return
 * void - This function either parses the statement and updates the structures
 *        or it generates an error message and possible halts the program if
 *        it encounters a problem.
 */

/*
 * Should reorganize the code to create both pool and pd-pool -- KEA TODO
 */

void
parse_pool6_statement(struct parse *cfile, int type)
{
	enum dhcp_token token;
	const char *val;
	isc_boolean_t done = ISC_FALSE;
	struct element *pool;
	struct element *pools;
	struct element *permit;
	struct element *prohibit;
	int declaration = 0;

	if (local_family != AF_INET6)
		parse_error(cfile, "pool6 statement is only supported "
			    "in DHCPv6 mode.");

	pool = createMap();
	pool->kind = POOL_DECL;
	TAILQ_CONCAT(&pool->comments, &cfile->comments);

	if (type != SUBNET_DECL)
		parse_error(cfile, "pool6s are only valid inside "
			    "subnet statements.");
	parse_lbrace(cfile);

	pools = mapGet(cfile->stack[cfile->stack_top], "pools");
	if (pools == NULL) {
		pools = createList();
		pools->kind = POOL_DECL;
		mapSet(cfile->stack[cfile->stack_top], pools, "pools");
	}
	listPush(pools, pool);
	stackPush(cfile, pool);
	type = POOL_DECL;

	permit = createList();
	permit->skip = ISC_TRUE;
	prohibit = createList();
	prohibit->skip = ISC_TRUE;

	do {
		token = peek_token(&val, NULL, cfile);
		switch (token) {
		case RANGE6:
			skip_token(NULL, NULL, cfile);
			parse_address_range6(cfile, type, cfile->stack_top);
			break;

		case PREFIX6:
			skip_token(NULL, NULL, cfile);
			parse_prefix6(cfile, SUBNET_DECL,
				      cfile->stack_top - 1);
			break;

		case ALLOW:
			skip_token(NULL, NULL, cfile);
			get_permit(cfile, permit);
			mapSet(pool, permit, "allow");
			cfile->issue_counter++;
			break;

		case DENY:
			skip_token(NULL, NULL, cfile);
			get_permit(cfile, prohibit);
			mapSet(pool, prohibit, "deny");
			cfile->issue_counter++;
			break;
			
		case RBRACE:
			skip_token(&val, NULL, cfile);
			done = ISC_TRUE;
			break;

		case END_OF_FILE:
			/*
			 * We can get to END_OF_FILE if, for instance,
			 * the parse_statement() reads all available tokens
			 * and leaves us at the end.
			 */
			parse_error(cfile, "unexpected end of file");

		default:
			declaration = parse_statement(cfile, POOL_DECL,
						      declaration);
			break;
		}
	} while (!done);

	cfile->stack_top--;
}

/* allow-deny-keyword :== BOOTP
   			| BOOTING
			| DYNAMIC_BOOTP
			| UNKNOWN_CLIENTS */

struct element *
parse_allow_deny(struct parse *cfile, int flag)
{
	enum dhcp_token token;
	const char *val;
	const char *action;
	const char *option;
	struct element *sv_option;

	switch (flag) {
	case 0:
		action = "deny";
		break;
	case 1:
		action = "allow";
		break;
	case 2:
		action = "ignore";
		break;
	default:
		action = "unknown?";
		break;
	}

	token = next_token(&val, NULL, cfile);
	switch (token) {
	case TOKEN_BOOTP:
		option = "allow-bootp";
		break;

	case BOOTING:
		option = "allow-booting";
		break;

	case DYNAMIC_BOOTP:
		option = "dynamic-bootp";
		break;

	case UNKNOWN_CLIENTS:
		option = "boot-unknown-clients";
		break;

	case DUPLICATES:
		option = "duplicates";
		break;

	case DECLINES:
		option = "declines";
		break;

	case CLIENT_UPDATES:
		option = "client-updates";
		break;

	case LEASEQUERY:
		option = "leasequery";
		break;

	default:
		parse_error(cfile, "expecting allow/deny key");
	}
	parse_semi(cfile);

	sv_option = createMap();
	mapSet(sv_option, createString(makeString(-1, action)), "data");
	mapSet(sv_option, createString(makeString(-1, option)), "name");
	mapSet(sv_option, createString(makeString(-1, "_server_")), "space");
	sv_option->skip = ISC_TRUE;
	cfile->issue_counter++;
	return sv_option;
}

/*
 * When we parse a server-duid statement in a config file, we will
 * have the type of the server DUID to generate, and possibly the
 * actual value defined.
 *
 * server-duid llt;
 * server-duid llt ethernet|ieee802|fddi 213982198 00:16:6F:49:7D:9B;
 * server-duid ll;
 * server-duid ll ethernet|ieee802|fddi 00:16:6F:49:7D:9B;
 * server-duid en 2495 "enterprise-specific-identifier-1234";
 */
void 
parse_server_duid_conf(struct parse *cfile) {
	enum dhcp_token token;
	const char *val;
	unsigned int len;
	struct string *ll_addr;
	struct string *duid;
	struct element *sv_duid;

	/*
	 * Consume the SERVER_DUID token.
	 */
	next_token(&val, NULL, cfile);
	duid = makeString(-1, val);

	/*
	 * Obtain the DUID type.
	 */
	token = next_token(&val, NULL, cfile);
	appendString(duid, " ");
	appendString(duid, val);

	/* 
	 * Enterprise is the easiest - enterprise number and raw data
	 * are required.
	 */
	if (token == EN) {
		/*
		 * Get enterprise number and identifier.
		 */
		token = next_token(&val, NULL, cfile);
		if (token != NUMBER)
			parse_error(cfile, "enterprise number expected");
		appendString(duid, " ");
		appendString(duid, val);

		token = next_token(&val, &len, cfile);
		if (token != STRING)
			parse_error(cfile, "identifier expected");
		appendString(duid, " ");
		appendString(duid, val);
	}

	/* 
	 * Next easiest is the link-layer DUID. It consists only of
	 * the LL directive, or optionally the specific value to use.
	 *
	 * If we have LL only, then we set the type. If we have the
	 * value, then we set the actual DUID.
	 */
	else if (token == LL) {
		if (peek_token(NULL, NULL, cfile) != SEMI) {
			/*
			 * Get our hardware type and address.
			 */
			token = next_token(NULL, NULL, cfile);
			appendString(duid, " ");
			appendString(duid, val);

			ll_addr = parse_cshl(cfile);
			if (ll_addr == NULL)
				parse_error(cfile,
					    "can't get hardware address");
			appendString(duid, " ");
			appendString(duid, ll_addr->content);
		}
	}

	/* 
	 * Finally the link-layer DUID plus time. It consists only of
	 * the LLT directive, or optionally the specific value to use.
	 *
	 * If we have LLT only, then we set the type. If we have the
	 * value, then we set the actual DUID.
	 */
	else if (token == LLT) {
		if (peek_token(NULL, NULL, cfile) != SEMI) {
			/*
			 * Get our hardware type, timestamp, and address.
			 */
			token = next_token(NULL, NULL, cfile);
			appendString(duid, " ");
			appendString(duid, val);

			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile, "timestamp expected");
			appendString(duid, " ");
			appendString(duid, val);

			ll_addr = parse_cshl(cfile);
			if (ll_addr == NULL)
				parse_error(cfile,
					    "can't get hardware address");
			appendString(duid, " ");
			appendString(duid, ll_addr->content);
			memset(&ll_addr, 0, sizeof(ll_addr));
		}
	}

	/*
	 * If users want they can use a number for DUID types.
	 * This is useful for supporting future, not-yet-defined
	 * DUID types.
	 *
	 * In this case, they have to put in the complete value.
	 *
	 * This also works for existing DUID types of course. 
	 */
	else if (token == NUMBER) {
		token = next_token(&val, &len, cfile);
		if (token != STRING)
			parse_error(cfile, "identifier expected");
		appendString(duid, " ");
		appendString(duid, val);
	}

	/*
	 * Anything else is an error.
	 */
	else
		parse_error(cfile, "DUID type of LLT, EN, or LL expected");

	/*
	 * Finally consume our trailing semicolon.
	 */
	token = next_token(NULL, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "semicolon expected");

	sv_duid = createString(duid);
	sv_duid->skip = ISC_TRUE;
	TAILQ_CONCAT(&sv_duid->comments, &cfile->comments);
	cfile->issue_counter++;
	mapSet(cfile->stack[cfile->stack_top], sv_duid, "server-duid");
}

/*
 * Push new interface on the interface list when it is not already.
 */
static void
new_network_interface(struct parse *cfile, struct element *iface)
{
	struct element *ifconf;
	struct element *iflist;
	struct string *name = stringValue(iface);
	int i;

	ifconf = mapGet(cfile->stack[1], "interfaces-config");
	if (ifconf == NULL) {
		ifconf = createMap();
		mapSet(cfile->stack[1], ifconf, "interfaces-config");
	}

	iflist = mapGet(ifconf, "interfaces");
	if (iflist == NULL) {
		iflist = createList();
		mapSet(ifconf, iflist, "interfaces");
	}

	for (i = 0; i < listSize(iflist); ++i) {
		struct element *item;

		item = listGet(iflist, i);
		if ((item != NULL) &&
		    (item->type == ELEMENT_STRING) &&
		    eqString(stringValue(item), name))
			return;
	}

	listPush(iflist, createString(name));
}

/* Convert address and mask in binary into address/len text */

static const uint32_t bitmasks[32 + 1] = {
	0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff,
	0x0fffffff, 0x07ffffff, 0x03ffffff, 0x01ffffff,
	0x00ffffff, 0x007fffff, 0x003fffff, 0x001fffff,
	0x000fffff, 0x0007ffff, 0x0003ffff, 0x0001ffff,
	0x0000ffff, 0x00007fff, 0x00003fff, 0x00001fff,
	0x00000fff, 0x000007ff, 0x000003ff, 0x000001ff,
	0x000000ff, 0x0000007f, 0x0000003f, 0x0000001f,
	0x0000000f, 0x00000007, 0x00000003, 0x00000001,
	0x00000000 };

static struct string *
addrmask(const struct string *address, const struct string *netmask)
{
	char addr[40], buf[40];
	int plen, cc;
	uint32_t mask;

	memset(addr, 0, sizeof(addr));
	if (!inet_ntop(AF_INET, address->content, addr, sizeof(addr)))
		return NULL;

	memcpy(&mask, netmask->content, 4);
	mask = ntohl(mask);
	for (plen = 0; plen <= 32; ++plen)
		if (~mask == bitmasks[plen])
			break;
	if (plen > 32)
		return NULL;

	memset(buf, 0, sizeof(buf));
	cc = snprintf(buf, sizeof(buf), "%s/%d", addr, plen);
	if (cc < 0 || cc >= 40)
		return NULL;
	return makeString(-1, buf);
}

static struct element *
find_match(struct parse *cfile, struct element *host)
{
	struct element *address;
	struct subnet *subnet;
	char addr[16];
	size_t i, len;

	if (local_family == AF_INET) {
		address = mapGet(host, "ip-address");
		if (address == NULL) {
			if (TAILQ_EMPTY(&known_subnets))
				return cfile->stack[1];
			return TAILQ_LAST(&known_subnets, subnets)->subnet;
		}
		len = 4;
	} else {
		address = mapGet(host, "ip-addresses");
		if (address == NULL) {
			if (TAILQ_EMPTY(&known_subnets))
				return cfile->stack[1];
			return TAILQ_LAST(&known_subnets, subnets)->subnet;
		}
		address = listGet(address, 0);
		if (address == NULL)
			return TAILQ_LAST(&known_subnets, subnets)->subnet;
		len = 16;
	}

	if (inet_pton(local_family, stringValue(address)->content, addr) != 1)
		parse_error(cfile, "bad address %s",
			    stringValue(address)->content);
	TAILQ_FOREACH(subnet, &known_subnets) {
		isc_boolean_t matching = ISC_TRUE;

		if (subnet->mask->length != len)
			continue;
		for (i = 0; i < len; i++)
			if ((addr[i] & subnet->mask->content[i]) !=
					subnet->addr->content[i]) {
				matching = ISC_FALSE;
				break;
			}
		if (matching)
			return subnet->subnet;
	}
	return cfile->stack[1];
}

static int
get_prefix_length(const char *low, const char *high)
{
	uint32_t low_int;
	uint32_t high_int;
	uint32_t xor_int;
	int plen;

	memcpy(&low_int, low, 4);
	memcpy(&high_int, high, 4);
	xor_int = low_int ^ high_int;
	for (plen = 0; plen <= 32; ++plen)
		if (xor_int == bitmasks[plen])
			return plen;
	return -1;
}
