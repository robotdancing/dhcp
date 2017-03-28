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

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

static void new_network_interface(struct parse *, struct element *);
static struct string *addrmask(const struct string *, const struct string *);
static int get_prefix_length(const char *, const char *);

/* conf-file :== parameters declarations END_OF_FILE
   parameters :== <nil> | parameter | parameters parameter
   declarations :== <nil> | declaration | declarations declaration

   Add head config file comments to the DHCP server map */

size_t
conf_file_parse(struct parse *cfile)
{
	struct element *top;
	struct element *dhcp;

	top = createMap();
	top->kind = TOPLEVEL;
	dhcp = createMap();
	dhcp->kind = ROOT_GROUP;
	TAILQ_CONCAT(&dhcp->comments, &cfile->comments, next);
	stackPush(cfile, dhcp);
	assert(cfile->stack_top == 1);
	cfile->stack[0] = top;

	if (local_family == AF_INET)
		mapSet(top, dhcp, "Dhcp4");
	else if (local_family == AF_INET6)
		mapSet(top, dhcp, "Dhcp6");
	else
		parse_error(cfile, "address family is not set");

	return conf_file_subparse(cfile, ROOT_GROUP);
}

size_t
read_conf_file(struct parse *parent, const char *filename, int group_type)
{
	int file;
	struct parse *cfile;
	size_t amount = parent->stack_size * sizeof(struct element *);
	size_t cnt;

	if ((file = open (filename, O_RDONLY)) < 0)
		parse_error(parent, "Can't open %s: %m", filename);

	cfile = new_parse(file, NULL, 0, filename, 0);
	if (cfile == NULL)
		parse_error(parent, "Can't create new parse structure");

	cfile->stack = (struct element **)malloc(amount);
	if (cfile->stack == NULL)
		parse_error(parent, "Can't create new element stack");
	memcpy(cfile->stack, parent->stack, amount);
	cfile->stack_size = parent->stack_size;
	cfile->stack_top = parent->stack_top;
	cnt = cfile->issue_counter = parent->issue_counter;

	cnt = conf_file_subparse(cfile, group_type);
	parent->issue_counter = cfile->issue_counter;
	end_parse(cfile);

	return parent->issue_counter - cnt;
}

/* conf-file :== parameters declarations END_OF_FILE
   parameters :== <nil> | parameter | parameters parameter
   declarations :== <nil> | declaration | declarations declaration */

size_t
conf_file_subparse(struct parse *cfile, int type)
{
	const char *val;
	enum dhcp_token token;
	int declaration = 0;

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

int
parse_statement(struct parse *cfile, int type, int declaration)
{
	enum dhcp_token token;
	const char *val;
	struct element *hardware;
	struct element *cache;
#if 0
	isc_boolean_t lose;
	char *n;
#endif
	isc_boolean_t authoritative;
	struct element *option;
	unsigned code;
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
		skip_token(&val, NULL, cfile);
		if (type == CLASS_DECL)
			parse_error(cfile,
				    "class declarations not allowed here.");
		parse_class_declaration(cfile, CLASS_TYPE_VENDOR);
		return 1;

	case USER_CLASS:
		skip_token(&val, NULL, cfile);
		if (type == CLASS_DECL)
			parse_error(cfile,
				    "class declarations not allowed here.");
		parse_class_declaration(cfile, CLASS_TYPE_USER);
		return 1;

	case CLASS:
		skip_token(&val, NULL, cfile);
		if (type == CLASS_DECL)
			parse_error(cfile,
				    "class declarations not allowed here.");
		parse_class_declaration(cfile, CLASS_TYPE_CLASS);
		return 1;

	case SUBCLASS:
		skip_token(&val, NULL, cfile);
		if (type == CLASS_DECL)
			parse_error(cfile,
				    "class declarations not allowed here.");
		parse_class_declaration(cfile, CLASS_TYPE_SUBCLASS);
		return 1;

	case HARDWARE:
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
		if (((token == FIXED_ADDR) &&
		     mapContains(cfile->stack[host_decl], "ip-address")) ||
		    ((token == FIXED_ADDR6) &&
		     mapContains(cfile->stack[host_decl], "ip-addresses")))
			parse_error(cfile, "Only one fixed address "
				    "declaration per host.");
		cache = parse_fixed_addr_param(cfile, token);
		if (token == FIXED_ADDR) {
			mapSet(cfile->stack[host_decl],
			       listGet(cache, 0), "ip-address");
			listRemove(cache, 0);
			if (listSize(cache) > 0) {
				cache->skip = ISC_TRUE;
				cfile->issue_counter++;
				mapSet(cfile->stack[host_decl],
				       cache, "extra-ip-addresses");
			}
		} else
			mapSet(cfile->stack[host_decl], cache, "ip-addresses");
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
		cache = createBool(authoritative);
		cache->skip = ISC_TRUE;
		mapSet(cfile->stack[cfile->stack_top], cache, "authoritative");
		cfile->issue_counter++;
		parse_semi(cfile);
		break;

		/* "server-identifier" is a special hack, equivalent to
		   "option dhcp-server-identifier". */
	case SERVER_IDENTIFIER:
		code = DHO_DHCP_SERVER_IDENTIFIER;
		option = createMap();
		mapSet(option, createInt(code), "code");
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

		option = parse_option_name(cfile);
		token = peek_token(&val, NULL, cfile);
		if (token == CODE) {
			if (type != ROOT_GROUP)
				parse_error(cfile,
					    "option definitions%s",
					    " may not be scoped.");
			skip_token(&val, NULL, cfile);

			parse_option_code_definition(cfile, option);
			return declaration;
		}
	finish_option:
		parse_option_statement(NULL, cfile, option,
				       supersede_option_statement);
		return declaration;
		break;

	case FAILOVER:
		if (type != ROOT_GROUP && type != SHARED_NET_DECL)
			parse_error(cfile, "failover peers may only be %s",
				    "defined in shared-network\n"
				    "declarations and the outer scope.");
		token = next_token(&val, NULL, cfile);
		parse_error(cfile, "No failover support.");
		break;
			
	case SERVER_DUID:
		if (local_family != AF_INET6)
			goto unknown;
		parse_server_duid_conf(cfile);
		break;

	case LEASE_ID_FORMAT:
		token = next_token(&val, NULL, cfile);
		/* ignore: ISC DHCP specific */
		break;

	default:
	unknown:
/* Kea todo */
#if 0
		et = NULL;
		lose = ISC_FALSE;
		if (!parse_executable_statement(&et, cfile, &lose,
						context_any)) {
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
		if (!et)
#endif
			return declaration;
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

	if (type != SUBNET_DECL && type != SHARED_NET_DECL)
		parse_error(cfile, "Dynamic pools are only valid inside "
			    "subnet or shared-network statements.");
	parse_lbrace(cfile);

	pools = mapGet(cfile->stack[cfile->stack_top], "pools");
	if (pools == NULL) {
		pools = createList();
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
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (token != FAILOVER ||
			    (token = next_token(&val, NULL, cfile)) != PEER)
				parse_error(cfile,
					   "expecting \"failover peer\".");
			break;
				
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
	int declaration = 0;
	isc_boolean_t dynamicp = ISC_FALSE;
	isc_boolean_t deleted = ISC_FALSE;
#if 0
	int known;
	struct option *option;
	struct expression *expr = NULL;
#endif

	name = parse_host_name(cfile);
	if (!name)
		parse_error(cfile, "expecting a name for host declaration.");

	host = createMap();
	host->kind = HOST_DECL;

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
			dynamicp = ISC_TRUE;
			skip_token(&val, NULL, cfile);
			parse_semi(cfile);
			continue;
		}
		/* If the host declaration was created by the server,
		   remember to save it. */
		if (token == TOKEN_DELETED) {
			deleted = ISC_TRUE;
			skip_token(&val, NULL, cfile);
			parse_semi(cfile);
			continue;
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
				unsigned len = 0;

				client_id = parse_numeric_aggregate
					(cfile, NULL, &len, ':', 16, 8);
				if (!client_id)
					parse_error(cfile,
						    "expecting hex list.");
			}
			mapSet(host, createString(client_id), "client-id");

			parse_semi(cfile);
			continue;
		}

		if (token == HOST_IDENTIFIER) {
			struct string *host_id;
			struct element *elem;

			if (mapContains(host, "host-identifier"))
				parse_error(cfile,
					    "only one host-identifier allowed "
					    "per host");
	      		skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			host_id = makeString(-1, val);
			if (token != V6RELOPT && token != OPTION)
				parse_error(cfile, 
					    "host-identifier must be an option"
					    " or v6relopt");
			while (peek_raw_token(NULL, NULL, cfile) != SEMI) {
				next_raw_token(&val, NULL, cfile);
				appendString(host_id, val);
			}

			parse_semi(cfile);

			elem = createString(host_id);
			elem->skip = ISC_TRUE;
			cfile->issue_counter++;
			mapSet(host, elem, "host-identifier");
			continue;
		}

		declaration = parse_statement(cfile, HOST_DECL, declaration);
	}

	cfile->stack_top--;
	if (!deleted) {
		struct element *hosts;
		size_t parent;
		size_t i;
		int kind = 0;

		for (i = cfile->stack_top; i > 0; --i) {
			kind = cfile->stack[i]->kind;
			if ((kind == GROUP_DECL) || (kind == ROOT_GROUP)) {
				parent = i;
				break;
			}
		}
		if (kind == 0)
			parse_error(cfile, "can't find a place to put "
				    "host %s declaration", name->content);
		hosts = mapGet(cfile->stack[parent], "reservations");
		if (hosts == NULL) {
			hosts = createList();
			mapSet(cfile->stack[parent], hosts, "reservations");
		}
		listPush(hosts, host);
	}
}

/* class-declaration :== STRING LBRACE parameters declarations RBRACE
*/

int
parse_class_declaration(struct parse *cfile, int type)
{
	const char *val;
	enum dhcp_token token;
	struct element *classes;
	struct element *class = NULL, *pc = NULL;
	struct element *children;
	struct element *lease_limit;
	int declaration = 0;
	struct string *data;
	char *name;
	const char *tname;
	isc_boolean_t new = ISC_TRUE;
#if 0
	isc_boolean_t lose = ISC_FALSE;
	isc_boolean_t matchedonce = ISC_FALSE;
	isc_boolean_t submatchedonce = ISC_FALSE;
	unsigned code;
#endif
	int i;
	isc_boolean_t has_superclass = ISC_FALSE;
	int flags = 0;
	
	token = next_token(&val, NULL, cfile);
	if (token != STRING)
		parse_error(cfile, "Expecting class name");

	/* See if there's already a class with the specified name. */
	classes = mapGet(cfile->stack[1], "client-classes");
	if (classes == NULL) {
		classes = createList();
		mapSet(cfile->stack[1], classes, "client-classes");
	} else {
		int i;

		for (i = 0; i < listSize(classes); ++i) {
			struct element *item;
			struct element *name;

			item = listGet(classes, i);
			name = mapGet(item, "name");
			if ((name != NULL) &&
			    (name->type == ELEMENT_STRING) &&
			    (strcmp(stringValue(name)->content, val) == 0)) {
				pc = item;
				break;
			}
		}
	}

	/* If it is a class, we're updating it.  If it's any of the other
	 * types (subclass, vendor or user class), the named class is a
	 * reference to the parent class so its mandatory.
	 */
	if (pc && (type == CLASS_TYPE_CLASS)) {
		new = ISC_FALSE;
		class = pc;
	} else if (!pc && (type != CLASS_TYPE_CLASS))
		parse_error(cfile, "no class named %s", val);

	/* The old vendor-class and user-class declarations had an implicit
	   match.   We don't do the implicit match anymore.   Instead, for
	   backward compatibility, we have an implicit-vendor-class and an
	   implicit-user-class.   vendor-class and user-class declarations
	   are turned into subclasses of the implicit classes, and the
	   submatch expression of the implicit classes extracts the contents of
	   the vendor class or user class. */
	if ((type == CLASS_TYPE_VENDOR) || (type == CLASS_TYPE_USER)) {
		data = makeString(-1, val);

		tname = (type == CLASS_TYPE_VENDOR) ?
		  "implicit-vendor-class" : "implicit-user-class";

	} else if (type == CLASS_TYPE_CLASS) {
		tname = val;
	} else {
		tname = NULL;
	}

	if (tname) {
		name = strdup(tname);
		if (!name)
			parse_error(cfile, "No memory for class name %s.",
				    tname);
	} else
		name = NULL;

	/* If this is a straight subclass, parse the hash string. */
	if (type == CLASS_TYPE_SUBCLASS) {
		token = peek_token(&val, NULL, cfile);
		if (token == STRING) {
			unsigned data_len;

			skip_token(&val, &data_len, cfile);
			data = makeString(data_len, val);
		} else if (token == NUMBER_OR_NAME || token == NUMBER)
			data = parse_cshl(cfile);
		else
			parse_error(cfile, "Expecting string or hex list.");
	}

	/* See if there's already a class in the hash table matching the
	   hash data. */
	if (type != CLASS_TYPE_CLASS) {
		children = mapGet(pc, "children");
		if (children == NULL) {
			children = createList();
			children->skip = ISC_TRUE;
			mapSet(pc, children, "children");
			lease_limit = mapGet(pc, "lease-limit");
			if (lease_limit != NULL) {
				struct element *copy;

				copy = createInt(intValue(lease_limit));
				copy->skip = lease_limit->skip;
				mapSet(class, copy, "lease-limit");
			}
		} else {
			for (i = 0; i < listSize(children); ++i) {
				struct element *child;
				struct element *hash;

				child = listGet(children, i);
				hash = mapGet(child, "hash");
				if ((hash != NULL) &&
				    (hash->type == ELEMENT_STRING) &&
				    eqString(stringValue(hash), data)) {
					class = child;
					has_superclass = ISC_TRUE;
					break;
				}
			}
		}
	}

	/* If we didn't find an existing class, allocate a new one. */
	if (!class) {
		/* Allocate the class structure... */
		class = createMap();
		class->kind = CLASS_DECL;
		class->skip = ISC_TRUE;
		cfile->issue_counter++;
		if (type == CLASS_TYPE_SUBCLASS) {
			struct element *sub;

			sub = createBool(ISC_TRUE);
			mapSet(class, sub, "subclass");
		}
		if (pc) {
			listPush(children, class);
			mapSet(class, createString(data), "hash");
			has_superclass = ISC_TRUE;
		}

/* Kea TODO */
#if 0
		/* If this is an implicit vendor or user class, add a
		   statement that causes the vendor or user class ID to
		   be sent back in the reply. */
		if (type == CLASS_TYPE_VENDOR || type == CLASS_TYPE_USER) {
			stmt = NULL;
			if (!executable_statement_allocate(&stmt, MDL))
				log_fatal("no memory for class statement.");
			stmt->op = supersede_option_statement;
			if (option_cache_allocate(&stmt->data.option,
						  MDL)) {
				stmt->data.option->data = data;
				code = (type == CLASS_TYPE_VENDOR)
					? DHO_VENDOR_CLASS_IDENTIFIER
					: DHO_USER_CLASS;
				option_code_hash_lookup(
						&stmt->data.option->option,
							dhcp_universe.code_hash,
							&code, 0, MDL);
			}
			class->statements = stmt;
		}
#endif
		/* Save the name, if there is one. */
		if (mapContains(class, "name"))
			mapRemove(class, "name");
		mapSet(class, createString(makeString(-1, name)), "name");
	}

	/* Spawned classes don't have to have their own settings. */
	if (has_superclass) {
		token = peek_token(&val, NULL, cfile);
		if (token == SEMI) {
			skip_token(&val, NULL, cfile);

			return 1;
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
			break;
		} else if (token == DYNAMIC) {
			flags |= CLASS_DECL_DYNAMIC;
			skip_token(&val, NULL, cfile);
			parse_semi(cfile);
			continue;
		} else if (token == TOKEN_DELETED) {
			flags |= CLASS_DECL_DELETED;
			skip_token(&val, NULL, cfile);
			parse_semi(cfile);
			continue;
		} else if (token == MATCH) {
			if (pc) {
				parse_error(cfile,
					    "invalid match in subclass.");
				skip_to_semi(cfile);
				break;
			}
			skip_token(&val, NULL, cfile);
			token = peek_token(&val, NULL, cfile);
/* Kea TODO */
#if 0
			if (token != IF)
				goto submatch;
			skip_token(&val, NULL, cfile);
			if (matchedonce)
				parse_error(cfile, "A class may only have "
					    "one 'match if' clause.");
			matchedonce = ISC_TRUE;
			if (class->expr)
				expression_dereference(&class->expr, MDL);
			if (!parse_boolean_expression(&class->expr, cfile,
						      &lose)) {
				if (!lose)
					parse_error(cfile,
						    "expecting boolean expr.");
			} else {
				parse_semi(cfile);
			}
		} else if (token == SPAWN) {
			skip_token(&val, NULL, cfile);
			if (pc)
				parse_error(cfile,
					    "invalid spawn in subclass.");
			class->spawning = 1;
			token = next_token(&val, NULL, cfile);
			if (token != WITH)
				parse_error(cfile,
					    "expecting with after spawn");
		submatch:
			if (submatchedonce)
				parse_error(cfile,
					    "can't override existing %s.",
					    "submatch/spawn");
			submatchedonce = ISC_TRUE;
			if (class->submatch)
				expression_dereference(&class->submatch, MDL);
			if (!parse_data_expression(&class->submatch,
						   cfile, &lose)) {
				if (!lose)
					parse_error(cfile,
						    "expecting data expr.");
			} else {
				parse_semi(cfile);
			}
#endif
		} else if (token == LEASE) {
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (token != LIMIT)
				parse_error(cfile, "expecting \"limit\"");
			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile, "expecting a number");
			lease_limit = createInt(atoll(val));
			lease_limit->skip = ISC_TRUE;
			cfile->issue_counter++;
			mapSet(class, lease_limit, "lease-limit");
			parse_semi(cfile);
		} else {
			declaration = parse_statement(cfile, CLASS_DECL,
						      declaration);
		}
	}

	if (flags & CLASS_DECL_DELETED) {
		if (type != CLASS_TYPE_CLASS) {
			for (i = 0; i < listSize(children); ++i) {
				struct element *child;
				struct element *hash;

				child = listGet(children, i);
				hash = mapGet(child, "hash");
				if ((hash != NULL) &&
				    (hash->type == ELEMENT_STRING) &&
				    eqString(stringValue(hash), data))
					listRemove(children, i);
			}
		}
	} else if (type == CLASS_TYPE_CLASS && new)
		listPush(classes, class);

	cfile->stack_top--;

	return 1;
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
	share->skip = ISC_TRUE;
	share->kind = SHARED_NET_DECL;

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
		cfile->issue_counter++;
		return;
	}

	/* There is one subnet so the shared network is useless */
	subnet = listGet(subnets, 0);
	listRemove(subnets, 0);
	mapRemove(share, "name");
	mapRemove(share, "subnets");
	merge(subnet, share);

	if (local_family == AF_INET) {
		subnets = mapGet(cfile->stack[1], "subnet4");
		if (subnets == NULL) {
			subnets = createList();
			mapSet(cfile->stack[1], subnets, "subnet4");
		}
	} else {
		subnets = mapGet(cfile->stack[1], "subnet6");
		if (subnets == NULL) {
			subnets = createList();
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
			mapSet(cfile->stack[1], subnets, "subnet4");
		}
	}

	/* Get the network number... */
	address = parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
	if (address == NULL)
		parse_error(cfile, "can't decode network number");

	token = next_token(&val, NULL, cfile);
	if (token != NETMASK)
		parse_error(cfile, "Expecting netmask");

	/* Get the netmask... */
	netmask = parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
	if (netmask == NULL)
		parse_error(cfile, "can't decode network mask");

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
parse_subnet6_declaration(struct parse *cfile) {
	enum dhcp_token token;
	const char *val;
	struct element *subnet;
	struct element *subnets;
	struct string *address;
	struct string *prefix;
	size_t parent;
        size_t i;
        int kind = 0;
	char paddr[80];

        if (local_family != AF_INET6)
                parse_error(cfile, "subnet6 statement is only supported "
				   "in DHCPv6 mode.");

	subnet = createMap();
	subnet->kind = SUBNET_DECL;

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
			mapSet(cfile->stack[1], subnets, "subnet6");
		}
	}

	address = parse_ip6_addr(cfile);
	if (address == NULL)
		parse_error(cfile, "can't decode network number");
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
	isc_boolean_t deletedp = ISC_FALSE;
	isc_boolean_t dynamicp = ISC_FALSE;
	isc_boolean_t staticp = ISC_FALSE;

	group = createMap();
	group->skip = ISC_TRUE;
	group->kind = GROUP_DECL;

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
			parse_semi(cfile);
			deletedp = ISC_TRUE;
		} else if (token == DYNAMIC) {
			skip_token(&val, NULL, cfile);
			parse_semi(cfile);
			dynamicp = ISC_TRUE;
		} else if (token == STATIC) {
			skip_token(&val, NULL, cfile);
			parse_semi(cfile);
			staticp = ISC_TRUE;
		}
		declaration = parse_statement(cfile, GROUP_DECL, declaration);
	}

	cfile->stack_top--;

	if (name && !deletedp) {
		mapSet(group, createString(name), "name");
		/* Kea todo */
	}
	cfile->issue_counter++;
}

/* fixed-addr-parameter :== ip-addrs-or-hostnames SEMI
   ip-addrs-or-hostnames :== ip-addr-or-hostname
			   | ip-addrs-or-hostnames ip-addr-or-hostname */

struct element *
parse_fixed_addr_param(struct parse *cfile, enum dhcp_token type) {
	const char *val;
	enum dhcp_token token;
	struct element *addresses;
	struct string *address;
	isc_boolean_t ipaddr = ISC_TRUE;

	addresses = createList();

	do {
		address = NULL;
		if (type == FIXED_ADDR)
			address = parse_ip_addr_or_hostname(cfile, &ipaddr);
		else if (type == FIXED_ADDR6)
			address = parse_ip6_addr_txt(cfile);
		else
			parse_error(cfile, "requires FIXED_ADDR[6]");
		if (address == NULL)
			parse_error(cfile, "can't parse fixed address");
		if (ipaddr) {
			struct element *name;
			struct comment *comment;

			name = createString(address);
			ipaddr = ISC_TRUE;
			name->skip = ISC_TRUE;
			cfile->issue_counter++;
			comment = createComment("### please resolve this "
						"name into one address");
			TAILQ_INSERT_TAIL(&name->comments, comment, next);
			listPush(addresses, name);
		} else
			listPush(addresses, createString(address));
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

	if ((token = peek_token(&val,
				 NULL, cfile)) == DYNAMIC_BOOTP) {
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
		struct element *permit;
		struct element *pools;

		group = cfile->stack[where];
		pool = createMap();
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

		pools = mapGet(group, "pools");
		if (pools == NULL) {
			pools = createList();
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

	mapSet(pool, createString(range), "pool");
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
			mapSet(group, pools, "pools");
		}
		listPush(pools, pool);
	} else
		pool = cfile->stack[where];

	range = createString(lo);
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
			mapSet(group, pools, "pd-pools");
		}
		listPush(pools, pool);
	} else
		pool = cfile->stack[where];

	mapSet(pool, createString(lo), "prefix");
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

	listPush(prefixes, createString(ia));
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

	if (type != SUBNET_DECL)
		parse_error(cfile, "pool6s are only valid inside "
			    "subnet statements.");
	parse_lbrace(cfile);

	pools = mapGet(cfile->stack[cfile->stack_top], "pools");
	if (pools == NULL) {
		pools = createList();
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
	struct element *expr;

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
		option = "allow bootp";
		break;

	case BOOTING:
		option = "allow booting";
		break;

	case DYNAMIC_BOOTP:
		option = "dynamic bootp";
		break;

	case UNKNOWN_CLIENTS:
		option = "boot unknown clients";
		break;

	case DUPLICATES:
		option = "duplicates";
		break;

	case DECLINES:
		option = "declines";
		break;

	case CLIENT_UPDATES:
		option = "client updates";
		break;

	case LEASEQUERY:
		option = "leasequery";
		break;

	default:
		parse_error(cfile, "expecting allow/deny key");
	}
	parse_semi(cfile);

	sv_option = createMap();
	mapSet(sv_option, createString(makeString(-1, action)), "action");
	mapSet(sv_option, createString(makeString(-1, option)), "name");
	expr = createMap();
	expr->skip = ISC_TRUE;
	cfile->issue_counter++;
	mapSet(expr, sv_option, "server-option");
	return expr;
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
