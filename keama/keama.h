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

#ifndef EOL
#define EOL '\n'
#endif

#include "data.h"
#include "dhctoken.h"

#include <time.h>

/* From includes/dhcp.h */

#define DHO_DHCP_SERVER_IDENTIFIER		54
#define DHO_VENDOR_CLASS_IDENTIFIER		60
#define DHO_USER_CLASS				77

/* From includes/dhcpd.h */

extern int local_family;

/* A parsing context. */

struct parse {
	int lexline;
	int lexchar;
	char *token_line;
	char *prev_line;
	char *cur_line;
	const char *tlname;
	int eol_token;

	/*
	 * In order to give nice output when we have a parsing error
	 * in our file, we keep track of where we are in the line so
	 * that we can show the user.
	 *
	 * We need to keep track of two lines, because we can look
	 * ahead, via the "peek" function, to the next line sometimes.
	 *
	 * The "line1" and "line2" variables act as buffers for this
	 * information. The "lpos" variable tells us where we are in the
	 * line.
	 *
	 * When we "put back" a character from the parsing context, we
	 * do not want to have the character appear twice in the error
	 * output. So, we set a flag, the "ugflag", which the
	 * get_char() function uses to check for this condition.
	 */
	char line1[81];
	char line2[81];
	int lpos;
	int line;
	int tlpos;
	int tline;
	enum dhcp_token token;
	int ugflag;
	char *tval;
	int tlen;
	char tokbuf[1500];

	int warnings_occurred;
	int file;
	char *inbuf;
	size_t bufix, buflen;
	size_t bufsiz;

	struct parse *saved_state;

	/*
	 * Additions for the Kea Migration Assistant.
	 */
	struct comments comments;
	struct element **stack;
	size_t stack_size;
	size_t stack_top;
	size_t issue_counter;
};

#define PARAMETER	0
#define TOPLEVEL	1
#define	ROOT_GROUP	2
#define HOST_DECL	3
#define SHARED_NET_DECL	4
#define SUBNET_DECL	5
#define CLASS_DECL	6
#define	GROUP_DECL	7
#define POOL_DECL	8

/* Used as an argument to parse_class_decl() */
#define CLASS_TYPE_VENDOR	0
#define CLASS_TYPE_USER		1
#define CLASS_TYPE_CLASS	2
#define CLASS_TYPE_SUBCLASS	3

#define CLASS_DECL_DELETED	1
#define CLASS_DECL_DYNAMIC	2
#define CLASS_DECL_STATIC	4
#define CLASS_DECL_SUBCLASS	8

/* Authentication and BOOTP policy possibilities (not all values work
   for each). */
enum policy { P_IGNORE, P_ACCEPT, P_PREFER, P_REQUIRE, P_DONT };

/* Kea parse tools */
void stackPush(struct parse *cfile, struct element *elem);

/* From common/parse.c */
void parse_error(struct parse *, const char *, ...)
	__attribute__((__format__(__printf__,2,3)))
	__attribute__((noreturn));

/* conflex.c */
struct parse *new_parse(int, char *, size_t, const char *, int);
void end_parse(struct parse *);
void save_parse_state(struct parse *cfile);
void restore_parse_state(struct parse *cfile);
enum dhcp_token next_token(const char **, unsigned *, struct parse *);
enum dhcp_token peek_token(const char **, unsigned *, struct parse *);
enum dhcp_token next_raw_token(const char **rval, unsigned *rlen,
			       struct parse *cfile);
enum dhcp_token peek_raw_token(const char **rval, unsigned *rlen,
			       struct parse *cfile);
/*
 * Use skip_token when we are skipping a token we have previously
 * used peek_token on as we know what the result will be in this case.
 */
#define skip_token(a,b,c) ((void) next_token((a),(b),(c)))

/* confparse.c */
size_t conf_file_parse(struct parse *);
size_t read_conf_file(struct parse *, const char *, int);
size_t conf_file_subparse(struct parse *, int);
int parse_statement(struct parse *, int, int);
void get_permit(struct parse *, struct element *);
void parse_pool_statement(struct parse *, int);
void parse_lbrace(struct parse *);
void parse_host_declaration(struct parse *);
int parse_class_declaration(struct parse *, int);
void parse_shared_net_declaration(struct parse *);
void parse_subnet_declaration(struct parse *);
void parse_subnet6_declaration(struct parse *);
void parse_group_declaration(struct parse *);
struct element *parse_fixed_addr_param(struct parse *, enum dhcp_token);
void parse_address_range(struct parse *, int, size_t);
void parse_address_range6(struct parse *, int, size_t);
void parse_prefix6(struct parse *, int, size_t);
void parse_fixed_prefix6(struct parse *, size_t);
void parse_pool6_statement(struct parse *, int);
struct element *parse_allow_deny(struct parse *, int);
void parse_server_duid_conf(struct parse *cfile);

/* parse.c */
void skip_to_semi(struct parse *);
void skip_to_rbrace(struct parse *, int);
void parse_semi(struct parse *);
void parse_string(struct parse *, char **, unsigned *);
struct string *parse_host_name(struct parse *);
struct string *parse_ip_addr_or_hostname(struct parse *, int);
/* parse_ip_addr */
struct string *parse_ip6_addr(struct parse *);
struct string *parse_ip6_addr_expr(struct parse *);
/* parse_ip6_prefix */
/* parse_ip_addr_with_subnet */
struct element *parse_hardware_param(struct parse *);
void parse_lease_time(struct parse *, time_t *);
struct string *parse_numeric_aggregate(struct parse *,
				       unsigned char *, unsigned *,
				       int, int, unsigned);
void convert_num(struct parse *, unsigned char *, const char *,
		 int, unsigned);
time_t parse_date(struct parse *);
time_t parse_date_core(struct parse *);
/* parse_option_name */
void parse_option_space_decl(struct parse *);
/* parse_option_code_definition */
/* parse_base64 */
struct string *parse_cshl(struct parse *);
/* parse_executable_statements */
/* parse_executable_statement */
/* parse_zone */
int parse_key(struct parse *);
/* parse_on_statement */
/* parse_switch_statement */
/* parse_case_statement */
/* parse_if_statement */
/* parse_boolean_expression */
int parse_boolean(struct parse *);
/* parse_data_expression */
/* parse_numeric_expression */
/* parse_non_binary */
/* parse_expression */
/* parse_option_data */
/* parse_option_statement */
/* parse_option_token */
/* parse_option_decl */
/* parse_X */
struct expression *parse_domain_list(struct parse *cfile, int);

/* json.c */
struct element *json_parse(struct parse *);
struct element *json_list_parse(struct parse *);
struct element *json_map_parse(struct parse *);
