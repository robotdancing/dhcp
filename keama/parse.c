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

#include "keama.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static uint32_t getULong(const unsigned char *buf);
static int32_t getLong(const unsigned char *buf);
static uint32_t getUShort(const unsigned char *buf);
static int32_t getShort(const unsigned char *buf);
static void putULong(unsigned char *obuf, uint32_t val);
static void putLong(unsigned char *obuf, int32_t val);
static void putUShort(unsigned char *obuf, uint32_t val);
static void putShort(unsigned char *obuf, int32_t val);
static void putUChar(unsigned char *obuf, uint32_t val);
static uint32_t getUChar(const unsigned char *obuf);

static isc_boolean_t is_boolean_expression(struct element *);
static isc_boolean_t is_data_expression(struct element *);
static isc_boolean_t is_numeric_expression(struct element *);
static isc_boolean_t is_compound_expression(struct element *);

/* Skip to the semicolon ending the current statement.   If we encounter
   braces, the matching closing brace terminates the statement.
*/
void
skip_to_semi(struct parse *cfile)
{
	skip_to_rbrace(cfile, 0);
}

/* Skips everything from the current point upto (and including) the given
 number of right braces.  If we encounter a semicolon but haven't seen a
 left brace, consume it and return.
 This lets us skip over:

   	statement;
	statement foo bar { }
	statement foo bar { statement { } }
	statement}
 
	...et cetera. */
void
skip_to_rbrace(struct parse *cfile, int brace_count)
{
	enum dhcp_token token;
	const char *val;

	do {
		token = peek_token(&val, NULL, cfile);
		if (token == RBRACE) {
			if (brace_count > 0) {
				--brace_count;
			}

			if (brace_count == 0) {
				/* Eat the brace and return. */
				skip_token(&val, NULL, cfile);
				return;
			}
		} else if (token == LBRACE) {
			brace_count++;
		} else if (token == SEMI && (brace_count == 0)) {
			/* Eat the semicolon and return. */
			skip_token(&val, NULL, cfile);
			return;
		} else if (token == EOL) {
			/* EOL only happens when parsing /etc/resolv.conf,
			   and we treat it like a semicolon because the
			   resolv.conf file is line-oriented. */
			skip_token(&val, NULL, cfile);
			return;
		}

		/* Eat the current token */
		token = next_token(&val, NULL, cfile);
	} while (token != END_OF_FILE);
}

void
parse_semi(struct parse *cfile)
{
	enum dhcp_token token;
	const char *val;

	token = next_token(&val, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "semicolon expected.");
}

/* string-parameter :== STRING SEMI */

void
parse_string(struct parse *cfile, char **sptr, unsigned *lptr)
{
	const char *val;
	enum dhcp_token token;
	char *s;
	unsigned len;

	token = next_token(&val, &len, cfile);
	if (token != STRING)
		parse_error(cfile, "expecting a string");
	s = (char *)malloc(len + 1);
	parse_error(cfile, "no memory for string %s.", val);
	memcpy(s, val, len + 1);

	parse_semi(cfile);
	if (sptr)
		*sptr = s;
	else
		free(s);
	if (lptr)
		*lptr = len;
}

/*
 * hostname :== IDENTIFIER
 *		| IDENTIFIER DOT
 *		| hostname DOT IDENTIFIER
 */

struct string *
parse_host_name(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	struct string *s = NULL;
	
	/* Read a dotted hostname... */
	do {
		/* Read a token, which should be an identifier. */
		token = peek_token(&val, NULL, cfile);
		if (!is_identifier(token) && token != NUMBER)
			break;
		skip_token(&val, NULL, cfile);

		/* Store this identifier... */
		if (s == NULL)
			s = makeString(-1, val);
		else
			appendString(s, val);
		/* Look for a dot; if it's there, keep going, otherwise
		   we're done. */
		token = peek_token(&val, NULL, cfile);
		if (token == DOT) {
			token = next_token(&val, NULL, cfile);
			appendString(s, val);
		}
	} while (token == DOT);

	return s;
}

/* ip-addr-or-hostname :== ip-address | hostname
   ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
   
   Parse an ip address or a hostname.

   Note that RFC1123 permits hostnames to consist of all digits,
   making it difficult to quickly disambiguate them from ip addresses.
*/

struct string *
parse_ip_addr_or_hostname(struct parse *cfile, isc_boolean_t *ipaddr)
{
	const char *val;
	enum dhcp_token token;
	unsigned char addr[4];
	unsigned len = sizeof(addr);

	*ipaddr = ISC_FALSE;

	token = peek_token(&val, NULL, cfile);
	if (token == NUMBER) {
		/*
		 * a hostname may be numeric, but domain names must
		 * start with a letter, so we can disambiguate by
		 * looking ahead a few tokens.  we save the parse
		 * context first, and restore it after we know what
		 * we're dealing with.
		 */
		save_parse_state(cfile);
		skip_token(NULL, NULL, cfile);
		if (next_token(NULL, NULL, cfile) == DOT &&
		    next_token(NULL, NULL, cfile) == NUMBER)
			*ipaddr = ISC_TRUE;
		restore_parse_state(cfile);

		if (*ipaddr)
			return parse_numeric_aggregate(cfile, addr, &len,
						       DOT, 10, 8);
	}

	if (is_identifier(token) || token == NUMBER)
		return parse_host_name(cfile);
	return NULL;
}
	
/*
 * ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
 */

struct string *
parse_ip_addr(struct parse *cfile)
{
	unsigned char addr[4];
	unsigned len = sizeof(addr);

	return parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8);
}	

/*
 * Return true if every character in the string is hexadecimal.
 */
static isc_boolean_t
is_hex_string(const char *s)
{
	while (*s != '\0') {
		if (!isxdigit((int)*s)) {
			return ISC_FALSE;
		}
		s++;
	}
	return ISC_TRUE;
}

/*
 * ip-address6 :== (complicated set of rules)
 *
 * See section 2.2 of RFC 1884 for details.
 *
 * We are lazy for this. We pull numbers, names, colons, and dots 
 * together and then throw the resulting string at the inet_pton()
 * function.
 */

struct string *
parse_ip6_addr(struct parse *cfile)
{
	enum dhcp_token token;
	const char *val;
	char addr[16];
	int val_len;
	char v6[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	int v6_len;

	/*
	 * First token is non-raw. This way we eat any whitespace before 
	 * our IPv6 address begins, like one would expect.
	 */
	token = peek_token(&val, NULL, cfile);

	/*
	 * Gather symbols.
	 */
	v6_len = 0;
	for (;;) {
		if ((((token == NAME) || (token == NUMBER_OR_NAME)) &&
		     is_hex_string(val)) ||
		    (token == NUMBER) ||
		    (token == TOKEN_ADD) ||
		    (token == DOT) ||
		    (token == COLON)) {

			next_raw_token(&val, NULL, cfile);
			val_len = strlen(val);
			if ((v6_len + val_len) >= sizeof(v6))
				parse_error(cfile, "Invalid IPv6 address.");
			memcpy(v6+v6_len, val, val_len);
			v6_len += val_len;

		} else {
			break;
		}
		token = peek_raw_token(&val, NULL, cfile);
	}
	v6[v6_len] = '\0';

	/*
	 * Use inet_pton() for actual work.
	 */
	if (inet_pton(AF_INET6, v6, addr) <= 0)
		parse_error(cfile, "Invalid IPv6 address.");
	return makeString(16, addr);
}

/*
 * Same as parse_ip6_addr() above, but returns the value as a text
 * rather than in an address binary structure.
 */
struct string *
parse_ip6_addr_txt(struct parse *cfile)
{
	const struct string *bin;
	char buf[80];

	bin = parse_ip6_addr(cfile);
	memset(buf, 0, sizeof(buf));
	if (!inet_ntop(AF_INET6, bin->content, buf, sizeof(buf)))
		parse_error(cfile, "can't print IPv6 address");
	return makeString(-1, buf);
}

/*
 * hardware-parameter :== HARDWARE hardware-type colon-separated-hex-list SEMI
 * hardware-type :== ETHERNET | TOKEN_RING | TOKEN_FDDI | INFINIBAND
 * Note that INFINIBAND may not be useful for some items, such as classification
 * as the hardware address won't always be available.
 */

struct element *
parse_hardware_param(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	isc_boolean_t ether = ISC_FALSE;
	unsigned hlen, i;
	struct string *t, *r;
	struct element *hw;
	char buf[HARDWARE_ADDR_LEN * 4];

	token = next_token(&val, NULL, cfile);
	if (token == ETHERNET)
		ether = ISC_TRUE;
	else {
		r = makeString(-1, val);
		appendString(r, " ");
	}

	/* Parse the hardware address information.   Technically,
	   it would make a lot of sense to restrict the length of the
	   data we'll accept here to the length of a particular hardware
	   address type.   Unfortunately, there are some broken clients
	   out there that put bogus data in the chaddr buffer, and we accept
	   that data in the lease file rather than simply failing on such
	   clients.   Yuck. */
	hlen = 0;
	token = peek_token(&val, NULL, cfile);
	if (token == SEMI)
		parse_error(cfile, "empty hardware address");
	t = parse_numeric_aggregate(cfile, NULL, &hlen, COLON, 16, 8);
	if (t == NULL)
		parse_error(cfile, "can't get hardware address");
	if (hlen > HARDWARE_ADDR_LEN)
		parse_error(cfile, "hardware address too long");
	token = next_token(&val, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "expecting semicolon.");

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < hlen; ++i) {
		size_t used;
		if (i == 0) {
			(void)snprintf(buf, sizeof(buf),
				       "%02x", t->content[i]);
			continue;
		}
		used = strlen(buf);
		(void)snprintf(buf + used, sizeof(buf) - used,
			       ":%02x", t->content[i]);
	}
	if (ether)
		r = makeString(-1, buf);
	else
		appendString(r, buf);
	hw = createString(r);
	if (!ether || (hlen != 6)) {
		hw->skip = ISC_TRUE;
		cfile->issue_counter++;
	}
	return hw;
}

/* No BNF for numeric aggregates - that's defined by the caller.  What
   this function does is to parse a sequence of numbers separated by
   the token specified in separator.  If max is zero, any number of
   numbers will be parsed; otherwise, exactly max numbers are
   expected.  Base and size tell us how to internalize the numbers
   once they've been tokenized.

   buf - A pointer to space to return the parsed value, if it is null
   then the function will allocate space for the return.

   max - The maximum number of items to store.  If zero there is no
   maximum.  When buf is null and the function needs to allocate space
   it will do an allocation of max size at the beginning if max is non
   zero.  If max is zero then the allocation will be done later, after
   the function has determined the size necessary for the incoming
   string.

   returns NULL on errors or a pointer to the string structure on success.
 */

struct string *
parse_numeric_aggregate(struct parse *cfile, unsigned char *buf,
			unsigned *max, int separator,
			int base, unsigned size)
{
	const char *val;
	enum dhcp_token token;
	unsigned char *bufp = buf, *s;
	unsigned count = 0;
	struct string *r = NULL, *t;

	if (!bufp && *max) {
		bufp = (unsigned char *)malloc(*max * size / 8);
		if (!bufp)
			parse_error(cfile, "no space for numeric aggregate");
	}
	s = bufp;
	if (!s) {
		r = makeString(0, NULL);
		t = makeString(size / 8, "bigger than needed");
	}

	do {
		if (count) {
			token = peek_token(&val, NULL, cfile);
			if (token != separator) {
				if (!*max)
					break;
				if (token != RBRACE && token != LBRACE)
					token = next_token(&val, NULL, cfile);
				parse_error(cfile, "too few numbers.");
			}
			skip_token(&val, NULL, cfile);
		}
		token = next_token(&val, NULL, cfile);

		if (token == END_OF_FILE)
			parse_error(cfile, "unexpected end of file");

		/* Allow NUMBER_OR_NAME if base is 16. */
		if (token != NUMBER &&
		    (base != 16 || token != NUMBER_OR_NAME))
			parse_error(cfile, "expecting numeric value.");
		/* If we can, convert the number now; otherwise, build
		   a linked list of all the numbers. */
		if (s) {
			convert_num(cfile, s, val, base, size);
			s += size / 8;
		} else {
			convert_num(cfile, (unsigned char *)t->content,
				    val, base, size);
			concatString(r, t);
		}
	} while (++count != *max);

	if (bufp)
		r = makeString(count * size / 8, (char *)bufp);

	return r;
}

void
convert_num(struct parse *cfile, unsigned char *buf, const char *str,
	    int base, unsigned size)
{
	const unsigned char *ptr = (const unsigned char *)str;
	int negative = 0;
	uint32_t val = 0;
	int tval;
	int max;

	if (*ptr == '-') {
		negative = 1;
		++ptr;
	}

	/* If base wasn't specified, figure it out from the data. */
	if (!base) {
		if (ptr[0] == '0') {
			if (ptr[1] == 'x') {
				base = 16;
				ptr += 2;
			} else if (isascii(ptr[1]) && isdigit(ptr[1])) {
				base = 8;
				ptr += 1;
			} else {
				base = 10;
			}
		} else {
			base = 10;
		}
	}

	do {
		tval = *ptr++;
		/* XXX assumes ASCII... */
		if (tval >= 'a')
			tval = tval - 'a' + 10;
		else if (tval >= 'A')
			tval = tval - 'A' + 10;
		else if (tval >= '0')
			tval -= '0';
		else
			parse_error(cfile, "Bogus number: %s.", str);
		if (tval >= base)
			parse_error(cfile,
				    "Bogus number %s: digit %d not in base %d",
				    str, tval, base);
		val = val * base + tval;
	} while (*ptr);

	if (negative)
		max = (1 << (size - 1));
	else
		max = (1 << (size - 1)) + ((1 << (size - 1)) - 1);
	if (val > max) {
		switch (base) {
		case 8:
			parse_error(cfile,
				    "%s%lo exceeds max (%d) for precision.",
				    negative ? "-" : "",
				    (unsigned long)val, max);
			break;
		case 16:
			parse_error(cfile,
				    "%s%lx exceeds max (%d) for precision.",
				    negative ? "-" : "",
				    (unsigned long)val, max);
			break;
		default:
			parse_error(cfile,
				    "%s%lu exceeds max (%d) for precision.",
				    negative ? "-" : "",
				    (unsigned long)val, max);
			break;
		}
	}

	if (negative) {
		switch (size) {
		case 8:
			*buf = -(unsigned long)val;
			break;
		case 16:
			putShort(buf, -(long)val);
			break;
		case 32:
			putLong(buf, -(long)val);
			break;
		default:
			parse_error (cfile,
				     "Unexpected integer size: %d\n", size);
			break;
		}
	} else {
		switch (size) {
		case 8:
			*buf = (uint8_t)val;
			break;
		case 16:
			putUShort (buf, (uint16_t)val);
			break;
		case 32:
			putULong (buf, val);
			break;
		default:
			parse_error (cfile,
				     "Unexpected integer size: %d\n", size);
		}
	}
}

/*
 * option-name :== IDENTIFIER |
 		   IDENTIFIER . IDENTIFIER
 */

struct element *
parse_option_name(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	struct string *uname;
	struct string *name;
	struct element *option;
	isc_boolean_t know_universe = ISC_TRUE;
	unsigned code;

	token = next_token(&val, NULL, cfile);
	if (!is_identifier(token))
		parse_error(cfile,
			    "expecting identifier after option keyword.");
	
	uname = makeString(-1, val);
	token = peek_token(&val, NULL, cfile);
	if (token == DOT) {
		/* Go ahead and take the DOT token... */
		skip_token(&val, NULL, cfile);

		/* The next token should be an identifier... */
		token = next_token(&val, NULL, cfile);
		if (!is_identifier(token))
			parse_error(cfile, "expecting identifier after '.'");

		name = makeString(-1, val);
		/* map universe to Kea space */
		if (strcmp(uname->content, "dhcp") == 0) {
			uname = makeString(-1, "dhcp4");
		} else if (strcmp(uname->content, "vendor") == 0) {
			uname = makeString(-1,
				    "vendor-encapsulated-options-space");
		} else if (strcmp(uname->content, "agent") == 0) {
			uname = makeString(-1, "dhcp-agent-options-space");
		} else if (strcmp(uname->content, "dhcp6") == 0) {
			/* same name */
		} else if (strcmp(uname->content, "vsio") == 0) {
			uname = makeString(-1, "vendor-opts-space");
		} else
			know_universe = ISC_FALSE;
	} else {
		/* Use the default hash table, which contains all the
		   standard dhcp option names. */
		name = uname;
		uname = makeString(-1, "dhcp4");
		val = name->content;
	}

	option = createMap();
	mapSet(option, createString(uname), "space");

	/* If the option name is of the form unknown-[decimal], use
	 * the trailing decimal value to find the option definition.
	 * If there is no definition, construct one.  This is to
	 * support legacy use of unknown options in config files or
	 * lease databases.
	 */
	if (strncasecmp(val, "unknown-", 8) == 0) {
		code = atoi(val + 8);
		mapSet(option, createInt(code), "code");
	} else {
		mapSet(option, createString(name), "name");
	}
	if (!know_universe) {
		option->skip = ISC_TRUE;
		cfile->issue_counter++;
	}

	return option;
}

/* IDENTIFIER[WIDTHS] SEMI
 *   WIDTHS ~= LENGTH WIDTH NUMBER
 *             CODE WIDTH NUMBER
 */

void
parse_option_space_decl(struct parse *cfile)
{
	int token;
	const char *val;
	struct element *nu;
	struct element *p;
	int tsize = 1, lsize = 1;

	skip_token(&val, NULL, cfile);  /* Discard the SPACE token,
						     which was checked by the
						     caller. */
	token = next_token(&val, NULL, cfile);
	if (!is_identifier(token))
		parse_error(cfile, "expecting identifier.");
	nu = createMap();
	nu->skip = ISC_TRUE;
	cfile->issue_counter++;
	
	/* Set up the server option universe... */
	mapSet(nu, createString(makeString(-1, val)), "name");

	do {
		token = next_token(&val, NULL, cfile);
		switch(token) {
		case SEMI:
			break;

		case CODE:
			token = next_token(&val, NULL, cfile);
			if (token != WIDTH)
				parse_error(cfile, "expecting width token.");

			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile,
					    "expecting number 1, 2, 4.");

			tsize = atoi(val);
			p = createInt(tsize);

			if ((local_family == AF_INET) && (tsize != 1)) {
				struct comment *comment;

				comment = createComment("### only code width "
							"1 is supported");
				TAILQ_INSERT_TAIL(&p->comments,
						  comment, next);
			} else if ((local_family == AF_INET6) &&
				   (tsize != 2)) {
				struct comment *comment;

				comment = createComment("### only code width "
							"2 is supported");
				TAILQ_INSERT_TAIL(&p->comments,
						  comment, next);
			}
			mapSet(nu, p, "code-width");
			break;

		case LENGTH:
			token = next_token(&val, NULL, cfile);
			if (token != WIDTH)
				parse_error(cfile, "expecting width token.");

			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile, "expecting number 1 or 2.");

			lsize = atoi(val);
			p = createInt(lsize);

			if ((local_family == AF_INET) && (lsize != 1)) {
				struct comment *comment;

				comment = createComment("### only length "
							"width 1 is "
							"supported");
				TAILQ_INSERT_TAIL(&p->comments,
						  comment, next);
			} else if ((local_family == AF_INET6) &&
				   (lsize != 2)) {
				struct comment *comment;

				comment = createComment("### only length "
							"width 2 is "
							"supported");
				TAILQ_INSERT_TAIL(&p->comments,
						  comment, next);
			}
			mapSet(nu, p, "length-width");
			break;

		case HASH:
			token = next_token(&val, NULL, cfile);
			if (token != SIZE)
				parse_error(cfile, "expecting size token.");

			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile,
					    "expecting a 10base number");
			break;

		default:
			parse_error(cfile, "Unexpected token.");
		}
	} while (token != SEMI);

	mapSet(cfile->stack[1], nu, "option-space");
}

/* This is faked up to look good right now.   Ideally, this should do a
   recursive parse and allow arbitrary data structure definitions, but for
   now it just allows you to specify a single type, an array of single types,
   a sequence of types, or an array of sequences of types.

   ocd :== NUMBER EQUALS ocsd SEMI

   ocsd :== ocsd_type |
	    ocsd_type_sequence |
	    ARRAY OF ocsd_simple_type_sequence

   ocsd_type_sequence :== LBRACE ocsd_types RBRACE

   ocsd_simple_type_sequence :== LBRACE ocsd_simple_types RBRACE

   ocsd_types :== ocsd_type |
		  ocsd_types ocsd_type

   ocsd_type :== ocsd_simple_type |
		 ARRAY OF ocsd_simple_type

   ocsd_simple_types :== ocsd_simple_type |
			 ocsd_simple_types ocsd_simple_type

   ocsd_simple_type :== BOOLEAN |
			INTEGER NUMBER |
			SIGNED INTEGER NUMBER |
			UNSIGNED INTEGER NUMBER |
			IP-ADDRESS |
			TEXT |
			STRING |
			ENCAPSULATE identifier */

void
parse_option_code_definition(struct parse *cfile, struct element *option)
{
	const char *val;
	enum dhcp_token token;
	unsigned arrayp = 0;
	int recordp = 0;
	isc_boolean_t no_more_in_record = ISC_FALSE;
	char *type;
	isc_boolean_t is_signed;
	isc_boolean_t has_encapsulation = ISC_FALSE;
	isc_boolean_t not_supported = ISC_FALSE;
	struct string *encapsulated;
	struct string *datatype;
	struct string *saved;
	struct element *optdef;
	
	/* Parse the option code. */
	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "expecting option code number.");
	mapSet(option, createInt(atoi(val)), "code");

	token = next_token(&val, NULL, cfile);
	if (token != EQUAL)
		parse_error(cfile, "expecting \"=\"");
	saved = makeString(0, NULL);

	/* See if this is an array. */
	token = next_token(&val, NULL, cfile);
	if (token == ARRAY) {
		token = next_token(&val, NULL, cfile);
		if (token != OF)
			parse_error(cfile, "expecting \"of\".");
		arrayp = 1;
		token = next_token(&val, NULL, cfile);
		appendString(saved, "array of");
	}

	if (token == LBRACE) {
		recordp = 1;
		token = next_token(&val, NULL, cfile);
		appendString(saved, "[");
	}

	/* At this point we're expecting a data type. */
	datatype = makeString(0, NULL);
    next_type:
	if (saved->length > 0)
		appendString(saved, " ");
	type = NULL;
	if (has_encapsulation)
		parse_error(cfile,
			    "encapsulate must always be the last item.");

	switch (token) {
	case ARRAY:
		if (arrayp)
			parse_error(cfile, "no nested arrays.");
		if (recordp) {
			struct comment *comment;

			comment = createComment("### unsupported array "
						"inside a record");
			TAILQ_INSERT_TAIL(&option->comments, comment, next);
			option->skip = ISC_TRUE;
			not_supported = ISC_TRUE;
			cfile->issue_counter++;
		}
		token = next_token(&val, NULL, cfile);
		if (token != OF)
			parse_error(cfile, "expecting \"of\".");
		arrayp = recordp + 1;
		token = next_token(&val, NULL, cfile);
		if ((recordp) && (token == LBRACE))
			parse_error(cfile,
				    "only uniform array inside record.");
		if (token == LBRACE) {
			struct comment *comment;

			comment = createComment("### unsupported record "
						"inside an array");
			TAILQ_INSERT_TAIL(&option->comments, comment, next);
			option->skip = ISC_TRUE;
			not_supported = ISC_TRUE;
			cfile->issue_counter++;
		}
		appendString(saved, "array of");
		goto next_type;
	case BOOLEAN:
		type = "boolean";
		break;
	case INTEGER:
		is_signed = ISC_TRUE;
	parse_integer:
		token = next_token(&val, NULL, cfile);
		if (token != NUMBER)
			parse_error(cfile, "expecting number.");
		switch (atoi(val)) {
		case 8:
			type = is_signed ? "int8" : "uint8";
			break;
		case 16:
			type = is_signed ? "int16" : "uint16";
			break;
		case 32:
			type = is_signed ? "int32" : "uint32";
			break;
		default:
			parse_error(cfile,
				    "%s bit precision is not supported.", val);
		}
		break;
	case SIGNED:
		is_signed = ISC_TRUE;
	parse_signed:
		token = next_token(&val, NULL, cfile);
		if (token != INTEGER)
			parse_error(cfile, "expecting \"integer\" keyword.");
		goto parse_integer;
	case UNSIGNED:
		is_signed = ISC_FALSE;
		goto parse_signed;

	case IP_ADDRESS:
		type = "ipv4-address";
		break;
	case IP6_ADDRESS:
		type = "ipv6-address";
		break;
	case DOMAIN_NAME:
		type = "fqdn";
		goto no_arrays;
	case DOMAIN_LIST:
		/* Consume optional compression indicator. */
		token = peek_token(&val, NULL, cfile);
		appendString(saved, "list of ");
		if (token == COMPRESSED) {
			struct comment *comment;

			skip_token(&val, NULL, cfile);
			comment = createComment("### unsupported "
						"compressed fqdn list");
			TAILQ_INSERT_TAIL(&option->comments, comment, next);
			option->skip = ISC_TRUE;
			not_supported = ISC_TRUE;
			cfile->issue_counter++;
			type = "compressed fqdn";
			appendString(saved, "compressed ");
		} else
			type = "fqdn";
		if (arrayp)
			parse_error(cfile, "arrays of text strings not %s",
				    "yet supported.");
		arrayp = 1;
		no_more_in_record = ISC_TRUE;
		break;
	case TEXT:
		type = "string";
	no_arrays:
		if (arrayp)
			parse_error(cfile, "arrays of text strings not %s",
				    "yet supported.");
		no_more_in_record = ISC_TRUE;
		break;
	case STRING_TOKEN:
		type = "binary";
		goto no_arrays;

	case ENCAPSULATE:
		token = next_token(&val, NULL, cfile);
		if (!is_identifier(token))
			parse_error(cfile,
				    "expecting option space identifier");
		encapsulated = makeString(-1, val);
		has_encapsulation = ISC_TRUE;
		appendString(saved, "encapsulate ");
		appendString(saved, val);
		break;

	case ZEROLEN:
		type = "empty";
		if (arrayp)
			parse_error(cfile, "array incompatible with zerolen.");
		no_more_in_record = ISC_TRUE;
		break;

	default:
		parse_error(cfile, "unknown data type %s", val);
	}
	appendString(saved, type);
	appendString(datatype, type);

	if (recordp) {
		token = next_token(&val, NULL, cfile);
		if (arrayp > recordp)
			arrayp = 0;
		if (token == COMMA) {
			if (no_more_in_record)
				parse_error(cfile,
					    "%s must be at end of record.",
					    type);
			token = next_token(&val, NULL, cfile);
			appendString(saved, ",");
			appendString(datatype, ", ");
			goto next_type;
		}
		if (token != RBRACE)
			parse_error(cfile, "expecting right brace.");
		appendString(saved, "]");
	}
	parse_semi(cfile);
	if (has_encapsulation && arrayp)
		parse_error(cfile,
			    "Arrays of encapsulations don't make sense.");
	if (arrayp)
		mapSet(option, createBool(arrayp), "array");
	if (recordp) {
		mapSet(option, createString(datatype), "record-types");
		mapSet(option, createString(makeString(-1, "record")), "type");
	} else
		mapSet(option, createString(datatype), "type");
	if (not_supported)
		mapSet(option, createString(saved), "definition");
	if (has_encapsulation)
		mapSet(option, createString(encapsulated), "encapsulate");

	optdef = mapGet(cfile->stack[1], "option-def");
	if (optdef == NULL) {
		optdef = createList();
		mapSet(cfile->stack[1], optdef, "option-def");
	}
	listPush(optdef, option);
}

/*
 * base64 :== NUMBER_OR_STRING
 */

struct string *
parse_base64(struct parse *cfile)
{
	const char *val;
	unsigned l;
	unsigned i, j, k;
	unsigned acc = 0;
	static unsigned char
		from64[] = {64, 64, 64, 64, 64, 64, 64, 64,  /*  \"#$%&' */
			     64, 64, 64, 62, 64, 64, 64, 63,  /* ()*+,-./ */
			     52, 53, 54, 55, 56, 57, 58, 59,  /* 01234567 */
			     60, 61, 64, 64, 64, 64, 64, 64,  /* 89:;<=>? */
			     64, 0, 1, 2, 3, 4, 5, 6,	      /* @ABCDEFG */
			     7, 8, 9, 10, 11, 12, 13, 14,     /* HIJKLMNO */
			     15, 16, 17, 18, 19, 20, 21, 22,  /* PQRSTUVW */
			     23, 24, 25, 64, 64, 64, 64, 64,  /* XYZ[\]^_ */
			     64, 26, 27, 28, 29, 30, 31, 32,  /* 'abcdefg */
			     33, 34, 35, 36, 37, 38, 39, 40,  /* hijklmno */
			     41, 42, 43, 44, 45, 46, 47, 48,  /* pqrstuvw */
			     49, 50, 51, 64, 64, 64, 64, 64}; /* xyz{|}~  */
	struct element *bufs;
	struct string *t;
	struct string *data;
	char *buf;
	unsigned cc = 0;
	isc_boolean_t terminated = ISC_FALSE;
	isc_boolean_t valid_base64;
	size_t it;
	
	bufs = createList();

	/* It's possible for a + or a / to cause a base64 quantity to be
	   tokenized into more than one token, so we have to parse them all
	   in before decoding. */
	do {
		(void)next_token(&val, &l, cfile);
		t = makeString(l, val);
		cc += l;
		listPush(bufs, createString(t));
		(void)peek_token(&val, NULL, cfile);
		valid_base64 = ISC_TRUE;
		for (i = 0; val[i]; i++) {
			/* Check to see if the character is valid.  It
			   may be out of range or within the right range
			   but not used in the mapping */
			if (((val[i] < ' ') || (val[i] > 'z')) ||
			    ((from64[val[i] - ' '] > 63) && (val[i] != '='))) {
				valid_base64 = ISC_FALSE;
				break; /* no need to continue for loop */
			}
		}
	} while (valid_base64);

	l = (cc * 3) / 4;
	buf = (char *)malloc(l);
	if (buf == NULL)
		parse_error(cfile, "can't allocate buffer for base64 data.");
	memset(buf, 0, l);
	data = makeString(l, buf);
	free(buf);

	j = k = 0;
	for (it = 0; it < listSize(bufs); it++) {
	    t = stringValue(listGet(bufs, it));
	    for (i = 0; i < t->length; i++) {
		unsigned foo = t->content[i];

		if (terminated && foo != '=')
			parse_error(cfile,
				    "stuff after base64 '=' terminator: %s.",
				    t->content + i);
		if ((foo < ' ') || (foo > 'z')) {
		    bad64:
			parse_error(cfile,
				    "invalid base64 character %d.",
				    t->content[i]);
			goto out;
		}
		if (foo == '=')
			terminated = ISC_TRUE;
		else {
			foo = from64[foo - ' '];
			if (foo == 64)
				goto bad64;
			acc = (acc << 6) + foo;
			switch (k % 4) {
			case 0:
				break;
			case 1:
				data->content[j++] = (acc >> 4);
				acc = acc & 0x0f;
				break;
				
			case 2:
				data->content[j++] = (acc >> 2);
				acc = acc & 0x03;
				break;
			case 3:
				data->content[j++] = acc;
				acc = 0;
				break;
			}
		}
		k++;
	    }
	}
	if ((k % 4) && acc)
		parse_error(cfile,
			    "partial base64 value left over: %d.",
			    acc);
	data->length = j;
    out:
	do {
		struct element *b;

		b = listGet(bufs, 0);
		listRemove(bufs, 0);
		t = stringValue(b);
		if (t->content != NULL)
			free(t->content);
		free(t);
		free(b);
	} while (listSize(bufs) > 0);
	if (data->length > 0)
		return data;
	else
		return NULL;
}

/*
 * colon-separated-hex-list :== NUMBER |
 *				NUMBER COLON colon-separated-hex-list
 */

struct string *
parse_cshl(struct parse *cfile)
{
	uint8_t ibuf;
	struct string *data;
	enum dhcp_token token;
	const char *val;

	data = makeString(0, NULL);

	for (;;) {
		token = next_token(&val, NULL, cfile);
		if (token != NUMBER && token != NUMBER_OR_NAME)
			parse_error(cfile, "expecting hexadecimal number.");
		convert_num(cfile, &ibuf, val, 16, 8);
		concatString(data, makeString(1, (char *)&ibuf));

		token = peek_token(&val, NULL, cfile);
		if (token != COLON)
			break;
		skip_token(&val, NULL, cfile);
	}

	return data;
}

/*
 * executable-statements :== executable-statement executable-statements |
 *			     executable-statement
 *
 * executable-statement :==
 *	IF if-statement |
 * 	ADD class-name SEMI |
 *	BREAK SEMI |
 *	OPTION option-parameter SEMI |
 *	SUPERSEDE option-parameter SEMI |
 *	PREPEND option-parameter SEMI |
 *	APPEND option-parameter SEMI
 */

isc_boolean_t
parse_executable_statements(struct element *statements,
			    struct parse *cfile, isc_boolean_t *lose,
			    enum expression_context case_context)
{
	while (parse_executable_statement(statements, cfile,
					  lose, case_context))
		/* continue */
	if (!*lose)
		return ISC_TRUE;
	return ISC_FALSE;
}

isc_boolean_t
parse_executable_statement(struct element *result,
			   struct parse *cfile, isc_boolean_t *lose,
			   enum expression_context case_context)
{
	enum dhcp_token token;
	const char *val;
	struct element *st;
	struct element *option;
	struct element *var;
	struct element *pri;
	struct element *expr;
	int flag;
	int i;
	struct element *zone;
	struct string *s;

	token = peek_token(&val, NULL, cfile);
	switch (token) {
	case DB_TIME_FORMAT:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token == DEFAULT)
			s = makeString(-1, val);
		else if (token == LOCAL)
			s = makeString(-1, val);
		else
			parse_error(cfile, "Expecting 'local' or 'default'.");

		token = next_token(&val, NULL, cfile);
		if (token != SEMI)
			parse_error(cfile, "Expecting a semicolon.");
		st = createString(s);
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "db-time-format");

		/* We're done here. */
		return ISC_TRUE;

	case IF:
		skip_token(&val, NULL, cfile);
		return parse_if_statement(result, cfile, lose);

	case TOKEN_ADD:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != STRING)
			parse_error(cfile, "expecting class name.");
		s = makeString(-1, val);
		parse_semi(cfile);
		st = createString(s);
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "add-class");
		break;

	case BREAK:
		skip_token(&val, NULL, cfile);
		s = makeString(-1, val);
		parse_semi(cfile);
		st = createNull();
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "break");
		break;

	case SEND:
		skip_token(&val, NULL, cfile);
	        option = parse_option_name(cfile);
		if (option == NULL) {
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		if (!option->skip) {
			option->skip = ISC_TRUE;
			cfile->issue_counter++;
		}
		mapSet(result, option, "send");
		return ISC_TRUE;

	case SUPERSEDE:
	case OPTION:
		skip_token(&val, NULL, cfile);
		option = parse_option_name(cfile);
		if (option == NULL) {
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		if ((token == SUPERSEDE) && !option->skip) {
			option->skip = ISC_TRUE;
			cfile->issue_counter++;
		}
		return parse_option_statement(result, cfile, option,
					      supersede_option_statement);

	case ALLOW:
		flag = 1;
		goto pad;
	case DENY:
		flag = 0;
		goto pad;
	case IGNORE:
		flag = 2;
	pad:
		skip_token(&val, NULL, cfile);
		option = parse_allow_deny(cfile, flag);
		st = mapGet(option, "server-option");
		if (st == NULL)
			return ISC_FALSE;
		mapSet(result, st, "server-option");
		break;

	case DEFAULT:
		skip_token(&val, NULL, cfile);
		token = peek_token(&val, NULL, cfile);
		if (token == COLON)
			goto switch_default;
		option = parse_option_name(cfile);
		if (option == NULL) {
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		return parse_option_statement(result, cfile, option,
					      default_option_statement);
	case PREPEND:
		skip_token(&val, NULL, cfile);
		option = parse_option_name(cfile);
		if (option == NULL) {
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		return parse_option_statement(result, cfile, option,
					      prepend_option_statement);
	case APPEND:
		skip_token(&val, NULL, cfile);
		option = parse_option_name(cfile);
		if (option == NULL) {
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		return parse_option_statement(result, cfile, option,
					      append_option_statement);

	case ON:
		skip_token(&val, NULL, cfile);
		return parse_on_statement(result, cfile, lose);
			
	case SWITCH:
		skip_token(&val, NULL, cfile);
		return parse_switch_statement(result, cfile, lose);

	case CASE:
		skip_token(&val, NULL, cfile);
		if (case_context == context_any)
			parse_error(cfile,
				    "case statement in inappropriate scope.");
		return parse_case_statement(result,
					    cfile, lose, case_context);

	switch_default:
		skip_token(&val, NULL, cfile);
		if (case_context == context_any)
			parse_error(cfile, "switch default statement in %s",
				    "inappropriate scope.");
		s = makeString(-1, "default");
		st = createNull();
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "default");
		return ISC_TRUE;
			
	case DEFINE:
	case TOKEN_SET:
		skip_token(&val, NULL, cfile);
		if (token == DEFINE)
			flag = 1;
		else
			flag = 0;

		token = next_token(&val, NULL, cfile);
		if (token != NAME && token != NUMBER_OR_NAME)
			parse_error(cfile,
				    "%s can't be a variable name", val);
		st = createMap();
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, flag ? "define" : "set");
		var = createString(makeString(-1, val));
		mapSet(st, var, "name");
		token = next_token(&val, NULL, cfile);

		if (token == LPAREN) {
			struct string *value;

			value = makeString(0, NULL);
			do {
				token = next_token(&val, NULL, cfile);
				if (token == RPAREN)
					break;
				if (token != NAME && token != NUMBER_OR_NAME)
					parse_error(cfile,
						    "expecting argument name");
				if (value->length > 0)
					appendString(value, ", ");
				appendString(value, val);
				token = next_token(&val, NULL, cfile);
			} while (token == COMMA);

			if (token != RPAREN) {
				parse_error(cfile, "expecting right paren.");
			badx:
				skip_to_semi(cfile);
				*lose = ISC_TRUE;
				return ISC_FALSE;
			}
			mapSet(st, createString(value), "arguments");

			token = next_token(&val, NULL, cfile);
			if (token != LBRACE)
				parse_error(cfile, "expecting left brace.");

			expr = createMap();
			if (!parse_executable_statements(expr, cfile,
							 lose, case_context)) {
				if (*lose)
					goto badx;
			}
			mapSet(st, expr, "function-body");

			token = next_token(&val, NULL, cfile);
			if (token != RBRACE)
				parse_error(cfile, "expecting rigt brace.");
		} else {
			if (token != EQUAL)
				parse_error(cfile,
					    "expecting '=' in %s statement.",
					    flag ? "define" : "set");

			expr = createMap();
			if (!parse_expression(expr, cfile, lose, context_any,
					      NULL, expr_none)) {
				if (!*lose)
					parse_error(cfile,
						    "expecting expression.");
				else
					*lose = ISC_TRUE;
				skip_to_semi(cfile);
				return ISC_FALSE;
			}
			mapSet(st, expr, "value");
			parse_semi(cfile);
		}
		break;

	case UNSET:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != NAME && token != NUMBER_OR_NAME)
			parse_error(cfile, "%s can't be a variable name", val);

		st = createMap();
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "unset");
		var = createString(makeString(-1, val));
		mapSet(st, var, "name");
		parse_semi(cfile);
		break;

	case EVAL:
		skip_token(&val, NULL, cfile);
		expr = createMap();

		if (!parse_expression(expr,
				      cfile, lose, context_data, /* XXX */
				      NULL, expr_none)) {
			if (!*lose)
				parse_error(cfile,
					    "expecting data expression.");
			else
				*lose = ISC_TRUE;
			skip_to_semi(cfile);
			return ISC_FALSE;
		}
		mapSet(result, expr, "eval");
		parse_semi(cfile);
		break;

	case EXECUTE:
		parse_error(cfile, "ENABLE_EXECUTE is not portable");

	case RETURN:
		skip_token(&val, NULL, cfile);

		expr = createMap();

		if (!parse_expression(expr, cfile, lose, context_data,
				      NULL, expr_none)) {
			if (!*lose)
				parse_error(cfile,
					    "expecting data expression.");
			else
				*lose = ISC_TRUE;
			skip_to_semi(cfile);
			return ISC_FALSE;
		}
		mapSet(result, expr, "return");
		parse_semi(cfile);
		break;

	case LOG:
		skip_token(&val, NULL, cfile);

		st = createMap();
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "log");

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			parse_error(cfile, "left parenthesis expected.");

		token = peek_token(&val, NULL, cfile);
		i = 1;
		if (token == FATAL)
			s = makeString(-1, val);
		else if (token == ERROR)
			s = makeString(-1, val);
		else if (token == TOKEN_DEBUG)
			s = makeString(-1, val);
		else if (token == INFO)
			s = makeString(-1, val);
		else {
			s = makeString(-1, "DEBUG");
			i = 0;
		}
		if (i) {
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (token != COMMA)
				parse_error(cfile, "comma expected.");
		}
		pri = createString(s);
		mapSet(st, pri, "priority");

		expr = createMap();
		if (!parse_data_expression(expr, cfile, lose)) {
			skip_to_semi(cfile);
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			parse_error(cfile, "right parenthesis expected.");

		token = next_token(&val, NULL, cfile);
		if (token != SEMI)
			parse_error (cfile, "semicolon expected.");
		break;

	case PARSE_VENDOR_OPT:
		/* The parse-vendor-option; The statement has no arguments.
		 * We simply set up the statement and when it gets executed it
		 * will find all information it needs in the packet and options.
		 */
		skip_token(&val, NULL, cfile);
		parse_semi(cfile);

		st = createNull();
		st->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, st, "parse-vendor-option");
		break;

		/* Not really a statement, but we parse it here anyway
		   because it's appropriate for all DHCP agents with
		   parsers. */
	case ZONE:
		skip_token(&val, NULL, cfile);
		zone = createMap();
		zone->skip = ISC_TRUE;
		cfile->issue_counter++;
		mapSet(result, zone, "zone");

		s = parse_host_name(cfile);
		if (s == NULL) {
			parse_error(cfile, "expecting hostname.");
		badzone:
			*lose = ISC_TRUE;
			skip_to_semi(cfile);
			return ISC_FALSE;
		}
		if (s->content[s->length - 1] != '.')
			appendString(s, ".");
		mapSet(zone, createString(s), "name");
		if (!parse_zone(zone, cfile))
			goto badzone;
		return ISC_TRUE;
		
		/* Also not really a statement, but same idea as above. */
	case KEY:
		skip_token(&val, NULL, cfile);
		if (!parse_key(result, cfile)) {
			/* Kea TODO */
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		return ISC_FALSE;

	default:
		if (is_identifier(token)) {
			skip_token(&val, NULL, cfile);
			option = createMap();
			return parse_option_statement(result, cfile, option,
						supersede_option_statement);
		}

		if (token == NUMBER_OR_NAME || token == NAME) {
			/* This is rather ugly.  Since function calls are
			   data expressions, fake up an eval statement. */
			expr = createMap();

			if (!parse_expression(expr, cfile, lose, context_data,
					      NULL, expr_none)) {
				if (!*lose)
					parse_error(cfile, "expecting "
						    "function call.");
				else
					*lose = ISC_TRUE;
				skip_to_semi(cfile);
				return ISC_FALSE;
			}
			mapSet(result, expr, "eval");
			parse_semi(cfile);
			break;
		}

		*lose = ISC_FALSE;
		return ISC_FALSE;
	}

	return ISC_TRUE;
}

/* zone-statements :== zone-statement |
		       zone-statement zone-statements
   zone-statement :==
	PRIMARY ip-addresses SEMI |
	SECONDARY ip-addresses SEMI |
	PRIMARY6 ip-address6 SEMI |
	SECONDARY6 ip-address6 SEMI |
	key-reference SEMI
   ip-addresses :== ip-addr-or-hostname |
		  ip-addr-or-hostname COMMA ip-addresses
   key-reference :== KEY STRING |
		    KEY identifier */

isc_boolean_t
parse_zone(struct element *zone, struct parse *cfile)
{
	int token;
	const char *val;
	struct element *values;
	struct string *key_name;
	isc_boolean_t done = ISC_FALSE;

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "expecting left brace");

	do {
	    token = peek_token(&val, NULL, cfile);
	    switch (token) {
	    case PRIMARY:
		    if (mapContains(zone, "primary"))
			    parse_error(cfile, "more than one primary.");
		    values = createList();
		    mapSet(zone, values, "primary");
		    goto consemup;
		    
	    case SECONDARY:
		    if (mapContains(zone, "secondary"))
			    parse_error(cfile, "more than one secondary.");
		    values = createList();
		    mapSet(zone, values, "secondary");
	    consemup:
		    skip_token(&val, NULL, cfile);
		    do {
			    struct string *value;
			    isc_boolean_t ia;

			    value = parse_ip_addr_or_hostname(cfile, &ia);
			    if (value == NULL)
				parse_error(cfile,
					   "expecting IP addr or hostname.");
			    listPush(values, createString(value));
			    token = next_token(&val, NULL, cfile);
		    } while (token == COMMA);
		    if (token != SEMI)
			    parse_error(cfile, "expecting semicolon.");
		    break;

	    case PRIMARY6:
		    if (mapContains(zone, "primary6"))
			    parse_error(cfile, "more than one primary6.");
		    values = createList();
		    mapSet(zone, values, "primary6");
		    goto consemup6;

	    case SECONDARY6:
		    if (mapContains(zone, "secondary6"))
			    parse_error(cfile, "more than one secondary6.");
		    values = createList();
		    mapSet(zone, values, "secondary6");
	    consemup6:
		    skip_token(&val, NULL, cfile);
		    do {
			    struct string *addr;

			    addr = parse_ip6_addr_txt(cfile);
			    if (addr == NULL)
				    parse_error(cfile, "expecting IPv6 addr.");
			    listPush(values, createString(addr));
			    token = next_token(&val, NULL, cfile);
		    } while (token == COMMA);
		    if (token != SEMI)
			    parse_error(cfile, "expecting semicolon.");
		    break;

	    case KEY:
		    skip_token(&val, NULL, cfile);
		    token = peek_token(&val, NULL, cfile);
		    if (token == STRING) {
			    skip_token(&val, NULL, cfile);
			    key_name = makeString(-1, val);
		    } else {
			    key_name = parse_host_name(cfile);
			    if (!key_name)
				    parse_error(cfile, "expecting key name.");
		    }
		    if (mapContains(zone, "key"))
			    parse_error(cfile, "Multiple key definitions");
		    mapSet(zone, createString(key_name), "key");
		    parse_semi(cfile);
		    break;
		    
	    default:
		    done = 1;
		    break;
	    }
	} while (!done);

	token = next_token(&val, NULL, cfile);
	if (token != RBRACE)
		parse_error(cfile, "expecting right brace.");
	return (1);
}

/* key-statements :== key-statement |
		      key-statement key-statements
   key-statement :==
	ALGORITHM host-name SEMI |
	secret-definition SEMI
   secret-definition :== SECRET base64val |
			 SECRET STRING

   Kea: where to put this? It is a D2 value */

isc_boolean_t
parse_key(struct element* result, struct parse *cfile)
{
	int token;
	const char *val;
	isc_boolean_t done = ISC_FALSE;
	struct element *key;
	struct string *alg;
	struct string *sec;
	struct element *keys;
	char *s;

	key = createMap();
	key->skip = ISC_TRUE;
	cfile->issue_counter++;

	token = peek_token(&val, NULL, cfile);
	if (token == STRING) {
		skip_token(&val, NULL, cfile);
		mapSet(key, createString(makeString(-1, val)), "name");
	} else {
		struct string *name;

		name = parse_host_name(cfile);
		if (name == NULL)
			parse_error(cfile, "expecting key name.");
		mapSet(key, createString(name), "name");
	}

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "expecting left brace");

	do {
		token = next_token(&val, NULL, cfile);
		switch (token) {
		case ALGORITHM:
			if (mapContains(key, "algorithm"))
				parse_error(cfile, "key: too many algorithms");
			alg = parse_host_name(cfile);
			if (alg == NULL)
				parse_error(cfile,
					    "expecting key algorithm name.");
			parse_semi(cfile);
			/* If the algorithm name isn't an FQDN, tack on
			   the .SIG-ALG.REG.NET. domain. */
			s = strrchr(alg->content, '.');
			if (!s)
				appendString(alg, ".SIG-ALG.REG.INT.");
			/* If there is no trailing '.', hack one in. */
			else 
				appendString(alg, ".");
			mapSet(key, createString(alg), "algorithm");
			break;

		case SECRET:
			if (mapContains(key, "secret"))
				parse_error(cfile, "key: too many secrets");

			sec = parse_base64(cfile);
			if (sec == NULL) {
				skip_to_rbrace(cfile, 1);
				return ISC_FALSE;
			}
			mapSet(key, createString(sec), "secret");

			parse_semi(cfile);
			break;

		default:
			done = ISC_TRUE;
			break;
		}
	} while (!done);
	if (token != RBRACE)
		parse_error(cfile, "expecting right brace.");
	/* Allow the BIND 8 syntax, which has a semicolon after each
	   closing brace. */
	token = peek_token(&val, NULL, cfile);
	if (token == SEMI)
		skip_token(&val, NULL, cfile);

	/* Remember the key. */
	keys = mapGet(result, "tsig-keys");
	if (keys == NULL) {
		keys = createList();
		mapSet(result, keys, "tsig-keys");
	}
	listPush(keys, key);
	return ISC_TRUE;
}

/*
 * on-statement :== event-types LBRACE executable-statements RBRACE
 * event-types :== event-type OR event-types |
 *		   event-type
 * event-type :== EXPIRY | COMMIT | RELEASE
 */

isc_boolean_t
parse_on_statement(struct element *result,
		   struct parse *cfile,
		   isc_boolean_t *lose)
{
	enum dhcp_token token;
	const char *val;
	struct element *statement;
	struct string *cond;
	struct element *body;

	statement = createMap();
	statement->skip = ISC_TRUE;
	cfile->issue_counter++;
	mapSet(result, statement, "on");

	cond = makeString(0, NULL);
	do {
		token = next_token(&val, NULL, cfile);
		switch (token) {
		case EXPIRY:
		case COMMIT:
		case RELEASE:
		case TRANSMISSION:
			appendString(cond, val);      
			break;

		default:
			parse_error(cfile, "expecting a lease event type");
		}
		token = next_token(&val, NULL, cfile);
		if (token == OR)
			appendString(cond, " or ");
	} while (token == OR);
		
	mapSet(statement, createString(cond), "condition");

	/* Semicolon means no statements. */
	if (token == SEMI)
		return ISC_TRUE;

	if (token != LBRACE)
		parse_error(cfile, "left brace expected.");

	body = createMap();
	if (!parse_executable_statements(body, cfile, lose, context_any)) {
		if (*lose) {
			/* Try to even things up. */
			do {
				token = next_token(&val, NULL, cfile);
			} while (token != END_OF_FILE && token != RBRACE);
			return ISC_FALSE;
		}
	}
	token = next_token(&val, NULL, cfile);
	if (token != RBRACE)
		parse_error(cfile, "right brace expected.");
	return ISC_TRUE;
}

/*
 * switch-statement :== LPAREN expr RPAREN LBRACE executable-statements RBRACE
 *
 */

isc_boolean_t
parse_switch_statement(struct element *result,
		       struct parse *cfile,
		       isc_boolean_t *lose)
{
	enum dhcp_token token;
	const char *val;
	struct element *statement;
	struct element *cond;
	struct element *body;

	statement = createMap();
	statement->skip = ISC_TRUE;
	cfile->issue_counter++;
	mapSet(result, statement, "switch");

	token = next_token(&val, NULL, cfile);
	if (token != LPAREN) {
		parse_error(cfile, "expecting left brace.");
		*lose = ISC_TRUE;
		skip_to_semi(cfile);
		return ISC_FALSE;
	}

	cond = createMap();
	if (!parse_expression(cond, cfile, lose, context_data_or_numeric,
			      NULL, expr_none)) {
		if (!*lose)
			parse_error(cfile,
				    "expecting data or numeric expression.");
		return ISC_FALSE;
	}
	mapSet(statement, cond, "condition");

	token = next_token(&val, NULL, cfile);
	if (token != RPAREN)
		parse_error(cfile, "right paren expected.");

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "left brace expected.");

	body = createMap();
	if (!parse_executable_statements(body, cfile, lose,
	      (is_data_expression(cond) ? context_data : context_numeric))) {
		if (*lose) {
			skip_to_rbrace(cfile, 1);
			return ISC_FALSE;
		}
	}
	mapSet(statement, body, "body");
	token = next_token(&val, NULL, cfile);
	if (token != RBRACE)
		parse_error(cfile, "right brace expected.");
	return ISC_TRUE;
}

/*
 * case-statement :== CASE expr COLON
 *
 */

isc_boolean_t
parse_case_statement(struct element *result,
		     struct parse *cfile,
		     isc_boolean_t *lose,
		     enum expression_context case_context)
{
	enum dhcp_token token;
	const char *val;
	struct element *expr;

	expr = createMap();
	if (!parse_expression(expr, cfile, lose, case_context,
			      NULL, expr_none))
	{
		if (!*lose)
			parse_error(cfile, "expecting %s expression.",
				    (case_context == context_data
				     ? "data" : "numeric"));
		*lose = ISC_TRUE;
		skip_to_semi(cfile);
		return ISC_FALSE;
	}

	token = next_token(&val, NULL, cfile);
	if (token != COLON)
		parse_error(cfile, "colon expected.");
	mapSet(result, expr, "case");
	return ISC_TRUE;
}

/*
 * if-statement :== boolean-expression LBRACE executable-statements RBRACE
 *						else-statement
 *
 * else-statement :== <null> |
 *		      ELSE LBRACE executable-statements RBRACE |
 *		      ELSE IF if-statement |
 *		      ELSIF if-statement
 */

isc_boolean_t
parse_if_statement(struct element *result,
		   struct parse *cfile,
		   isc_boolean_t *lose)
{
	enum dhcp_token token;
	const char *val;
	isc_boolean_t parenp;
	struct element *statement;
	struct element *cond;
	struct element *branch;

	statement = createMap();
	statement->skip = ISC_TRUE;
	cfile->issue_counter++;

	mapSet(result, statement, "if");

	token = peek_token(&val, NULL, cfile);
	if (token == LPAREN) {
		parenp = ISC_TRUE;
		skip_token(&val, NULL, cfile);
	} else
		parenp = ISC_FALSE;

	cond = createMap();
	if (!parse_boolean_expression(cond, cfile, lose)) {
		if (!*lose)
			parse_error(cfile, "boolean expression expected.");
		*lose = ISC_TRUE;
		return ISC_FALSE;
	}
	mapSet(statement, cond, "condition");
	if (parenp) {
		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			parse_error(cfile, "expecting right paren.");
	}
	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "left brace expected.");
	branch = createMap();
	if (!parse_executable_statements(branch, cfile, lose, context_any)) {
		if (*lose) {
			/* Try to even things up. */
			do {
				token = next_token(&val, NULL, cfile);
			} while (token != END_OF_FILE && token != RBRACE);
			return ISC_FALSE;
		}
	}
	mapSet(statement, branch, "then");
	token = next_token(&val, NULL, cfile);
	if (token != RBRACE)
		parse_error(cfile, "right brace expected.");
	token = peek_token(&val, NULL, cfile);
	if (token == ELSE) {
		skip_token(&val, NULL, cfile);
		branch = createMap();
		token = peek_token(&val, NULL, cfile);
		if (token == IF) {
			skip_token(&val, NULL, cfile);
			if (!parse_if_statement(branch, cfile, lose)) {
				if (!*lose)
					parse_error(cfile,
						    "expecting if statement");
				*lose = ISC_TRUE;
				return ISC_FALSE;
			}
		} else if (token != LBRACE)
			parse_error(cfile, "left brace or if expected.");
		else {
			skip_token(&val, NULL, cfile);
			if (!parse_executable_statements(branch, cfile,
							 lose, context_any))
				return ISC_FALSE;
			token = next_token(&val, NULL, cfile);
			if (token != RBRACE)
				parse_error(cfile, "right brace expected.");
		}
		mapSet(statement, branch, "else");
	} else if (token == ELSIF) {
		skip_token(&val, NULL, cfile);
		branch = createMap();
		if (!parse_if_statement(branch, cfile, lose)) {
			if (!*lose)
				parse_error(cfile,
					    "expecting conditional.");
			*lose = ISC_TRUE;
			return ISC_FALSE;
		}
		mapSet(statement, branch, "else");
	}
	
	return ISC_TRUE;
}

/*
 * boolean_expression :== CHECK STRING |
 *  			  NOT boolean-expression |
 *			  data-expression EQUAL data-expression |
 *			  data-expression BANG EQUAL data-expression |
 *			  data-expression REGEX_MATCH data-expression |
 *			  boolean-expression AND boolean-expression |
 *			  boolean-expression OR boolean-expression
 *			  EXISTS OPTION-NAME
 */
   			  
isc_boolean_t
parse_boolean_expression(struct element *expr,
			 struct parse *cfile,
			 isc_boolean_t *lose)
{
	/* Parse an expression... */
	if (!parse_expression(expr, cfile, lose, context_boolean,
			      NULL, expr_none))
		return ISC_FALSE;

	if (!is_boolean_expression(expr) &&
	    !mapContains(expr, "variable-reference") &&
	    !mapContains(expr, "funcall"))
		parse_error(cfile, "Expecting a boolean expression.");
	return ISC_FALSE;
}

/* boolean :== ON SEMI | OFF SEMI | TRUE SEMI | FALSE SEMI */

isc_boolean_t
parse_boolean(struct parse *cfile)
{
	const char *val;
	isc_boolean_t rv;

        (void)next_token(&val, NULL, cfile);
	if (!strcasecmp (val, "true")
	    || !strcasecmp (val, "on"))
		rv = ISC_TRUE;
	else if (!strcasecmp (val, "false")
		 || !strcasecmp (val, "off"))
		rv = ISC_FALSE;
	else
		parse_error(cfile,
			    "boolean value (true/false/on/off) expected");
	parse_semi(cfile);
	return rv;
}

/*
 * data_expression :== SUBSTRING LPAREN data-expression COMMA
 *					numeric-expression COMMA
 *					numeric-expression RPAREN |
 *		       CONCAT LPAREN data-expression COMMA 
 *					data-expression RPAREN
 *		       SUFFIX LPAREN data_expression COMMA
 *		       		     numeric-expression RPAREN |
 *		       LCASE LPAREN data_expression RPAREN |
 *		       UCASE LPAREN data_expression RPAREN |
 *		       OPTION option_name |
 *		       HARDWARE |
 *		       PACKET LPAREN numeric-expression COMMA
 *				     numeric-expression RPAREN |
 *		       V6RELAY LPAREN numeric-expression COMMA
 *				      data-expression RPAREN |
 *		       STRING |
 *		       colon_separated_hex_list
 */

isc_boolean_t
parse_data_expression(struct element *expr,
		      struct parse *cfile,
		      isc_boolean_t *lose)
{
	/* Parse an expression... */
	if (!parse_expression(expr, cfile, lose, context_data,
			      NULL, expr_none))
		return ISC_FALSE;

	if (!is_data_expression(expr) &&
	    !mapContains(expr, "variable-reference") &&
	    !mapContains(expr, "funcall"))
		parse_error(cfile, "Expecting a data expression.");
	return ISC_TRUE;
}

/*
 * numeric-expression :== EXTRACT_INT LPAREN data-expression
 *					     COMMA number RPAREN |
 *			  NUMBER
 */

isc_boolean_t
parse_numeric_expression(struct element *expr,
			 struct parse *cfile,
			 isc_boolean_t *lose)
{
	/* Parse an expression... */
	if (!parse_expression(expr, cfile, lose, context_numeric,
			      NULL, expr_none))
		return ISC_FALSE;

	if (!is_numeric_expression(expr) &&
	    !mapContains(expr, "variable-reference") &&
	    !mapContains(expr, "funcall"))
		parse_error(cfile, "Expecting a numeric expression.");
	return ISC_TRUE;
}

/* Parse a subexpression that does not contain a binary operator. */

isc_boolean_t
parse_non_binary(struct element *expr,
		 struct parse *cfile,
		 isc_boolean_t *lose,
		 enum expression_context context)
{
////////////
	enum dhcp_token token;
	const char *val;
	struct collection *col;
	struct expression *nexp, **ep;
	int known;
	char *cptr;
	isc_result_t status;
	unsigned len;

	token = peek_token(&val, NULL, cfile);

	/* Check for unary operators... */
	switch (token) {
	      case CHECK:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != STRING) {
			parse_warn (cfile, "string expected.");
			skip_to_semi(cfile);
			*lose = 1;
			return 0;
		}
		for (col = collections; col; col = col->next)
			if (!strcmp (col->name, val))
				break;
		if (!col) {
			parse_warn (cfile, "unknown collection.");
			*lose = 1;
			return 0;
		}
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_check;
		(*expr)->data.check = col;
		break;

	      case TOKEN_NOT:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_not;
		if (!parse_non_binary (&(*expr)->data.not,
				       cfile, lose, context_boolean)) {
			if (!*lose) {
				parse_warn (cfile, "expression expected");
				skip_to_semi(cfile);
			}
			*lose = 1;
			expression_dereference(expr, MDL);
			return (0);
		}
		if (!is_boolean_expression ((*expr)->data.not)) {
			*lose = 1;
			parse_warn (cfile, "boolean expression expected");
			skip_to_semi(cfile);
			expression_dereference(expr, MDL);
			return 0;
		}
		break;

	      case LPAREN:
		skip_token(&val, NULL, cfile);
		if (!parse_expression (expr, cfile, lose, context,
				       NULL, expr_none)) {
			if (!*lose) {
				parse_warn (cfile, "expression expected");
				skip_to_semi(cfile);
			}
			*lose = 1;
			return 0;
		}
		token = next_token(&val, NULL, cfile);
		if (token != RPAREN) {
			*lose = 1;
			parse_warn (cfile, "right paren expected");
			skip_to_semi(cfile);
			return 0;
		}
		break;

	      case EXISTS:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_exists;
		known = 0;
		/* Pass reference directly to expression structure. */
		status = parse_option_name(cfile, 0, &known,
					   &(*expr)->data.option);
		if (status != ISC_R_SUCCESS ||
		    (*expr)->data.option == NULL) {
			*lose = 1;
			expression_dereference(expr, MDL);
			return (0);
		}
		break;

	      case STATIC:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_static;
		break;

	      case KNOWN:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_known;
		break;

	      case SUBSTRING:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_substring;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN) {
		      nolparen:
			expression_dereference(expr, MDL);
			parse_warn (cfile, "left parenthesis expected.");
			*lose = 1;
			return 0;
		}

		if (!parse_data_expression (&(*expr)->data.substring.expr,
					    cfile, lose)) {
		      nodata:
			expression_dereference(expr, MDL);
			if (!*lose) {
				parse_warn (cfile,
					    "expecting data expression.");
				skip_to_semi(cfile);
				*lose = 1;
			}
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != COMMA) {
		      nocomma:
			expression_dereference(expr, MDL);
			parse_warn (cfile, "comma expected.");
			*lose = 1;

			return 0;
		}

		if (!parse_numeric_expression
		    (&(*expr)->data.substring.offset,cfile, lose)) {
		      nonum:
			if (!*lose) {
				parse_warn (cfile,
					    "expecting numeric expression.");
				skip_to_semi(cfile);
				*lose = 1;
			}
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_numeric_expression
		    (&(*expr)->data.substring.len, cfile, lose))
			goto nonum;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN) {
		      norparen:
			parse_warn (cfile, "right parenthesis expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		break;

	      case SUFFIX:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_suffix;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_data_expression (&(*expr)->data.suffix.expr,
					    cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_numeric_expression (&(*expr)->data.suffix.len,
					       cfile, lose))
			goto nonum;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case LCASE:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_lcase;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_data_expression(&(*expr)->data.lcase, cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case UCASE:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_ucase;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_data_expression(&(*expr)->data.ucase,
					   cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case CONCAT:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_concat;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_data_expression (&(*expr)->data.concat[0],
					    cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

	      concat_another:
		if (!parse_data_expression (&(*expr)->data.concat[1],
					    cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);

		if (token == COMMA) {
			nexp = NULL;
			if (!expression_allocate(&nexp, MDL))
				parse_error(cfile, "can't allocate at CONCAT2");
			nexp->op = expr_concat;
			expression_reference(&nexp->data.concat[0],
					      *expr, MDL);
			expression_dereference(expr, MDL);
			expression_reference(expr, nexp, MDL);
			expression_dereference(&nexp, MDL);
			goto concat_another;
		}

		if (token != RPAREN)
			goto norparen;
		break;

	      case BINARY_TO_ASCII:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_binary_to_ascii;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_numeric_expression (&(*expr)->data.b2a.base,
					       cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_numeric_expression (&(*expr)->data.b2a.width,
					       cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_data_expression (&(*expr)->data.b2a.separator,
					    cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_data_expression (&(*expr)->data.b2a.buffer,
					    cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case REVERSE:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_reverse;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!(parse_numeric_expression
		      (&(*expr)->data.reverse.width, cfile, lose)))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!(parse_data_expression
		      (&(*expr)->data.reverse.buffer, cfile, lose)))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case PICK:
		/* pick (a, b, c) actually produces an internal representation
		   that looks like pick (a, pick (b, pick (c, nil))). */
		skip_token(&val, NULL, cfile);
		if (!(expression_allocate(expr, MDL)))
			parse_error(cfile, "can't allocate expression");

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		nexp = NULL;
		expression_reference(&nexp, *expr, MDL);
		do {
		    nexp->op = expr_pick_first_value;
		    if (!(parse_data_expression
			  (&nexp->data.pick_first_value.car,
			   cfile, lose)))
			goto nodata;

		    token = next_token(&val, NULL, cfile);
		    if (token == COMMA) {
			struct expression *foo = NULL;
			if (!expression_allocate(&foo, MDL))
			    parse_error(cfile, "can't allocate expr");
			expression_reference
				(&nexp->data.pick_first_value.cdr, foo, MDL);
			expression_dereference(&nexp, MDL);
			expression_reference(&nexp, foo, MDL);
			expression_dereference(&foo, MDL);
		    }
		} while (token == COMMA);
		expression_dereference(&nexp, MDL);

		if (token != RPAREN)
			goto norparen;
		break;

	      case OPTION:
	      case CONFIG_OPTION:
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = (token == OPTION
				 ? expr_option
				 : expr_config_option);
		skip_token(&val, NULL, cfile);
		known = 0;
		/* Pass reference directly to expression structure. */
		status = parse_option_name(cfile, 0, &known,
					   &(*expr)->data.option);
		if (status != ISC_R_SUCCESS ||
		    (*expr)->data.option == NULL) {
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		break;

	      case HARDWARE:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_hardware;
		break;

	      case LEASED_ADDRESS:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_leased_address;
		break;

	      case CLIENT_STATE:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_client_state;
		break;

	      case FILENAME:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_filename;
		break;

	      case SERVER_NAME:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_sname;
		break;

	      case LEASE_TIME:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_lease_time;
		break;

	      case TOKEN_NULL:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_null;
		break;

	      case HOST_DECL_NAME:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_host_decl_name;
		break;

	      case PACKET:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_packet;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_numeric_expression (&(*expr)->data.packet.offset,
					       cfile, lose))
			goto nonum;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_numeric_expression (&(*expr)->data.packet.len,
					       cfile, lose))
			goto nonum;

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;
		
	      case STRING:
		skip_token(&val, &len, cfile);
		if (!make_const_data (expr, (const unsigned char *)val,
				      len, 1, 1, MDL))
			parse_error(cfile, "can't make constant string expression.");
		break;

	      case EXTRACT_INT:
		skip_token(&val, NULL, cfile);	
		token = next_token(&val, NULL, cfile);
		if (token != LPAREN) {
			parse_warn (cfile, "left parenthesis expected.");
			*lose = 1;
			return 0;
		}

		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");

		if (!parse_data_expression (&(*expr)->data.extract_int,
					    cfile, lose)) {
			if (!*lose) {
				parse_warn (cfile,
					    "expecting data expression.");
				skip_to_semi(cfile);
				*lose = 1;
			}
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != COMMA) {
			parse_warn (cfile, "comma expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != NUMBER) {
			parse_warn (cfile, "number expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		switch (atoi(val)) {
		      case 8:
			(*expr)->op = expr_extract_int8;
			break;

		      case 16:
			(*expr)->op = expr_extract_int16;
			break;

		      case 32:
			(*expr)->op = expr_extract_int32;
			break;

		      default:
			parse_warn (cfile,
				    "unsupported integer size %d", atoi(val));
			*lose = 1;
			skip_to_semi(cfile);
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN) {
			parse_warn (cfile, "right parenthesis expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		break;
	
	      case ENCODE_INT:
		skip_token(&val, NULL, cfile);	
		token = next_token(&val, NULL, cfile);
		if (token != LPAREN) {
			parse_warn (cfile, "left parenthesis expected.");
			*lose = 1;
			return 0;
		}

		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");

		if (!parse_numeric_expression (&(*expr)->data.encode_int,
					       cfile, lose)) {
			parse_warn (cfile, "expecting numeric expression.");
			skip_to_semi(cfile);
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != COMMA) {
			parse_warn (cfile, "comma expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != NUMBER) {
			parse_warn (cfile, "number expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		switch (atoi(val)) {
		      case 8:
			(*expr)->op = expr_encode_int8;
			break;

		      case 16:
			(*expr)->op = expr_encode_int16;
			break;

		      case 32:
			(*expr)->op = expr_encode_int32;
			break;

		      default:
			parse_warn (cfile,
				    "unsupported integer size %d", atoi(val));
			*lose = 1;
			skip_to_semi(cfile);
			expression_dereference(expr, MDL);
			return 0;
		}

		token = next_token(&val, NULL, cfile);
		if (token != RPAREN) {
			parse_warn (cfile, "right parenthesis expected.");
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		break;
	
	      case NUMBER:
		/* If we're in a numeric context, this should just be a
		   number, by itself. */
		if (context == context_numeric ||
		    context == context_data_or_numeric) {
			skip_token(&val, NULL, cfile);
			if (!expression_allocate(expr, MDL))
				parse_error(cfile, "can't allocate expression");
			(*expr)->op = expr_const_int;
			(*expr)->data.const_int = atoi(val);
			break;
		}

	      case NUMBER_OR_NAME:
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");

		(*expr)->op = expr_const_data;
		if (!parse_cshl (&(*expr)->data.const_data, cfile)) {
			expression_dereference(expr, MDL);
			return 0;
		}
		break;

	      case NS_FORMERR:
		known = FORMERR;
		goto ns_const;
	      ns_const:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_const_int;
		(*expr)->data.const_int = known;
		break;
		
	      case NS_NOERROR:
		known = ISC_R_SUCCESS;
		goto ns_const;

	      case NS_NOTAUTH:
		known = DHCP_R_NOTAUTH;
		goto ns_const;

	      case NS_NOTIMP:
		known = ISC_R_NOTIMPLEMENTED;
		goto ns_const;

	      case NS_NOTZONE:
		known = DHCP_R_NOTZONE;
		goto ns_const;

	      case NS_NXDOMAIN:
		known = DHCP_R_NXDOMAIN;
		goto ns_const;

	      case NS_NXRRSET:
		known = DHCP_R_NXRRSET;
		goto ns_const;

	      case NS_REFUSED:
		known = DHCP_R_REFUSED;
		goto ns_const;

	      case NS_SERVFAIL:
		known = DHCP_R_SERVFAIL;
		goto ns_const;

	      case NS_YXDOMAIN:
		known = DHCP_R_YXDOMAIN;
		goto ns_const;

	      case NS_YXRRSET:
		known = DHCP_R_YXRRSET;
		goto ns_const;

	      case BOOTING:
		known = S_INIT;
		goto ns_const;

	      case REBOOT:
		known = S_REBOOTING;
		goto ns_const;

	      case SELECT:
		known = S_SELECTING;
		goto ns_const;

	      case REQUEST:
		known = S_REQUESTING;
		goto ns_const;

	      case BOUND:
		known = S_BOUND;
		goto ns_const;

	      case RENEW:
		known = S_RENEWING;
		goto ns_const;

	      case REBIND:
		known = S_REBINDING;
		goto ns_const;

	      case DEFINED:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		token = next_token(&val, NULL, cfile);
		if (token != NAME && token != NUMBER_OR_NAME) {
			parse_warn (cfile, "%s can't be a variable name", val);
			skip_to_semi(cfile);
			*lose = 1;
			return 0;
		}

		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_variable_exists;
		(*expr)->data.variable = dmalloc (strlen (val) + 1, MDL);
		if (!(*expr)->data.variable)
			parse_error(cfile, "can't allocate variable name");
		strcpy((*expr)->data.variable, val);
		token = next_token(&val, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

		/* This parses 'gethostname()'. */
	      case GETHOSTNAME:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_gethostname;

		token = next_token(NULL, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		token = next_token(NULL, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case GETHOSTBYNAME:
		skip_token(&val, NULL, cfile);
		token = next_token(NULL, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		/* The argument is a quoted string. */
		token = next_token(&val, NULL, cfile);
		if (token != STRING) {
			parse_warn(cfile, "Expecting quoted literal: "
					  "\"foo.example.com\"");
			skip_to_semi(cfile);
			*lose = 1;
			return 0;
		}
		if (!make_host_lookup(expr, val))
			parse_error(cfile, "Error creating gethostbyname() internal "
				  "record. (%s:%d)", MDL);

		token = next_token(NULL, NULL, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case V6RELAY:
		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_v6relay;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_numeric_expression (&(*expr)->data.v6relay.relay,
						cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_data_expression (&(*expr)->data.v6relay.roption,
					    cfile, lose))
			goto nodata;

		token = next_token(&val, NULL, cfile);

		if (token != RPAREN)
			goto norparen;
		break;

		/* Not a valid start to an expression... */
	      default:
		if (token != NAME && token != NUMBER_OR_NAME)
			return 0;

		skip_token(&val, NULL, cfile);

		/* Save the name of the variable being referenced. */
		cptr = dmalloc (strlen (val) + 1, MDL);
		if (!cptr)
			parse_error(cfile, "can't allocate variable name");
		strcpy(cptr, val);

		/* Simple variable reference, as far as we can tell. */
		token = peek_token(&val, NULL, cfile);
		if (token != LPAREN) {
			if (!expression_allocate(expr, MDL))
				parse_error(cfile, "can't allocate expression");
			(*expr)->op = expr_variable_reference;
			(*expr)->data.variable = cptr;
			break;
		}

		skip_token(&val, NULL, cfile);
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "can't allocate expression");
		(*expr)->op = expr_funcall;
		(*expr)->data.funcall.name = cptr;

		/* Now parse the argument list. */
		ep = &(*expr)->data.funcall.arglist;
		do {
			if (!expression_allocate(ep, MDL))
				parse_error(cfile, "can't allocate expression");
			(*ep)->op = expr_arg;
			if (!parse_expression (&(*ep)->data.arg.val,
					       cfile, lose, context_any,
					       NULL,
					       expr_none)) {
				if (!*lose) {
					parse_warn (cfile,
						    "expecting expression.");
					*lose = 1;
				}
				skip_to_semi(cfile);
				expression_dereference(expr, MDL);
				return 0;
			}
			ep = &((*ep)->data.arg.next);
			token = next_token(&val, NULL, cfile);
		} while (token == COMMA);
		if (token != RPAREN) {
			parse_warn (cfile, "Right parenthesis expected.");
			skip_to_semi(cfile);
			*lose = 1;
			expression_dereference(expr, MDL);
			return 0;
		}
		break;
	}
	return 1;
}

/* Parse an expression. */

isc_boolean_t
parse_expression(struct element *expr, struct parse *cfile,
		 isc_boolean_t *lose, enum expression_context context,
		 struct expression **plhs, enum expr_op binop)
{
	enum dhcp_token token;
	const char *val;
	struct expression *rhs = NULL, *tmp;
	struct expression *lhs = NULL;
	enum expr_op next_op;
	enum expression_context
		lhs_context = context_any,
		rhs_context = context_any;

	/* Consume the left hand side we were passed. */
	if (plhs) {
		expression_reference(&lhs, *plhs, MDL);
		expression_dereference(plhs, MDL);
	}

      new_rhs:
	if (!parse_non_binary (&rhs, cfile, lose, context)) {
		/* If we already have a left-hand side, then it's not
		   okay for there not to be a right-hand side here, so
		   we need to flag it as an error. */
		if (lhs) {
			if (!*lose) {
				parse_warn (cfile,
					    "expecting right-hand side.");
				*lose = 1;
				skip_to_semi(cfile);
			}
			expression_dereference(&lhs, MDL);
		}
		return 0;
	}

	/* At this point, rhs contains either an entire subexpression,
	   or at least a left-hand-side.   If we do not see a binary token
	   as the next token, we're done with the expression. */

	token = peek_token(&val, NULL, cfile);
	switch (token) {
	      case BANG:
		skip_token(&val, NULL, cfile);
		token = peek_token(&val, NULL, cfile);
		if (token != EQUAL) {
			parse_warn (cfile, "! in boolean context without =");
			*lose = 1;
			skip_to_semi(cfile);
			if (lhs)
				expression_dereference(&lhs, MDL);
			return 0;
		}
		next_op = expr_not_equal;
		context = expression_context (rhs);
		break;

	      case EQUAL:
		next_op = expr_equal;
		context = expression_context (rhs);
		break;

	      case TILDE:
#ifdef HAVE_REGEX_H
		skip_token(&val, NULL, cfile);
		token = peek_token(&val, NULL, cfile);

		if (token == TILDE)
			next_op = expr_iregex_match;
		else if (token == EQUAL)
			next_op = expr_regex_match;
		else {
			parse_warn(cfile, "expecting ~= or ~~ operator");
			*lose = 1;
			skip_to_semi(cfile);
			if (lhs)
				expression_dereference(&lhs, MDL);
			return 0;
		}

		context = expression_context(rhs);
#else
		parse_warn(cfile, "No support for regex operator.");
		*lose = 1;
		skip_to_semi(cfile);
		if (lhs != NULL)
			expression_dereference(&lhs, MDL);
		return 0;
#endif
		break;

	      case AND:
		next_op = expr_and;
		context = expression_context (rhs);
		break;

	      case OR:
		next_op = expr_or;
		context = expression_context (rhs);
		break;

	      case PLUS:
		next_op = expr_add;
		context = expression_context (rhs);
		break;

	      case MINUS:
		next_op = expr_subtract;
		context = expression_context (rhs);
		break;

	      case SLASH:
		next_op = expr_divide;
		context = expression_context (rhs);
		break;

	      case ASTERISK:
		next_op = expr_multiply;
		context = expression_context (rhs);
		break;

	      case PERCENT:
		next_op = expr_remainder;
		context = expression_context (rhs);
		break;

	      case AMPERSAND:
		next_op = expr_binary_and;
		context = expression_context (rhs);
		break;

	      case PIPE:
		next_op = expr_binary_or;
		context = expression_context (rhs);
		break;

	      case CARET:
		next_op = expr_binary_xor;
		context = expression_context (rhs);
		break;

	      default:
		next_op = expr_none;
	}

	/* If we have no lhs yet, we just parsed it. */
	if (!lhs) {
		/* If there was no operator following what we just parsed,
		   then we're done - return it. */
		if (next_op == expr_none) {
			*expr = rhs;
			return 1;
		}
		lhs = rhs;
		rhs = NULL;
		binop = next_op;
		skip_token(&val, NULL, cfile);
		goto new_rhs;
	}

	/* If the next binary operator is of greater precedence than the
	 * current operator, then rhs we have parsed so far is actually
	 * the lhs of the next operator.  To get this value, we have to
	 * recurse.
	 */
	if (binop != expr_none && next_op != expr_none &&
	    op_precedence (binop, next_op) < 0) {

		/* Eat the subexpression operator token, which we pass to
		 * parse_expression...we only peek()'d earlier.
		 */
		skip_token(&val, NULL, cfile);

		/* Continue parsing of the right hand side with that token. */
		tmp = rhs;
		rhs = NULL;
		if (!parse_expression (&rhs, cfile, lose, op_context (next_op),
				       &tmp, next_op)) {
			if (!*lose) {
				parse_warn (cfile,
					    "expecting a subexpression");
				*lose = 1;
			}
			return 0;
		}
		next_op = expr_none;
	}

	if (binop != expr_none) {
	  rhs_context = expression_context(rhs);
	  lhs_context = expression_context(lhs);

	  if ((rhs_context != context_any) && (lhs_context != context_any) &&
			(rhs_context != lhs_context)) {
	    parse_warn (cfile, "illegal expression relating different types");
	    skip_to_semi(cfile);
	    expression_dereference(&rhs, MDL);
	    expression_dereference(&lhs, MDL);
	    *lose = 1;
	    return 0;
	  }

	  switch(binop) {
	    case expr_not_equal:
	    case expr_equal:
		if ((rhs_context != context_data_or_numeric) &&
		    (rhs_context != context_data) &&
		    (rhs_context != context_numeric) &&
		    (rhs_context != context_any)) {
			parse_warn (cfile, "expecting data/numeric expression");
			skip_to_semi(cfile);
			expression_dereference(&rhs, MDL);
			*lose = 1;
			return 0;
		}
		break;

	    case expr_regex_match:
#ifdef HAVE_REGEX_H
		if (expression_context(rhs) != context_data) {
			parse_warn(cfile, "expecting data expression");
			skip_to_semi(cfile);
			expression_dereference(&rhs, MDL);
			*lose = 1;
			return 0;
		}
#else
		/* It should not be possible to attempt to parse the right
		 * hand side of an operator there is no support for.
		 */
		parse_error(cfile, "Impossible condition at %s:%d.", MDL);
#endif
		break;

	    case expr_and:
	    case expr_or:
		if ((rhs_context != context_boolean) &&
		    (rhs_context != context_any)) {
			parse_warn (cfile, "expecting boolean expressions");
			skip_to_semi(cfile);
			expression_dereference(&rhs, MDL);
			*lose = 1;
			return 0;
		}
		break;

	    case expr_add:
	    case expr_subtract:
	    case expr_divide:
	    case expr_multiply:
	    case expr_remainder:
	    case expr_binary_and:
	    case expr_binary_or:
	    case expr_binary_xor:
		if ((rhs_context != context_numeric) &&
		    (rhs_context != context_any)) {
			parse_warn (cfile, "expecting numeric expressions");
                        skip_to_semi(cfile);
                        expression_dereference(&rhs, MDL);
                        *lose = 1;
                        return 0;
		}
		break;

	    default:
		break;
	  }
	}

	/* Now, if we didn't find a binary operator, we're done parsing
	   this subexpression, so combine it with the preceding binary
	   operator and return the result. */
	if (next_op == expr_none) {
		if (!expression_allocate(expr, MDL))
			parse_error(cfile, "Can't allocate expression!");

		(*expr)->op = binop;
		/* All the binary operators' data union members
		   are the same, so we'll cheat and use the member
		   for the equals operator. */
		(*expr)->data.equal[0] = lhs;
		(*expr)->data.equal[1] = rhs;
		return 1;
	}

	/* Eat the operator token - we now know it was a binary operator... */
	skip_token(&val, NULL, cfile);

	/* Now combine the LHS and the RHS using binop. */
	tmp = NULL;
	if (!expression_allocate(&tmp, MDL))
		parse_error(cfile, "No memory for equal precedence combination.");
	
	/* Store the LHS and RHS. */
	tmp->data.equal[0] = lhs;
	tmp->data.equal[1] = rhs;
	tmp->op = binop;
	
	lhs = tmp;
	tmp = NULL;
	rhs = NULL;

	binop = next_op;
	goto new_rhs;
}	

int parse_option_data (expr, cfile, lookups, option)
struct expression **expr;
struct parse *cfile;
int lookups;
struct option *option;
{
	const char *val;
	const char *fmt = NULL;
	struct expression *tmp;
	enum dhcp_token token;

	do {
		/*
                 * Set a flag if this is an array of a simple type (i.e.,
                 * not an array of pairs of IP addresses, or something like
                 * that.
                 */
		int uniform = 0;

	      and_again:
		/* Set fmt to start of format for 'A' and one char back
		 * for 'a'.
		 */
		if ((fmt != NULL) && (fmt != option->format) && (*fmt == 'a'))
			fmt -= 1;
		else if ((fmt == NULL) || (*fmt == 'A'))
			fmt = option->format;

		/* 'a' means always uniform */
		if ((fmt[0] != 'Z') && (tolower((unsigned char)fmt[1]) == 'a')) 
			uniform = 1;

		do {
			if ((*fmt == 'A') || (*fmt == 'a'))
				break;
			if (*fmt == 'o') {
				/* consume the optional flag */
				fmt++;
				continue;
			}

			if (fmt[1] == 'o') {
				/*
				 * A value for the current format is
				 * optional - check to see if the next
				 * token is a semi-colon if so we don't
				 * need to parse it and doing so would
				 * consume the semi-colon which our
				 * caller is expecting to parse
				 */
				token = peek_token(&val, NULL,
						   cfile);
				if (token == SEMI) {
					fmt++;
					continue;
				}
			}

			tmp = *expr;
			*expr = NULL;

			if (!parse_option_token(expr, cfile, &fmt, tmp,
						uniform, lookups)) {
				if (fmt[1] != 'o') {
					if (tmp)
						expression_dereference(&tmp,
									MDL);
					return 0;
				}
				*expr = tmp;
				tmp = NULL;
			}
			if (tmp)
				expression_dereference(&tmp, MDL);

			fmt++;
		} while (*fmt != '\0');

		if ((*fmt == 'A') || (*fmt == 'a')) {
			token = peek_token(&val, NULL, cfile);
			/* Comma means: continue with next element in array */
			if (token == COMMA) {
				skip_token(&val, NULL, cfile);
				continue;
			}
			/* no comma: end of array.
			   'A' or end of string means: leave the loop */
			if ((*fmt == 'A') || (fmt[1] == '\0'))
				break;
			/* 'a' means: go on with next char */
			if (*fmt == 'a') {
				fmt++;
				goto and_again;
			}
		}
	} while ((*fmt == 'A') || (*fmt == 'a'));

        return 1;
}

/* option-statement :== identifier DOT identifier <syntax> SEMI
		      | identifier <syntax> SEMI

   Option syntax is handled specially through format strings, so it
   would be painful to come up with BNF for it.   However, it always
   starts as above and ends in a SEMI. */

int parse_option_statement (result, cfile, lookups, option, op)
	struct executable_statement **result;
	struct parse *cfile;
	int lookups;
	struct option *option;
	enum statement_op op;
{
	const char *val;
	enum dhcp_token token;
	struct expression *expr = NULL;
	int lose;

	token = peek_token(&val, NULL, cfile);
	if ((token == SEMI) && (option->format[0] != 'Z')) {
		/* Eat the semicolon... */
		/*
		 * XXXSK: I'm not sure why we should ever get here, but we 
		 * 	  do during our startup. This confuses things if
		 * 	  we are parsing a zero-length option, so don't
		 * 	  eat the semicolon token in that case.
		 */
		skip_token(&val, NULL, cfile);
	} else if (token == EQUAL) {
		/* Eat the equals sign. */
		skip_token(&val, NULL, cfile);

		/* Parse a data expression and use its value for the data. */
		if (!parse_data_expression (&expr, cfile, &lose)) {
			/* In this context, we must have an executable
			   statement, so if we found something else, it's
			   still an error. */
			if (!lose) {
				parse_warn (cfile,
					    "expecting a data expression.");
				skip_to_semi(cfile);
			}
			return 0;
		}
	} else {
		if (! parse_option_data(&expr, cfile, lookups, option))
			return 0;
	}

	parse_semi(cfile);
	if (!executable_statement_allocate(result, MDL))
		parse_error(cfile, "no memory for option statement.");

        (*result)->op = op;
	if (expr && !option_cache (&(*result)->data.option,
				   NULL, expr, option, MDL))
		parse_error(cfile, "no memory for option cache");

	if (expr)
		expression_dereference(&expr, MDL);

	return 1;
}

int parse_option_token (rv, cfile, fmt, expr, uniform, lookups)
	struct expression **rv;
	struct parse *cfile;
	const char **fmt;
	struct expression *expr;
	int uniform;
	int lookups;
{
	const char *val;
	enum dhcp_token token;
	struct expression *t = NULL;
	unsigned char buf[4];
	unsigned len;
	struct iaddr addr;
	int compress;
	isc_boolean_t freeval = ISC_FALSE;
	const char *f, *g;
	struct enumeration_value *e;

	switch (**fmt) {
	      case 'U':
		token = next_token(&val, &len, cfile);
		if (!is_identifier(token)) {
			if ((*fmt)[1] != 'o') {
				parse_warn (cfile, "expecting identifier.");
				if (token != SEMI)
					skip_to_semi(cfile);
			}
			return 0;
		}
		if (!make_const_data (&t, (const unsigned char *)val,
				      len, 1, 1, MDL))
			parse_error(cfile, "No memory for %s", val);
		break;

	      case 'E':
		g = strchr (*fmt, '.');
		if (!g) {
			parse_warn (cfile,
				    "malformed encapsulation format (bug!)");
			skip_to_semi(cfile);
			return 0;
		}
		*fmt = g;
		/* FALL THROUGH */
		/* to get string value for the option */
	      case 'X':
		token = peek_token(&val, NULL, cfile);
		if (token == NUMBER_OR_NAME || token == NUMBER) {
			if (!expression_allocate(&t, MDL))
				return 0;
			if (!parse_cshl (&t->data.const_data, cfile)) {
				expression_dereference(&t, MDL);
				return 0;
			}
			t->op = expr_const_data;
		} else {
			token = next_token(&val, &len, cfile);

			if(token == STRING) {
				if (!make_const_data (&t,
						(const unsigned char *)val,
							len, 1, 1, MDL))
					parse_error(cfile, "No memory for \"%s\"", val);
			} else {
                                if ((*fmt)[1] != 'o') {
				        parse_warn (cfile, "expecting string "
					            "or hexadecimal data.");
				        skip_to_semi(cfile);
                                }
				return 0;
			}
		}
		break;

              case 'D': /* Domain list... */
		if ((*fmt)[1] == 'c') {
			compress = 1;
			/* Skip the compress-flag atom. */
			(*fmt)++;
		} else
			compress = 0;

		t = parse_domain_list(cfile, compress);

		if (!t) {
			if ((*fmt)[1] != 'o')
				skip_to_semi(cfile);
			return 0;
		}

		break;

	      case 'd': /* Domain name... */
		val = parse_host_name (cfile);
		if (!val) {
			parse_warn (cfile, "not a valid domain name.");
			skip_to_semi(cfile);
			return 0;
		}
		len = strlen (val);
		freeval = ISC_TRUE;
		goto make_string;

	      case 't': /* Text string... */
		token = next_token(&val, &len, cfile);
		if (token != STRING && !is_identifier(token)) {
			if ((*fmt)[1] != 'o') {
				parse_warn (cfile, "expecting string.");
				if (token != SEMI)
					skip_to_semi(cfile);
			}
			return 0;
		}
	      make_string:
		if (!make_const_data (&t, (const unsigned char *)val,
				      len, 1, 1, MDL))
			parse_error(cfile, "No memory for concatenation");
		if (freeval == ISC_TRUE) {
			dfree((char *)val, MDL);
			freeval = ISC_FALSE;
			POST(freeval);
		}
		break;
		
	      case 'N':
		f = (*fmt) + 1;
		g = strchr (*fmt, '.');
		if (!g) {
			parse_warn (cfile, "malformed %s (bug!)",
				    "enumeration format");
		      foo:
			skip_to_semi(cfile);
			return 0;
		}
		*fmt = g;
		token = next_token(&val, NULL, cfile);
		if (!is_identifier(token)) {
			parse_warn (cfile,
				    "identifier expected");
			goto foo;
		}
		e = find_enumeration_value (f, (*fmt) - f, &len, val);
		if (!e) {
			parse_warn (cfile, "unknown value");
			goto foo;
		}
		if (!make_const_data (&t, &e->value, len, 0, 1, MDL))
			return 0;
		break;

	      case 'I': /* IP address or hostname. */
		if (lookups) {
			if (!parse_ip_addr_or_hostname (&t, cfile, uniform))
				return 0;
		} else {
			if (!parse_ip_addr(cfile, &addr))
				return 0;
			if (!make_const_data (&t, addr.iabuf, addr.len,
					      0, 1, MDL))
				return 0;
		}
		break;

	      case '6': /* IPv6 address. */
		if (!parse_ip6_addr(cfile, &addr)) {
			return 0;
		}
		if (!make_const_data(&t, addr.iabuf, addr.len, 0, 1, MDL)) {
			return 0;
		}
		break;
		
	      case 'T':	/* Lease interval. */
		token = next_token(&val, NULL, cfile);
		if (token != INFINITE)
			goto check_number;
		putLong(buf, -1);
		if (!make_const_data (&t, buf, 4, 0, 1, MDL))
			return 0;
		break;

	      case 'L': /* Unsigned 32-bit integer... */
	      case 'l':	/* Signed 32-bit integer... */
		token = next_token(&val, NULL, cfile);
	      check_number:
		if ((token != NUMBER) && (token != NUMBER_OR_NAME)) {
		      need_number:
			if ((*fmt)[1] != 'o') {
				parse_warn (cfile, "expecting number.");
				if (token != SEMI)
					skip_to_semi(cfile);
			}
			return 0;
		}
		convert_num(cfile, buf, val, 0, 32);
		if (!make_const_data (&t, buf, 4, 0, 1, MDL))
			return 0;
		break;

	      case 's':	/* Signed 16-bit integer. */
	      case 'S':	/* Unsigned 16-bit integer. */
		token = next_token(&val, NULL, cfile);
		if ((token != NUMBER) && (token != NUMBER_OR_NAME))
			goto need_number;
		convert_num(cfile, buf, val, 0, 16);
		if (!make_const_data (&t, buf, 2, 0, 1, MDL))
			return 0;
		break;

	      case 'b':	/* Signed 8-bit integer. */
	      case 'B':	/* Unsigned 8-bit integer. */
		token = next_token(&val, NULL, cfile);
		if ((token != NUMBER) && (token != NUMBER_OR_NAME))
			goto need_number;
		convert_num(cfile, buf, val, 0, 8);
		if (!make_const_data (&t, buf, 1, 0, 1, MDL))
			return 0;
		break;

	      case 'f': /* Boolean flag. */
		token = next_token(&val, NULL, cfile);
		if (!is_identifier(token)) {
			if ((*fmt)[1] != 'o')
				parse_warn (cfile, "expecting identifier.");
		      bad_flag:
			if ((*fmt)[1] != 'o') {
				if (token != SEMI)
					skip_to_semi(cfile);
			}
			return 0;
		}
		if (!strcasecmp (val, "true")
		    || !strcasecmp (val, "on"))
			buf[0] = 1;
		else if (!strcasecmp (val, "false")
			 || !strcasecmp (val, "off"))
			buf[0] = 0;
		else if (!strcasecmp (val, "ignore"))
			buf[0] = 2;
		else {
			if ((*fmt)[1] != 'o')
				parse_warn (cfile, "expecting boolean.");
			goto bad_flag;
		}
		if (!make_const_data (&t, buf, 1, 0, 1, MDL))
			return 0;
		break;

	      case 'Z': /* Zero-length option. */
		token = peek_token(&val, NULL, cfile);
		if (token != SEMI) {
			parse_warn(cfile, "semicolon expected.");
			skip_to_semi(cfile);
		}
		buf[0] = '\0';
		if (!make_const_data(&t,        /* expression */
				     buf,       /* buffer */ 
				     0,         /* length */ 
				     0,         /* terminated */ 
				     1,         /* allocate */ 
				     MDL)) 
			return 0;
		break;

	      default:
		parse_warn (cfile, "Bad format '%c' in parse_option_token.",
			    **fmt);
		skip_to_semi(cfile);
		return 0;
	}
	if (expr) {
		if (!make_concat (rv, expr, t))
			return 0;
	} else
		expression_reference(rv, t, MDL);
	expression_dereference(&t, MDL);
	return 1;
}

int parse_option_decl (oc, cfile)
	struct option_cache **oc;
	struct parse *cfile;
{
	const char *val;
	int token;
	uint8_t buf[4];
	uint8_t hunkbuf[1024];
	unsigned hunkix = 0;
	const char *fmt, *f;
	struct option *option=NULL;
	struct iaddr ip_addr;
	uint8_t *dp;
	const uint8_t *cdp;
	unsigned len;
	int nul_term = 0;
	struct buffer *bp;
	int known = 0;
	int compress;
	struct expression *express = NULL;
	struct enumeration_value *e;
	isc_result_t status;

	status = parse_option_name(cfile, 0, &known, &option);
	if (status != ISC_R_SUCCESS || option == NULL)
		return 0;

	fmt = option->format;

	/* Parse the option data... */
	do {
		for (; *fmt; fmt++) {
			if (*fmt == 'A') {
				/* 'A' is an array of records, start at
				 *  the beginning
				 */
				fmt = option->format;
				break;
			}

			if (*fmt == 'a') {
				/* 'a' is an array of the last field,
				 * back up one format character
				 */
				fmt--;
				break;
			}
			if (*fmt == 'o' && fmt != option->format)
				continue;
			switch (*fmt) {
			      case 'E':
				fmt = strchr (fmt, '.');
				if (!fmt) {
					parse_warn (cfile,
						    "malformed %s (bug!)",
						    "encapsulation format");
					goto parse_exit;
				}
				/* FALL THROUGH */
				/* to get string value for the option */
			      case 'X':
				len = parse_X (cfile, &hunkbuf[hunkix],
					       sizeof hunkbuf - hunkix);
				hunkix += len;
				break;
					
			      case 't': /* Text string... */
				token = peek_token(&val,
						    &len, cfile);
				if (token == SEMI && fmt[1] == 'o') {
					fmt++;
					break;
				}
				token = next_token(&val,
						    &len, cfile);
				if (token != STRING) {
					parse_warn (cfile,
						    "expecting string.");
					goto parse_exit;
				}
				if (hunkix + len + 1 > sizeof hunkbuf) {
					parse_warn (cfile,
						    "option data buffer %s",
						    "overflow");
					goto parse_exit;
				}
				memcpy (&hunkbuf[hunkix], val, len + 1);
				nul_term = 1;
				hunkix += len;
				break;

			      case 'D':
				if (fmt[1] == 'c') {
					compress = 1;
					fmt++;
				} else
					compress = 0;

				express = parse_domain_list(cfile, compress);

				if (express == NULL)
					goto exit;

				if (express->op != expr_const_data) {
					parse_warn(cfile, "unexpected "
							  "expression");
					goto parse_exit;
				}

				len = express->data.const_data.len;
				cdp = express->data.const_data.data;

				if ((hunkix + len) > sizeof(hunkbuf)) {
					parse_warn(cfile, "option data buffer "
							  "overflow");
					goto parse_exit;
				}
				memcpy(&hunkbuf[hunkix], cdp, len);
				hunkix += len;

				expression_dereference(&express, MDL);
				break;

			      case 'N':
				f = fmt + 1;
				fmt = strchr (fmt, '.');
				if (!fmt) {
					parse_warn (cfile,
						    "malformed %s (bug!)",
						    "enumeration format");
					goto parse_exit;
				}
				token = next_token(&val,
						    NULL, cfile);
				if (!is_identifier(token)) {
					parse_warn (cfile,
						    "identifier expected");
					goto parse_exit;
				}
				e = find_enumeration_value (f, fmt - f,
							    &len, val);
				if (!e) {
					parse_warn (cfile,
						    "unknown value");
					goto parse_exit;
				}
				dp = &e->value;
				goto alloc;

			      case '6':
				if (!parse_ip6_addr(cfile, &ip_addr))
					goto exit;
				len = ip_addr.len;
				dp = ip_addr.iabuf;
				goto alloc;

			      case 'I': /* IP address. */
				if (!parse_ip_addr(cfile, &ip_addr))
					goto exit;
				len = ip_addr.len;
				dp = ip_addr.iabuf;

			      alloc:
				if (hunkix + len > sizeof hunkbuf) {
					parse_warn (cfile,
						    "option data buffer %s",
						    "overflow");
					goto parse_exit;
				}
				memcpy (&hunkbuf[hunkix], dp, len);
				hunkix += len;
				break;

			      case 'L': /* Unsigned 32-bit integer... */
			      case 'l':	/* Signed 32-bit integer... */
				token = next_token(&val,
						    NULL, cfile);
				if ((token != NUMBER) &&
				    (token != NUMBER_OR_NAME)) {
				      need_number:
					parse_warn (cfile,
						    "expecting number.");
					if (token != SEMI)
						goto parse_exit;
					else
						goto exit;
				}
				convert_num(cfile, buf, val, 0, 32);
				len = 4;
				dp = buf;
				goto alloc;

			      case 's':	/* Signed 16-bit integer. */
			      case 'S':	/* Unsigned 16-bit integer. */
				token = next_token(&val,
						    NULL, cfile);
				if ((token != NUMBER) &&
				    (token != NUMBER_OR_NAME))
					goto need_number;
				convert_num(cfile, buf, val, 0, 16);
				len = 2;
				dp = buf;
				goto alloc;

			      case 'b':	/* Signed 8-bit integer. */
			      case 'B':	/* Unsigned 8-bit integer. */
				token = next_token(&val,
						    NULL, cfile);
				if ((token != NUMBER) &&
				    (token != NUMBER_OR_NAME))
					goto need_number;
				convert_num(cfile, buf, val, 0, 8);
				len = 1;
				dp = buf;
				goto alloc;

			      case 'f': /* Boolean flag. */
				token = next_token(&val,
						    NULL, cfile);
				if (!is_identifier(token)) {
					parse_warn (cfile,
						    "expecting identifier.");
				      bad_flag:
					if (token != SEMI)
						goto parse_exit;
					else
						goto exit;
				}
				if (!strcasecmp (val, "true")
				    || !strcasecmp (val, "on"))
					buf[0] = 1;
				else if (!strcasecmp (val, "false")
					 || !strcasecmp (val, "off"))
					buf[0] = 0;
				else {
					parse_warn (cfile,
						    "expecting boolean.");
					goto bad_flag;
				}
				len = 1;
				dp = buf;
				goto alloc;

			      case 'Z':	/* Zero-length option */
				token = peek_token(&val, NULL, cfile);
				if (token != SEMI) {
					parse_warn(cfile,
						   "semicolon expected.");
					goto parse_exit;
				}
				len = 0;
				buf[0] = '\0';
				break;

			      default:
				log_error ("parse_option_param: Bad format %c",
				      *fmt);
				goto parse_exit;
			}
		}
		token = next_token(&val, NULL, cfile);
	} while (*fmt && token == COMMA);

	if (token != SEMI) {
		parse_warn (cfile, "semicolon expected.");
		goto parse_exit;
	}

	bp = (struct buffer *)0;
	if (!buffer_allocate(&bp, hunkix + nul_term, MDL))
		parse_error(cfile, "no memory to store option declaration.");
	memcpy (bp->data, hunkbuf, hunkix + nul_term);
	
	if (!option_cache_allocate(oc, MDL))
		parse_error(cfile, "out of memory allocating option cache.");

	(*oc)->data.buffer = bp;
	(*oc)->data.data = &bp->data[0];
	(*oc)->data.terminated = nul_term;
	(*oc)->data.len = hunkix;
	option_reference(&(*oc)->option, option, MDL);
	option_dereference(&option, MDL);
	return 1;

parse_exit:
	if (express != NULL)
		expression_dereference(&express, MDL);
	skip_to_semi(cfile);
exit:
	option_dereference(&option, MDL);

	return 0;
}

/* Consider merging parse_cshl into this. */

int parse_X (cfile, buf, max)
	struct parse *cfile;
	uint8_t *buf;
	unsigned max;
{
	int token;
	const char *val;
	unsigned len;

	token = peek_token(&val, NULL, cfile);
	if (token == NUMBER_OR_NAME || token == NUMBER) {
		len = 0;
		do {
			token = next_token(&val, NULL, cfile);
			if (token != NUMBER && token != NUMBER_OR_NAME) {
				parse_warn (cfile,
					    "expecting hexadecimal constant.");
				skip_to_semi(cfile);
				return 0;
			}
			convert_num(cfile, &buf[len], val, 16, 8);
			if (len++ > max) {
				parse_warn (cfile,
					    "hexadecimal constant too long.");
				skip_to_semi(cfile);
				return 0;
			}
			token = peek_token(&val, NULL, cfile);
			if (token == COLON)
				token = next_token(&val,
						    NULL, cfile);
		} while (token == COLON);
		val = (char *)buf;
	} else if (token == STRING) {
		skip_token(&val, &len, cfile);
		if (len + 1 > max) {
			parse_warn (cfile, "string constant too long.");
			skip_to_semi(cfile);
			return 0;
		}
		memcpy (buf, val, len + 1);
	} else {
		parse_warn (cfile, "expecting string or hexadecimal data");
		skip_to_semi(cfile);
		return 0;
	}
	return len;
}

/* parse_error moved to keama.c */

struct expression *
parse_domain_list(struct parse *cfile, int compress)
{
	const char *val;
	enum dhcp_token token = SEMI;
	struct expression *t = NULL;
	unsigned len, clen = 0;
	int result;
	unsigned char compbuf[256 * NS_MAXCDNAME];
	const unsigned char *dnptrs[256], **lastdnptr;

	memset(compbuf, 0, sizeof(compbuf));
	memset(dnptrs, 0, sizeof(dnptrs));
	dnptrs[0] = compbuf;
	lastdnptr = &dnptrs[255];

	do {
		/* Consume the COMMA token if peeked. */
		if (token == COMMA)
			skip_token(&val, NULL, cfile);

		/* Get next (or first) value. */
		token = next_token(&val, &len, cfile);

		if (token != STRING) {
			parse_warn(cfile, "Expecting a domain string.");
			return NULL;
		}

		/* If compression pointers are enabled, compress.  If not,
		 * just pack the names in series into the buffer.
		 */
		if (compress) {
			result = MRns_name_compress(val, compbuf + clen,
						    sizeof(compbuf) - clen,
						    dnptrs, lastdnptr);

			if (result < 0) {
				parse_warn(cfile, "Error compressing domain "
						  "list: %m");
				return NULL;
			}

			clen += result;
		} else {
			result = MRns_name_pton(val, compbuf + clen,
						sizeof(compbuf) - clen);

			/* result == 1 means the input was fully qualified.
			 * result == 0 means the input wasn't.
			 * result == -1 means bad things.
			 */
			if (result < 0) {
				parse_warn(cfile, "Error assembling domain "
						  "list: %m");
				return NULL;
			}

			/*
			 * We need to figure out how many bytes to increment
			 * our buffer pointer since pton doesn't tell us.
			 */
			while (compbuf[clen] != 0)
				clen += compbuf[clen] + 1;

			/* Count the last label (0). */
			clen++;
		}

		if (clen > sizeof(compbuf))
			parse_error(cfile, "Impossible error at %s:%d", MDL);

		token = peek_token(&val, NULL, cfile);
	} while (token == COMMA);

	if (!make_const_data(&t, compbuf, clen, 1, 1, MDL))
		parse_error(cfile, "No memory for domain list object.");

	return t;
}

/* From omapi/convert.c */

static uint32_t
getULong(const unsigned char *buf)
{
	uint32_t ibuf;

	memcpy(&ibuf, buf, sizeof(uint32_t));
	return ntohl(ibuf);
}

static int32_t
getLong(const unsigned char *buf)
{
	int32_t ibuf;

	memcpy(&ibuf, buf, sizeof(int32_t));
	return ntohl(ibuf);
}

static uint32_t
getUShort(const unsigned char *buf)
{
	unsigned short ibuf;

	memcpy(&ibuf, buf, sizeof(uint16_t));
	return ntohs(ibuf);
}

static int32_t
getShort(const unsigned char *buf)
{
	short ibuf;

	memcpy(&ibuf, buf, sizeof(int16_t));
	return ntohs(ibuf);
}

static void
putULong(unsigned char *obuf, uint32_t val)
{
	uint32_t tmp = htonl(val);
	memcpy(obuf, &tmp, sizeof(tmp));
}

static void
putLong(unsigned char *obuf, int32_t val)
{
	int32_t tmp = htonl(val);
	memcpy(obuf, &tmp, sizeof(tmp));
}

static void
putUShort(unsigned char *obuf, uint32_t val)
{
	uint16_t tmp = htons(val);
	memcpy(obuf, &tmp, sizeof(tmp));
}

static void
putShort(unsigned char *obuf, int32_t val)
{
	int16_t tmp = htons(val);
	memcpy(obuf, &tmp, sizeof(tmp));
}

static void
putUChar(unsigned char *obuf, uint32_t val)
{
	*obuf = val;
}

static uint32_t
getUChar(const unsigned char *obuf)
{
	return obuf[0];
}

/* From common/tree.c */

static isc_boolean_t
is_boolean_expression(struct element *expr)
{
	return (mapContains(expr, "check") ||
		mapContains(expr, "exists") ||
		mapContains(expr, "variable-exists") ||
		mapContains(expr, "equal") ||
		mapContains(expr, "not-equal") ||
		mapContains(expr, "regex-match") ||
		mapContains(expr, "iregex-match") ||
		mapContains(expr, "and") ||
		mapContains(expr, "or") ||
		mapContains(expr, "not") ||
		mapContains(expr, "known") ||
		mapContains(expr, "static"));
}

static isc_boolean_t
is_data_expression(struct expression *expr)
{
	return (mapContains(expr, "substring") ||
		mapContains(expr, "suffix") ||
		mapContains(expr, "lcase") ||
		mapContains(expr, "ucase") ||
		mapContains(expr, "option") ||
		mapContains(expr, "hardware") ||
		mapContains(expr, "const-data") ||
		mapContains(expr, "packet") ||
		mapContains(expr, "concat") ||
		mapContains(expr, "encapsulate") ||
		mapContains(expr, "encode-int8") ||
		mapContains(expr, "encode-int16") ||
		mapContains(expr, "encode-int32") ||
		mapContains(expr, "host-lookup") ||
		mapContains(expr, "binary-to-ascii") ||
		mapContains(expr, "filename") ||
		mapContains(expr, "sname") ||
		mapContains(expr, "reverse") ||
		mapContains(expr, "pick-first-value") ||
		mapContains(expr, "host-decl-name") ||
		mapContains(expr, "leased-address") ||
		mapContains(expr, "config-option") ||
		mapContains(expr, "null") ||
		mapContains(expr, "gethostname") ||
	        mapContains(expr, "v6relay"));
}

static isc_boolean_t
is_numeric_expression(struct expression *expr)
{
	return (mapContains(expr, "extract-int8") ||
		mapContains(expr, "extract-int16") ||
		mapContains(expr, "extract-int32") ||
		mapContains(expr, "const-int") ||
		mapContains(expr, "lease-time") ||
		mapContains(expr, "add") ||
		mapContains(expr, "subtract") ||
		mapContains(expr, "multiply") ||
		mapContains(expr, "divide") ||
		mapContains(expr, "remainder") ||
		mapContains(expr, "binary-and") ||
		mapContains(expr, "binary-or") ||
		mapContains(expr, "binary-xor") ||
		mapContains(expr, "client-state"));
}

static isc_boolean_t
is_compound_expression(struct element *expr)
{
	return (mapContains(expr, "substring") ||
		mapContains(expr, "suffix") ||
		mapContains(expr, "option") ||
		mapContains(expr, "concat") ||
		mapContains(expr, "encode-int8") ||
		mapContains(expr, "encode-int16") ||
		mapContains(expr, "encode-int32") ||
		mapContains(expr, "binary-to-ascii") ||
		mapContains(expr, "reverse") ||
		mapContains(expr, "pick-first-value") ||
		mapContains(expr, "config-option") ||
		mapContains(expr, "extract-int8") ||
		mapContains(expr, "extract-int16") ||
		mapContains(expr, "extract-int32") ||
		mapContains(expr, "v6relay"));
}

