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
#include <stdlib.h>
#include <string.h>

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

char *
parse_host_name(struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	unsigned len = 0;
	char *s;
	char *t;
	pair c = NULL;
	int ltid = 0;
	
	/* Read a dotted hostname... */
	do {
		/* Read a token, which should be an identifier. */
		token = peek_token(&val, NULL, cfile);
		if (!is_identifier(token) && token != NUMBER)
			break;
		skip_token(&val, NULL, cfile);

		/* Store this identifier... */
		if (!(s = (char *)malloc(strlen(val) + 1)))
			parse_error(cfile,
				    "can't allocate temp space for hostname.");
		strcpy(s, val);
		c = cons((caddr_t)s, c);
		len += strlen(s) + 1;
		/* Look for a dot; if it's there, keep going, otherwise
		   we're done. */
		token = peek_token(&val, NULL, cfile);
		if (token == DOT) {
			token = next_token(&val, NULL, cfile);
			ltid = 1;
		} else
			ltid = 0;
	} while (token == DOT);

	/* Should be at least one token. */
	if (!len)
		return NULL;

	/* Assemble the hostname together into a string. */
	if (!(s = (char *)malloc(len + ltid)))
		parse_error(cfile, "can't allocate space for hostname.");
	t = s + len + ltid;
	*--t = 0;
	if (ltid)
		*--t = '.';
	while (c) {
		pair cdr = c->cdr;
		unsigned l = strlen((char *)(c->car));
		t -= l;
		memcpy(t, (char *)(c->car), l);
		/* Free up temp space. */
		free(c->car);
		free(c);
		c = cdr;
		if (t != s)
			*--t = '.';
	}
	return s;
}

/* ip-addr-or-hostname :== ip-address | hostname
   ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
   
   Parse an ip address or a hostname.   If uniform is zero, put in
   an expr_substring node to limit hostnames that evaluate to more
   than one IP address.

   Note that RFC1123 permits hostnames to consist of all digits,
   making it difficult to quickly disambiguate them from ip addresses.
*/

isc_boolean_t
parse_ip_addr_or_hostname(struct expression **expr, struct parse *cfile,
			  int uniform)
{
	const char *val;
	enum dhcp_token token;
	unsigned char addr[4];
	unsigned len = sizeof(addr);
	char *name;
	struct expression *x = NULL;
	isc_boolean_t ipaddr = ISC_FALSE;

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
			ipaddr = ISC_TRUE;
		restore_parse_state(cfile);

		if (ipaddr &&
		    parse_numeric_aggregate(cfile, addr, &len, DOT, 10, 8))
			return make_const_data(expr, addr, len, 0, 1, MDL);

	}

	if (is_identifier(token) || token == NUMBER) {
		name = parse_host_name(cfile);
		if (!name)
			return ISC_FALSE;
		if (!make_host_lookup(expr, name)) {
			free(name);
			return ISC_FALSE;
		}
		free(name);
		if (!uniform) {
			if (!make_limit(&x, *expr, 4))
				return ISC_FALSE;
			expression_dereference(expr, MDL);
			*expr = x;
		}
	} else {
		if (token != RBRACE && token != LBRACE)
			token = next_token(&val, NULL, cfile);
		parse_error(cfile, "%s (%d): expecting IP address or hostname",
			    val, token);
	}

	return ISC_TRUE;
}
	
/*
 * ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
 */

isc_boolean_t
parse_ip_addr(struct parse *cfile, struct iaddr *addr)
{
	addr->len = 4;
	if (parse_numeric_aggregate(cfile, addr->iabuf,
				    &addr->len, DOT, 10, 8))
		return ISC_TRUE;
	return ISC_FALSE;
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

void
parse_ip6_addr(struct parse *cfile, struct iaddr *addr)
{
	enum dhcp_token token;
	const char *val;
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
	if (inet_pton(AF_INET6, v6, addr->iabuf) <= 0)
		parse_error(cfile, "Invalid IPv6 address.");
	addr->len = 16;
}

/*
 * Same as parse_ip6_addr() above, but returns the value in the 
 * expression rather than in an address structure.
 */
int
parse_ip6_addr_expr(struct expression **expr, struct parse *cfile)
{
	struct iaddr addr;

	parse_ip6_addr(cfile, &addr);
	return make_const_data(expr, addr.iabuf, addr.len, 0, 1, MDL);
}

/*
 * ip6-prefix :== ip6-address "/" NUMBER
 */
void
parse_ip6_prefix(struct parse *cfile, struct iaddr *addr, uint8_t *plen)
{
	enum dhcp_token token;
	const char *val;
	int n;

	parse_ip6_addr(cfile, addr);
	token = next_token(&val, NULL, cfile);
	if (token != SLASH)
		parse_error(cfile, "Slash expected.");
	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "Number expected.");
	n = atoi(val);
	if ((n < 0) || (n > 128))
		parse_error(cfile, "Invalid IPv6 prefix length.");
	if (!is_cidr_mask_valid(addr, n))
		parse_error(cfile, "network mask too short.");
	*plen = n;
}

/*
 * ip-address-with-subnet :== ip-address |
 *                          ip-address "/" NUMBER
 */

void
parse_ip_addr_with_subnet(struct parse *cfile, struct iaddrmatch *match)
{
	const char *val, *orig;
	enum dhcp_token token;
	int prefixlen;
	int fflen;
	unsigned char newval, warnmask = 0;

	parse_ip_addr(cfile, &match->addr);
	/* default to host mask */
	prefixlen = match->addr.len * 8;

	token = peek_token(&val, NULL, cfile);

	if (token == SLASH) {
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);

		if (token != NUMBER)
			parse_error(cfile, "Invalid CIDR prefix length:"
				    " expecting a number.");

		prefixlen = atoi(val);

		if (prefixlen < 0 || prefixlen > (match->addr.len * 8))
			parse_error(cfile, "subnet prefix is out of "
				    "range [0..%d].",
				    match->addr.len * 8);

	}

	/* construct a suitable mask field */

	/* copy length */
	match->mask.len = match->addr.len;

	/* count of 0xff bytes in mask */
	fflen = prefixlen / 8;

	/* set leading mask */
	memset(match->mask.iabuf, 0xff, fflen);

	/* set zeroes */
	if (fflen < match->mask.len) {
		match->mask.iabuf[fflen] =
			"\x00\x80\xc0\xe0\xf0\xf8\xfc\xfe"[prefixlen % 8];

		memset(match->mask.iabuf+fflen+1, 0x00, 
		       match->mask.len - fflen - 1);

		/* AND-out insignificant bits from supplied netmask. */
		orig = piaddr(match->addr);
		do {
			newval = match->addr.iabuf[fflen] &
				match->mask.iabuf[fflen];

			if (newval != match->addr.iabuf[fflen]) {
				warnmask = 1;
				match->addr.iabuf[fflen] = newval;
			}
		} while (++fflen < match->mask.len);

		if (warnmask)
			parse_error("Warning: Extraneous bits removed "
				    "in address component of %s/%d.",
				    orig, prefixlen);
	}
}

/*
 * hardware-parameter :== HARDWARE hardware-type colon-separated-hex-list SEMI
 * hardware-type :== ETHERNET | TOKEN_RING | TOKEN_FDDI | INFINIBAND
 * Note that INFINIBAND may not be useful for some items, such as classification
 * as the hardware address won't always be available.
 */

void
parse_hardware_param(struct parse *cfile, struct hardware *hardware)
{
	const char *val;
	enum dhcp_token token;
	unsigned hlen;
	unsigned char *t;

	token = next_token(&val, NULL, cfile);
	switch (token) {
	case ETHERNET:
		hardware->hbuf[0] = HTYPE_ETHER;
		break;
	case TOKEN_RING:
		hardware->hbuf[0] = HTYPE_IEEE802;
		break;
	case TOKEN_FDDI:
		hardware->hbuf[0] = HTYPE_FDDI;
		break;
	case TOKEN_INFINIBAND:
		hardware->hbuf[0] = HTYPE_INFINIBAND;
		break;
	default:
		if (!strncmp(val, "unknown-", 8)) {
			hardware->hbuf[0] = atoi(&val[8]);
		} else {
			parse_error(cfile,
				    "expecting a network hardware type");
		}
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
	if (token == SEMI) {
		hardware->hlen = 1;
		goto out;
	}
	t = parse_numeric_aggregate(cfile, NULL, &hlen, COLON, 16, 8);
	if (t == NULL) {
		hardware->hlen = 1;
		return;
	}
	if (hlen + 1 > sizeof(hardware->hbuf)) {
		parse_error(cfile, "hardware address too long");
	} else {
		hardware->hlen = hlen + 1;
		memcpy((unsigned char *)&hardware->hbuf[1], t, hlen);
		if (hlen + 1 < sizeof(hardware->hbuf))
			memset(&hardware->hbuf[hlen + 1], 0,
			       (sizeof(hardware->hbuf)) - hlen - 1);
		free(t);
	}
	
    out:
	token = next_token(&val, NULL, cfile);
	if (token != SEMI)
		parse_error(cfile, "expecting semicolon.");
}

/* lease-time :== NUMBER SEMI */

void
parse_lease_time(struct parse *cfile, time_t *timep)
{
	const char *val;
	enum dhcp_token token;
	uint32_t num;

	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "Expecting numeric lease time");
	convert_num(cfile, (unsigned char *)&num, val, 10, 32);
	/* Unswap the number - convert_num returns stuff in NBO. */
	*timep = ntohl(num);

	parse_semi(cfile);
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

   returns NULL on errors or a pointer to the value string on success.
   The pointer will either be buf if it was non-NULL or newly allocated
   space if buf was NULL
 */


unsigned char *
parse_numeric_aggregate(struct parse *cfile, unsigned char *buf,
			unsigned *max, int separator,
			int base, unsigned size)
{
	const char *val;
	enum dhcp_token token;
	unsigned char *bufp = buf, *s, *t;
	unsigned count = 0;
	pair c = NULL;

	if (!bufp && *max) {
		bufp = (unsigned char *)malloc(*max * size / 8);
		if (!bufp)
			parse_error(cfile, "no space for numeric aggregate");
	}
	s = bufp;

	do {
		if (count) {
			token = peek_token(&val, NULL, cfile);
			if (token != separator) {
				if (!*max)
					break;
				if (token != RBRACE && token != LBRACE)
					token = next_token(&val,
							   NULL,
							   cfile);
				parse_error(cfile, "too few numbers.");
			}
			skip_token(&val, NULL, cfile);
		}
		token = next_token(&val, NULL, cfile);

		if (token == END_OF_FILE)
			parse_error(cfile, "unexpected end of file");

		/* Allow NUMBER_OR_NAME if base is 16. */
		if (token != NUMBER &&
		    (base != 16 || token != NUMBER_OR_NAME)) {
			parse_error(cfile, "expecting numeric value.");
			skip_to_semi(cfile);
		}
		/* If we can, convert the number now; otherwise, build
		   a linked list of all the numbers. */
		if (s) {
			convert_num (cfile, s, val, base, size);
			s += size / 8;
		} else {
			t = (unsigned char *)malloc(strlen(val) + 1);
			if (!t)
				parse_error(cfile,
					    "no temp space for number.");
			strcpy((char *)t, val);
			c = cons((caddr_t)t, c);
		}
	} while (++count != *max);

	/* If we had to cons up a list, convert it now. */
	if (c) {
		/*
		 * No need to cleanup bufp, to get here we didn't allocate
		 * bufp above
		 */
		bufp = (unsigned char *)malloc(count * size / 8);
		if (!bufp)
			parse_error(cfile, "no space for numeric aggregate.");
		s = bufp + count - size / 8;
		*max = count;
	}
	while (c) {
		pair cdr = c->cdr;
		convert_num(cfile, s, (char *)(c->car), base, size);
		s -= size / 8;
		/* Free up temp space. */
		free(c->car);
		free(c);
		c = cdr;
	}
	return bufp;
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
			parse_errro(cfile,
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
			putShort (buf, -(long)val);
			break;
		case 32:
			putLong (buf, -(long)val);
			break;
		default:
			parse_warn (cfile,
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
 * date :== NUMBER NUMBER SLASH NUMBER SLASH NUMBER 
 *		NUMBER COLON NUMBER COLON NUMBER |
 *          NUMBER NUMBER SLASH NUMBER SLASH NUMBER 
 *		NUMBER COLON NUMBER COLON NUMBER NUMBER |
 *          EPOCH NUMBER |
 *	    NEVER
 *
 * Dates are stored in UTC or with a timezone offset; first number is day
 * of week; next is year/month/day; next is hours:minutes:seconds on a
 * 24-hour clock, followed by the timezone offset in seconds, which is
 * optional.
 */

/*
 * just parse the date
 * any trailing semi must be consumed by the caller of this routine
 */
time_t 
parse_date_core(struct parse *cfile)
{
	int guess;
	int tzoff, year, mon, mday, hour, min, sec;
	const char *val;
	enum dhcp_token token;
	static int months[11] = { 31, 59, 90, 120, 151, 181,
				  212, 243, 273, 304, 334 };

	/* "never", "epoch" or day of week */
	token = peek_token(&val, NULL, cfile);
	if (token == NEVER) {
		skip_token(&val, NULL, cfile); /* consume NEVER */
		return(MAX_TIME);
	}

	/* This indicates 'local' time format. */
	if (token == EPOCH) {
		skip_token(&val, NULL, cfile); /* consume EPOCH */
		token = peek_token(&val, NULL, cfile);

		if (token != NUMBER) {
			if (token != SEMI)
				skip_token(&val, NULL, cfile);
			parse_error(cfile, "Seconds since epoch expected.");
		}

		skip_token(&val, NULL, cfile); /* consume number */
		guess = atoi(val);

		return((time_t)guess);
	}

	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric day of week expected.");
	}
	skip_token(&val, NULL, cfile); /* consume day of week */
        /* we are not using this for anything */

	/* Year... */
	token = peek_token(&val, NULL, cfile);
	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric year expected.");
	}
	skip_token(&val, NULL, cfile); /* consume year */

	/* Note: the following is not a Y2K bug - it's a Y1.9K bug.   Until
	   somebody invents a time machine, I think we can safely disregard
	   it.   This actually works around a stupid Y2K bug that was present
	   in a very early beta release of dhcpd. */
	year = atoi(val);
	if (year > 1900)
		year -= 1900;

	/* Slash separating year from month... */
	token = peek_token(&val, NULL, cfile);
	if (token != SLASH) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile,
			    "expected slash separating year from month.");
	}
	skip_token(&val, NULL, cfile); /* consume SLASH */

	/* Month... */
	token = peek_token(&val, NULL, cfile);
	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric month expected.");
	}
	skip_token(&val, NULL, cfile); /* consume month */	
	mon = atoi(val) - 1;

	/* Slash separating month from day... */
	token = peek_token(&val, NULL, cfile);
	if (token != SLASH) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile,
			    "expected slash separating month from day.");
	}
	skip_token(&val, NULL, cfile); /* consume SLASH */

	/* Day of month... */
	token = peek_token(&val, NULL, cfile);
	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric day of month expected.");
	}
	skip_token(&val, NULL, cfile); /* consume day of month */
	mday = atoi(val);

	/* Hour... */
	token = peek_token(&val, NULL, cfile);
	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric hour expected.");
	}
	skip_token(&val, NULL, cfile); /* consume hour */
	hour = atoi(val);

	/* Colon separating hour from minute... */
	token = peek_token(&val, NULL, cfile);
	if (token != COLON) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile,
			    "expected colon separating hour from minute.");
	}
	skip_token(&val, NULL, cfile); /* consume colon */

	/* Minute... */
	token = peek_token(&val, NULL, cfile);
	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric minute expected.");
	}
	skip_token(&val, NULL, cfile); /* consume minute */
	min = atoi(val);

	/* Colon separating minute from second... */
	token = peek_token(&val, NULL, cfile);
	if (token != COLON) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile,
			    "expected colon separating minute from second.");
	}
	skip_token(&val, NULL, cfile); /* consume colon */

	/* Second... */
	token = peek_token(&val, NULL, cfile);
	if (token != NUMBER) {
		if (token != SEMI)
			skip_token(&val, NULL, cfile);
		parse_error(cfile, "numeric second expected.");
	}
	skip_token(&val, NULL, cfile); /* consume second */
	sec = atoi(val);

	tzoff = 0;
	token = peek_token(&val, NULL, cfile);
	if (token == NUMBER) {
		skip_token(&val, NULL, cfile); /* consume tzoff */
		tzoff = atoi(val);
	} else if (token != SEMI) {
		skip_token(&val, NULL, cfile);
		parse_error(cfile,
			    "Time zone offset or semicolon expected.");
	}

	/* If the year is 2038 or greater return the max time to avoid
	 * overflow issues.  We could try and be more precise but there
	 * doesn't seem to be a good reason to worry about it and waste
	 * the cpu looking at the rest of the date. */
	if (year >= 138)
		return(MAX_time_t);

	/* Guess the time value... */
	guess = ((((((365 * (year - 70) +	/* Days in years since '70 */
		      (year - 69) / 4 +		/* Leap days since '70 */
		      (mon			/* Days in months this year */
		       ? months[mon - 1]
		       : 0) +
		      (mon > 1 &&		/* Leap day this year */
		       !((year - 72) & 3)) +
		      mday - 1) * 24) +		/* Day of month */
		    hour) * 60) +
		  min) * 60) + sec + tzoff;

	/* This guess could be wrong because of leap seconds or other
	   weirdness we don't know about that the system does.   For
	   now, we're just going to accept the guess, but at some point
	   it might be nice to do a successive approximation here to
	   get an exact value.   Even if the error is small, if the
	   server is restarted frequently (and thus the lease database
	   is reread), the error could accumulate into something
	   significant. */

	return((time_t)guess);
}

/*
 * Wrapper to consume the semicolon after the date
 * :== date semi
 */

time_t 
parse_date(struct parse *cfile)
{
       time_t guess;
       guess = parse_date_core(cfile);

       /* Make sure the date ends in a semicolon... */
       parse_semi(cfile);
       return(guess);
}

/*
 * option-name :== IDENTIFIER |
 		   IDENTIFIER . IDENTIFIER
 */

void
parse_option_name(struct parse *cfile, int allocate,
		  int *known, struct option **opt)
{
	const char *val;
	enum dhcp_token token;
	char *uname;
	struct universe *universe;
	struct option *option;
	unsigned code;

	if (opt == NULL)
		parse_error(cfile, "invalid argument (opt==NULL)");

	token = next_token(&val, NULL, cfile);
	if (!is_identifier(token))
		parse_error(cfile,
			    "expecting identifier after option keyword.");
	uname = (char *)malloc(strlen(val) + 1);
	if (!uname)
		parse_error(cfile, "no memory for uname information.");
	strcpy(uname, val);
	token = peek_token(&val, NULL, cfile);
	if (token == DOT) {
		/* Go ahead and take the DOT token... */
		skip_token(&val, NULL, cfile);

		/* The next token should be an identifier... */
		token = next_token(&val, NULL, cfile);
		if (!is_identifier(token))
			parse_error(cfile, "expecting identifier after '.'");

		/* Look up the option name hash table for the specified
		   uname. */
		universe = NULL;
		if (!universe_hash_lookup(&universe, universe_hash,
					  uname, 0, MDL))
			parse_error(cfile, "no option space named %s.", uname);
	} else {
		/* Use the default hash table, which contains all the
		   standard dhcp option names. */
		val = uname;
		universe = &dhcp_universe;
	}

	/* Look up the actual option info... */
	option_name_hash_lookup(opt, universe->name_hash, val, 0, MDL);
	option = *opt;

	/* If we didn't get an option structure, it's an undefined option. */
	if (option) {
		if (known)
			*known = 1;
	/* If the option name is of the form unknown-[decimal], use
	 * the trailing decimal value to find the option definition.
	 * If there is no definition, construct one.  This is to
	 * support legacy use of unknown options in config files or
	 * lease databases.
	 */
	} else if (strncasecmp(val, "unknown-", 8) == 0) {
		code = atoi(val+8);

		/* Option code 0 is always illegal for us, thanks
		 * to the option decoder.
		 */
		if (code == 0 || code == universe->end)
			parse_error(cfile, "Option codes 0 and %u are illegal "
				    "in the %s space.", universe->end,
				    universe->name);

		/* It's odd to think of unknown option codes as
		 * being known, but this means we know what the
		 * parsed name is talking about.
		 */
		if (known)
			*known = 1;

		option_code_hash_lookup(opt, universe->code_hash,
					&code, 0, MDL);
		option = *opt;

		/* If we did not find an option of that code,
		 * manufacture an unknown-xxx option definition.
		 * Its single reference will ensure that it is
		 * deleted once the option is recycled out of
		 * existence (by the parent).
		 */
		if (option == NULL) {
			option = new_option(val, MDL);
			option->universe = universe;
			option->code = code;
			option->format = default_option_format;
			option_reference(opt, option, MDL);
		} else
			log_info("option %s has been redefined as option %s.  "
				 "Please update your configs if neccessary.",
				 val, option->name);
	/* If we've been told to allocate, that means that this
	 * (might) be an option code definition, so we'll create
	 * an option structure and return it for the parent to
	 * decide.
	 */
	} else if (allocate) {
		option = new_option(val, MDL);
		option->universe = universe;
		option_reference(opt, option, MDL);
	} else {
		parse_error(cfile, "no option named %s in space %s",
			    val, universe->name);
	}

	/* Free the initial identifier token. */
	free(uname);
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
	struct universe **ua, *nu;
	char *nu_name;
	int tsize = 1, lsize = 1, hsize = 0;

	skip_token(&val, NULL, cfile);  /* Discard the SPACE token,
						     which was checked by the
						     caller. */
	token = next_token(&val, NULL, cfile);
	if (!is_identifier(token))
		parse_error(cfile, "expecting identifier.");
	nu = new_universe(MDL);
	if (!nu)
		parse_error(cfile, "No memory for new option space.");

	/* Set up the server option universe... */
	nu_name = malloc(strlen(val) + 1);
	if (!nu_name)
		parse_error(cfile, "No memory for new option space name.");
	strcpy(nu_name, val);
	nu->name = nu_name;

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

			switch (tsize) {
			case 1:
				if (!hsize)
					hsize = BYTE_NAME_HASH_SIZE;
				break;
			case 2:
				if (!hsize)
					hsize = WORD_NAME_HASH_SIZE;
				break;
			case 4:
				if (!hsize)
					hsize = QUAD_NAME_HASH_SIZE;
				break;
			default:
				parse_error(cfile, "invalid code width (%d), "
					    "expecting a 1, 2 or 4.", tsize);
			}
			break;

		case LENGTH:
			token = next_token(&val, NULL, cfile);
			if (token != WIDTH)
				parse_error(cfile, "expecting width token.");

			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile, "expecting number 1 or 2.");

			lsize = atoi(val);
			if (lsize != 1 && lsize != 2)
				parse_error(cfile, "invalid length width (%d) "
					    "expecting 1 or 2.", lsize);
			break;

		case HASH:
			token = next_token(&val, NULL, cfile);
			if (token != SIZE)
				parse_error(cfile, "expecting size token.");

			token = next_token(&val, NULL, cfile);
			if (token != NUMBER)
				parse_error(cfile,
					    "expecting a 10base number");

			/* (2^31)-1 is the highest Mersenne prime we should
			 * probably allow...
			 */
			hsize = atoi(val);
			if (hsize < 0 || hsize > 0x7FFFFFFF)
				parse_error(cfile, "invalid hash length: %d",
					    hsize);
			break;

		default:
			parse_error(cfile, "Unexpected token.");
		}
	} while (token != SEMI);

	if (!hsize)
		hsize = DEFAULT_SPACE_HASH_SIZE;

	nu->lookup_func = lookup_hashed_option;
	nu->option_state_dereference = hashed_option_state_dereference;
	nu->foreach = hashed_option_space_foreach;
	nu->save_func = save_hashed_option;
	nu->delete_func = delete_hashed_option;
	nu->encapsulate = hashed_option_space_encapsulate;
	nu->decode = parse_option_buffer;
	nu->length_size = lsize;
	nu->tag_size = tsize;
	switch (tsize) {
	case 1:
		nu->get_tag = getUChar;
		nu->store_tag = putUChar;
		break;
	case 2:
		nu->get_tag = getUShort;
		nu->store_tag = putUShort;
		break;
	case 4:
		nu->get_tag = getULong;
		nu->store_tag = putULong;
		break;
	default:
		parse_error(cfile, "Impossible condition.");
	}
	switch (lsize) {
	case 0:
		nu->get_length = NULL;
		nu->store_length = NULL;
		break;
	case 1:
		nu->get_length = getUChar;
		nu->store_length = putUChar;
		break;
	case 2:
		nu->get_length = getUShort;
		nu->store_length = putUShort;
		break;
	default:
		parse_error(cfile, "Impossible condition.");
	}
	nu->index = universe_count++;
	if (nu->index >= universe_max) {
		ua = malloc(universe_max * 2 * sizeof(*ua));
		if (!ua)
			parse_error(cfile,
				    "No memory to expand option space array.");
		memcpy(ua, universes, universe_max * sizeof *ua);
		universe_max *= 2;
		free(universes);
		universes = ua;
	}
	universes[nu->index] = nu;
	if (!option_name_new_hash(&nu->name_hash, hsize, MDL) ||
	    !option_code_new_hash(&nu->code_hash, hsize, MDL))
		parse_error(cfile, "Can't allocate %s option hash table.",
			    nu->name);
	universe_hash_add(universe_hash, nu->name, 0, nu, MDL);
	return;
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

int
parse_option_code_definition(struct parse *cfile, struct option *option)
{
	const char *val;
	enum dhcp_token token;
	struct option *oldopt;
	unsigned arrayp = 0;
	int recordp = 0;
	int no_more_in_record = 0;
	char tokbuf[128];
	unsigned tokix = 0;
	char type;
	int is_signed;
	char *s;
	int has_encapsulation = 0;
	struct universe *encapsulated;
	
	/* Parse the option code. */
	token = next_token(&val, NULL, cfile);
	if (token != NUMBER)
		parse_error(cfile, "expecting option code number.");
	option->code = atoi(val);

	token = next_token(&val, NULL, cfile);
	if (token != EQUAL)
		parse_error(cfile, "expecting \"=\"");

	/* See if this is an array. */
	token = next_token(&val, NULL, cfile);
	if (token == ARRAY) {
		token = next_token(&val, NULL, cfile);
		if (token != OF)
			parse_error(cfile, "expecting \"of\".");
		arrayp = 1;
		token = next_token(&val, NULL, cfile);
	}

	if (token == LBRACE) {
		recordp = 1;
		token = next_token(&val, NULL, cfile);
	}

	/* At this point we're expecting a data type. */
      next_type:
	if (has_encapsulation)
		parse_error(cfile,
			    "encapsulate must always be the last item.");

	switch (token) {
	case ARRAY:
		if (arrayp)
			parse_error(cfile, "no nested arrays.");
		token = next_token(&val, NULL, cfile);
		if (token != OF)
			parse_error(cfile, "expecting \"of\".");
		arrayp = recordp + 1;
		token = next_token(&val, NULL, cfile);
		if ((recordp) && (token == LBRACE))
			parse_error(cfile,
				    "only uniform array inside record.");
		goto next_type;
	case BOOLEAN:
		type = 'f';
		break;
	case INTEGER:
		is_signed = 1;
	parse_integer:
		token = next_token(&val, NULL, cfile);
		if (token != NUMBER)
			parse_error(cfile, "expecting number.");
		switch (atoi(val)) {
		case 8:
			type = is_signed ? 'b' : 'B';
			break;
		case 16:
			type = is_signed ? 's' : 'S';
			break;
		case 32:
			type = is_signed ? 'l' : 'L';
			break;
		default:
			parse_error(cfile,
				    "%s bit precision is not supported.", val);
		}
		break;
	case SIGNED:
		is_signed = 1;
	parse_signed:
		token = next_token(&val, NULL, cfile);
		if (token != INTEGER)
			parse_error(cfile, "expecting \"integer\" keyword.");
		goto parse_integer;
	case UNSIGNED:
		is_signed = 0;
		goto parse_signed;

	case IP_ADDRESS:
		type = 'I';
		break;
	case IP6_ADDRESS:
		type = '6';
		break;
	case DOMAIN_NAME:
		type = 'd';
		goto no_arrays;
	case DOMAIN_LIST:
		/* Consume optional compression indicator. */
		token = peek_token(&val, NULL, cfile);
		if (token == COMPRESSED) {
			skip_token(&val, NULL, cfile);
			tokbuf[tokix++] = 'D';
			type = 'c';
		} else
			type = 'D';
		goto no_arrays;
	case TEXT:
		type = 't';
	no_arrays:
		if (arrayp)
			parse_error(cfile, "arrays of text strings not %s",
				    "yet supported.");
		no_more_in_record = 1;
		break;
	case STRING_TOKEN:
		type = 'X';
		goto no_arrays;

	case ENCAPSULATE:
		token = next_token(&val, NULL, cfile);
		if (!is_identifier(token))
			parse_error(cfile,
				    "expecting option space identifier");
		encapsulated = NULL;
		if (!universe_hash_lookup(&encapsulated, universe_hash,
					  val, strlen(val), MDL))
			parse_error(cfile, "unknown option space %s", val);
		if (strlen (val) + tokix + 2 > sizeof (tokbuf))
			goto toobig;
		tokbuf[tokix++] = 'E';
		strcpy(&tokbuf[tokix], val);
		tokix += strlen (val);
		type = '.';
		has_encapsulation = 1;
		break;

	case ZEROLEN:
		type = 'Z';
		if (arrayp)
			parse_error(cfile, "array incompatible with zerolen.");
		no_more_in_record = 1;
		break;

	default:
		parse_error(cfile, "unknown data type %s", val);
	}

	if (tokix == sizeof tokbuf) {
	    toobig:
		parse_error(cfile, "too many types in record.");
	}
	tokbuf[tokix++] = type;

	if (recordp) {
		token = next_token(&val, NULL, cfile);
		if (arrayp > recordp) {
			if (tokix == sizeof tokbuf)
				parse_error(cfile,
					    "too many types in record.");
			arrayp = 0;
			tokbuf[tokix++] = 'a';
		}
		if (token == COMMA) {
			if (no_more_in_record)
				parse_error(cfile,
					    "%s must be at end of record.",
					    type == 't' ? "text" : "string");
			token = next_token(&val, NULL, cfile);
			goto next_type;
		}
		if (token != RBRACE)
			parse_error(cfile, "expecting right brace.");
	}
	parse_semi(cfile);
	if (has_encapsulation && arrayp)
		parse_error(cfile,
			    "Arrays of encapsulations don't make sense.");
	s = malloc(tokix + (arrayp ? 1 : 0) + 1);
	if (s == NULL)
		parse_error(cfile, "no memory for option format.");
	memcpy(s, tokbuf, tokix);
	if (arrayp) {
		s[tokix++] = (arrayp > recordp) ? 'a' : 'A';
	}
	s[tokix] = '\0';

	option->format = s;

	oldopt = NULL;
	option_code_hash_lookup(&oldopt, option->universe->code_hash,
				&option->code, 0, MDL);
	if (oldopt != NULL) {
		/*
		 * XXX: This illegalizes a configuration syntax that was
		 * valid in 3.0.x, where multiple name->code mappings are
		 * given, but only one code->name mapping survives.  It is
		 * unclear what can or should be done at this point, but it
		 * seems best to retain 3.0.x behaviour for upgrades to go
		 * smoothly.
		 *
		option_name_hash_delete(option->universe->name_hash,
					oldopt->name, 0, MDL);
		 */
		option_code_hash_delete(option->universe->code_hash,
					&oldopt->code, 0, MDL);

		option_dereference(&oldopt, MDL);
	}
	option_code_hash_add(option->universe->code_hash, &option->code, 0,
			     option, MDL);
	option_name_hash_add(option->universe->name_hash, option->name, 0,
			     option, MDL);
	if (has_encapsulation) {
		/* INSIST(tokbuf[0] == 'E'); */
		/* INSIST(encapsulated != NULL); */
		if (!option_code_hash_lookup(&encapsulated->enc_opt,
					     option->universe->code_hash, 
					     &option->code, 0, MDL))
			parse_error(cfile,
				    "error finding encapsulated option)");
	}
	return 1;
}

/*
 * base64 :== NUMBER_OR_STRING
 */

int
parse_base64(struct data_string *data, struct parse *cfile)
{
	const char *val;
	int i, j, k;
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
	struct string_list *bufs = NULL,
			   *last = NULL,
			   *t;
	int cc = 0;
	int terminated = 0;
	int valid_base64;
	
	/* It's possible for a + or a / to cause a base64 quantity to be
	   tokenized into more than one token, so we have to parse them all
	   in before decoding. */
	do {
		unsigned l;

		(void)next_token(&val, &l, cfile);
		t = malloc(l + sizeof(*t));
		if (t == NULL)
			parse_error(cfile, "no memory for base64 buffer.");
		memset(t, 0, (sizeof(*t)) - 1);
		memcpy(t->string, val, l + 1);
		cc += l;
		if (last)
			last->next = t;
		else
			bufs = t;
		last = t;
		(void)peek_token(&val, NULL, cfile);
		valid_base64 = 1;
		for (i = 0; val[i]; i++) {
			/* Check to see if the character is valid.  It
			   may be out of range or within the right range
			   but not used in the mapping */
			if (((val[i] < ' ') || (val[i] > 'z')) ||
			    ((from64[val[i] - ' '] > 63) && (val[i] != '='))) {
				valid_base64 = 0;
				break; /* no need to continue for loop */
			}
		}
	} while (valid_base64);

	data->len = cc;
	data->len = (data->len * 3) / 4;
	if (!buffer_allocate(&data->buffer, data->len, MDL))
		parse_error(cfile, "can't allocate buffer for base64 data.");
		
	j = k = 0;
	for (t = bufs; t; t = t->next) {
	    for (i = 0; t->string[i]; i++) {
		unsigned foo = t->string[i];
		if (terminated && foo != '=')
			parse_error(cfile,
				    "stuff after base64 '=' terminator: %s.",
				    &t->string[i]);
		if ((foo < ' ') || (foo > 'z')) {
		    bad64:
			parse_error(cfile,
				    "invalid base64 character %d.",
				    t->string[i]);
		    bad:
			data_string_forget(data, MDL);
			goto out;
		}
		if (foo == '=')
			terminated = 1;
		else {
			foo = from64[foo - ' '];
			if (foo == 64)
				goto bad64;
			acc = (acc << 6) + foo;
			switch (k % 4) {
			case 0:
				break;
			case 1:
				data->buffer->data[j++] = (acc >> 4);
				acc = acc & 0x0f;
				break;
				
			case 2:
				data->buffer->data[j++] = (acc >> 2);
				acc = acc & 0x03;
				break;
			case 3:
				data->buffer->data[j++] = acc;
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
	data->len = j;
	data->data = data->buffer->data;
    out:
	for (t = bufs; t; t = last) {
		last = t->next;
		free(t);
	}
	if (data->len)
		return 1;
	else
		return 0;
}


/*
 * colon-separated-hex-list :== NUMBER |
 *				NUMBER COLON colon-separated-hex-list
 */

void
parse_cshl(struct data_string *data, struct parse *cfile)
{
	uint8_t ibuf[128];
	unsigned ilen = 0;
	unsigned tlen = 0;
	struct option_tag *sl = NULL;
	struct option_tag *next, **last = &sl;
	enum dhcp_token token;
	const char *val;
	unsigned char *rvp;

	for (;;) {
		token = next_token(&val, NULL, cfile);
		if (token != NUMBER && token != NUMBER_OR_NAME)
			parse_error(cfile, "expecting hexadecimal number.");
		if (ilen == sizeof ibuf) {
			next = (struct option_tag *)
				malloc(ilen - 1 + sizeof(struct option_tag));
			if (!next)
				parse_error(cfile,
					    "no memory for string list.");
			memcpy (next->data, ibuf, ilen);
			*last = next;
			last = &next->next;
			tlen += ilen;
			ilen = 0;
		}
		convert_num(cfile, &ibuf[ilen++], val, 16, 8);

		token = peek_token(&val, NULL, cfile);
		if (token != COLON)
			break;
		skip_token(&val, NULL, cfile);
	}

	if (!buffer_allocate(&data->buffer, tlen + ilen, MDL))
		parse_error(cfile, "no memory to store octet data.");
	data->data = &data->buffer->data[0];
	data->len = tlen + ilen;
	data->terminated = 0;

	rvp = &data->buffer->data[0];
	while (sl) {
		next = sl->next;
		memcpy(rvp, sl->data, sizeof ibuf);
		rvp += sizeof ibuf;
		free(sl);
		sl = next;
	}
	
	memcpy (rvp, ibuf, ilen);
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

int
parse_executable_statements(struct executable_statement **statements,
			    struct parse *cfile, int *lose,
			    enum expression_context case_context)
{
	struct executable_statement **next;

	next = statements;
	while (parse_executable_statement(next, cfile, lose, case_context))
		next = &((*next)->next);
	if (!*lose)
		return 1;
	return 0;
}

int
parse_executable_statement(struct executable_statement **result,
			   struct parse *cfile, int *lose,
			   enum expression_context case_context)
{
	enum dhcp_token token;
	const char *val;
	struct class *cta;
	struct option *option=NULL;
	struct option_cache *cache;
	int known;
	int flag;
	int i;
	struct dns_zone *zone;
	isc_result_t status;
	char *s;

	token = peek_token(&val, NULL, cfile);
	switch (token) {
	case DB_TIME_FORMAT:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token == DEFAULT) {
			db_time_format = DEFAULT_TIME_FORMAT;
		} else if (token == LOCAL) {
			db_time_format = LOCAL_TIME_FORMAT;
		} else
			parse_error(cfile, "Expecting 'local' or 'default'.");

		token = next_token(&val, NULL, cfile);
		if (token != SEMI)
			parse_error(cfile, "Expecting a semicolon.");

		/* We're done here. */
		return 1;

	case IF:
		skip_token(&val, NULL, cfile);
		return parse_if_statement(result, cfile, lose);

	case TOKEN_ADD:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != STRING)
			parse_error(cfile, "expecting class name.");
		cta = NULL;
		status = find_class(&cta, val, MDL);
		if (status != ISC_R_SUCCESS)
			parse_error(cfile, "class %s: %s",
				    val, isc_result_totext (status));
		parse_semi(cfile);
		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for new statement.");
		(*result)->op = add_statement;
		(*result)->data.add = cta;
		break;

	case BREAK:
		skip_token(&val, NULL, cfile);
		parse_semi(cfile);
		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for new statement.");
		(*result)->op = break_statement;
		break;

	case SEND:
		skip_token(&val, NULL, cfile);
		known = 0;
	        parse_option_name(cfile, 0, &known, &option);
		if (option == NULL) {
			*lose = 1;
			return 0;
		}
		status = parse_option_statement(result, cfile, 1, option,
						send_option_statement);
		option_dereference(&option, MDL);
		return status;

	case SUPERSEDE:
	case OPTION:
		skip_token(&val, NULL, cfile);
		known = 0;
		parse_option_name(cfile, 0, &known, &option);
		if (option == NULL) {
			*lose = 1;
			return 0;
		}
		status = parse_option_statement(result, cfile, 1, option,
						supersede_option_statement);
		option_dereference(&option, MDL);
		return status;

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
		cache = NULL;
		if (!parse_allow_deny (&cache, cfile, flag))
			return 0;
		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for new statement.");
		(*result)->op = supersede_option_statement;
		(*result)->data.option = cache;
		break;

	case DEFAULT:
		skip_token(&val, NULL, cfile);
		token = peek_token(&val, NULL, cfile);
		if (token == COLON)
			goto switch_default;
		known = 0;
		parse_option_name(cfile, 0, &known, &option);
		if (option == NULL) {
			*lose = 1;
			return 0;
		}
		status = parse_option_statement(result, cfile, 1, option,
						default_option_statement);
		option_dereference(&option, MDL);
		return status;

	case PREPEND:
		skip_token(&val, NULL, cfile);
		known = 0;
		parse_option_name(cfile, 0, &known, &option);
		if (option == NULL) {
			*lose = 1;
			return 0;
		}
		status = parse_option_statement(result, cfile, 1, option,
						prepend_option_statement);
		option_dereference(&option, MDL);
		return status;

	case APPEND:
		skip_token(&val, NULL, cfile);
		known = 0;
		parse_option_name(cfile, 0, &known, &option);
		if (option == NULL) {
			*lose = 1;
			return 0;
		}
		status = parse_option_statement(result, cfile, 1, option,
						append_option_statement);
		option_dereference(&option, MDL);
		return status;

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
		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for default statement.");
		(*result)->op = default_statement;
		return 1;
			
	case DEFINE:
	case TOKEN_SET:
		skip_token(&val, NULL, cfile);
		if (token == DEFINE)
			flag = 1;
		else
			flag = 0;

		token = next_token(&val, NULL, cfile);
		if (token != NAME && token != NUMBER_OR_NAME) {
			parse_error(cfile,
				    "%s can't be a variable name", val);
		    badset:
			skip_to_semi(cfile);
			*lose = 1;
			return 0;
		}

		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for set statement.");
		(*result)->op = flag ? define_statement : set_statement;
		(*result)->data.set.name = dmalloc (strlen (val) + 1, MDL);
		if (!(*result)->data.set.name)
			parse_error(cfile, "can't allocate variable name");
		strcpy((*result)->data.set.name, val);
		token = next_token(&val, NULL, cfile);

		if (token == LPAREN) {
			struct string_list *head, *cur, *new;
			struct expression *expr;
			head = cur = (struct string_list *)0;
			do {
				token = next_token(&val,
						    NULL, cfile);
				if (token == RPAREN)
					break;
				if (token != NAME && token != NUMBER_OR_NAME)
					parse_error(cfile,
						    "expecting argument name");
				new = ((struct string_list *)
				       malloc(sizeof(struct string_list) +
					      strlen(val)));
				if (!new)
					parse_error(cfile,
						    "can't allocate string.");
				memset(new, 0, sizeof *new);
				strcpy(new->string, val);
				if (cur) {
					cur->next = new;
					cur = new;
				} else {
					head = cur = new;
				}
				token = next_token(&val, NULL, cfile);
			} while (token == COMMA);

			if (token != RPAREN) {
				parse_error(cfile, "expecting right paren.");
			badx:
				skip_to_semi(cfile);
				*lose = 1;
				executable_statement_dereference(result, MDL);
				return 0;
			}

			token = next_token(&val, NULL, cfile);
			if (token != LBRACE)
				parse_error(cfile, "expecting left brace.");

			expr = NULL;
			if (!(expression_allocate(&expr, MDL)))
				parse_error(cfile,
					    "can't allocate expression.");
			expr->op = expr_function;
			if (!fundef_allocate(&expr->data.func, MDL))
				parse_error(cfile, "can't allocate fundef.");
			expr->data.func->args = head;
			(*result)->data.set.expr = expr;

			if (!(parse_executable_statements
			      (&expr->data.func->statements, cfile, lose,
			       case_context))) {
				if (*lose)
					goto badx;
			}

			token = next_token(&val, NULL, cfile);
			if (token != RBRACE)
				parse_error(cfile, "expecting rigt brace.");
		} else {
			if (token != EQUAL)
				parse_error(cfile,
					    "expecting '=' in %s statement.",
					    flag ? "define" : "set");

			if (!parse_expression(&(*result)->data.set.expr,
					      cfile, lose, context_any,
					      NULL, expr_none)) {
				if (!*lose)
					parse_error(cfile,
						    "expecting expression.");
				else
					*lose = 1;
				skip_to_semi(cfile);
				executable_statement_dereference(result, MDL);
				return 0;
			}
			parse_semi(cfile);
		}
		break;

	case UNSET:
		skip_token(&val, NULL, cfile);
		token = next_token(&val, NULL, cfile);
		if (token != NAME && token != NUMBER_OR_NAME)
			parse_error(cfile, "%s can't be a variable name", val);

		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for set statement.");
		(*result)->op = unset_statement;
		(*result)->data.unset = malloc(strlen(val) + 1);
		if (!(*result)->data.unset)
			parse_error(cfile, "can't allocate variable name");
		strcpy((*result)->data.unset, val);
		parse_semi(cfile);
		break;

	case EVAL:
		skip_token(&val, NULL, cfile);
		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for eval statement.");
		(*result)->op = eval_statement;

		if (!parse_expression (&(*result)->data.eval,
				       cfile, lose, context_data, /* XXX */
				       NULL, expr_none)) {
			if (!*lose)
				parse_error(cfile,
					    "expecting data expression.");
			else
				*lose = 1;
			skip_to_semi(cfile);
			executable_statement_dereference(result, MDL);
			return 0;
		}
		parse_semi(cfile);
		break;

	case EXECUTE:
		parse_error(cfile, "define ENABLE_EXECUTE in site.h to "
			    "enable execute(); expressions.");
		break;

	case RETURN:
		skip_token(&val, NULL, cfile);

		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for return statement.");
		(*result)->op = return_statement;

		if (!parse_expression(&(*result)->data.retval,
				      cfile, lose, context_data,
				      NULL, expr_none)) {
			if (!*lose)
				parse_error(cfile,
					    "expecting data expression.");
			else
				*lose = 1;
			skip_to_semi(cfile);
			executable_statement_dereference(result, MDL);
			return 0;
		}
		parse_semi(cfile);
		break;

	case LOG:
		skip_token(&val, NULL, cfile);

		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for log statement.");
		(*result)->op = log_statement;

		token = next_token(&val, NULL, cfile);
		if (token != LPAREN)
			parse_error(cfile, "left parenthesis expected.");

		token = peek_token(&val, NULL, cfile);
		i = 1;
		if (token == FATAL) {
			(*result)->data.log.priority = log_priority_fatal;
		} else if (token == ERROR) {
			(*result)->data.log.priority = log_priority_error;
		} else if (token == TOKEN_DEBUG) {
			(*result)->data.log.priority = log_priority_debug;
		} else if (token == INFO) {
			(*result)->data.log.priority = log_priority_info;
		} else {
			(*result)->data.log.priority = log_priority_debug;
			i = 0;
		}
		if (i) {
			skip_token(&val, NULL, cfile);
			token = next_token(&val, NULL, cfile);
			if (token != COMMA)
				parse_error(cfile, "comma expected.");
		}

		if (!(parse_data_expression
		      (&(*result)->data.log.expr, cfile, lose))) {
			skip_to_semi(cfile);
			*lose = 1;
			return 0;
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

		if (!executable_statement_allocate(result, MDL))
			parse_error(cfile, "no memory for execute statement.");
		(*result)->op = vendor_opt_statement;
		break;

		/* Not really a statement, but we parse it here anyway
		   because it's appropriate for all DHCP agents with
		   parsers. */
	case ZONE:
		skip_token(&val, NULL, cfile);
		zone = (struct dns_zone *)0;
		if (!dns_zone_allocate(&zone, MDL))
			parse_error(cfile, "no memory for new zone.");
		zone->name = parse_host_name (cfile);
		if (!zone->name) {
			parse_error(cfile, "expecting hostname.");
		badzone:
			*lose = 1;
			skip_to_semi(cfile);
			dns_zone_dereference(&zone, MDL);
			return 0;
		}
		i = strlen (zone->name);
		if (zone->name[i - 1] != '.') {
			s = malloc((unsigned)i + 2);
			if (!s)
				parse_error(cfile, "no trailing '.' on zone");
			strcpy(s, zone->name);
			s[i] = '.';
			s[i + 1] = 0;
			free(zone->name);
			zone->name = s;
		}
		if (!parse_zone (zone, cfile))
			goto badzone;
		status = enter_dns_zone (zone);
		if (status != ISC_R_SUCCESS)
			parse_error(cfile, "dns zone key %s: %s",
				    zone->name, isc_result_totext (status));
		dns_zone_dereference(&zone, MDL);
		return 1;
		
		/* Also not really a statement, but same idea as above. */
	case KEY:
		skip_token(&val, NULL, cfile);
		if (!parse_key(cfile)) {
			*lose = 1;
			return 0;
		}
		return 1;

	default:
		if (config_universe && is_identifier(token)) {
			option = (struct option *)0;
			option_name_hash_lookup(&option,
						config_universe->name_hash,
						val, 0, MDL);
			if (option) {
				skip_token(&val, NULL, cfile);
				status = parse_option_statement
						(result, cfile, 1, option,
						 supersede_option_statement);
				option_dereference(&option, MDL);
				return status;
			}
		}

		if (token == NUMBER_OR_NAME || token == NAME) {
			/* This is rather ugly.  Since function calls are
			   data expressions, fake up an eval statement. */
			if (!executable_statement_allocate(result, MDL))
				parse_error(cfile,
					    "no memory for eval statement.");
			(*result)->op = eval_statement;

			if (!parse_expression(&(*result)->data.eval,
					      cfile, lose, context_data,
					      NULL,
					      expr_none)) {
				if (!*lose)
					parse_error(cfile, "expecting "
						    "function call.");
				else
					*lose = 1;
				skip_to_semi(cfile);
				executable_statement_dereference(result, MDL);
				return 0;
			}
			parse_semi(cfile);
			break;
		}

		*lose = 0;
		return 0;
	}

	return 1;
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

int
parse_zone(struct dns_zone *zone, struct parse *cfile)
{
	int token;
	const char *val;
	char *key_name;
	struct option_cache *oc;
	int done = 0;

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "expecting left brace");

	do {
	    token = peek_token(&val, NULL, cfile);
	    switch (token) {
	    case PRIMARY:
		    if (zone->primary)
			    parse_error(cfile, "more than one primary.");
		    if (!option_cache_allocate(&zone->primary, MDL))
			    parse_error(cfile, "can't allocate primary option cache.");
		    oc = zone->primary;
		    goto consemup;
		    
	    case SECONDARY:
		    if (zone->secondary)
			    parse_error(cfile, "more than one secondary.");
		    if (!option_cache_allocate(&zone->secondary, MDL))
			    parse_error(cfile, "can't allocate secondary.");
		    oc = zone->secondary;
	    consemup:
		    skip_token(&val, NULL, cfile);
		    do {
			    struct expression *expr = NULL;
			    if (!parse_ip_addr_or_hostname (&expr, cfile, 0))
				parse_error(cfile,
					   "expecting IP addr or hostname.");
			    if (oc->expression) {
				    struct expression *old = NULL;
				    expression_reference(&old,
							 oc->expression,
							 MDL);
				    expression_dereference(&oc->expression,
							   MDL);
				    if (!make_concat(&oc->expression,
						     old, expr))
					parse_error(cfile,
						    "no memory for concat.");
				    expression_dereference(&expr, MDL);
				    expression_dereference(&old, MDL);
			    } else {
				    expression_reference(&oc->expression,
							 expr, MDL);
				    expression_dereference(&expr, MDL);
			    }
			    token = next_token(&val, NULL, cfile);
		    } while (token == COMMA);
		    if (token != SEMI)
			    parse_error(cfile, "expecting semicolon.");
		    break;

	    case PRIMARY6:
		    if (zone->primary6)
			    parse_error(cfile, "more than one primary6.");
		    if (!option_cache_allocate(&zone->primary6, MDL))
			    parse_error(cfile, "can't allocate primary6 "
					"option cache.");
		    oc = zone->primary6;
		    goto consemup6;

	    case SECONDARY6:
		    if (zone->secondary6)
			    parse_error(cfile, "more than one secondary6.");
		    if (!option_cache_allocate(&zone->secondary6, MDL))
			    parse_error(cfile, "can't allocate secondary6 "
				      "option cache.");
		    oc = zone->secondary6;
	    consemup6:
		    skip_token(&val, NULL, cfile);
		    do {
			    struct expression *expr = NULL;
			    if (parse_ip6_addr_expr(&expr, cfile) == 0)
				    parsee_rror(cfile, "expecting IPv6 addr.");
			    if (oc->expression) {
				    struct expression *old = NULL;
				    expression_reference(&old, oc->expression,
							 MDL);
				    expression_dereference(&oc->expression,
							   MDL);
				    if (!make_concat(&oc->expression,
						     old, expr))
					    parse_error(cfile, "no memory for concat.");
				    expression_dereference(&expr, MDL);
				    expression_dereference(&old, MDL);
			    } else {
				    expression_reference(&oc->expression,
							 expr, MDL);
				    expression_dereference(&expr, MDL);
			    }
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
			    key_name = NULL;
		    } else {
			    key_name = parse_host_name(cfile);
			    if (!key_name)
				    parse_error(cfile, "expecting key name.");
			    val = key_name;
		    }
		    if (zone->key)
			    parse_error(cfile, "Multiple key definitions "
					"for zone %s.", zone->name);
		    if (omapi_auth_key_lookup_name(&zone->key, val) !=
			ISC_R_SUCCESS)
			    parse_error(cfile, "unknown key %s", val);
		    if (key_name)
			    free(key_name);
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
			 SECRET STRING */

int
parse_key(struct parse *cfile)
{
	int token;
	const char *val;
	int done = 0;
	struct auth_key *key;
	struct data_string ds;
	isc_result_t status;
	char *s;

	key = NULL;
	if (omapi_auth_key_new (&key, MDL) != ISC_R_SUCCESS)
		parse_error(cfile, "no memory for key");

	token = peek_token(&val, NULL, cfile);
	if (token == STRING) {
		skip_token(&val, NULL, cfile);
		key->name = malloc(strlen(val) + 1);
		if (!key->name)
			parse_error(cfile, "no memory for key name.");
		strcpy(key->name, val);

	} else {
		key->name = parse_host_name (cfile);
		if (!key->name)
			parse_error(cfile, "expecting key name.");
	}

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE)
		parse_error(cfile, "expecting left brace");

	do {
		token = next_token(&val, NULL, cfile);
		switch (token) {
		case ALGORITHM:
			if (key->algorithm)
				parse_error(cfile,
					    "key %s: too many algorithms",
					    key->name);
			key->algorithm = parse_host_name(cfile);
			if (!key->algorithm)
				parse_error(cfile,
					    "expecting key algorithm name.");
			parse_semi(cfile);
			/* If the algorithm name isn't an FQDN, tack on
			   the .SIG-ALG.REG.NET. domain. */
			s = strrchr (key->algorithm, '.');
			if (!s) {
			    static char add[] = ".SIG-ALG.REG.INT.";
			    s = malloc(strlen(key->algorithm) + sizeof(add));
			    if (!s)
				    parse_error(cfile,
						"no memory for key %s.",
						"algorithm");
			    strcpy(s, key->algorithm);
			    strcat(s, add);
			    free(key->algorithm);
			    key->algorithm = s;
			} else if (s[1]) {
			    /* If there is no trailing '.', hack one in. */
			    s = malloc(strlen(key->algorithm) + 2);
			    if (!s)
				    parse_error(cfile,
						"no memory for key %s.",
						key->algorithm);
			    strcpy(s, key->algorithm);
			    strcat(s, ".");
			    free(key->algorithm);
			    key->algorithm = s;
			}
			break;

		case SECRET:
			if (key->key)
				parse_error(cfile, "key %s: too many secrets",
					    key->name);

			memset(&ds, 0, sizeof(ds));
			if (!parse_base64(&ds, cfile))
				goto rbad;
			status = omapi_data_string_new(&key->key, ds.len,
						       MDL);
			if (status != ISC_R_SUCCESS)
				goto rbad;
			memcpy(key->key->value,
			       ds.buffer->data, ds.len);
			data_string_forget(&ds, MDL);

			parse_semi(cfile);
			break;

		default:
			done = 1;
			break;
		}
	} while (!done);
	if (token != RBRACE)
		parse_error(cfile, "expecting right brace.");
	/* Allow the BIND 8 syntax, which has a semicolon after each
	   closing brace. */
	token = peek_token(&val, NULL, cfile);
	if (token == SEMI) {
		skip_token(&val, NULL, cfile);
	}

	/* Remember the key. */
	status = omapi_auth_key_enter(key);
	if (status != ISC_R_SUCCESS)
		parse_error(cfile, "tsig key %s: %s",
			    key->name, isc_result_totext (status));
	omapi_auth_key_dereference(&key, MDL);
	return 1;

      rbad:
	skip_to_rbrace(cfile, 1);
      bad:
	omapi_auth_key_dereference(&key, MDL);
	return 0;
}

#if 0
/*
 * on-statement :== event-types LBRACE executable-statements RBRACE
 * event-types :== event-type OR event-types |
 *		   event-type
 * event-type :== EXPIRY | COMMIT | RELEASE
 */

int parse_on_statement (result, cfile, lose)
	struct executable_statement **result;
	struct parse *cfile;
	int *lose;
{
	enum dhcp_token token;
	const char *val;

	if (!executable_statement_allocate(result, MDL))
		parse_error(cfile, "no memory for new statement.");
	(*result)->op = on_statement;

	do {
		token = next_token(&val, NULL, cfile);
		switch (token) {
		      case EXPIRY:
			(*result)->data.on.evtypes |= ON_EXPIRY;
			break;
		
		      case COMMIT:
			(*result)->data.on.evtypes |= ON_COMMIT;
			break;
			
		      case RELEASE:
			(*result)->data.on.evtypes |= ON_RELEASE;
			break;
			
		      case TRANSMISSION:
			(*result)->data.on.evtypes |= ON_TRANSMISSION;
			break;

		      default:
			parse_warn (cfile, "expecting a lease event type");
			skip_to_semi(cfile);
			*lose = 1;
			executable_statement_dereference(result, MDL);
			return 0;
		}
		token = next_token(&val, NULL, cfile);
	} while (token == OR);
		
	/* Semicolon means no statements. */
	if (token == SEMI)
		return 1;

	if (token != LBRACE) {
		parse_warn (cfile, "left brace expected.");
		skip_to_semi(cfile);
		*lose = 1;
		executable_statement_dereference(result, MDL);
		return 0;
	}
	if (!parse_executable_statements (&(*result)->data.on.statements,
					  cfile, lose, context_any)) {
		if (*lose) {
			/* Try to even things up. */
			do {
				token = next_token(&val,
						    NULL, cfile);
			} while (token != END_OF_FILE && token != RBRACE);
			executable_statement_dereference(result, MDL);
			return 0;
		}
	}
	token = next_token(&val, NULL, cfile);
	if (token != RBRACE) {
		parse_warn (cfile, "right brace expected.");
		skip_to_semi(cfile);
		*lose = 1;
		executable_statement_dereference(result, MDL);
		return 0;
	}
	return 1;
}

/*
 * switch-statement :== LPAREN expr RPAREN LBRACE executable-statements RBRACE
 *
 */

int parse_switch_statement (result, cfile, lose)
	struct executable_statement **result;
	struct parse *cfile;
	int *lose;
{
	enum dhcp_token token;
	const char *val;

	if (!executable_statement_allocate(result, MDL))
		parse_error(cfile, "no memory for new statement.");
	(*result)->op = switch_statement;

	token = next_token(&val, NULL, cfile);
	if (token != LPAREN) {
		parse_warn (cfile, "expecting left brace.");
	      pfui:
		*lose = 1;
		skip_to_semi(cfile);
	      gnorf:
		executable_statement_dereference(result, MDL);
		return 0;
	}

	if (!parse_expression (&(*result)->data.s_switch.expr,
			       cfile, lose, context_data_or_numeric,
			       NULL, expr_none)) {
		if (!*lose) {
			parse_warn (cfile,
				    "expecting data or numeric expression.");
			goto pfui;
		}
		goto gnorf;
	}

	token = next_token(&val, NULL, cfile);
	if (token != RPAREN) {
		parse_warn (cfile, "right paren expected.");
		goto pfui;
	}

	token = next_token(&val, NULL, cfile);
	if (token != LBRACE) {
		parse_warn (cfile, "left brace expected.");
		goto pfui;
	}
	if (!(parse_executable_statements
	      (&(*result)->data.s_switch.statements, cfile, lose,
	       (is_data_expression ((*result)->data.s_switch.expr)
		? context_data : context_numeric)))) {
		if (*lose) {
			skip_to_rbrace(cfile, 1);
			executable_statement_dereference(result, MDL);
			return 0;
		}
	}
	token = next_token(&val, NULL, cfile);
	if (token != RBRACE) {
		parse_warn (cfile, "right brace expected.");
		goto pfui;
	}
	return 1;
}

/*
 * case-statement :== CASE expr COLON
 *
 */

int parse_case_statement (result, cfile, lose, case_context)
	struct executable_statement **result;
	struct parse *cfile;
	int *lose;
	enum expression_context case_context;
{
	enum dhcp_token token;
	const char *val;

	if (!executable_statement_allocate(result, MDL))
		parse_error(cfile, "no memory for new statement.");
	(*result)->op = case_statement;

	if (!parse_expression (&(*result)->data.c_case,
			       cfile, lose, case_context,
			       NULL, expr_none))
	{
		if (!*lose) {
			parse_warn (cfile, "expecting %s expression.",
				    (case_context == context_data
				     ? "data" : "numeric"));
		}
	      pfui:
		*lose = 1;
		skip_to_semi(cfile);
		executable_statement_dereference(result, MDL);
		return 0;
	}

	token = next_token(&val, NULL, cfile);
	if (token != COLON) {
		parse_warn (cfile, "colon expected.");
		goto pfui;
	}
	return 1;
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

int parse_if_statement (result, cfile, lose)
	struct executable_statement **result;
	struct parse *cfile;
	int *lose;
{
	enum dhcp_token token;
	const char *val;
	int parenp;

	if (!executable_statement_allocate(result, MDL))
		parse_error(cfile, "no memory for if statement.");

	(*result)->op = if_statement;

	token = peek_token(&val, NULL, cfile);
	if (token == LPAREN) {
		parenp = 1;
		skip_token(&val, NULL, cfile);
	} else
		parenp = 0;


	if (!parse_boolean_expression (&(*result)->data.ie.expr,
				       cfile, lose)) {
		if (!*lose)
			parse_warn (cfile, "boolean expression expected.");
		executable_statement_dereference(result, MDL);
		*lose = 1;
		return 0;
	}
	if (parenp) {
		token = next_token(&val, NULL, cfile);
		if (token != RPAREN) {
			parse_warn (cfile, "expecting right paren.");
			*lose = 1;
			executable_statement_dereference(result, MDL);
			return 0;
		}
	}
	token = next_token(&val, NULL, cfile);
	if (token != LBRACE) {
		parse_warn (cfile, "left brace expected.");
		skip_to_semi(cfile);
		*lose = 1;
		executable_statement_dereference(result, MDL);
		return 0;
	}
	if (!parse_executable_statements (&(*result)->data.ie.tc,
					  cfile, lose, context_any)) {
		if (*lose) {
			/* Try to even things up. */
			do {
				token = next_token(&val,
						    NULL, cfile);
			} while (token != END_OF_FILE && token != RBRACE);
			executable_statement_dereference(result, MDL);
			return 0;
		}
	}
	token = next_token(&val, NULL, cfile);
	if (token != RBRACE) {
		parse_warn (cfile, "right brace expected.");
		skip_to_semi(cfile);
		*lose = 1;
		executable_statement_dereference(result, MDL);
		return 0;
	}
	token = peek_token(&val, NULL, cfile);
	if (token == ELSE) {
		skip_token(&val, NULL, cfile);
		token = peek_token(&val, NULL, cfile);
		if (token == IF) {
			skip_token(&val, NULL, cfile);
			if (!parse_if_statement (&(*result)->data.ie.fc,
						 cfile, lose)) {
				if (!*lose)
					parse_warn (cfile,
						    "expecting if statement");
				executable_statement_dereference(result, MDL);
				*lose = 1;
				return 0;
			}
		} else if (token != LBRACE) {
			parse_warn (cfile, "left brace or if expected.");
			skip_to_semi(cfile);
			*lose = 1;
			executable_statement_dereference(result, MDL);
			return 0;
		} else {
			skip_token(&val, NULL, cfile);
			if (!(parse_executable_statements
			      (&(*result)->data.ie.fc,
			       cfile, lose, context_any))) {
				executable_statement_dereference(result, MDL);
				return 0;
			}
			token = next_token(&val, NULL, cfile);
			if (token != RBRACE) {
				parse_warn (cfile, "right brace expected.");
				skip_to_semi(cfile);
				*lose = 1;
				executable_statement_dereference(result, MDL);
				return 0;
			}
		}
	} else if (token == ELSIF) {
		skip_token(&val, NULL, cfile);
		if (!parse_if_statement (&(*result)->data.ie.fc,
					 cfile, lose)) {
			if (!*lose)
				parse_warn (cfile,
					    "expecting conditional.");
			executable_statement_dereference(result, MDL);
			*lose = 1;
			return 0;
		}
	} else
		(*result)->data.ie.fc = (struct executable_statement *)0;
	
	return 1;
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
   			  
int parse_boolean_expression (expr, cfile, lose)
	struct expression **expr;
	struct parse *cfile;
	int *lose;
{
	/* Parse an expression... */
	if (!parse_expression (expr, cfile, lose, context_boolean,
			       NULL, expr_none))
		return 0;

	if (!is_boolean_expression (*expr) &&
	    (*expr)->op != expr_variable_reference &&
	    (*expr)->op != expr_funcall) {
		parse_warn (cfile, "Expecting a boolean expression.");
		*lose = 1;
		expression_dereference(expr, MDL);
		return 0;
	}
	return 1;
}

/* boolean :== ON SEMI | OFF SEMI | TRUE SEMI | FALSE SEMI */

int parse_boolean (cfile)
	struct parse *cfile;
{
	const char *val;
	int rv;

        (void)next_token(&val, NULL, cfile);
	if (!strcasecmp (val, "true")
	    || !strcasecmp (val, "on"))
		rv = 1;
	else if (!strcasecmp (val, "false")
		 || !strcasecmp (val, "off"))
		rv = 0;
	else {
		parse_warn (cfile,
			    "boolean value (true/false/on/off) expected");
		skip_to_semi(cfile);
		return 0;
	}
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

int parse_data_expression (expr, cfile, lose)
	struct expression **expr;
	struct parse *cfile;
	int *lose;
{
	/* Parse an expression... */
	if (!parse_expression (expr, cfile, lose, context_data,
			       NULL, expr_none))
		return 0;

	if (!is_data_expression (*expr) &&
	    (*expr)->op != expr_variable_reference &&
	    (*expr)->op != expr_funcall) {
		expression_dereference(expr, MDL);
		parse_warn (cfile, "Expecting a data expression.");
		*lose = 1;
		return 0;
	}
	return 1;
}

/*
 * numeric-expression :== EXTRACT_INT LPAREN data-expression
 *					     COMMA number RPAREN |
 *			  NUMBER
 */

int parse_numeric_expression (expr, cfile, lose)
	struct expression **expr;
	struct parse *cfile;
	int *lose;
{
	/* Parse an expression... */
	if (!parse_expression (expr, cfile, lose, context_numeric,
			       NULL, expr_none))
		return 0;

	if (!is_numeric_expression (*expr) &&
	    (*expr)->op != expr_variable_reference &&
	    (*expr)->op != expr_funcall) {
		expression_dereference(expr, MDL);
		parse_warn (cfile, "Expecting a numeric expression.");
		*lose = 1;
		return 0;
	}
	return 1;
}

/* Parse a subexpression that does not contain a binary operator. */

int parse_non_binary (expr, cfile, lose, context)
	struct expression **expr;
	struct parse *cfile;
	int *lose;
	enum expression_context context;
{
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

int parse_expression (expr, cfile, lose, context, plhs, binop)
	struct expression **expr;
	struct parse *cfile;
	int *lose;
	enum expression_context context;
	struct expression **plhs;
	enum expr_op binop;
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
#endif

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
			if (!parse_ip_addr (cfile, &addr))
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
		putLong (buf, -1);
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
		convert_num (cfile, buf, val, 0, 32);
		if (!make_const_data (&t, buf, 4, 0, 1, MDL))
			return 0;
		break;

	      case 's':	/* Signed 16-bit integer. */
	      case 'S':	/* Unsigned 16-bit integer. */
		token = next_token(&val, NULL, cfile);
		if ((token != NUMBER) && (token != NUMBER_OR_NAME))
			goto need_number;
		convert_num (cfile, buf, val, 0, 16);
		if (!make_const_data (&t, buf, 2, 0, 1, MDL))
			return 0;
		break;

	      case 'b':	/* Signed 8-bit integer. */
	      case 'B':	/* Unsigned 8-bit integer. */
		token = next_token(&val, NULL, cfile);
		if ((token != NUMBER) && (token != NUMBER_OR_NAME))
			goto need_number;
		convert_num (cfile, buf, val, 0, 8);
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
				if (!parse_ip_addr (cfile, &ip_addr))
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
				convert_num (cfile, buf, val, 0, 32);
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
				convert_num (cfile, buf, val, 0, 16);
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
				convert_num (cfile, buf, val, 0, 8);
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
			convert_num (cfile, &buf[len], val, 16, 8);
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

int parse_warn (struct parse *cfile, const char *fmt, ...)
{
	va_list list;
	char lexbuf[256];
	char mbuf[1024];
	char fbuf[1024];
	unsigned i, lix;
	
	do_percentm (mbuf, fmt);
	/* %Audit% This is log output. %2004.06.17,Safe%
	 * If we truncate we hope the user can get a hint from the log.
	 */
	snprintf (fbuf, sizeof fbuf, "%s line %d: %s",
		  cfile->tlname, cfile->lexline, mbuf);
	
	va_start (list, fmt);
	vsnprintf (mbuf, sizeof mbuf, fbuf, list);
	va_end (list);

	lix = 0;
	for (i = 0;
	     cfile->token_line[i] && i < (cfile->lexchar - 1); i++) {
		if (lix < (sizeof lexbuf) - 1)
			lexbuf[lix++] = ' ';
		if (cfile->token_line[i] == '\t') {
			for (; lix < (sizeof lexbuf) - 1 && (lix & 7); lix++)
				lexbuf[lix] = ' ';
		}
	}
	lexbuf[lix] = 0;

#ifndef DEBUG
	syslog (LOG_ERR, "%s", mbuf);
	syslog (LOG_ERR, "%s", cfile->token_line);
	if (cfile->lexchar < 81)
		syslog (LOG_ERR, "%s^", lexbuf);
#endif

	if (log_perror) {
		IGNORE_RET (write (STDERR_FILENO, mbuf, strlen (mbuf)));
		IGNORE_RET (write (STDERR_FILENO, "\n", 1));
		IGNORE_RET (write (STDERR_FILENO, cfile->token_line,
				   strlen (cfile->token_line)));
		IGNORE_RET (write (STDERR_FILENO, "\n", 1));
		if (cfile->lexchar < 81)
			IGNORE_RET (write (STDERR_FILENO, lexbuf, lix));
		IGNORE_RET (write (STDERR_FILENO, "^\n", 2));
	}

	cfile->warnings_occurred = 1;

	return 0;
}

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
