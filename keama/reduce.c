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

#include <sys/errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static struct element *reduce_equal_expression(struct element *left,
					       struct element *right);
static struct string *quote(struct string *);
static void debug(const char* fmt, ...);

/*
 * boolean_expression :== CHECK STRING |
 *                        NOT boolean-expression |
 *                        data-expression EQUAL data-expression |
 *                        data-expression BANG EQUAL data-expression |
 *                        data-expression REGEX_MATCH data-expression |
 *                        boolean-expression AND boolean-expression |
 *                        boolean-expression OR boolean-expression
 *                        EXISTS OPTION-NAME
 */

const char *
print_boolean_expression(struct element *expr, isc_boolean_t *lose)
{
	struct string *result;

	if (expr->type == ELEMENT_BOOLEAN) {
		if (boolValue(expr))
			return "true";
		else
			return "false";
	}

	/*
	 * From is_boolean_expression
	 */
	result = makeString(0, NULL);

	/* check */
	if (mapContains(expr, "check")) {
		struct element *name;

		appendString(result, "check ");
		name = mapGet(expr, "check");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
		} else
			concatString(result, stringValue(name));
		return result->content;
	}

	/* exists */
	if (mapContains(expr, "exists")) {
		struct element *arg;
		struct element *universe;
		struct element *name;

		appendString(result, "exists ");
		arg = mapGet(expr, "exists");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		universe = mapGet(arg, "universe");
		if ((universe == NULL) || (universe->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		concatString(result, stringValue(universe));
		appendString(result, ".");
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		concatString(result, stringValue(name));
		return result->content;
	}

	/* variable-exists */
	if (mapContains(expr, "variable-exists")) {
		struct element *name;

		appendString(result, "variable-exists ");
		name = mapGet(expr, "variable-exists");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
		} else
			concatString(result, stringValue(name));
		return result->content;
	}

	/* equal */
	if (mapContains(expr, "equal")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "equal ");
		arg = mapGet(expr, "equal");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_expression(left, lose));
		appendString(result, ") = (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* not-equal */
	if (mapContains(expr, "not-equal")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "not-equal ");
		arg = mapGet(expr, "not-equal");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1,"(");
		appendString(result, print_expression(left, lose));
		appendString(result, ") != (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* regex-match */
	if (mapContains(expr, "regex-match")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "regex-match ");
		arg = mapGet(expr, "regex-match");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1,"(");
		appendString(result, print_expression(left, lose));
		appendString(result, ") ~= ");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_expression(right, lose));
		return result->content;
	}

	/* iregex-match */
	if (mapContains(expr, "iregex-match")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "iregex-match ");
		arg = mapGet(expr, "iregex-match");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1,"(");
		appendString(result, print_expression(left, lose));
		appendString(result, ") ~~ ");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_expression(right, lose));
		return result->content;
	}

	/* and */
	if (mapContains(expr, "and")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "and ");
		arg = mapGet(expr, "and");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_boolean_expression(left, lose));
		appendString(result, ") and (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_boolean_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* or */
	if (mapContains(expr, "or")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "or ");
		arg = mapGet(expr, "or");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_boolean_expression(left, lose));
		appendString(result, ") or (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_boolean_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* not */
	if (mapContains(expr, "not")) {
		struct element *arg;

		appendString(result, "not ");
		arg = mapGet(expr, "not");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, "(");
		appendString(result, print_boolean_expression(arg, lose));
		appendString(result, ")");
		return result->content;
	}

	/* known */
	if (mapContains(expr, "known")) {
		return "known";
	}

	/* static */
	if (mapContains(expr, "static")) {
		return "static";
	}

	/* variable-reference */
	if (mapContains(expr, "variable-reference")) {
		struct element *name;

		appendString(result, "variable-reference ");
		name = mapGet(expr, "variable-reference");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		return stringValue(name)->content;
	}

	/* funcall */
	if (mapContains(expr, "funcall")) {
		struct element *arg;
		struct element *name;
		struct element *args;
		size_t i;

		appendString(result, "funcall ");
		arg = mapGet(expr, "funcall");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(0, NULL);
		concatString(result, stringValue(name));
		appendString(result, "(");
		args = mapGet(arg, "arguments");
		if ((args == NULL) || (args->type != ELEMENT_LIST)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		for (i = 0; i < listSize(args); i++) {
			struct element *item;

			if (i != 0)
				appendString(result, ", ");
			item = listGet(args, i);
			if (item == NULL) {
				debug("funcall null argument %u",
				      (unsigned)i);
				*lose = ISC_TRUE;
				appendString(result, "???");
				continue;
			}
			appendString(result, print_expression(item, lose));
		}
		appendString(result, ")");
		return result->content;
	}

	*lose = ISC_TRUE;
	appendString(result, "???");
	return result->content;
}

struct element *
reduce_boolean_expression(struct element *expr)
{
	/* trivial case: already done */
	if (expr->type == ELEMENT_BOOLEAN)
		return expr;

	/*
	 * From is_boolean_expression
	 */

	/* check */
	if (mapContains(expr, "check"))
		/*
		 * syntax := { "check": <collection_name> }
		 * semantic: check_collection
		 *  on server try to match classes of the collection
		 */
		return NULL;


	/* exists */
	if (mapContains(expr, "exists")) {
		/*
		 * syntax := { "exists":
		 *             { "universe": <option_space_old>,
		 *               "name":  <option_name> }
		 *           }
		 * semantic: check universe/code from incoming packet
		 */
		struct element *arg;
		struct element *universe;
		struct element *name;
		struct option *option;
		char result[80];

		arg = mapGet(expr, "exists");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get exists argument");
			return NULL;
		}
		universe = mapGet(arg, "universe");
		if ((universe == NULL) || (universe->type != ELEMENT_STRING)) {
			debug("can't get exists option universe");
			return NULL;
		}
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			debug("can't get exists option name");
			return NULL;
		}
		option = option_lookup_name(stringValue(universe)->content,
					    stringValue(name)->content);
		if ((option == NULL) || (option->code == 0))
			return NULL;
		if (((local_family == AF_INET) &&
		     (strcmp(option->space->name, "dhcp4") != 0)) ||
		    ((local_family == AF_INET6) &&
		     (strcmp(option->space->name, "dhcp6") != 0)))
			return NULL;
		snprintf(result, sizeof(result),
			 "option[%u].exists", option->code);
		return createString(makeString(-1, result));
	}

	/* variable-exists */
	if (mapContains(expr, "variable-exists"))
		/*
		 * syntax := { "variable-exists": <variable_name> }
		 * semantics: find_binding(scope, name)
		 */
		return NULL;

	/* equal */
	if (mapContains(expr, "equal")) {
		/*
		 * syntax := { "equal":
		 *             { "left":  <expression>,
		 *               "right": <expression> }
		 *           }
		 * semantics: evaluate branches and return true
		 * if same type and same value
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "equal");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get equal argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get equal left branch");
			return NULL;
		}
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get equal right branch");
			return NULL;
		}
		return reduce_equal_expression(left, right);
	}

	/* not-equal */
	if (mapContains(expr, "not-equal")) {
		/*
		 * syntax := { "not-equal":
		 *             { "left":  <expression>,
                 *               "right": <expression> }
                 *           }
                 * semantics: evaluate branches and return true
                 * if different type or different value
                 */
		struct element *arg;
		struct element *left;
		struct element *right;
		struct element *equal;

		arg = mapGet(expr, "not-equal");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get not-equal argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get not-equal left branch");
			return NULL;
		}
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get not-equal right branch");
			return NULL;
		}
		equal = reduce_equal_expression(left, right);
		if (equal == NULL)
			return NULL;
		if (equal->type == ELEMENT_BOOLEAN)
			return createBool(ISC_TF(!boolValue(equal)));
		if (equal->type == ELEMENT_STRING) {
			struct string *result;

			result = makeString(-1, "not (");
			concatString(result, stringValue(equal));
			appendString(result, ")");
			return createString(result);
		}
		debug("equal reduced to unexpected %s",
		      type2name(equal->type));
		return NULL;
	}

	/* regex-match */
	if (mapContains(expr, "regex-match"))
		/*
		 * syntax := { "regex-match":
		 *             { "left":  <data_expression>,
		 *               "right": <data_expression> }
		 *           }
		 * semantics: evaluate branches, compile right as a
		 * regex and apply it to left
		 */
		return NULL;

	/* iregex-match */
	if (mapContains(expr, "iregex-match"))
		/*
		 * syntax := { "regex-match":
		 *             { "left":  <data_expression>,
		 *               "right": <data_expression> }
		 *           }
		 * semantics: evaluate branches, compile right as a
		 * case insensistive regex and apply it to left
		 */
		return NULL;

	/* and */
	if (mapContains(expr, "and")) {
		/*
		 * syntax := { "and":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return true
		 * if both are true
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "and");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get and argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get and left branch");
			return NULL;
		}
		left = reduce_boolean_expression(left);
		if (left == NULL)
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get and right branch");
			return NULL;
		}
		right = reduce_boolean_expression(right);
		if (right == NULL)
			return NULL;
		if (left->type == ELEMENT_BOOLEAN) {
			if (!boolValue(left))
				return createBool(ISC_FALSE);
			return right;
		}
		if (right->type == ELEMENT_BOOLEAN) {
			if (!boolValue(right))
				return createBool(ISC_FALSE);
			return left;
		}
		if ((left->type == ELEMENT_STRING) &&
		    (right->type == ELEMENT_STRING)) {
			struct string *result;

			result = makeString(-1, "(");
			concatString(result, stringValue(left));
			appendString(result, ") and (");
			concatString(result, stringValue(right));
			appendString(result, ")");
			return createString(result);
		}
		if (left->type != ELEMENT_STRING)
			debug("and left branch reduced to unexpected %s",
			      type2name(left->type));
		if (right->type != ELEMENT_STRING)
			debug("and right branch reduced to unexpected %s",
			      type2name(right->type));
		return NULL;
	}

	/* or */
	if (mapContains(expr, "or")) {
		/*
		 * syntax := { "or":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return true
		 * if any is true
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "or");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get or argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get or left branch");
			return NULL;
		}
		left = reduce_boolean_expression(left);
		if (left == NULL)
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get or right branch");
			return NULL;
		}
		right = reduce_boolean_expression(right);
		if (right == NULL)
			return NULL;
		if (left->type == ELEMENT_BOOLEAN) {
			if (boolValue(left))
				return createBool(ISC_TRUE);
			return right;
		}
		if (right->type == ELEMENT_BOOLEAN) {
			if (boolValue(right))
				return createBool(ISC_TRUE);
			return left;
		}
		if ((left->type == ELEMENT_STRING) &&
		    (right->type == ELEMENT_STRING)) {
			struct string *result;

			result = makeString(-1, "(");
			concatString(result, stringValue(left));
			appendString(result, ") or (");
			concatString(result, stringValue(right));
			appendString(result, ")");
			return createString(result);
		}
		if (left->type != ELEMENT_STRING)
			debug("or left branch reduced to unexpected %s",
			      type2name(left->type));
		if (right->type != ELEMENT_STRING)
			debug("or right branch reduced to unexpected %s",
			      type2name(right->type));
		return NULL;
	}

	/* not */
	if (mapContains(expr, "not")) {
		/*
		 * syntax := { "not": <boolean_expression> }
		 * semantic: evaluate its branch and return its negation
		 */
		struct element *arg;

		arg = mapGet(expr, "not");
		if (arg == NULL) {
			debug("can't get not argument");
			return NULL;
		}
		arg = reduce_boolean_expression(arg);
		if (arg == NULL)
			return NULL;
		if (arg->type == ELEMENT_BOOLEAN)
			return createBool(ISC_TF(!boolValue(arg)));
		if (arg->type == ELEMENT_STRING) {
			struct string *result;

			result = makeString(-1, "not (");
			concatString(result, stringValue(arg));
			appendString(result, ")");
			return createString(result);
		}
		debug("not argument reduced to unexpected %s",
		      type2name(arg->type));
		return NULL;
	}

	/* known */
	if (mapContains(expr, "known"))
		/*
		 * syntax := { "known": null }
		 * semantics: client is known, i.e., has a matching
		 * host declaration (aka reservation in Kea)
		 */
		return NULL;

	/* static */
	if (mapContains(expr, "static"))
		/*
		 * syntax := { "static": null }
		 * semantics: lease is static (doesn't exist in Kea)
		 */
		return NULL;

	return NULL;
}

/*
 * data_expression :== SUBSTRING LPAREN data-expression COMMA
 *                                      numeric-expression COMMA
 *                                      numeric-expression RPAREN |
 *                     CONCAT LPAREN data-expression COMMA 
 *                                      data-expression RPAREN
 *                     SUFFIX LPAREN data_expression COMMA
 *                                   numeric-expression RPAREN |
 *                     LCASE LPAREN data_expression RPAREN |
 *                     UCASE LPAREN data_expression RPAREN |
 *                     OPTION option_name |
 *                     HARDWARE |
 *                     PACKET LPAREN numeric-expression COMMA
 *                                   numeric-expression RPAREN |
 *                     V6RELAY LPAREN numeric-expression COMMA
 *                                    data-expression RPAREN |
 *                     STRING |
 *                     colon_separated_hex_list
 */

const char *
print_data_expression(struct element *expr, isc_boolean_t *lose)
{
	struct string *result;

	if (expr->type == ELEMENT_INTEGER) {
		char buf[20];

		snprintf(buf, sizeof(buf), "%lld", (long long)intValue(expr));
		result = makeString(-1, buf);
		return result->content;
	}
	if (expr->type == ELEMENT_STRING)
		return quote(stringValue(expr))->content;

	/*
	 * From is_data_expression
	 */
	result = makeString(0, NULL);

	/* substring */
	if (mapContains(expr, "substring")) {
		struct element *arg;
		struct element *string;
		struct element *offset;
		struct element *length;

		appendString(result, "substring(");
		arg = mapGet(expr, "substring");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		string = mapGet(arg, "expression");
		if (string == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(string, lose));
		appendString(result, ", ");
		offset = mapGet(arg, "offset");
		if (offset  == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(offset, lose));
		appendString(result, ", ");
		length = mapGet(arg, "length");
		if (length  == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(length, lose));
		appendString(result, ")");
		return result->content;
	}

	/* suffix */
	if (mapContains(expr, "suffix")) {
		struct element *arg;
		struct element *string;
		struct element *length;

		appendString(result, "suffix(");
		arg = mapGet(expr, "suffix");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		string = mapGet(arg, "expression");
		if (string == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(string, lose));
		appendString(result, ", ");
		length = mapGet(arg, "length");
		if (length  == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(length, lose));
		appendString(result, ")");
		return result->content;
	}

	/* lowercase */
	if (mapContains(expr, "lowercase")) {
		struct element *arg;

		appendString(result, "lowercase(");
		arg = mapGet(expr, "lowercase");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(arg, lose));
		appendString(result, ")");
		return result->content;
	}

	/* uppercase */
	if (mapContains(expr, "uppercase")) {
		struct element *arg;

		appendString(result, "uppercase(");
		arg = mapGet(expr, "uppercase");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(arg, lose));
		appendString(result, ")");
		return result->content;
	}

	/* option */
	if (mapContains(expr, "option")) {
		struct element *arg;
		struct element *universe;
		struct element *name;

		appendString(result, "option ");
		arg = mapGet(expr, "option");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		universe = mapGet(arg, "universe");
		if ((universe == NULL) || (universe->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		concatString(result, stringValue(universe));
		appendString(result, ".");
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		concatString(result, stringValue(name));
		return result->content;
	}

	/* hardware */
	if (mapContains(expr, "hardware"))
		return "hardware";

	/* packet */
	if (mapContains(expr, "packet")) {
		struct element *arg;
		struct element *offset;
		struct element *length;

		appendString(result, "packet(");
		arg = mapGet(expr, "packet");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		offset = mapGet(arg, "offset");
		if (offset  == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(offset, lose));
		appendString(result, ", ");
		length = mapGet(arg, "length");
		if (length  == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(length, lose));
		appendString(result, ")");
		return result->content;
	}

	/* concat */
	if (mapContains(expr, "concat")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "concat(");
		arg = mapGet(expr, "concat");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(left, lose));
		appendString(result, ", ");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* encapsulate */
	if (mapContains(expr, "encapsulate")) {
		struct element *arg;

		appendString(result, "encapsulate ");
		arg = mapGet(expr, "encapsulate");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_data_expression(arg, lose));
		return result->content;
	}

	/* encode-int8 */
	if (mapContains(expr, "encode-int8")) {
		struct element *arg;

		appendString(result, "encode-int(");
		arg = mapGet(expr, "encode-int8");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???, 8)");
			return result->content;
		}
		appendString(result, print_numeric_expression(arg, lose));
		appendString(result, ", 8)");
		return result->content;
	}

	/* encode-int16 */
	if (mapContains(expr, "encode-int16")) {
		struct element *arg;

		appendString(result, "encode-int(");
		arg = mapGet(expr, "encode-int16");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???, 16)");
			return result->content;
		}
		appendString(result, print_numeric_expression(arg, lose));
		appendString(result, ", 16)");
		return result->content;
	}

	/* encode-int32 */
	if (mapContains(expr, "encode-int32")) {
		struct element *arg;

		appendString(result, "encode-int(");
		arg = mapGet(expr, "encode-int32");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???, 32)");
			return result->content;
		}
		appendString(result, print_numeric_expression(arg, lose));
		appendString(result, ", 32)");
		return result->content;
	}

	/* gethostbyname */
	if (mapContains(expr, "gethostbyname")) {
		struct element *arg;

		appendString(result, "gethostbyname ");
		arg = mapGet(expr, "gethostbyname");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_data_expression(arg, lose));
		return result->content;
	}

	/* binary-to-ascii */
	if (mapContains(expr, "binary-to-ascii")) {
		struct element *arg;
		struct element *base;
		struct element *width;
		struct element *separator;
		struct element *buffer;
		
		appendString(result, "binary-to-ascii(");
		arg = mapGet(expr, "binary-to-ascii");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		base = mapGet(arg, "base");
		if (base == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(base, lose));
		appendString(result, ", ");
		width = mapGet(arg, "width");
		if (width == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(width, lose));
		appendString(result, ", ");
		separator = mapGet(arg, "separator");
		if (separator == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(separator, lose));
		appendString(result, ", ");
		buffer = mapGet(arg, "buffer");
		if (buffer == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(buffer, lose));
		appendString(result, ")");
		return result->content;
	}

	/* filename */
	if (mapContains(expr, "filename"))
		return "filename";

	/* server-name */
	if (mapContains(expr, "server-name"))
		return "server-name";

	/* reverse */
	if (mapContains(expr, "reverse")) {
		struct element *arg;
		struct element *width;
		struct element *buffer;
		
		appendString(result, "reverse(");
		arg = mapGet(expr, "reverse");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		width = mapGet(arg, "width");
		if (width == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(width, lose));
		appendString(result, ", ");
		buffer = mapGet(arg, "buffer");
		if (buffer == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(buffer, lose));
		appendString(result, ")");
		return result->content;
	}

	/* pick-first-value */
	if (mapContains(expr, "pick-first-value")) {
		struct element *arg;
		size_t i;

		appendString(result, "pick-first-value(");
		arg = mapGet(expr, "pick-first-value");
		if ((arg == NULL) || (arg->type != ELEMENT_LIST)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		for (i = 0; i < listSize(arg); i++) {
			struct element *item;

			if (i != 0)
				appendString(result, ", ");
			item = listGet(arg, i);
			if (item == NULL) {
				*lose = ISC_TRUE;
				appendString(result, "???");
				continue;
			}
			appendString(result,
				     print_data_expression(item, lose));
		}
		appendString(result, ")");
		return result->content;
	}

	/* host-decl-name */
	if (mapContains(expr, "host-decl-name"))
		return "host-decl-name";

	/* leased-address */
	if (mapContains(expr, "leased-address"))
		return "leased-address";

	/* config-option */
	if (mapContains(expr, "config-option")) {
		struct element *arg;
		struct element *universe;
		struct element *name;

		appendString(result, "config-option ");
		arg = mapGet(expr, "config-option");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		universe = mapGet(arg, "universe");
		if ((universe == NULL) || (universe->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		concatString(result, stringValue(universe));
		appendString(result, ".");
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		concatString(result, stringValue(name));
		return result->content;
	}

	/* null */
	if (mapContains(expr, "null"))
		return "null";

	/* gethostname */
	if (mapContains(expr, "gethostname"))
		return "gethostname";

	/* v6relay */
	if (mapContains(expr, "v6relay")) {
		struct element *arg;
		struct element *relay;
		struct element *option;

		appendString(result, "v6relay(");
		arg = mapGet(expr, "v6relay");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		relay = mapGet(arg, "relay");
		if (relay == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_numeric_expression(relay, lose));
		appendString(result, ", ");
		option = mapGet(arg, "relay-option");
		if (option == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???" ")");
			return result->content;
		}
		appendString(result, print_data_expression(option, lose));
		appendString(result, ")");
		return result->content;
	}

	*lose = ISC_TRUE;
	appendString(result, "???");
	return result->content;
}

struct element *
reduce_data_expression(struct element *expr, isc_boolean_t *literalp)
{
	/* trivial case: already done */
	if (expr->type == ELEMENT_INTEGER)
		return expr;
	if (expr->type == ELEMENT_STRING) {
		if (literalp)
			*literalp = ISC_TRUE;
		return expr;
	}

	/*
	 * From is_data_expression
	 */

	/* substring */
	if (mapContains(expr, "substring")) {
		/*
		 * syntax := { "substring":
		 *             { "expression": <data_expression>,
		 *               "offset":     <numeric_expression>,
		 *               "length":     <numeric_expression> }
		 *           }
		 * semantic: evaluate arguments, if the string is
		 * shorter than offset return "" else return substring
		 */
		struct element *arg;
		struct element *string;
		struct element *offset;
		struct element *length;
		struct string *result;
		int64_t off;
		int64_t len;
		isc_boolean_t literal = ISC_FALSE;

		arg = mapGet(expr, "substring");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get substring argument");
			return NULL;
		}
		string = mapGet(arg, "expression");
		if (string == NULL) {
			debug("can't get substring expression");
			return NULL;
		}
		if (string->type == ELEMENT_STRING)
			literal = ISC_TRUE;
		else {
			string = reduce_data_expression(string, &literal);
			if ((string == NULL) ||
			    (string->type != ELEMENT_STRING))
			return NULL;
		}
		offset = mapGet(arg, "offset");
		if (offset  == NULL) {
			debug("can't get substring offset");
			return NULL;
		}
		offset = reduce_numeric_expression(offset);
		if ((offset == NULL) || (offset->type != ELEMENT_INTEGER))
			return NULL;
		off = intValue(offset);
		if (off < 0) {
			debug("substring with a negative offset (%lld)",
			      (long long)off);
			return NULL;
		}
		length = mapGet(arg, "length");
		if (length  == NULL) {
			debug("can't get substring length");
			return NULL;
		}
		length = reduce_numeric_expression(length);
		if ((length == NULL) || (length->type != ELEMENT_INTEGER))
			return NULL;
		len = intValue(length);
		if (len < 0) {
			debug("substring with a negative length (%lld)",
			      (long long)len);
			return NULL;
		}
		if (literal) {
			result = stringValue(string);
			if (result->length <= off) {
				result = makeString(-1, "''");
				return createString(result);
			}
			result = makeString(result->length - off,
					    result->content + off);
			if (result->length > len)
				result->length = len;
			return createString(quote(result));
		} else {
			char buf[80];

			result = makeString(-1, "substring(");
			concatString(result, stringValue(string));
			snprintf(buf, sizeof(buf),
				 ",%u,%u)", (unsigned)off, (unsigned)len);
			appendString(result, buf);
			return createString(result);
		}
	}

	/* suffix */
	if (mapContains(expr, "suffix")) {
		/*
		 * syntax := { "suffix":
		 *             { "expression": <data_expression>,
		 *               "length":     <numeric_expression> }
		 *           }
		 * semantic: evaluate arguments, if the string is
		 * shorter than length return it else return suffix
		 */
		struct element *arg;
		struct element *string;
		struct element *length;
		struct string *result;
		int64_t len;
		isc_boolean_t literal = ISC_FALSE;

		arg = mapGet(expr, "suffix");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get suffix argument");
			return NULL;
		}
		string = mapGet(arg, "expression");
		if (string == NULL) {
			debug("can't get suffix expression");
			return NULL;
		}
		if (string->type == ELEMENT_STRING)
			literal = ISC_TRUE;
		else {
			string = reduce_data_expression(string, &literal);
			if ((string == NULL) ||
			    (string->type != ELEMENT_STRING))
			return NULL;
		}
		length = mapGet(arg, "length");
		if (length  == NULL) {
			debug("can't get suffix length");
			return NULL;
		}
		length = reduce_numeric_expression(length);
		if ((length == NULL) || (length->type != ELEMENT_INTEGER))
			return NULL;
		len = intValue(length);
		if (len < 0) {
			debug("suffix with a negative length (%lld)",
			      (long long)len);
			return NULL;
		}
		if (literal) {
			result = stringValue(string);
			if (result->length > len)
				result = makeString(result->length - len,
						    result->content + len);
			result = quote(result);
		} else {
			char buf[80];

			result = makeString(-1, "substring(");
			concatString(result, stringValue(string));
			snprintf(buf, sizeof(buf), ",-%u,all)", (unsigned)len);
			appendString(result, buf);
		}
		return createString(result);			
	}

	/* lowercase */
	if (mapContains(expr, "lowercase")) {
		/*
		 * syntax := { "lowercase": <data_expression> }
		 * semantic: evaluate its argument and apply tolower to
		 * its content
		 */
		struct element *arg;
		struct string *result;
		size_t i;

		arg = mapGet(expr, "lowercase");
		if (arg == NULL) {
			debug("can't get lowercase argument");
			return NULL;
		}
		if (arg->type != ELEMENT_STRING)
			return NULL;
		result = makeString(stringValue(arg)->length,
				    stringValue(arg)->content);
		for (i = 0; i < result->length; i++)
			result->content[i] = tolower(result->content[i]);
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(result);
	}

	/* uppercase */
	if (mapContains(expr, "uppercase")) {
		/*
		 * syntax := { "uppercase": <data_expression> }
		 * semantic: evaluate its argument and apply toupper to
		 * its content
		 */
		struct element *arg;
		struct string *result;
		size_t i;

		arg = mapGet(expr, "uppercase");
		if (arg == NULL) {
			debug("can't get uppercase argument");
			return NULL;
		}
		if (arg->type != ELEMENT_STRING)
			return NULL;
		result = makeString(stringValue(arg)->length,
				    stringValue(arg)->content);
		for (i = 0; i < result->length; i++)
			result->content[i] = toupper(result->content[i]);
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(result);
	}

	/* option */
	if (mapContains(expr, "option")) {
		/*
		 * syntax := { "option":
		 *             { "universe": <option_space_old>,
		 *               "name":  <option_name> }
		 *           }
		 * semantic: get universe/code option from incoming packet
		 */
		struct element *arg;
		struct element *universe;
		struct element *name;
		struct option *option;
		char result[80];

		arg = mapGet(expr, "option");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get option argument");
			return NULL;
		}
		universe = mapGet(arg, "universe");
		if ((universe == NULL) || (universe->type != ELEMENT_STRING)) {
			debug("can't get option universe");
			return NULL;
		}
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			debug("can't get option name");
			return NULL;
		}
		option = option_lookup_name(stringValue(universe)->content,
					    stringValue(name)->content);
		if ((option == NULL) || (option->code == 0))
			return NULL;
		if (((local_family == AF_INET) &&
		     (strcmp(option->space->name, "dhcp4") != 0)) ||
		    ((local_family == AF_INET6) &&
		     (strcmp(option->space->name, "dhcp6") != 0)))
			return NULL;
		snprintf(result, sizeof(result),
			 "option[%u].hex", option->code);
		return createString(makeString(-1, result));
	}

	/* hardware */
	if (mapContains(expr, "hardware")) {
		/*
		 * syntax := { "hardware": null }
		 * semantic: get mac type and address from incoming packet
		 */
		struct string *result;

		if (local_family != AF_INET) {
			debug("get hardware for DHCPv6");
			return NULL;
		}
		result = makeString(-1,
			    "concat(substring(pkt4.htype,-1,all),pk4.mac)");
		return createString(result);
	}

	/* packet */
	if (mapContains(expr, "packet"))
		/*
		 * syntax := { "packet":
		 *             { "offset": <numeric_expression>,
		 *               "length": <numeric_expression> }
		 *           }
		 * semantic: return the selected substring of the incoming
		 * packet content
		 */
		return NULL;

	/* concat */
	if (mapContains(expr, "concat")) {
		/*
		 * syntax := { "concat":
		 *             { "left":  <data_expression>,
		 *               "right": <data_expression> }
		 *           }
		 * semantic: evaluate arguments and return the concatenation
		 */
		struct element *arg;
		struct element *left;
		struct element *right;
		struct string *result;
		isc_boolean_t lliteral = ISC_FALSE;
		isc_boolean_t rliteral = ISC_FALSE;

		arg = mapGet(expr, "concat");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get concat argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get concat left branch");
			return NULL;
		}
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get concat right branch");
			return NULL;
		}
		if ((left->type == ELEMENT_STRING) &&
		    (right->type == ELEMENT_STRING)) {
			result = makeString(0, NULL);
			concatString(result, stringValue(left));
			concatString(result, stringValue(right));
			if (literalp)
				*literalp = ISC_TRUE;
			return createString(result);
		}
		left = reduce_data_expression(left, &lliteral);
		if (left == NULL)
			return NULL;
		right = reduce_data_expression(right, &rliteral);
		if (left == NULL)
			return NULL;
		if ((left->type == ELEMENT_STRING) &&
		    (right->type == ELEMENT_STRING)) {
			result = makeString(-1, "concat(");
			if (lliteral)
				concatString(result,
					     quote(stringValue(left)));
			else
				concatString(result, stringValue(left));
			appendString(result, ", ");
			if (rliteral)
				concatString(result,
					     quote(stringValue(right)));
			else
				concatString(result, stringValue(right));
			appendString(result, ")");
			return createString(result);
		}
		if (left->type != ELEMENT_STRING)
			debug("concat left branch reduced to unexpected %s",
			      type2name(left->type));
		if (right->type != ELEMENT_STRING)
			debug("concat right branch reduced to unexpected %s",
			      type2name(right->type));
		return NULL;
	}

	/* encapsulate */
	if (mapContains(expr, "encapsulate"))
		/*
		 * syntax := { "encapsulate": <encapsulated_space> }
		 * semantic: encapsulate options of the given space
		 */
		return NULL;

	/* encode-int8 */
	if (mapContains(expr, "encode-int8")) {
		/*
		 * syntax := { "encode-int8": <numeric_expression> }
		 * semantic: return a string buffer with the evaluated
		 * number as content
		 */
		struct element *arg;
		uint8_t val;

		arg = mapGet(expr, "encode-int8");
		if (arg == NULL) {
			debug("can't get encode-int8 argument");
			return NULL;
		}
		arg = reduce_numeric_expression(arg);
		if ((arg == NULL) || (arg->type != ELEMENT_INTEGER))
			return NULL;
		val = (uint8_t)intValue(arg);
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(makeString(1, (char *)&val));
	}

	/* encode-int16 */
	if (mapContains(expr, "encode-int16")) {
		/*
		 * syntax := { "encode-int16": <numeric_expression> }
		 * semantic: return a string buffer with the evaluated
		 * number as content
		 */
		struct element *arg;
		uint16_t val;

		arg = mapGet(expr, "encode-int16");
		if (arg == NULL) {
			debug("can't get encode-int16 argument");
			return NULL;
		}
		arg = reduce_numeric_expression(arg);
		if ((arg == NULL) || (arg->type != ELEMENT_INTEGER))
			return NULL;
		val = (uint16_t)intValue(arg);
		val = htons(val);
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(makeString(2, (char *)&val));
	}

	/* encode-int32 */
	if (mapContains(expr, "encode-int32")) {
		/*
		 * syntax := { "encode-int32": <numeric_expression> }
		 * semantic: return a string buffer with the evaluated
		 * number as content
		 */
		struct element *arg;
		uint32_t val;

		arg = mapGet(expr, "encode-int32");
		if (arg == NULL) {
			debug("can't get encode-int32 argument");
			return NULL;
		}
		arg = reduce_numeric_expression(arg);
		if ((arg == NULL) || (arg->type != ELEMENT_INTEGER))
			return NULL;
		val = (uint32_t)intValue(arg);
		val = htonl(val);
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(makeString(2, (char *)&val));
	}

	/* gethostbyname */
	if (mapContains(expr, "gethostbyname")) {
		/*
		 * syntax := { "gethostbyname": <string> }
		 * semantic: call gethostbyname and return
		 * a binary buffer with addresses
		 */
		struct element *arg;
		struct string *result;
		char *hostname;
		struct hostent *h;
		size_t i;

		if (local_family != AF_INET) {
			debug("get gethostbyname for DHCPv6");
			return NULL;
		}
		arg = mapGet(expr, "gethostbyname");
		if ((arg == NULL) || (arg->type != ELEMENT_STRING)) {
			debug("can't get gethostbyname argument");
			return NULL;
		}
		hostname = stringValue(arg)->content;
		h = gethostbyname(hostname);
		result = makeString(0, NULL);
		if (h == NULL) {
			switch (h_errno) {
			case HOST_NOT_FOUND:
				debug("gethostbyname: %s: host unknown",
				      hostname);
				break;
			case TRY_AGAIN:
				debug("gethostbyname: %s: temporary name "
				      "server failure", hostname);
				break;
			case NO_RECOVERY:
				debug("gethostbyname: %s: name server failed",
				      hostname);
				break;
			case NO_DATA:
				debug("gethostbyname: %s: no A record "
				      "associated with address", hostname);
				break;
			}
			return createString(result);
		}
		for (i = 0; h->h_addr_list[i] != NULL; i++) {
			struct string *addr;

			addr = makeString(4, h->h_addr_list[i]);
			concatString(result, addr);
		}
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(result);
	}

	/* binary-to-ascii */
	if (mapContains(expr, "binary-to-ascii")) {
		/*
		 * syntax := { "binary-to-ascii":
		 *             { "base":      <numeric_expression 2..16>,
		 *               "width":     <numeric_expression 8, 16 or 32>,
		 *               "separator": <data_expression>,
		 *               "buffer":    <data_expression> }
		 *           }
		 * semantic: split the input buffer into int8/16/32 numbers,
		 * output them separated by the given string
		 */
		struct element *arg;
		struct element *base;
		struct element *width;
		struct element *separator;
		struct element *buffer;
		struct string *sep;
		struct string *buf;
		struct string *result;
		int64_t b;
		int64_t w;
		
		arg = mapGet(expr, "binary-to-ascii");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get binary-to-ascii argument");
			return NULL;
		}
		base = mapGet(arg, "base");
		if (base == NULL) {
			debug("can't get binary-to-ascii base");
			return NULL;
		}
		base = reduce_numeric_expression(base);
		if ((base == NULL) || (base->type != ELEMENT_INTEGER))
			return NULL;
		b = intValue(base);
		if ((b < 2) || (b > 16)) {
			debug("binary-to-ascii with illegal base (%lld)",
			      (long long)b);
			return NULL;
		}
		if ((b != 8) && (b != 10) && (b != 16))
			return NULL;
		width = mapGet(arg, "width");
		if (width == NULL) {
			debug("can't get binary-to-ascii width");
			return NULL;
		}
		width = reduce_numeric_expression(width);
		if ((width == NULL) || (width->type != ELEMENT_INTEGER))
			return NULL;
		w = intValue(width);
		if ((w != 8) && (w != 16) && (w != 32)) {
			debug("binary-to-ascii called with illegal width "
			      "(%lld)", (long long)w);
			return NULL;
		}
		separator = mapGet(arg, "separator");
		if (separator == NULL) {
			debug("can't get binary-to-ascii separator");
			return NULL;
		}
		if (separator->type != ELEMENT_STRING)
			return NULL;
		sep = stringValue(separator);
		buffer = mapGet(arg, "buffer");
		if (buffer == NULL) {
			debug("can't get binary-to-ascii buffer");
			return NULL;
		}
		if (buffer->type != ELEMENT_STRING)
			return NULL;
		buf = stringValue(buffer);
		result = makeString(0, NULL);
		if (w == 8) {
			size_t i;
			char *fmt;

			switch (b) {
			case 8:
				fmt = "o";
				break;
			case 10:
				fmt = "d";
				break;
			case 16:
				fmt = "x";
				break;
			}
			
			for (i = 0; i < buf->length; i++) {
				uint8_t val;
				char num[4];

				if (i != 0)
					concatString(result, sep);
				val = (uint8_t)buf->content[i];
				snprintf(num, sizeof(num), fmt, (int)val);
				appendString(result, num);
			}
			if (literalp)
				*literalp = ISC_TRUE;
			return createString(result);
		} else if (w == 16) {
			size_t i;
			char *fmt;

			if ((buf->length % 2) != 0) {
				debug("binary-to-ascii illegal buffer length "
				      "(%u, should be even)",
				      (unsigned)buf->length);
				return NULL;
			}
			
			switch (b) {
			case 8:
				fmt = "o";
				break;
			case 10:
				fmt = "d";
				break;
			case 16:
				fmt = "x";
				break;
			}
			
			for (i = 0; i < buf->length; i += 2) {
				uint16_t val;
				char num[8];
				
				if (i != 0)
					concatString(result, sep);
				memcmp(&val, buf->content + i, 2);
				val = ntohs(val);
				snprintf(num, sizeof(num), fmt, (int)val);
				appendString(result, num);
			}
			if (literalp)
				*literalp = ISC_TRUE;
			return createString(result);
		} else if (w == 32) {
			size_t i;
			char *fmt;

			if ((buf->length % 4) != 0) {
				debug("binary-to-ascii illegal buffer length "
				      "(%u, should be multiple of 4)",
				      (unsigned)buf->length);
				return NULL;
			}
			
			switch (b) {
			case 8:
				fmt = "llo";
				break;
			case 10:
				fmt = "lld";
				break;
			case 16:
				fmt = "llx";
				break;
			}
			
			for (i = 0; i < buf->length; i += 4) {
				uint32_t val;
				char num[40];
				
				if (i != 0)
					concatString(result, sep);
				memcmp(&val, buf->content + i, 4);
				val = ntohl(val);
				snprintf(num, sizeof(num), fmt,
					 (long long)val);
				appendString(result, num);
			}
			if (literalp)
				*literalp = ISC_TRUE;
			return createString(result);
		}
		debug("binary-to-ascii unreachable statement");
		return NULL;
	}

	/* filename */
	if (mapContains(expr, "filename")) {
		/*
		 * syntax := { "filename": null }
		 * semantic: get filename field from incoming DHCPv4 packet
		 */
		if (local_family != AF_INET)
			debug("get filename for DHCPv6");
		return NULL;
	}

	/* server-name */
	if (mapContains(expr, "server-name")) {
		/*
		 * syntax := { "server-name": null }
		 * semantic: get server-name field from incoming DHCPv4 packet
		 */
		if (local_family != AF_INET)
			debug("get server-name for DHCPv6");
		return NULL;
	}

	/* reverse */
	if (mapContains(expr, "reverse")) {
		/*
		 * syntax := { "reverse":
		 *             { "width": <numeric_expression>,
		 *               "buffer":    <data_expression> }
		 *           }
		 * semantic: reverse the input buffer by width chunks of bytes
		 */
		struct element *arg;
		struct element *width;
		struct element *buffer;
		struct string *buf;
		struct string *result;
		int64_t w;
		size_t i;

		arg = mapGet(expr, "reverse");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get reverse argument");
			return NULL;
		}
		width = mapGet(arg, "width");
		if (width == NULL) {
			debug("can't get reverse width");
			return NULL;
		}
		width = reduce_numeric_expression(width);
		if ((width == NULL) || (width->type != ELEMENT_INTEGER))
			return NULL;
		w = intValue(width);
		if (w <= 0) {
			debug("reverse called with illegal width (%lld)",
			      (long long)w);
			return NULL;
		}
		buffer = mapGet(arg, "buffer");
		if (buffer == NULL) {
			debug("can't get reverse buffer");
			return NULL;
		}
		if (buffer->type != ELEMENT_STRING)
			return NULL;
		buf = stringValue(buffer);
		if ((buf->length % w) != 0) {
			debug("reverse illegal buffer length (%u, should "
			      "be a multiple of %u)",
			      (unsigned)buf->length, (unsigned)w);
			return NULL;
		}
		result = makeString(0, NULL);
		concatString(result, buf);
		for (i = 0; i < buf->length; i += w) {
			memcpy(result->content + i,
			       buf->content + (buf->length - i - w),
			       w);
		}
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(result);
	}

	/* pick-first-value */
	if (mapContains(expr, "pick-first-value")) {
		/*
		 * syntax := { "pick-first-value":
		 *             [ <data_expression>, ... ]
		 *           }
		 * semantic: evaluates expressions and return the first
		 * not null, return null if all are null
		 */
		struct element *arg;
		size_t i;

		arg = mapGet(expr, "pick-first-value");
		if ((arg == NULL) || (arg->type != ELEMENT_LIST)) {
			debug("can't get pick-first-value argument");
			return NULL;
		}
		for (i = 0; i < listSize(arg); i++) {
			struct element *item;

			item = listGet(arg, i);
			if (item == NULL) {
				debug("pick-first-value void argument (%u)",
				      (unsigned)i);
				return NULL;
			}
			if (item->type != ELEMENT_STRING)
				return NULL;
			if (stringValue(item)->length != 0) {
				if (literalp)
					*literalp = ISC_TRUE;
				return item;
			}
		}
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(makeString(0, NULL));
	}

	/* host-decl-name */
	if (mapContains(expr, "host-decl-name"))
		/*
		 * syntax := { "host-decl-name": null }
		 * semantic: return the name of the matching host
		 * declaration (aka revervation in kea) or null
		 */
		return NULL;

	/* leased-address */
	if (mapContains(expr, "leased-address"))
		/*
		 * syntax := { "leased-address": null }
		 * semantic: return the address of the assigned lease or
		 * log a message
		 */
		return NULL;

	/* config-option */
	if (mapContains(expr, "config-option"))
		/*
		 * syntax := { "config-option":
		 *             { "universe": <option_space_old>,
		 *               "name":  <option_name> }
		 *           }
		 * semantic: get universe/code option to send
		 */
		return NULL;

	/* null */
	if (mapContains(expr, "null"))
		/*
		 * syntax := { "null": null }
		 * semantic: return null
		 */
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(makeString(0, NULL));

	/* gethostname */
	if (mapContains(expr, "gethostname")) {
		/*
		 * syntax := { "gethostname": null }
		 * semantic: return gethostname
		 */
		char buf[300];

		if (gethostname(buf, sizeof(buf)) != 0) {
			debug("gethostname fails: %s", strerror(errno));
			return NULL;
		}
		if (literalp)
			*literalp = ISC_TRUE;
		return createString(makeString(-1, buf));
	}

	/* v6relay */
	if (mapContains(expr, "v6relay")) {
		/*
		 * syntax := { "v6relay":
		 *             { "relay": <numeric_expression>,
		 *               "relay-option" <data_expression> }
		 *           }
		 * semantic: relay is a counter from client, 0 is no-op,
		 * 1 is the relay closest to the client, etc, option
		 * is a dhcp6 option ans is return when found
		 */
		struct element *arg;
		struct element *relay;
		struct element *universe;
		struct element *name;
		struct option *option;
		int64_t r;
		char result[100];

		if (local_family != AF_INET6) {
			debug("get v6relay for DHCPv4");
			return NULL;
		}
		arg = mapGet(expr, "v6relay");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get v6relay argument");
			return NULL;
		}
		relay = mapGet(arg, "relay");
		if (relay == NULL) {
			debug("can't get v6relay relay");
			return NULL;
		}
		relay = reduce_numeric_expression(relay);
		if ((relay == NULL) || (relay->type != ELEMENT_INTEGER))
			return NULL;
		r = intValue(relay);
		if ((r < 0) || (r > 32)) {
			debug("v6relay called with illegal relay (%lld)",
			      (long long)r);
		}
		/* unfortunately Kea nested level is incompatible */
		if (r != 0)
			return NULL;
		arg = mapGet(arg, "relay-option");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get v6relay relay-option");
			return NULL;
		}
		universe = mapGet(arg, "universe");
		if ((universe == NULL) || (universe->type != ELEMENT_STRING)) {
			debug("can't get v6relay option universe");
			NULL;
		}
		name = mapGet(arg, "name");
		if ((name == NULL) || (name->type != ELEMENT_STRING)) {
			debug("can't get v6relay option name");
			return NULL;
		}
		option = option_lookup_name(stringValue(universe)->content,
					    stringValue(name)->content);
		if ((option == NULL) || (option->code == 0) ||
		    (strcmp(option->space->name, "dhcp6") != 0))
			return NULL;
		snprintf(result, sizeof(result),
			 "option[%u].hex", option->code);
		/* could be "relay6[%u].option[%u].hes", r, code */
		return createString(makeString(-1, result));
	}

	return NULL;
}

/*
 * numeric-expression :== EXTRACT_INT LPAREN data-expression
 *                                           COMMA number RPAREN |
 *                        NUMBER
 */

const char *
print_numeric_expression(struct element *expr, isc_boolean_t *lose)
{
	struct string *result;

	if (expr->type == ELEMENT_INTEGER) {
		char buf[20];

		snprintf(buf, sizeof(buf), "%lld", (long long)intValue(expr));
		result = makeString(-1, buf);
		return result->content;
	}

	/*
	 * From is_numeric_expression
	 */
	result = makeString(0, NULL);

	/* extract-int8 */
	if (mapContains(expr, "extract-int8")) {
		struct element *arg;

		appendString(result, "extract-int(");
		arg = mapGet(expr, "extract-int8");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???, 8)");
			return result->content;
		}
		appendString(result, print_numeric_expression(arg, lose));
		appendString(result, ", 8)");
		return result->content;
	}

	/* extract-int16 */
	if (mapContains(expr, "extract-int16")) {
		struct element *arg;

		appendString(result, "extract-int(");
		arg = mapGet(expr, "extract-int16");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???, 16)");
			return result->content;
		}
		appendString(result, print_numeric_expression(arg, lose));
		appendString(result, ", 16)");
		return result->content;
	}

	/* extract-int32 */
	if (mapContains(expr, "extract-int32")) {
		struct element *arg;

		appendString(result, "extract-int(");
		arg = mapGet(expr, "extract-int32");
		if (arg == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???, 32)");
			return result->content;
		}
		appendString(result, print_numeric_expression(arg, lose));
		appendString(result, ", 32)");
		return result->content;
	}

	/* lease-time */
	if (mapContains(expr, "lease-time"))
		return "lease-time";

	/* add */
	if (mapContains(expr, "add")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "add ");
		arg = mapGet(expr, "add");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") + (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* subtract */
	if (mapContains(expr, "subtract")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "subtract ");
		arg = mapGet(expr, "subtract");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") - (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* multiply */
	if (mapContains(expr, "multiply")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "multiply ");
		arg = mapGet(expr, "multiply");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") * (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* divide */
	if (mapContains(expr, "divide")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "divide ");
		arg = mapGet(expr, "divide");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") / (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* remainder */
	if (mapContains(expr, "remainder")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "remainder ");
		arg = mapGet(expr, "remainder");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") % (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* binary-and */
	if (mapContains(expr, "binary-and")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "binary-and ");
		arg = mapGet(expr, "binary-and");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") & (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* binary-or */
	if (mapContains(expr, "binary-or")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "binary-or ");
		arg = mapGet(expr, "binary-or");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") | (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* binary-xor */
	if (mapContains(expr, "binary-xor")) {
		struct element *arg;
		struct element *left;
		struct element *right;

		appendString(result, "binary-xor ");
		arg = mapGet(expr, "binary-xor");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		result = makeString(-1, "(");
		appendString(result, print_numeric_expression(left, lose));
		appendString(result, ") ^ (");
		right = mapGet(arg, "right");
		if (right == NULL) {
			*lose = ISC_TRUE;
			appendString(result, "???");
			return result->content;
		}
		appendString(result, print_numeric_expression(right, lose));
		appendString(result, ")");
		return result->content;
	}

	/* client-state */
	if (mapContains(expr, "client-state"))
		return "client-state";

	*lose = ISC_TRUE;
	appendString(result, "???");
	return result->content;
}

struct element *
reduce_numeric_expression(struct element *expr)
{
	/* trivial case: already done */
	if (expr->type == ELEMENT_INTEGER)
		return expr;

	/*
	 * From is_numeric_expression
	 */

	/* extract-int8 */
	if (mapContains(expr, "extract-int8")) {
		/*
		 * syntax := { "extract-int8": <data_expression> }
		 * semantic: extract from the evalkuated string buffer
		 * a number
		 */
		struct element *arg;

		arg = mapGet(expr, "extract-int8");
		if (arg == NULL) {
			debug("can't get extract-int8 argument");
			return NULL;
		}
		if (arg->type != ELEMENT_STRING)
			return NULL;
		if (stringValue(arg)->length == 0) {
			debug("extract-int8 from empty buffer");
			return createInt(0);
		}
		return createInt(*stringValue(arg)->content);
	}

	/* extract-int16 */
	if (mapContains(expr, "extract-int16")) {
		/*
		 * syntax := { "extract-int16": <data_expression> }
		 * semantic: extract from the evalkuated string buffer
		 * a number
		 */
		struct element *arg;
		uint16_t val;

		arg = mapGet(expr, "extract-int8");
		if (arg == NULL) {
			debug("can't get extract-int8 argument");
			return NULL;
		}
		if (arg->type != ELEMENT_STRING)
			return NULL;
		if (stringValue(arg)->length < 2) {
			debug("extract-int8 from too small buffer");
			return NULL;
		}
		memcpy(&val, stringValue(arg)->content, 2);
		val = ntohs(val);
		return createInt(val);
	}

	/* extract-int32 */
	if (mapContains(expr, "extract-int32")) {
		/*
		 * syntax := { "extract-int32": <data_expression> }
		 * semantic: extract from the evalkuated string buffer
		 * a number
		 */
		struct element *arg;
		uint32_t val;

		arg = mapGet(expr, "extract-int8");
		if (arg == NULL) {
			debug("can't get extract-int8 argument");
			return NULL;
		}
		if (arg->type != ELEMENT_STRING)
			return NULL;
		if (stringValue(arg)->length < 4) {
			debug("extract-int8 from too small buffer");
			return NULL;
		}
		memcpy(&val, stringValue(arg)->content, 4);
		val = ntohl(val);
		return createInt(val);
	}

	/* lease-time */
	if (mapContains(expr, "lease-time"))
		/*
		 * syntax := { "lease-time": null }
		 * semantic: return duration of the current lease, i.e
		 * the difference between expire time and now
		 */
		return NULL;

	/* add */
	if (mapContains(expr, "add")) {
		/*
		 * syntax := { "add":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "add");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get add argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get add left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get add right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		return createInt(intValue(left) + intValue(right));
	}

	/* subtract */
	if (mapContains(expr, "subtract")) {
		/*
		 * syntax := { "subtract":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "subtract");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get subtract argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get subtract left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get subtract right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		return createInt(intValue(left) - intValue(right));
	}

	/* multiply */
	if (mapContains(expr, "multiply")) {
		/*
		 * syntax := { "multiply":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "multiply");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get multiply argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get multiply left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get multiply right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		return createInt(intValue(left) * intValue(right));
	}

	/* divide */
	if (mapContains(expr, "divide")) {
		/*
		 * syntax := { "divide":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "divide");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get divide argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get divide left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get divide right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		if (intValue(right) == 0) {
			debug("divide by zero");
			return NULL;
		}
		return createInt(intValue(left) / intValue(right));
	}

	/* remainder */
	if (mapContains(expr, "remainder")) {
		/*
		 * syntax := { "remainder":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "remainder");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get remainder argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get remainder left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get remainder right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		if (intValue(right) == 0) {
			debug("remainder by zero");
			return NULL;
		}
		return createInt(intValue(left) / intValue(right));
	}

	/* binary-and */
	if (mapContains(expr, "binary-and")) {
		/*
		 * syntax := { "binary-and":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "binary-and");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get binary-and argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get binary-and left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get binary-and right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		return createInt(intValue(left) & intValue(right));
	}

	/* binary-or */
	if (mapContains(expr, "binary-or")) {
		/*
		 * syntax := { "binary-or":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "binary-or");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get binary-or argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get binary-or left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get binary-or right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		return createInt(intValue(left) | intValue(right));
	}

	/* binary-xor */
	if (mapContains(expr, "binary-xor")) {
		/*
		 * syntax := { "binary-xor":
		 *             { "left":  <boolean_expression>,
		 *               "right": <boolean_expression> }
		 *           }
		 * semantics: evaluate branches, return left plus right
		 * branches
		 */
		struct element *arg;
		struct element *left;
		struct element *right;

		arg = mapGet(expr, "binary-xor");
		if ((arg == NULL) || (arg->type != ELEMENT_MAP)) {
			debug("can't get binary-xor argument");
			return NULL;
		}
		left = mapGet(arg, "left");
		if (left == NULL) {
			debug("can't get binary-xor left branch");
			return NULL;
		}
		left = reduce_numeric_expression(left);
		if ((left == NULL) || (left->type != ELEMENT_INTEGER))
			return NULL;
		right = mapGet(arg, "right");
		if (right == NULL) {
			debug("can't get binary-xor right branch");
			return NULL;
		}
		right = reduce_numeric_expression(right);
		if ((right == NULL) || (right->type != ELEMENT_INTEGER))
			return NULL;
		return createInt(intValue(left) ^ intValue(right));
	}

	/* client-state */
	if (mapContains(expr, "client-state"))
		/*
		 * syntax := { "client-state": null }
		 * semantic: return client state
		 */
		return NULL;

	return NULL;
}

static struct element *
reduce_equal_expression(struct element *left, struct element *right)
{
	struct element *rleft;
	struct element *rright;
	struct string *sleft;
	struct string *sright;
	struct string *result;
	isc_boolean_t lliteral = ISC_FALSE;
	isc_boolean_t rliteral = ISC_FALSE;

	if (is_boolean_expression(left)) {
		if (!is_boolean_expression(right)) {
			debug("equal left is a boolean expression, "
			      "right is not");
			return createBool(ISC_FALSE);
		}
		rleft = reduce_boolean_expression(left);
		if (rleft == NULL)
			return NULL;
		rright = reduce_boolean_expression(right);
		if (rright == NULL)
			return NULL;
	} else if (is_numeric_expression(left)) {
		if (!is_numeric_expression(left)) {
			debug("equal left is a numeric expression, "
			      "right is not");
			return createBool(ISC_FALSE);
		}
		rleft = reduce_numeric_expression(left);
		if (rleft == NULL)
			return NULL;
		rright = reduce_numeric_expression(right);
		if (rright == NULL)
			return NULL;
	} else if (is_data_expression(left)) {
		if (!is_data_expression(right)) {
			debug("equal left is a data expression, right is not");
			return createBool(ISC_FALSE);
		}
		rleft = reduce_data_expression(left, &lliteral);
		if (rleft == NULL)
			return NULL;
		rright = reduce_data_expression(right, &rliteral);
		if (rright == NULL)
			return NULL;
	} else {
		debug("equal: can't type left expression");
		return NULL;
	}
	if (rleft->type == ELEMENT_BOOLEAN) {
		if (rright->type != ELEMENT_BOOLEAN)
			return NULL;
		return createBool(ISC_TF(boolValue(rleft) ==
					 boolValue(rright)));
	}
	if (rleft->type == ELEMENT_INTEGER) {
		if (rright->type != ELEMENT_INTEGER)
			return NULL;
		return createBool(ISC_TF(intValue(rleft) ==
					 intValue(rright)));
	}
	if ((left->type == ELEMENT_STRING) &&
	    (right->type == ELEMENT_STRING)) {
		sleft = stringValue(left);
		sright = stringValue(right);
		if (sleft->length != sright->length)
			return createBool(ISC_FALSE);
		return createBool(ISC_TF(memcmp(sleft->content,
						sright->content,
						sleft->length) == 0));
	}
	if (rleft->type != ELEMENT_STRING) {
		debug("equal left branch reduced to unexpected %s",
		      type2name(rleft->type));
		return NULL;
	}
	if (rright->type != ELEMENT_STRING) {
		debug("equal right branch reduced to unexpected %s",
		      type2name(rright->type));
		return NULL;
	}
	sleft = stringValue(rleft);
	sright = stringValue(rright);
	result = makeString(0, NULL);
	if (lliteral)
		concatString(result, quote(sleft));
	else
		concatString(result, sleft);
	appendString(result, " == ");
	if (rliteral)
		concatString(result, quote(sright));
	else
		concatString(result, sright);
	return createString(result);
}

const char *
print_expression(struct element *expr, isc_boolean_t *lose)
{
	if (expr->type == ELEMENT_BOOLEAN)
		return print_boolean_expression(expr, lose);
	if (expr->type == ELEMENT_INTEGER)
		return print_numeric_expression(expr, lose);
	if (expr->type == ELEMENT_STRING)
		return print_data_expression(expr, lose);
		
	if (is_boolean_expression(expr))
		return print_boolean_expression(expr, lose);
	if (is_numeric_expression(expr))
		return print_numeric_expression(expr, lose);
	if (is_data_expression(expr))
		return print_data_expression(expr, lose);
	*lose = ISC_TRUE;
	return "???";
}

static struct string *
quote(struct string *s)
{
	struct string *result;

	result = makeString(-1, "'");
	concatString(result, s);
	appendString(result, "'");
	return result;
}

static void
debug(const char* fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	fprintf(stderr, "\n");
	va_end(list);
}
