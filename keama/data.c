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
 *   http://www.isc.org/
 */

#include "data.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct string *
allocString(void)
{
	struct string *result;

	result = (struct string *)malloc(sizeof(struct string));
	assert(result != NULL);
	memset(result, 0, sizeof(struct string));

	return result;
}

struct string *
makeString(int l, const char *s)
{
	struct string *result;

	result = allocString();
	if (l < 0)
		result->length = strlen(s);
	else
		result->length = (size_t)l;
	if (result->length > 0) {
		result->content = (char *)malloc(result->length + 1);
		assert(result->content != NULL);
		memcpy(result->content, s, result->length);
		result->content[result->length] = 0;
	}

	return result;
}

void
appendString(struct string *s, const char *a)
{
	size_t n;

	assert(s != NULL);

	if (a == NULL)
		return;
	n = strlen(a);
	if (n == 0)
		return;
	s->content = (char *)realloc(s->content, s->length + n + 1);
	assert(s->content != NULL);
	memcpy(s->content + s->length, a, n);
	s->length += n;
	s->content[s->length] = 0;
}

isc_boolean_t
eqString(const struct string *s, const struct string *o)
{
	assert(s != NULL);
	assert(o != NULL);

	if (s->length != o->length)
		return ISC_FALSE;
	if (s->length == 0)
		return ISC_TRUE;
	return ISC_TF(memcmp(s->content, o->content, s->length) == 0);
}

struct comment *
createComment(const char *line)
{
	struct comment *comment;

	assert(line != NULL);

	comment = (struct comment *)malloc(sizeof(struct comment));
	assert(comment != NULL);
	memset(comment, 0, sizeof(struct comment));

	comment->line = strdup(line);

	return comment;
}

int64_t
intValue(const struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_INTEGER);
	return e->value.int_value;
}

double
doubleValue(const struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_REAL);
	return e->value.double_value;
}

isc_boolean_t
boolValue(const struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_BOOLEAN);
	/* could check if 0 or 1 */
	return e->value.bool_value;
}

struct string *
stringValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_STRING);
	return &e->value.string_value;
}

struct list *
listValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_LIST);
	return &e->value.list_value;
}

struct map *
mapValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_MAP);
	return &e->value.map_value;
}

struct element *
create(void)
{
	struct element *elem;

	elem = (struct element *)malloc(sizeof(struct element));
	assert(elem != NULL);
	memset(elem, 0, sizeof(struct element));
	TAILQ_INIT(&elem->comments);

	return elem;
}

struct element *
createInt(int64_t i)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_INTEGER;
	elem->value.int_value = i;

	return elem;
}

struct element *
createDouble(double d)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_REAL;
	elem->value.double_value = d;

	return elem;
}

struct element *
createBool(isc_boolean_t b)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_BOOLEAN;
	elem->value.bool_value = b;

	return elem;
}

struct element *
createNull(void)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_NULL;

	return elem;
}

struct element *
createString(const struct string *s)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_STRING;
	elem->value.string_value = *s;

	return elem;
}

struct element *
createList(void)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_LIST;
	TAILQ_INIT(&elem->value.list_value);

	return elem;
}

struct element *
createMap(void)
{
	struct element *elem;

	elem = create();
	elem->type = ELEMENT_MAP;
	TAILQ_INIT(&elem->value.map_value);

	return elem;
}

struct element *
listGet(struct element *l, int i)
{
	struct element *elem;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(i >= 0);

	elem = TAILQ_FIRST(&l->value.list_value);
	assert(elem != NULL);
	assert(elem->key == NULL);

	for (unsigned j = i; j > 0; --j) {
		elem = TAILQ_NEXT(elem, next);
		assert(elem != NULL);
		assert(elem->key == NULL);
	}

	return elem;
}

void
listSet(struct element *l, struct element *e, int i)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(e != NULL);
	assert(i >= 0);

	if (i == 0) {
		TAILQ_INSERT_HEAD(&l->value.list_value, e, next);
	} else {
		struct element *prev;
		
		prev = TAILQ_FIRST(&l->value.list_value);
		assert(prev != NULL);
		assert(prev->key == NULL);

		for (unsigned j = i; j > 1; --j) {
			prev = TAILQ_NEXT(prev, next);
			assert(prev != NULL);
			assert(prev->key == NULL);
		}

		TAILQ_INSERT_AFTER(&l->value.list_value, prev, e, next);
	}
}

void
listPush(struct element *l, struct element *e)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(e != NULL);

	TAILQ_INSERT_TAIL(&l->value.list_value, e, next);
}

void
listRemove(struct element *l, int i)
{
	struct element *elem;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(i >= 0);

	elem = TAILQ_FIRST(&l->value.list_value);
	assert(elem != NULL);
	assert(elem->key == NULL);

	for (unsigned j = i; j > 0; --j) {
		elem = TAILQ_NEXT(elem, next);
		assert(elem != NULL);
		assert(elem->key == NULL);
	}

	TAILQ_REMOVE(&l->value.list_value, elem, next);
}

size_t
listSize(const struct element *l)
{
	struct element *elem;
	size_t cnt;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);

	cnt = 0;
	TAILQ_FOREACH(elem, &l->value.list_value, next) {
		assert(elem->key == NULL);
		cnt++;
	}

	return cnt;
}

void
concat(struct element *l, struct element *o)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(o != NULL);
	assert(o->type == ELEMENT_LIST);

	TAILQ_CONCAT(&l->value.list_value, &o->value.list_value, next);
}

struct element *
mapGet(struct element *m, const char *k)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(elem, &m->value.map_value, next) {
		assert(elem->key != NULL);
		if (strcmp(elem->key, k) == 0)
			break;
	}

	return elem;
}

void
mapSet(struct element *m, struct element *e, const char *k)
{
	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(e != NULL);
	assert(k != NULL);
#if 0
	assert(mapGet(m, k) == NULL);
#endif
	e->key = strdup(k);
	assert(e->key != NULL);
	TAILQ_INSERT_TAIL(&m->value.map_value, e, next);
}

void
mapRemove(struct element *m, const char *k)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(elem, &m->value.map_value, next) {
		assert(elem->key != NULL);
		if (strcmp(elem->key, k) == 0)
			break;
	}

	assert(elem != NULL);
	TAILQ_REMOVE(&m->value.map_value, elem, next);
}

isc_boolean_t
mapContains(const struct element *m, const char *k)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(elem, &m->value.map_value, next) {
		assert(elem->key != NULL);
		if (strcmp(elem->key, k) == 0)
			break;
	}

	return ISC_TF(elem != NULL);
}

size_t
mapSize(const struct element *m)
{
	struct element *elem;
	size_t cnt;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);

	cnt = 0;
	TAILQ_FOREACH(elem, &m->value.map_value, next) {
		assert(elem->key != NULL);
		cnt++;
	}

	return cnt;
}

void
merge(struct element *m, struct element *o)
{
	struct element *elem;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(o != NULL);
	assert(o->type == ELEMENT_MAP);

	TAILQ_FOREACH(elem, &o->value.map_value, next) {
		assert(elem->key != NULL);
		TAILQ_REMOVE(&o->value.map_value, elem, next);
		if (!mapContains(m, elem->key)) {
			TAILQ_INSERT_TAIL(&m->value.map_value, elem, next);
		}
	}
}

const char *
type2name(int t)
{
	switch (t) {
	case ELEMENT_NONE:
		return "not initialized?";
	case ELEMENT_INTEGER:
		return "integer";
	case ELEMENT_REAL:
		return "real";
	case ELEMENT_BOOLEAN:
		return "boolean";
	case ELEMENT_NULL:
		return "(unused) null";
	case ELEMENT_STRING:
		return "string";
	case ELEMENT_LIST:
		return "list";
	case ELEMENT_MAP:
		return "map";
	default:
#if 0
		assert(0);
#endif
		return "unknown?";
	}
}

int
name2type(const char *n)
{
	assert(n != NULL);
	if (strcmp(n, "integer") == 0)
		return ELEMENT_INTEGER;
	if (strcmp(n, "real") == 0)
		return ELEMENT_REAL;
	if (strcmp(n, "boolean") == 0)
		return ELEMENT_BOOLEAN;
	if (strcmp(n, "null") == 0)
		return ELEMENT_NULL;
	if (strcmp(n, "string") == 0)
		return ELEMENT_STRING;
	if (strcmp(n, "list") == 0)
		return ELEMENT_LIST;
	if (strcmp(n, "map") == 0)
		return ELEMENT_MAP;
#if 0
	assert(0);
#endif
	return ELEMENT_NONE;
}

void
print(FILE *fp, const struct element *e, isc_boolean_t skip, unsigned indent)
{
	assert(fp != NULL);
	assert(e != NULL);

	switch (e->type) {
	case ELEMENT_LIST:
		printList(fp, &e->value.list_value, skip, indent);
		return;
	case ELEMENT_MAP:
		printMap(fp, &e->value.map_value, skip, indent);
		return;
	case ELEMENT_STRING:
		printString(fp, &e->value.string_value);
		return;
	case ELEMENT_INTEGER:
		fprintf(fp, "%lld", (long long)e->value.int_value);
		return;
	case ELEMENT_REAL:
		fprintf(fp, "%f", e->value.double_value);
		return;
	case ELEMENT_BOOLEAN:
		if (e->value.bool_value)
			fprintf(fp, "true");
		else
			fprintf(fp, "false");
		return;
	case ELEMENT_NULL:
		fprintf(fp, "null");
		return;
	default:
		assert(0);
	}
}

static void
addIndent(FILE *fp, int skip, unsigned indent)
{
	unsigned sp;

	if (skip) {
		fprintf(fp, "//");
		if (indent > 2)
			for (sp = 0; sp < indent - 2; ++sp)
				fprintf(fp, " ");
	} else
		for (sp = 0; sp < indent; ++sp)
			fprintf(fp, " ");
}	

void
printList(FILE *fp, const struct list *l, isc_boolean_t skip, unsigned indent)
{
	struct element *elem;
	struct comment *comment;
	isc_boolean_t first;

	assert(fp != NULL);
	assert(l != NULL);

	if (TAILQ_EMPTY(l)) {
		fprintf(fp, "[ ]");
		return;
	}

	fprintf(fp, "[\n");
	first = ISC_TRUE;
	TAILQ_FOREACH(elem, l, next) {
		isc_boolean_t skip_elem = skip;
		assert(elem->key == NULL);
		if (!skip)
			skip_elem = elem->skip;
		if (!first)
			fprintf(fp, ",\n");
		first = ISC_FALSE;
		TAILQ_FOREACH(comment, &elem->comments, next) {
			addIndent(fp, skip_elem, indent + 2);
			fprintf(fp, "%s\n", comment->line);
		}
		addIndent(fp, skip_elem, indent + 2);
		print(fp, elem, skip_elem, indent + 2);
	}
	fprintf(fp, "\n");
	addIndent(fp, skip, indent);
	fprintf(fp, "]");
}

void
printMap(FILE *fp, const struct map *m, isc_boolean_t skip, unsigned indent)
{
	struct element *elem;
	struct comment *comment;
	isc_boolean_t first;

	assert(fp != NULL);
	assert(m != NULL);

	if (TAILQ_EMPTY(m)) {
		fprintf(fp, "{ }");
		return;
	}

	fprintf(fp, "{\n");
	first = ISC_TRUE;
	TAILQ_FOREACH(elem, m, next) {
		isc_boolean_t skip_elem = skip;
		assert(elem->key != NULL);
		if (!skip)
			skip_elem = elem->skip;
		if (!first)
			fprintf(fp, ",\n");
		first = ISC_FALSE;
		TAILQ_FOREACH(comment, &elem->comments, next) {
			addIndent(fp, skip_elem, indent + 2);
			fprintf(fp, "%s\n", comment->line);
		}
		addIndent(fp, skip_elem, indent + 2);
		fprintf(fp, "\"%s\": ", elem->key);
		print(fp, elem, skip_elem, indent + 2);
	}
	fprintf(fp, "\n");
	addIndent(fp, skip, indent);
	fprintf(fp, "}");
}

void
printString(FILE *fp, const struct string *s)
{
	size_t i;

	assert(fp != NULL);
	assert(s != NULL);

	fprintf(fp, "\"");
	for (i = 0; i < s->length; ++i) {
		char c = *(s->content + i);

		switch (c) {
		case '"':
			fprintf(fp, "\\\"");
			break;
		case '\\':
			fprintf(fp, "\\\\");
			break;
		case '\b':
			fprintf(fp, "\\b");
			break;
		case '\f':
			fprintf(fp, "\\f");
			break;
		case '\n':
			fprintf(fp, "\\n");
			break;
		case '\r':
			fprintf(fp, "\\r");
			break;
		case '\t':
			fprintf(fp, "\\t");
			break;
		default:
			if ((c >= 0) && (c < 0x20)) {
				fprintf(fp, "\\u%04x", (unsigned)c & 0xff);
			} else {
				fprintf(fp, "%c", c);
			}
		}
	}
	fprintf(fp, "\"");
}

isc_boolean_t
derive(struct element *parent, struct element *child, const char *param)
{
	struct element *x;
	struct element *y;

	assert(parent != NULL);
	assert(parent->type == ELEMENT_MAP);
	assert(child != NULL);
	assert(child->type == ELEMENT_MAP);
	assert(param != NULL);

	x = mapGet(parent, param);
	if (x == NULL)
		return ISC_FALSE;
	y = mapGet(child, param);
	if (y != NULL)
		return ISC_FALSE;
	mapSet(child, x, param);
	return ISC_TRUE;
}
