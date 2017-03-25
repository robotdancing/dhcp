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
makeString(size_t l, char *s)
{
	struct string *result;

	result = allocString();
	result->length = l;
	if (l > 0) {
		result->content = (char *)malloc(l + 1);
		assert(result->content != NULL);
		memcpy(result->content, s, l);
		result->content[l] = 0;
	}

	return result;
}

struct item *
allocItem(void)
{
	struct item *result;

	result = (struct item *)malloc(sizeof(struct item));
	assert(result != NULL);
	memset(result, 0, sizeof(struct item));

	return result;
}

int64_t
intValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_INTEGER);
	return e->value.int_value;
}

double
doubleValue(struct element *e)
{
	assert(e != NULL);
	assert(e->type == ELEMENT_REAL);
	return e->value.double_value;
}

int
boolValue(struct element *e)
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
	struct element *result;

	result = (struct element *)malloc(sizeof(struct element));
	assert(result != NULL);
	memset(result, 0, sizeof(struct element));

	return result;
}

struct element *
createInt(int64_t i)
{
	struct element *result;

	result = create();
	result->type = ELEMENT_INTEGER;
	result->value.int_value = i;

	return result;
}

struct element *
createDouble(double d)
{
	struct element *result;

	result = create();
	result->type = ELEMENT_REAL;
	result->value.double_value = d;

	return result;
}

struct element *
createBool(int b)
{
	struct element *result;

	result = create();
	result->type = ELEMENT_BOOLEAN;
	result->value.bool_value = b;

	return result;
}

struct element *
createString(struct string *s)
{
	struct element *result;

	result = create();
	result->type = ELEMENT_STRING;
	result->value.string_value = *s;

	return result;
}

struct element *
createList(void)
{
	struct element *result;

	result = create();
	result->type = ELEMENT_LIST;
	TAILQ_INIT(&result->value.list_value);

	return result;
}

struct element *
createMap(void)
{
	struct element *result;

	result = create();
	result->type = ELEMENT_MAP;
	TAILQ_INIT(&result->value.map_value);

	return result;
}

struct element *
listGet(struct element *l, int i)
{
	struct item *item;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(i >= 0);

	item = TAILQ_FIRST(&l->value.list_value);
	assert(item != NULL);
	assert(item->key == NULL);
	assert(item->value != NULL);

	for (unsigned j = i; j > 0; --j) {
		item = TAILQ_NEXT(item, next);
		assert(item != NULL);
		assert(item->key == NULL);
		assert(item->value != NULL);
	}

	return item->value;
}

void
listSet(struct element *l, struct element *e, int i)
{
	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(e != NULL);
	assert(i >= 0);

	if (i == 0) {
		struct item *item;

		item = allocItem();
		item->value = e;
		TAILQ_INSERT_HEAD(&l->value.list_value, item, next);
	} else {
		struct item *prev;
		struct item *item;
		
		prev = TAILQ_FIRST(&l->value.list_value);
		assert(prev != NULL);
		assert(prev->key == NULL);
		assert(prev->value != NULL);

		for (unsigned j = i; j > 1; --j) {
			prev = TAILQ_NEXT(prev, next);
			assert(prev != NULL);
			assert(prev->key == NULL);
			assert(prev->value != NULL);
		}

		item = allocItem();
		item->value = e;
		TAILQ_INSERT_AFTER(&l->value.list_value, prev, item, next);
	}
}

void
listPush(struct element *l, struct element *e)
{
	struct item *item;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(e != NULL);

	item = allocItem();
	item->value = e;
	TAILQ_INSERT_TAIL(&l->value.list_value, item, next);
}

void
listRemove(struct element *l, int i)
{
	struct item *item;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);
	assert(i >= 0);

	item = TAILQ_FIRST(&l->value.list_value);
	assert(item != NULL);
	assert(item->key == NULL);
	assert(item->value != NULL);

	for (unsigned j = i; j > 0; --j) {
		item = TAILQ_NEXT(item, next);
		assert(item != NULL);
		assert(item->key == NULL);
	}

	TAILQ_REMOVE(&l->value.list_value, item, next);
}

size_t
listSize(struct element *l)
{
	struct item *item;
	size_t cnt;

	assert(l != NULL);
	assert(l->type == ELEMENT_LIST);

	cnt = 0;
	TAILQ_FOREACH(item, &l->value.list_value, next) {
		assert(item->key == NULL);
		assert(item->value != NULL);
		cnt++;
	}

	return cnt;
}

struct element *
mapGet(struct element *m, char *k)
{
	struct item *item;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(item, &m->value.map_value, next) {
		assert(item->key != NULL);
		assert(item->value != NULL);
		if (strcmp(item->key, k) == 0)
			break;
	}

	return item->value;
}

void
mapSet(struct element *m, struct element *e, char *k)
{
	struct item *item;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(e != NULL);
	assert(k != NULL);
#if 0
	assert(mapGet(m, k) == NULL);
#endif

	item = allocItem();
	item->key = strdup(k);
	assert(item->key != NULL);
	assert(item->value != NULL);
	item->value = e;
	TAILQ_INSERT_TAIL(&m->value.map_value, item, next);
}

void
mapRemove(struct element *m, char *k)
{
	struct item *item;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(item, &m->value.map_value, next) {
		assert(item->key != NULL);
		assert(item->value != NULL);
		if (strcmp(item->key, k) == 0)
			break;
	}

	assert(item != NULL);
	TAILQ_REMOVE(&m->value.map_value, item, next);
}

int
mapContains(struct element *m, char *k)
{
	struct item *item;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(k != NULL);

	TAILQ_FOREACH(item, &m->value.map_value, next) {
		assert(item->key != NULL);
		assert(item->value != NULL);
		if (strcmp(item->key, k) == 0)
			break;
	}

	return item != NULL;
}

size_t
mapSize(struct element *m)
{
	struct item *item;
	size_t cnt;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);

	cnt = 0;
	TAILQ_FOREACH(item, &m->value.map_value, next) {
		assert(item->key != NULL);
		assert(item->value != NULL);
		cnt++;
	}

	return cnt;
}

void
merge(struct element *m, struct element *o)
{
	struct item *item;

	assert(m != NULL);
	assert(m->type == ELEMENT_MAP);
	assert(o != NULL);
	assert(o->type == ELEMENT_MAP);

	TAILQ_FOREACH(item, &o->value.map_value, next) {
		assert(item->key != NULL);
		assert(item->value != NULL);
		if (!mapContains(m, item->key))
			mapSet(m, item->value, item->key);
	}
}

char *
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
name2type(char *n)
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
print(FILE *fp, struct element *e, int skip, unsigned indent)
{
	assert(fp != NULL);
	assert(e != NULL);

	// TODO comments

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

void
printList(FILE *fp, struct list *l, int skip, unsigned indent)
{
	struct item *item;
	unsigned sp;
	int first;

	assert(fp != NULL);
	assert(l != NULL);

	if (TAILQ_EMPTY(l)) {
		fprintf(fp, "[ ]");
		return;
	}

	fprintf(fp, "[\n");
	first = 1;
	TAILQ_FOREACH(item, l, next) {
		assert(item->key == NULL);
		assert(item->value != NULL);
		if (!first)
			fprintf(fp, ",\n");
		first = 0;
		if (skip)
			fprintf(fp, "//");
		for (sp = 0; sp < indent; ++sp)
			fprintf(fp, " ");
		if (!skip)
			fprintf(fp, "  ");
		print(fp, item->value, skip, indent + 2);
	}
	fprintf(fp, "\n");
	if (skip) {
		fprintf(fp, "//");
		if (indent > 2)
			for (sp = 0; sp < indent - 2; ++sp)
				fprintf(fp, " ");
	} else
		for (sp = 0; sp < indent; ++sp)
			fprintf(fp, " ");
	fprintf(fp, "]");
}

void
printMap(FILE *fp, struct map *m, int skip, unsigned indent)
{
	struct item *item;
	unsigned sp;
	int first;

	assert(fp != NULL);
	assert(m != NULL);

	if (TAILQ_EMPTY(m)) {
		fprintf(fp, "{ }");
		return;
	}

	fprintf(fp, "{\n");
	first = 1;
	TAILQ_FOREACH(item, m, next) {
		assert(item->key != NULL);
		assert(item->value != NULL);
		if (!first)
			fprintf(fp, ",\n");
		first = 0;
		if (skip)
			fprintf(fp, "//");
		for (sp = 0; sp < indent; ++sp)
			fprintf(fp, " ");
		if (!skip)
			fprintf(fp, "  ");
		fprintf(fp, "\"%s\": ", item->key);
		print(fp, item->value, skip, indent + 2);
	}
	fprintf(fp, "\n");
	if (skip) {
		fprintf(fp, "//");
		if (indent > 2)
			for (sp = 0; sp < indent - 2; ++sp)
				fprintf(fp, " ");
	} else
		for (sp = 0; sp < indent; ++sp)
			fprintf(fp, " ");
	fprintf(fp, "}");
}

void
printString(FILE *fp, struct string *s)
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

int
derive(struct element *parent, struct element *child, char *param)
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
		return 0;
	y = mapGet(child, param);
	if (y != NULL)
		return 0;
	mapSet(child, x, param);
	return 1;
}
