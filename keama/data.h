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

#ifndef DATA_H
#define DATA_H

#include <stdint.h>
#include <stdio.h>

/* From FreeBSD sys/queue.h */

/*
 * Tail queue declarations.
 */
#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue functions.
 */
#define	TAILQ_CONCAT(head1, head2, field) do {				\
	if (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
	}								\
} while (0)

#define	TAILQ_EMPTY(head)	((head)->tqh_first == NULL)

#define	TAILQ_FIRST(head)	((head)->tqh_first)

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	TAILQ_INIT(head) do {						\
	TAILQ_FIRST((head)) = NULL;					\
	(head)->tqh_last = &TAILQ_FIRST((head));			\
} while (0)

#define	TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if ((TAILQ_NEXT((elm), field) = TAILQ_NEXT((listelm), field)) != NULL)\
		TAILQ_NEXT((elm), field)->field.tqe_prev = 		\
		    &TAILQ_NEXT((elm), field);				\
	else {								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	}								\
	TAILQ_NEXT((listelm), field) = (elm);				\
	(elm)->field.tqe_prev = &TAILQ_NEXT((listelm), field);		\
} while (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	TAILQ_NEXT((elm), field) = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);		\
} while (0)

#define	TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((TAILQ_NEXT((elm), field) = TAILQ_FIRST((head))) != NULL)	\
		TAILQ_FIRST((head))->field.tqe_prev =			\
		    &TAILQ_NEXT((elm), field);				\
	else								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	TAILQ_FIRST((head)) = (elm);					\
	(elm)->field.tqe_prev = &TAILQ_FIRST((head));			\
} while (0)

#define	TAILQ_INSERT_TAIL(head, elm, field) do {			\
	TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &TAILQ_NEXT((elm), field);			\
} while (0)

#define	TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define	TAILQ_REMOVE(head, elm, field) do {				\
	if ((TAILQ_NEXT((elm), field)) != NULL)				\
		TAILQ_NEXT((elm), field)->field.tqe_prev = 		\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);		\
} while (0)

#define TAILQ_SWAP(head1, head2, type, field) do {			\
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)

/* From Kea src/lib/cc/data.h */

struct element;

#define ELEMENT_NONE		0
#define ELEMENT_INTEGER		1
#define ELEMENT_REAL		2
#define ELEMENT_BOOLEAN		3
#define ELEMENT_NULL		4
#define ELEMENT_STRING		5
#define ELEMENT_LIST		6
#define ELEMENT_MAP		7

/* Element string */
struct string {
	size_t length;		/* string length */
	char *content;		/* string data */
};

struct string *allocString(void);
struct string *makeString(size_t l, char *s);

/* Element list or map item */
struct item {
	char *key;		/* item key (for map) */
	struct element *value;	/* item value */
	TAILQ_ENTRY(item) next;	/* next item in chain */
};

struct item *allocItem(void);

/* Element list */
TAILQ_HEAD(list, item);

/* Element map */
TAILQ_HEAD(map, item);

/* Element value */
union value {
	int64_t int_value;		/* integer */
	double double_value;		/* real */
	int bool_value;			/* boolean */
        /**/				/* null */
	struct string string_value;	/* string */
	struct list list_value;		/* list */
	struct map map_value;		/* map */
};

/* Element */
struct element {
	int type;		/* element type (ELEMENT_XXX) */
	char *comment;		/* comment associated with this element */
	union value value;	/* value */
};

/* Value getters */
int64_t intValue(struct element *e);
double doubleValue(struct element *e);
int boolValue(struct element *e);
struct string *stringValue(struct element *e);
struct list *listValue(struct element *e);
struct map *mapValue(struct element *e);

/* Creators */
struct element *create(void);
struct element *createInt(int64_t i);
struct element *createDouble(double d);
struct element *createBool(int b);
struct element *createString(struct string *s);
struct element *createList(void);
struct element *createMap(void);

/* List functions */
struct element *listGet(struct element *l, int i);
void listSet(struct element *l, struct element *e, int i);
void listPush(struct element *l, struct element *e);
void listRemove(struct element *l, int i);
size_t listSize(struct element *l);

/* Map functions */
struct element *mapGet(struct element *m, char *k);
void mapSet(struct element *m, struct element *e, char *k);
void mapRemove(struct element *m, char *k);
int mapContains(struct element *m, char *k);
size_t mapSize(struct element *m);
void merge(struct element *m, struct element *o);

/* Tools */
char *type2name(int t);
int name2type(char *n);
void print(FILE *fp, struct element *e, int skip, unsigned indent);
void printList(FILE *fp, struct list *l, int skip, unsigned indent);
void printMap(FILE *fp, struct map *m, int skip, unsigned indent);
void printString(FILE *fp, struct string *s);

/* Inheritance */
int derive(struct element *parent, struct element *child, char *param);

#endif /* DATA_H */
