/*
 * Copyright(c) 2017 by Internet Systems Consortium, Inc.("ISC")
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

#include "data.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define KEAMA_USAGE "Usage: keama [-4|-6] [-i input-file] [-o output-file]"

static void
usage(const char *sfmt, const char *sarg) {
	if (sfmt != NULL) {
		fprintf(stderr, sfmt, sarg);
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "%s\n", KEAMA_USAGE);
	exit(1);
}

int local_family = 0;
char *input_file = NULL;
char *output_file = NULL;
FILE *input = NULL;
FILE *output = NULL;

static const char use_noarg[] = "No argument for command: %s";

int 
main(int argc, char **argv) {
	int i;
	size_t cnt = 0;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-4") == 0)
			local_family = AF_INET;
		else if (strcmp(argv[i], "-6") == 0)
			local_family = AF_INET6;
		else if (strcmp(argv[i], "-i") == 0) {
			if (++i == argc)
				usage(use_noarg, argv[i -  1]);
			input_file = argv[i];
		} else if (strcmp(argv[i], "-o") == 0) {
			if (++i == argc)
				usage(use_noarg, argv[i -  1]);
			output_file = argv[i];
 		} else 
			usage("Unknown command: %s", argv[i]);
	}

	if (input_file) {
		input = fopen(input_file, "r");
		if (input == NULL)
			usage("Cannot open '%s' for reading", input_file);
	} else
		input = stdin;
	if (output_file) {
		output = fopen(output_file, "w");
		if (output == NULL)
			usage("Cannot open '%s' for writing", output_file);
	} else
		output = stdout;

	exit(cnt);
}
