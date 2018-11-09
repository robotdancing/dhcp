#!/bin/sh

#set -x

if [ $# -ne 0 ]; then
	echo "usage: $0" >&2
	exit 1
fi

cd "$(dirname "$0")"
cd ..

file=fordhcp/dhcpd.conf
expected=fordhcp/kea.json
out=/tmp/dans.out$$

../keama -4 -N -i  $file -o $out >&2
status=$?
if [ $status -eq 255 ]; then
	echo "Dan's config raised an error" >&2
	exit 1
fi

diff --brief $out $expected
if [ $? -ne 0 ]; then
	echo "Dan's config doesn't provide expected output" >&2
	exit 1
fi

exit $status
