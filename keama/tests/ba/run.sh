#!/bin/sh

#set -x

if [ $# -ne 0 ]; then
	echo "usage: $0" >&2
	exit 1
fi

cd "$(dirname "$0")"
cd ..

file=ba/dhcpd.conf
expected=ba/kea.json
out=/tmp/ba.out$$

../keama -4 -i  $file -o $out >&2
status=$?
if [ $status -eq 255 ]; then
	echo "BA config raised an error" >&2
	exit 1
fi

diff --brief $out $expected
if [ $? -ne 0 ]; then
	echo "BA config doesn't provide expected output" >&2
	exit 1
fi

exit $status
