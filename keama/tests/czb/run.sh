#!/bin/sh

#set -x

if [ $# -ne 0 ]; then
	echo "usage: $0" >&2
	exit 1
fi

cd "$(dirname "$0")"
cd ..

file=czb/dhcpd.conf
expected=czb/kea.json
out=/tmp/czb.out$$

../keama -4 -N -i  $file -o $out >&2
status=$?
if [ $status -eq 255 ]; then
	echo "Czb config raised an error" >&2
	exit 1
fi

diff --brief $out $expected
if [ $? -ne 0 ]; then
	echo "Czb config doesn't provide expected output" >&2
	exit 1
fi

exit $status
