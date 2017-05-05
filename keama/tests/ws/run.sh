#!/bin/sh

#set -x

if [ $# -ne 0 ]; then
	echo "usage: $0" >&2
	exit 1
fi

cd "$(dirname "$0")"
cd ..

file=ws/dhcpd.conf
expected=ws/kea.json
out=/tmp/ws.out$$

../keama -4 -i  $file -o $out >&2
status=$?
if [ $status -eq 255 ]; then
	echo "WS config raised an error" >&2
	exit 1
fi

diff --brief $out $expected
if [ $? -ne 0 ]; then
	echo "WS config doesn't provide expected output" >&2
	exit 1
fi

exit $status
