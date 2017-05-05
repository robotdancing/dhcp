#!/bin/sh

#set -x

if [ $# -ne 0 ]; then
	echo "usage: $0" >&2
	exit 1
fi

cd "$(dirname "$0")"
cd ..

file=dhcp3/master.dhcpd.conf
expected=dhcp3/kea.json
out=/tmp/pavlovs.out$$

../keama -4 -i  $file -o $out >&2
status=$?
if [ $status -eq 255 ]; then
	echo "Pavlov's config raised an error" >&2
	exit 1
fi

diff --brief $out $expected
if [ $? -ne 0 ]; then
	echo "Pavlov's config doesn't provide expected output" >&2
	exit 1
fi

exit $status
