#!/bin/sh

#set -x

if [ $# -ne 0 ]; then
	echo "usage: $0" >&2
	exit 1
fi

cd "$(dirname "$0")"
cd ..

# Use a sample provided by Jordan Tinsley <jtinsley@lrecok.coop>

file=jt/dhcpd.conf
expected=jt/kea.json
out=/tmp/jt.out$$

../keama -4 -i  $file -o $out >&2
status=$?
if [ $status -eq 255 ]; then
	echo "JT config raised an error" >&2
	exit 1
fi

diff --brief $out $expected
if [ $? -ne 0 ]; then
	echo "JT config doesn't provide expected output" >&2
	exit 1
fi

exit $status
