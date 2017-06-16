#!/bin/sh
# This very simple script. It prints out the reason passed to echo.log file.
# This script is used in dhclient_tests.sh (and possibly other tests as well).
echo "reason=${reason}" > ./echo.log
