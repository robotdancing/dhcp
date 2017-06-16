#!/bin/sh
# This very simple script pretends to be ip tool, used by linux script.
# It is called instead of the real ip tool from iproute2 package.
echo "ip $@" >> echo.log
