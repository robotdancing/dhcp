#!/bin/sh

#set -x

cd "$(dirname "$0")"

echo subdirs:
for d in fordhcp dhcp3 czb ws ba gcet jt
do
	echo $d
	/bin/sh $d/run.sh
done
/bin/sh samples/runall.sh

echo tests:
for t in *.err* *.in*
do
	echo `basename $t`
	/bin/sh runone.sh $t
done
