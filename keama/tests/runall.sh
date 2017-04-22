#!/bin/sh

#set -x

cd "$(dirname "$0")"

for t in *.err* *.in*
do
	echo `basename $t`
	/bin/sh runone.sh $t
done
