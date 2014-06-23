#!/usr/bin/env bash
#
# Voxer build script
#
# Author: Dave Eddy <dave@daveeddy.com>
# Date: 6/19/14

out=$1
arch=${2:-x64}

if [[ -z $out ]]; then
	echo 'error: out directory must be specified as the first argument'
	exit 1
fi

if [[ $arch != x64 ]]; then
	echo 'error: only x64 builds supported for stud' >&2
	exit 1
fi

echo '> running make clean'
make clean > /dev/null

echo '> pulling git submodules'
git submodule update --init --recursive

echo '> running make'
make > /dev/null || exit 1

echo "> copying files to $out"
mkdir -p "$out/bin"
mv stud "$out/bin" || exit 1

echo "> stud built in $SECONDS seconds, saved to $out"
echo

sha256sum "$out/bin/stud"
