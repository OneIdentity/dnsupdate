#! /bin/sh

set -ex

rm -rf autom4te.cache install-sh missing Makefile.in  install.sh
rm -rf ipwatchd/Makefile.in configure aclocal.m4 config.h.in 
rm -rf config.guess config.sub depcomp compile

autoreconf --install --verbose

