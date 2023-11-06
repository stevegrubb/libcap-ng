#! /bin/sh
set -x -e
# --no-recursive is available only in recent autoconf versions
touch NEWS
autoreconf -fv --install
