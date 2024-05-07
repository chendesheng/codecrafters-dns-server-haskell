#!/bin/sh
#
# DON'T EDIT THIS!
#
# CodeCrafters uses this file to test your code. Don't make any changes here!
#
# DON'T EDIT THIS!
set -e

( cd $(dirname "$0") &&
	cabal install --installdir . --overwrite-policy=always)

exec "$(dirname $0)/hs-dns-server-exe" "$@"