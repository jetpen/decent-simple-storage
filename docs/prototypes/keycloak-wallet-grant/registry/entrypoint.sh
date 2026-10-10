#!/bin/sh
set -eu
exec decent-registry node --host 0.0.0.0 --port 9000 --datastore-path /var/lib/decent/registry -v
