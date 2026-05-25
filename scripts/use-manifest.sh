#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: ./scripts/use-manifest.sh chromium|firefox" >&2
  exit 1
fi

case "$1" in
  chromium)
    cp manifest.chromium.json manifest.json
    ;;
  firefox)
    cp manifest.firefox.json manifest.json
    ;;
  *)
    echo "Unknown target: $1" >&2
    exit 1
    ;;
esac

echo "manifest.json updated for $1"