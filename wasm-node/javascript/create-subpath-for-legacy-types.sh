#!/bin/bash
#   https://github.com/smol-dot/smoldot/issues/787#issuecomment-1606157019
#

for SUBPATH in bytecode no-auto-bytecode worker
do
  mkdir -p $SUBPATH
  cp ./dist/mjs/public-types.d.ts ./$SUBPATH/
  cp ./dist/mjs/$SUBPATH-browser.d.ts ./$SUBPATH/index.d.ts
done
